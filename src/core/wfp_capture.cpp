#include "wfp_capture.h"

#ifdef Q_OS_WIN

#include "http_parser.h"
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QStandardPaths>
#include <QDateTime>
#include <QCoreApplication>
#include <QDir>
#include <QRegularExpression>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Include WinDivert header with custom import macro
#define WINDIVERTEXPORT
#include "WinDivert.h"

static void wfpLog(const QString &msg) {
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/wfp_capture.log";
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream ts(&f);
        ts << QDateTime::currentDateTime().toString("hh:mm:ss.zzz") << " " << msg << "\n";
    }
}

// ============================================================================
// WfpCaptureThread
// ============================================================================

WfpCaptureThread::WfpCaptureThread(void *handle, const WinDivertApi *api, QObject *parent)
    : QThread(parent), m_handle(handle), m_api(api)
{
}

void WfpCaptureThread::requestStop()
{
    m_stopRequested = true;
    if (m_handle) {
        // WinDivert shutdown will unblock the recv call
        // We cast to the function pointer type via the DLL handle
        // The actual shutdown is done in WfpCapture::stop()
    }
}

void WfpCaptureThread::run()
{
    if (!m_handle || !m_api) return;

    wfpLog("WfpCaptureThread::run() started");

    UINT8 packet[65535];
    UINT recvLen = 0;
    WINDIVERT_ADDRESS addr;

    while (!m_stopRequested) {
        memset(&addr, 0, sizeof(addr));
        recvLen = 0;

        BOOL ok = m_api->recv(m_handle, packet, sizeof(packet), &recvLen, &addr);
        if (!ok) {
            if (m_stopRequested) break;
            DWORD err = GetLastError();
            if (err == 995 || err == 1229) break;  // ERROR_OPERATION_ABORTED / shutdown
            continue;
        }
        if (recvLen == 0) continue;

        m_packetCount++;

        // Periodically emit stale streams
        if ((m_packetCount & 0x1F) == 0) {
            emitStaleStreams();
        }

        // Parse the packet
        WINDIVERT_IPHDR *ipHdr = nullptr;
        WINDIVERT_IPV6HDR *ip6Hdr = nullptr;
        WINDIVERT_TCPHDR *tcpHdr = nullptr;
        WINDIVERT_UDPHDR *udpHdr = nullptr;
        UINT8 protocol = 0;
        PVOID payload = nullptr;
        UINT payloadLen = 0;

        m_api->parsePacket(packet, recvLen, &ipHdr, &ip6Hdr, &protocol,
                nullptr, nullptr, &tcpHdr, &udpHdr,
                &payload, &payloadLen, nullptr, nullptr);

        bool outbound = (addr.Outbound != 0);
        bool loopback = (addr.Loopback != 0);

        // Skip loopback traffic to port 9527 (our proxy)
        if (loopback) {
            if (tcpHdr) {
                UINT16 srcPort = ntohs(tcpHdr->SrcPort);
                UINT16 dstPort = ntohs(tcpHdr->DstPort);
                if (srcPort == 9527 || dstPort == 9527) {
                    continue;
                }
            }
            if (udpHdr) {
                UINT16 srcPort = ntohs(udpHdr->SrcPort);
                UINT16 dstPort = ntohs(udpHdr->DstPort);
                if (srcPort == 9527 || dstPort == 9527) {
                    continue;
                }
            }
        }

        if (tcpHdr && payloadLen > 0) {
            if (ipHdr) {
                processTcpPacket(ipHdr, tcpHdr, (const quint8 *)payload, payloadLen, outbound);
            } else if (ip6Hdr) {
                processTcpPacketV6(ip6Hdr, tcpHdr, (const quint8 *)payload, payloadLen, outbound);
            }
        } else if (tcpHdr && (tcpHdr->Fin || tcpHdr->Rst)) {
            // FIN/RST with no payload - check for stream completion
            char srcBuf[64], dstBuf[64];
            if (ipHdr) {
                m_api->formatIPv4(ipHdr->SrcAddr, srcBuf, sizeof(srcBuf));
                m_api->formatIPv4(ipHdr->DstAddr, dstBuf, sizeof(dstBuf));
            } else if (ip6Hdr) {
                m_api->formatIPv6(ip6Hdr->SrcAddr, srcBuf, sizeof(srcBuf));
                m_api->formatIPv6(ip6Hdr->DstAddr, dstBuf, sizeof(dstBuf));
            } else {
                continue;
            }
            UINT16 srcPort = ntohs(tcpHdr->SrcPort);
            UINT16 dstPort = ntohs(tcpHdr->DstPort);
            WfpConnKey key = WfpConnKey::canonical(QString(srcBuf), srcPort, QString(dstBuf), dstPort);
            QMutexLocker lock(&m_mutex);
            auto it = m_streams.find(key);
            if (it != m_streams.end()) {
                checkStreamComplete(key, it.value());
            }
        }
    }

    // Emit remaining streams
    QMutexLocker lock(&m_mutex);
    for (auto it = m_streams.begin(); it != m_streams.end(); ++it) {
        WfpTcpStream &stream = it.value();
        if (!stream.requestData.isEmpty() || !stream.sniHost.isEmpty()) {
            RequestItem item;
            item.id = m_nextId++;
            item.timestamp = QDateTime::fromMSecsSinceEpoch(stream.startTime);
            item.host = stream.sniHost.isEmpty() ? stream.dstIp : stream.sniHost;
            item.protocol = stream.isHttps ? "HTTPS" : "HTTP";
            item.duration = QDateTime::currentMSecsSinceEpoch() - stream.startTime;
            item.requestSize = stream.requestData.size();
            item.responseSize = stream.responseData.size();

            if (stream.isHttps) {
                item.method = "CONNECT";
                item.path = stream.sniHost + ":" + QString::number(stream.dstPort);
                item.url = "https://" + item.host;
            } else {
                if (!stream.requestData.isEmpty()) {
                    HttpParser::parseRequest(stream.requestData, item);
                    if (!stream.responseData.isEmpty()) {
                        HttpParser::parseResponse(stream.responseData, item);
                    }
                }
            }
            emit httpCaptured(item);
        }
    }
    m_streams.clear();

    wfpLog("WfpCaptureThread::run() stopped, packets=" + QString::number(m_packetCount));
}

void WfpCaptureThread::processTcpPacket(const WINDIVERT_IPHDR *ipHdr,
                                         const WINDIVERT_TCPHDR *tcpHdr,
                                         const quint8 *payload, UINT payloadLen,
                                         bool outbound)
{
    char srcBuf[64], dstBuf[64];
    if (!m_api->formatIPv4) return;
    m_api->formatIPv4(ipHdr->SrcAddr, srcBuf, sizeof(srcBuf));
    m_api->formatIPv4(ipHdr->DstAddr, dstBuf, sizeof(dstBuf));

    UINT16 srcPort = ntohs(tcpHdr->SrcPort);
    UINT16 dstPort = ntohs(tcpHdr->DstPort);

    bool isHttps = (dstPort == 443 || srcPort == 443 ||
                    dstPort == 8443 || srcPort == 8443 ||
                    dstPort == 9443 || srcPort == 9443);

    WfpConnKey key = WfpConnKey::canonical(QString(srcBuf), srcPort, QString(dstBuf), dstPort);
    bool clientToServer = (key.clientIp == QString(srcBuf) && key.clientPort == srcPort);

    quint32 seqNum = ntohl(tcpHdr->SeqNum);

    QMutexLocker lock(&m_mutex);
    WfpTcpStream &stream = m_streams[key];

    if (stream.startTime == 0) {
        stream.startTime = QDateTime::currentMSecsSinceEpoch();
        stream.srcIp = key.clientIp;
        stream.srcPort = key.clientPort;
        stream.dstIp = key.serverIp;
        stream.dstPort = key.serverPort;
        stream.isHttps = isHttps;
    }

    if (clientToServer) {
        if (isHttps && stream.sniHost.isEmpty()) {
            stream.sniHost = extractSniFromClientHello(QByteArray((const char *)payload, payloadLen));
        }
        if (!stream.clientSeqInit) {
            stream.clientSeq = seqNum;
            stream.clientSeqInit = true;
            stream.requestData.append((const char *)payload, payloadLen);
        } else {
            quint32 expected = stream.clientSeq + (quint32)stream.requestData.size();
            quint32 diff = seqNum - expected;
            if (diff < 0x80000000u || seqNum == stream.clientSeq) {
                stream.requestData.append((const char *)payload, payloadLen);
            }
        }
    } else {
        if (!stream.serverSeqInit) {
            stream.serverSeq = seqNum;
            stream.serverSeqInit = true;
            stream.responseData.append((const char *)payload, payloadLen);
        } else {
            quint32 expected = stream.serverSeq + (quint32)stream.responseData.size();
            quint32 diff = seqNum - expected;
            if (diff < 0x80000000u || seqNum == stream.serverSeq) {
                stream.responseData.append((const char *)payload, payloadLen);
            }
        }
    }

    checkStreamComplete(key, stream);
}

void WfpCaptureThread::processTcpPacketV6(const WINDIVERT_IPV6HDR *ip6Hdr,
                                           const WINDIVERT_TCPHDR *tcpHdr,
                                           const quint8 *payload, UINT payloadLen,
                                           bool outbound)
{
    char srcBuf[64], dstBuf[64];
    if (!m_api->formatIPv6) return;
    m_api->formatIPv6(ip6Hdr->SrcAddr, srcBuf, sizeof(srcBuf));
    m_api->formatIPv6(ip6Hdr->DstAddr, dstBuf, sizeof(dstBuf));

    UINT16 srcPort = ntohs(tcpHdr->SrcPort);
    UINT16 dstPort = ntohs(tcpHdr->DstPort);

    bool isHttps = (dstPort == 443 || srcPort == 443 ||
                    dstPort == 8443 || srcPort == 8443 ||
                    dstPort == 9443 || srcPort == 9443);

    WfpConnKey key = WfpConnKey::canonical(QString(srcBuf), srcPort, QString(dstBuf), dstPort);
    bool clientToServer = (key.clientIp == QString(srcBuf) && key.clientPort == srcPort);

    quint32 seqNum = ntohl(tcpHdr->SeqNum);

    QMutexLocker lock(&m_mutex);
    WfpTcpStream &stream = m_streams[key];

    if (stream.startTime == 0) {
        stream.startTime = QDateTime::currentMSecsSinceEpoch();
        stream.srcIp = key.clientIp;
        stream.srcPort = key.clientPort;
        stream.dstIp = key.serverIp;
        stream.dstPort = key.serverPort;
        stream.isHttps = isHttps;
    }

    if (clientToServer) {
        if (isHttps && stream.sniHost.isEmpty()) {
            stream.sniHost = extractSniFromClientHello(QByteArray((const char *)payload, payloadLen));
        }
        if (!stream.clientSeqInit) {
            stream.clientSeq = seqNum;
            stream.clientSeqInit = true;
            stream.requestData.append((const char *)payload, payloadLen);
        } else {
            quint32 expected = stream.clientSeq + (quint32)stream.requestData.size();
            quint32 diff = seqNum - expected;
            if (diff < 0x80000000u || seqNum == stream.clientSeq) {
                stream.requestData.append((const char *)payload, payloadLen);
            }
        }
    } else {
        if (!stream.serverSeqInit) {
            stream.serverSeq = seqNum;
            stream.serverSeqInit = true;
            stream.responseData.append((const char *)payload, payloadLen);
        } else {
            quint32 expected = stream.serverSeq + (quint32)stream.responseData.size();
            quint32 diff = seqNum - expected;
            if (diff < 0x80000000u || seqNum == stream.serverSeq) {
                stream.responseData.append((const char *)payload, payloadLen);
            }
        }
    }

    checkStreamComplete(key, stream);
}

void WfpCaptureThread::checkStreamComplete(const WfpConnKey &key, WfpTcpStream &stream)
{
    // Check if HTTP response is complete
    if (stream.requestData.isEmpty() || stream.responseData.isEmpty())
        return;

    // Parse response to check completeness
    QByteArray respData = stream.responseData;
    int headerEnd = respData.indexOf("\r\n\r\n");
    if (headerEnd < 0) return;

    QByteArray respHeaders = respData.left(headerEnd);
    QString headersStr = QString::fromLatin1(respHeaders);

    bool complete = false;
    if (headersStr.contains("Content-Length:", Qt::CaseInsensitive)) {
        QRegularExpression re("Content-Length:\\s*(\\d+)", QRegularExpression::CaseInsensitiveOption);
        auto match = re.match(headersStr);
        if (match.hasMatch()) {
            int contentLen = match.captured(1).toInt();
            int bodyStart = headerEnd + 4;
            int bodyLen = respData.size() - bodyStart;
            if (bodyLen >= contentLen) complete = true;
        }
    } else if (headersStr.contains("Transfer-Encoding: chunked", Qt::CaseInsensitive)) {
        if (respData.endsWith("0\r\n\r\n")) complete = true;
    } else {
        // No Content-Length and not chunked - assume complete if we have headers
        complete = true;
    }

    if (!complete) return;

    RequestItem item;
    item.id = m_nextId++;
    item.timestamp = QDateTime::fromMSecsSinceEpoch(stream.startTime);
    item.duration = QDateTime::currentMSecsSinceEpoch() - stream.startTime;
    item.requestSize = stream.requestData.size();
    item.responseSize = stream.responseData.size();

    if (stream.isHttps) {
        item.host = stream.sniHost.isEmpty() ? stream.dstIp : stream.sniHost;
        item.method = "CONNECT";
        item.path = item.host + ":" + QString::number(stream.dstPort);
        item.url = "https://" + item.host;
        item.protocol = "HTTPS";
    } else {
        HttpParser::parseRequest(stream.requestData, item);
        HttpParser::parseResponse(stream.responseData, item);
    }

    emit httpCaptured(item);
    m_streams.remove(key);
}

void WfpCaptureThread::emitStaleStreams()
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    QMutexLocker lock(&m_mutex);
    for (auto it = m_streams.begin(); it != m_streams.end(); ) {
        if (now - it.value().startTime > 3000) {  // 3 second timeout
            WfpTcpStream &stream = it.value();
            if (!stream.requestData.isEmpty() || !stream.sniHost.isEmpty()) {
                RequestItem item;
                item.id = m_nextId++;
                item.timestamp = QDateTime::fromMSecsSinceEpoch(stream.startTime);
                item.host = stream.sniHost.isEmpty() ? stream.dstIp : stream.sniHost;
                item.protocol = stream.isHttps ? "HTTPS" : "HTTP";
                item.duration = now - stream.startTime;
                item.requestSize = stream.requestData.size();
                item.responseSize = stream.responseData.size();

                if (stream.isHttps) {
                    item.method = "CONNECT";
                    item.path = stream.sniHost + ":" + QString::number(stream.dstPort);
                    item.url = "https://" + item.host;
                } else {
                    if (!stream.requestData.isEmpty()) {
                        HttpParser::parseRequest(stream.requestData, item);
                        if (!stream.responseData.isEmpty()) {
                            HttpParser::parseResponse(stream.responseData, item);
                        }
                    }
                }
                emit httpCaptured(item);
            }
            it = m_streams.erase(it);
        } else {
            ++it;
        }
    }
}

QString WfpCaptureThread::extractSniFromClientHello(const QByteArray &data)
{
    // Same SNI extraction logic as PacketCapture
    if (data.size() < 5) return {};
    if ((quint8)data[0] != 0x16) return {};  // Not TLS handshake
    if ((quint8)data[1] != 0x03 || (quint8)data[2] < 1) return {};  // Not TLS 1.x

    int pos = 5;  // Skip TLS record header
    if (pos >= data.size()) return {};
    if ((quint8)data[pos] != 0x01) return {};  // Not ClientHello

    pos += 4;  // Skip handshake header
    pos += 2;  // Skip version
    pos += 32; // Skip random

    if (pos >= data.size()) return {};
    int sessionIdLen = (quint8)data[pos++];
    pos += sessionIdLen;

    if (pos + 2 > data.size()) return {};
    int cipherSuitesLen = ((quint8)data[pos] << 8) | (quint8)data[pos + 1];
    pos += 2 + cipherSuitesLen;

    if (pos >= data.size()) return {};
    int compMethodsLen = (quint8)data[pos++];
    pos += compMethodsLen;

    if (pos + 2 > data.size()) return {};
    int extensionsLen = ((quint8)data[pos] << 8) | (quint8)data[pos + 1];
    pos += 2;

    int extEnd = pos + extensionsLen;
    while (pos + 4 <= extEnd && extEnd <= data.size()) {
        int extType = ((quint8)data[pos] << 8) | (quint8)data[pos + 1];
        int extLen = ((quint8)data[pos + 2] << 8) | (quint8)data[pos + 3];
        pos += 4;

        if (extType == 0x0000 && pos + extLen <= data.size()) {  // SNI extension
            if (pos + 5 > data.size()) return {};
            int sniListLen = ((quint8)data[pos] << 8) | (quint8)data[pos + 1];
            int sniPos = pos + 2;
            if (sniPos + 3 > data.size()) return {};
            int sniType = (quint8)data[sniPos];
            if (sniType == 0x00) {  // hostname
                int nameLen = ((quint8)data[sniPos + 1] << 8) | (quint8)data[sniPos + 2];
                if (sniPos + 3 + nameLen <= data.size()) {
                    return QString::fromLatin1(data.mid(sniPos + 3, nameLen));
                }
            }
        }
        pos += extLen;
    }
    return {};
}

// ============================================================================
// WfpCapture
// ============================================================================

WfpCapture::WfpCapture(QObject *parent)
    : QObject(parent)
{
}

WfpCapture::~WfpCapture()
{
    stop();
}

bool WfpCapture::loadWinDivert()
{
    if (m_dllHandle) return true;

    // Try loading from application directory first
    QString appDir = QCoreApplication::applicationDirPath();
    QString dllPath = appDir + "/WinDivert.dll";

    if (!QFile::exists(dllPath)) {
        wfpLog("WinDivert.dll not found at: " + dllPath);
        emit captureStatusChanged("WinDivert.dll not found");
        return false;
    }

    m_dllHandle = LoadLibraryW((LPCWSTR)dllPath.utf16());
    if (!m_dllHandle) {
        DWORD err = GetLastError();
        wfpLog(QString("Failed to load WinDivert.dll, error=%1").arg(err));
        emit captureStatusChanged(QString("Failed to load WinDivert.dll (error %1)").arg(err));
        return false;
    }

    m_api.open = (WinDivertOpenFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertOpen");
    m_api.recv = (WinDivertRecvFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertRecv");
    m_api.close = (WinDivertCloseFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertClose");
    m_api.shutdown = (WinDivertShutdownFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertShutdown");
    m_api.parsePacket = (WinDivertHelperParsePacketFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperParsePacket");
    m_api.formatIPv4 = (WinDivertHelperFormatIPv4AddressFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperFormatIPv4Address");
    m_api.formatIPv6 = (WinDivertHelperFormatIPv6AddressFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperFormatIPv6Address");

    if (!m_api.open || !m_api.recv || !m_api.close || !m_api.shutdown) {
        wfpLog("WinDivert.dll missing required functions");
        FreeLibrary((HMODULE)m_dllHandle);
        m_dllHandle = nullptr;
        emit captureStatusChanged("WinDivert.dll is corrupted");
        return false;
    }

    m_api.loaded = true;
    wfpLog("WinDivert.dll loaded successfully");
    return true;
}

bool WfpCapture::start()
{
    if (m_thread) {
        stop();
    }

    if (!loadWinDivert()) {
        return false;
    }

    // Open WinDivert handle: capture all TCP/UDP, sniff mode (read-only), no install check
    // Filter excludes our proxy port 9527 on loopback
    const char *filter = "tcp or udp";
    m_wdHandle = m_api.open(filter, 0 /* WINDIVERT_LAYER_NETWORK */, 0,
                            WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (!m_wdHandle || m_wdHandle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        wfpLog(QString("WinDivertOpen failed, error=%1").arg(err));

        if (err == 5) {  // ERROR_ACCESS_DENIED
            emit captureStatusChanged("WinDivert requires Administrator privileges");
        } else if (err == 2) {  // ERROR_FILE_NOT_FOUND
            emit captureStatusChanged("WinDivert driver not found. Ensure WinDivert.dll and WinDivert64.sys are in the app directory");
        } else {
            emit captureStatusChanged(QString("WinDivertOpen failed (error %1)").arg(err));
        }
        return false;
    }

    m_thread = new WfpCaptureThread(m_wdHandle, &m_api, this);
    connect(m_thread, &WfpCaptureThread::httpCaptured,
            this, &WfpCapture::requestCaptured);
    m_thread->start();

    wfpLog("WinDivert capture started");
    emit captureStatusChanged("WinDivert capture active");
    return true;
}

void WfpCapture::stop()
{
    if (m_wdHandle && m_wdHandle != INVALID_HANDLE_VALUE) {
        if (m_api.shutdown) {
            m_api.shutdown(m_wdHandle, 3 /* WINDIVERT_SHUTDOWN_BOTH */);
        }
    }

    if (m_thread) {
        m_thread->requestStop();
        m_thread->wait(3000);
        delete m_thread;
        m_thread = nullptr;
    }

    if (m_wdHandle && m_wdHandle != INVALID_HANDLE_VALUE) {
        if (m_api.close) {
            m_api.close(m_wdHandle);
        }
        m_wdHandle = nullptr;
    }
}

bool WfpCapture::isRunning() const
{
    return m_thread && m_thread->isRunning();
}

bool WfpCapture::isAvailable() const
{
    // Check if WinDivert.dll exists in app directory
    QString appDir = QCoreApplication::applicationDirPath();
    return QFile::exists(appDir + "/WinDivert.dll");
}

#endif // Q_OS_WIN
