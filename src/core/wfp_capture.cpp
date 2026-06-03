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
}

static bool isValidHttpRequest(const QByteArray &data)
{
    if (data.size() < 10) return false;
    // Check if data starts with a valid HTTP method
    static const char *methods[] = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "
    };
    for (const char *m : methods) {
        if (data.startsWith(m)) return true;
    }
    return false;
}

static QString extractHostFromRequest(const QByteArray &data)
{
    // Try to find Host header even in partial HTTP request data
    int headerEnd = data.indexOf("\r\n\r\n");
    QByteArray headers = (headerEnd >= 0) ? data.left(headerEnd) : data;
    int hostIdx = headers.indexOf("Host:");
    if (hostIdx < 0) hostIdx = headers.indexOf("host:");
    if (hostIdx < 0) hostIdx = headers.indexOf("HOST:");
    if (hostIdx >= 0) {
        int lineEnd = headers.indexOf("\r\n", hostIdx);
        if (lineEnd < 0) lineEnd = headers.size();
        QString hostValue = QString::fromLatin1(headers.mid(hostIdx + 5, lineEnd - hostIdx - 5).trimmed());
        // Strip port if present
        int colonIdx = hostValue.lastIndexOf(':');
        if (colonIdx > 0) hostValue = hostValue.left(colonIdx);
        return hostValue;
    }
    return {};
}

QString WfpCaptureThread::reverseDnsLookup(const QString &ip)
{
    // Check cache first
    auto it = m_dnsCache.find(ip);
    if (it != m_dnsCache.end()) return it.value();

    // Do reverse DNS lookup using getnameinfo
    // This blocks briefly per unique IP; cache prevents repeated lookups
    QByteArray ipBytes = ip.toLatin1();
    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    int addrLen = 0;

    struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
    addr4->sin_family = AF_INET;
    if (inet_pton(AF_INET, ipBytes.constData(), &addr4->sin_addr) == 1) {
        addrLen = sizeof(sockaddr_in);
    } else {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
        addr6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, ipBytes.constData(), &addr6->sin6_addr) == 1) {
            addrLen = sizeof(sockaddr_in6);
        } else {
            m_dnsCache[ip] = QString();
            return QString();
        }
    }

    char host[NI_MAXHOST];
    int ret = getnameinfo((struct sockaddr *)&addr, addrLen,
                          host, sizeof(host), nullptr, 0, 0);
    if (ret == 0) {
        QString hostname = QString::fromLatin1(host);
        if (hostname != ip && !hostname.endsWith(".in-addr.arpa") && !hostname.endsWith(".ip6.arpa")) {
            m_dnsCache[ip] = hostname;
            return hostname;
        }
    }

    m_dnsCache[ip] = QString(); // Cache miss to avoid repeated lookups
    return QString();
}

void WfpCaptureThread::emitStream(const WfpTcpStream &stream, bool force)
{
    // Filter out noise during normal operation (not on shutdown)
    if (!force) {
        // For HTTP, only emit if we have actual HTTP content (request or response data)
        if (!stream.isHttps) {
            bool hasHttpRequest = !stream.requestData.isEmpty()
                                  && isValidHttpRequest(stream.requestData);
            bool hasHttpResponse = !stream.responseData.isEmpty()
                                   && stream.responseData.indexOf("\r\n\r\n") >= 0;
            if (!hasHttpRequest && !hasHttpResponse) {
                return; // No parseable HTTP content — skip
            }
        }
        // HTTPS: always emit. Direct connections from apps (WPS, etc.) bypass
        // the proxy and only WinDivert can see them. Show IP/SNI/size/timing.
    }

    RequestItem item;
    item.id = m_nextId++;
    item.timestamp = QDateTime::fromMSecsSinceEpoch(stream.startTime);
    item.duration = QDateTime::currentMSecsSinceEpoch() - stream.startTime;
    item.requestSize = stream.requestData.size();
    item.responseSize = stream.responseData.size();

    if (stream.isHttps) {
        item.protocol = "HTTPS";
        item.method = "CONNECT";
        // Use SNI if available, otherwise reverse DNS lookup
        QString host = stream.sniHost;
        if (host.isEmpty()) {
            host = reverseDnsLookup(stream.dstIp);
        }
        if (host.isEmpty()) host = stream.dstIp;
        item.host = host;
        item.path = host + ":" + QString::number(stream.dstPort);
        item.url = "https://" + host;
    } else {
        item.protocol = "HTTP";
        // Parse what we have — may be partial data from fragmented TCP
        if (!stream.requestData.isEmpty()) {
            HttpParser::parseRequest(stream.requestData, item);
        }
        if (!stream.responseData.isEmpty()) {
            HttpParser::parseResponse(stream.responseData, item);
        }
        // Fallback: extract Host from partial request headers if parser didn't find it
        if (item.host.isEmpty() && !stream.requestData.isEmpty()) {
            item.host = extractHostFromRequest(stream.requestData);
        }
        // Fallback: reverse DNS lookup
        if (item.host.isEmpty()) {
            item.host = reverseDnsLookup(stream.dstIp);
        }
        if (item.host.isEmpty()) item.host = stream.dstIp;
        if (item.url.isEmpty()) {
            // Build URL from host and first line of request
            if (!stream.requestData.isEmpty()) {
                int firstLineEnd = stream.requestData.indexOf("\r\n");
                QByteArray firstLine = (firstLineEnd > 0) ? stream.requestData.left(firstLineEnd) : stream.requestData.left(200);
                item.url = QString::fromLatin1(firstLine);
            } else {
                item.url = item.host + ":" + QString::number(stream.dstPort);
            }
        }
    }
    emit httpCaptured(item);
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

        int ok = m_api->recv(m_handle, packet, sizeof(packet), &recvLen, &addr);
        if (!ok) {
            if (m_stopRequested) break;
            DWORD err = GetLastError();
            if (err == 995 || err == 1229) break;
            continue;
        }
        if (recvLen == 0) continue;

        m_packetCount++;

        if ((m_packetCount & 0x1F) == 0) {
            emitStaleStreams();
        }

        WINDIVERT_IPHDR *ipHdr = nullptr;
        WINDIVERT_IPV6HDR *ip6Hdr = nullptr;
        WINDIVERT_TCPHDR *tcpHdr = nullptr;
        WINDIVERT_UDPHDR *udpHdr = nullptr;
        UINT8 protocol = 0;
        PVOID payload = nullptr;
        UINT payloadLen = 0;

        m_api->parsePacket(packet, recvLen,
                (void **)&ipHdr, (void **)&ip6Hdr, &protocol,
                nullptr, nullptr, (void **)&tcpHdr, (void **)&udpHdr,
                &payload, &payloadLen, nullptr, nullptr);

        bool outbound = (addr.Outbound != 0);
        bool loopback = (addr.Loopback != 0);

        // Skip ALL loopback traffic (local IPC, not interesting for network monitoring)
        if (loopback) continue;

        UINT16 srcPort = 0, dstPort = 0;
        if (tcpHdr) {
            srcPort = ntohs(tcpHdr->SrcPort);
            dstPort = ntohs(tcpHdr->DstPort);
        } else if (udpHdr) {
            srcPort = ntohs(udpHdr->SrcPort);
            dstPort = ntohs(udpHdr->DstPort);
        }

        // Skip common UDP noise: DNS, mDNS, LLMNR, NetBIOS, SSDP, DHCP, TFTP
        if (udpHdr) {
            if (srcPort == 53 || dstPort == 53 ||
                srcPort == 5353 || dstPort == 5353 ||
                srcPort == 5355 || dstPort == 5355 ||
                srcPort == 137 || dstPort == 137 ||
                srcPort == 138 || dstPort == 138 ||
                srcPort == 1900 || dstPort == 1900 ||
                srcPort == 67 || dstPort == 67 ||
                srcPort == 68 || dstPort == 68 ||
                srcPort == 69 || dstPort == 69) {
                continue;
            }
            // Skip all other UDP — we only care about TCP (HTTP/HTTPS)
            continue;
        }

        // Only skip truly non-HTTP system ports (keep it minimal to avoid missing traffic)
        if (tcpHdr) {
            auto isSystemPort = [](UINT16 port) -> bool {
                return port == 22 ||    // SSH
                       port == 3389 ||  // RDP
                       port == 445 ||   // SMB
                       port == 139;     // NetBIOS
            };
            if (isSystemPort(srcPort) || isSystemPort(dstPort)) continue;
        }

        if (tcpHdr && payloadLen > 0) {
            if (ipHdr) {
                processTcpPacket(ipHdr, tcpHdr, (const quint8 *)payload, payloadLen, outbound, false);
            } else if (ip6Hdr) {
                processTcpPacket(ip6Hdr, tcpHdr, (const quint8 *)payload, payloadLen, outbound, true);
            }
        } else if (tcpHdr && (tcpHdr->Fin || tcpHdr->Rst)) {
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
            WfpConnKey key = WfpConnKey::canonical(QString(srcBuf), srcPort, QString(dstBuf), dstPort);
            QMutexLocker lock(&m_mutex);
            auto it = m_streams.find(key);
            if (it != m_streams.end()) {
                WfpTcpStream &stream = it.value();
                if (stream.isHttps) {
                    emitStream(stream);
                    m_streams.erase(it);
                } else {
                    checkStreamComplete(key, stream);
                }
            }
        }
    }

    QMutexLocker lock(&m_mutex);
    for (auto it = m_streams.begin(); it != m_streams.end(); ++it) {
        emitStream(it.value(), true);
    }
    m_streams.clear();

    wfpLog("WfpCaptureThread::run() stopped, packets=" + QString::number(m_packetCount));
}

void WfpCaptureThread::processTcpPacket(void *ipHdrVoid, void *tcpHdrVoid,
                                         const quint8 *payload, unsigned int payloadLen,
                                         bool outbound, bool isIpv6)
{
    char srcBuf[64], dstBuf[64];
    UINT16 srcPort, dstPort;
    UINT32 seqNum;

    auto *tcpHdr = static_cast<const WINDIVERT_TCPHDR *>(tcpHdrVoid);
    srcPort = ntohs(tcpHdr->SrcPort);
    dstPort = ntohs(tcpHdr->DstPort);
    seqNum = ntohl(tcpHdr->SeqNum);

    if (isIpv6) {
        auto *ip6Hdr = static_cast<const WINDIVERT_IPV6HDR *>(ipHdrVoid);
        if (!m_api->formatIPv6) return;
        m_api->formatIPv6(ip6Hdr->SrcAddr, srcBuf, sizeof(srcBuf));
        m_api->formatIPv6(ip6Hdr->DstAddr, dstBuf, sizeof(dstBuf));
    } else {
        auto *ipHdr = static_cast<const WINDIVERT_IPHDR *>(ipHdrVoid);
        if (!m_api->formatIPv4) return;
        m_api->formatIPv4(ipHdr->SrcAddr, srcBuf, sizeof(srcBuf));
        m_api->formatIPv4(ipHdr->DstAddr, dstBuf, sizeof(dstBuf));
    }

    bool isHttps = (dstPort == 443 || srcPort == 443 ||
                    dstPort == 8443 || srcPort == 8443 ||
                    dstPort == 9443 || srcPort == 9443);

    WfpConnKey key = WfpConnKey::canonical(QString(srcBuf), srcPort, QString(dstBuf), dstPort);
    bool clientToServer = (key.clientIp == QString(srcBuf) && key.clientPort == srcPort);

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
    // For HTTPS, emit on FIN/RST or stale timeout (not every packet)
    if (stream.isHttps) {
        return;
    }

    // For HTTP, need both request and response with valid headers
    if (stream.requestData.isEmpty() || stream.responseData.isEmpty())
        return;

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
        complete = true;
    }

    if (!complete) return;

    RequestItem item;
    item.id = m_nextId++;
    item.timestamp = QDateTime::fromMSecsSinceEpoch(stream.startTime);
    item.duration = QDateTime::currentMSecsSinceEpoch() - stream.startTime;
    item.requestSize = stream.requestData.size();
    item.responseSize = stream.responseData.size();

    HttpParser::parseRequest(stream.requestData, item);
    HttpParser::parseResponse(stream.responseData, item);

    if (item.host.isEmpty()) {
        item.host = extractHostFromRequest(stream.requestData);
    }
    if (item.host.isEmpty()) {
        item.host = reverseDnsLookup(stream.dstIp);
    }
    if (item.host.isEmpty()) item.host = stream.dstIp;
    if (item.url.isEmpty()) item.url = stream.dstIp + ":" + QString::number(stream.dstPort);

    emit httpCaptured(item);
    m_streams.remove(key);
}

void WfpCaptureThread::emitStaleStreams()
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    QMutexLocker lock(&m_mutex);
    for (auto it = m_streams.begin(); it != m_streams.end(); ) {
        if (now - it.value().startTime > 15000) {
            emitStream(it.value());
            it = m_streams.erase(it);
        } else {
            ++it;
        }
    }
}

QString WfpCaptureThread::extractSniFromClientHello(const QByteArray &data)
{
    if (data.size() < 5) return {};
    if ((quint8)data[0] != 0x16) return {};
    if ((quint8)data[1] != 0x03 || (quint8)data[2] < 1) return {};

    int pos = 5;
    if (pos >= data.size()) return {};
    if ((quint8)data[pos] != 0x01) return {};

    pos += 4;
    pos += 2;
    pos += 32;

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

        if (extType == 0x0000 && pos + extLen <= data.size()) {
            if (pos + 5 > data.size()) return {};
            int sniListLen = ((quint8)data[pos] << 8) | (quint8)data[pos + 1];
            int sniPos = pos + 2;
            if (sniPos + 3 > data.size()) return {};
            int sniType = (quint8)data[sniPos];
            if (sniType == 0x00) {
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
    m_api.send = (WinDivertSendFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertSend");
    m_api.parsePacket = (WinDivertHelperParsePacketFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperParsePacket");
    m_api.formatIPv4 = (WinDivertHelperFormatIPv4AddressFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperFormatIPv4Address");
    m_api.formatIPv6 = (WinDivertHelperFormatIPv6AddressFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperFormatIPv6Address");
    m_api.calcChecksums = (WinDivertHelperCalcChecksumsFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperCalcChecksums");

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

    // Only capture TCP — UDP is filtered out anyway (DNS, mDNS, etc.)
    // Skip loopback at kernel level to reduce noise
    const char *filter = "tcp and !loopback";
    m_wdHandle = m_api.open(filter, 0, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (!m_wdHandle || m_wdHandle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        wfpLog(QString("WinDivertOpen failed, error=%1").arg(err));

        if (err == 5) {
            emit captureStatusChanged("WinDivert requires Administrator privileges");
        } else if (err == 2) {
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
            m_api.shutdown(m_wdHandle, 3);
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
    QString appDir = QCoreApplication::applicationDirPath();
    return QFile::exists(appDir + "/WinDivert.dll");
}

void WfpCapture::setMitmActive(bool active)
{
    if (m_thread) m_thread->setMitmActive(active);
}

#endif // Q_OS_WIN
