#include "packet_capture.h"
#include "http_parser.h"
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QStandardPaths>
#include <QDateTime>

#ifdef Q_OS_WIN
// ============================================================================
// Windows: delegate to WfpCapture (WinDivert-based)
// ============================================================================
#include "wfp_capture.h"

PacketCapture::PacketCapture(QObject *parent)
    : QObject(parent)
{
}

PacketCapture::~PacketCapture()
{
    stop();
}

bool PacketCapture::start()
{
    if (m_wfpCapture) {
        stop();
    }

    m_wfpCapture = new WfpCapture(this);
    connect(m_wfpCapture, &WfpCapture::requestCaptured,
            this, &PacketCapture::requestCaptured, Qt::QueuedConnection);
    connect(m_wfpCapture, &WfpCapture::captureStatusChanged,
            this, &PacketCapture::captureStatusChanged);

    if (!m_wfpCapture->start()) {
        qWarning() << "PacketCapture: WfpCapture start failed";
        delete m_wfpCapture;
        m_wfpCapture = nullptr;
        return false;
    }

    qDebug() << "PacketCapture: WinDivert capture started";
    return true;
}

void PacketCapture::stop()
{
    if (m_wfpCapture) {
        m_wfpCapture->stop();
        delete m_wfpCapture;
        m_wfpCapture = nullptr;
    }
}

bool PacketCapture::isRunning() const
{
    return m_wfpCapture && m_wfpCapture->isRunning();
}

void PacketCapture::setMitmActive(bool active)
{
    if (m_wfpCapture) m_wfpCapture->setMitmActive(active);
}

QStringList PacketCapture::availableInterfaces()
{
    // WinDivert captures all interfaces at WFP level — no enumeration needed
    return {};
}

#else
// ============================================================================
// macOS: pcap-based capture
// ============================================================================
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

static void logToFile(const QString &msg) {
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/npcap.log";
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream ts(&f);
        ts << QDateTime::currentDateTime().toString("hh:mm:ss.zzz") << " " << msg << "\n";
    }
}

// ============================================================================
// Packet header structures (minimal, cross-platform)
// ============================================================================

#pragma pack(push, 1)

struct EthHeader {
    u_char dst[6];
    u_char src[6];
    u_short type;
};

struct IpHeader {
    u_char verIhl;
    u_char tos;
    u_short totalLen;
    u_short id;
    u_short flagsFrag;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_int srcIp;
    u_int dstIp;
};

struct Ip6Header {
    u_int verTcFl;
    u_short payloadLen;
    u_char nextHeader;
    u_char hopLimit;
    u_char srcAddr[16];
    u_char dstAddr[16];
};

struct TcpHeader {
    u_short srcPort;
    u_short dstPort;
    u_int seqNum;
    u_int ackNum;
    u_char dataOffset;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgent;
};

struct UdpHeader {
    u_short srcPort;
    u_short dstPort;
    u_short length;
    u_short checksum;
};

#pragma pack(pop)

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10

// ============================================================================
// SNI extraction from TLS ClientHello
// ============================================================================

static QString extractSNI(const u_char *data, int len)
{
    // TLS record:ContentType(1),Version(2),Length(2)
    if (len < 5) return {};
    if (data[0] != 0x16) return {};  // Not handshake

    int pos = 5;  // Skip TLS record header
    // Handshake:Type(1),Length(3)
    if (pos + 4 > len) return {};
    if (data[pos] != 0x01) return {};  // Not ClientHello
    pos += 4;

    // ClientHello:Version(2),Random(32)
    pos += 34;
    if (pos > len) return {};

    // Session ID
    if (pos + 1 > len) return {};
    int sessionIdLen = data[pos];
    pos += 1 + sessionIdLen;
    if (pos > len) return {};

    // Cipher Suites
    if (pos + 2 > len) return {};
    int cipherSuitesLen = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipherSuitesLen;
    if (pos > len) return {};

    // Compression Methods
    if (pos + 1 > len) return {};
    int compMethodsLen = data[pos];
    pos += 1 + compMethodsLen;
    if (pos > len) return {};

    // Extensions
    if (pos + 2 > len) return {};
    int extensionsLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    int extensionsEnd = pos + extensionsLen;
    if (extensionsEnd > len) extensionsEnd = len;

    while (pos + 4 <= extensionsEnd) {
        u_short extType = (data[pos] << 8) | data[pos + 1];
        u_short extLen = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (extType == 0x0000) {  // server_name
            // ServerNameList length(2)
            if (pos + 2 > extensionsEnd) return {};
            int nameListLen = (data[pos] << 8) | data[pos + 1];
            int nameListEnd = pos + 2 + nameListLen;
            if (nameListEnd > extensionsEnd) nameListEnd = extensionsEnd;
            pos += 2;

            while (pos + 3 <= nameListEnd) {
                u_char nameType = data[pos];
                u_short nameLen = (data[pos + 1] << 8) | data[pos + 2];
                pos += 3;
                if (pos + nameLen > nameListEnd) return {};
                if (nameType == 0) {  // host_name
                    return QString::fromLatin1((const char *)(data + pos), nameLen);
                }
                pos += nameLen;
            }
            return {};
        }
        pos += extLen;
    }
    return {};
}

// ============================================================================
// CaptureThread
// ============================================================================

CaptureThread::CaptureThread(pcap_t *handle, QObject *parent)
    : QThread(parent), m_handle(handle)
{
}

void CaptureThread::requestStop()
{
    m_stopRequested = true;
    if (m_handle) {
        pcap_breakloop(m_handle);
    }
}

void CaptureThread::run()
{
    if (!m_handle) return;

    logToFile("CaptureThread::run() started");
    qDebug() << "PacketCapture: capture loop started";
    pcap_loop(m_handle, -1, packetHandler, (u_char *)this);
    logToFile("CaptureThread::run() stopped, packets=" + QString::number(m_packetCount));
    qDebug() << "PacketCapture: capture loop stopped";

    // Emit any remaining streams
    QMutexLocker lock(&m_mutex);
    for (auto it = m_streams.begin(); it != m_streams.end(); ++it) {
        TcpStream &stream = it.value();
        if (!stream.requestData.isEmpty()) {
            RequestItem item;
            item.id = m_nextId++;
            item.timestamp = QDateTime::fromMSecsSinceEpoch(stream.startTime);
            item.host = stream.sniHost.isEmpty() ? stream.dstIp : stream.sniHost;
            item.protocol = stream.isHttps ? "HTTPS" : "HTTP";
            item.duration = QDateTime::currentMSecsSinceEpoch() - stream.startTime;

            if (stream.isHttps) {
                item.method = "CONNECT";
                item.path = stream.sniHost + ":" + QString::number(stream.dstPort);
                item.url = "https://" + item.host;
            } else {
                HttpParser::parseRequest(stream.requestData, item);
                if (!stream.responseData.isEmpty()) {
                    HttpParser::parseResponse(stream.responseData, item);
                }
            }
            emit httpCaptured(item);
        }
    }
    m_streams.clear();
}

void CaptureThread::packetHandler(u_char *user, const struct pcap_pkthdr *header, const u_char *data)
{
    CaptureThread *self = reinterpret_cast<CaptureThread *>(user);
    if (self->m_stopRequested) return;
    self->m_packetCount++;
    self->processPacket(header, data);
}

void CaptureThread::processPacket(const struct pcap_pkthdr *header, const u_char *data)
{
    // Periodically emit stale streams (every 32 packets)
    if ((m_packetCount & 0x1F) == 0) {
        emitStaleStreams();
    }

    int offset = 0;
    u_short etherType;

    // Check if this is Ethernet (link type 1) or raw IP (link type 101)
    etherType = (data[12] << 8) | data[13];
    if (etherType == 0x0800 || etherType == 0x86DD || etherType == 0x8100) {
        // Ethernet frame
        offset = 14;
        if (etherType == 0x8100) {  // VLAN tag
            offset += 4;
            etherType = (data[16] << 8) | data[17];
        }
    } else {
        // Assume raw IP (link type 101 - DLT_RAW)
        // Check IP version to determine if IPv4 or IPv6
        u_char ver = (data[0] >> 4) & 0x0F;
        offset = 0;
        etherType = (ver == 6) ? 0x86DD : 0x0800;
    }

    // Extract IP addresses, protocol, and ports
    char srcBuf[64], dstBuf[64];
    u_short srcPort = 0, dstPort = 0;
    int protocol = 0;

    if (etherType == 0x0800) {
        // IPv4
        if (offset + (int)sizeof(IpHeader) > (int)header->caplen) return;
        const IpHeader *ip = (const IpHeader *)(data + offset);
        int ipHdrLen = (ip->verIhl & 0x0F) * 4;
        protocol = ip->protocol;
        if (protocol != 6 && protocol != 17) return;  // Only TCP and UDP

        struct in_addr addr;
        addr.s_addr = ip->srcIp;
        inet_ntop(AF_INET, &addr, srcBuf, sizeof(srcBuf));
        addr.s_addr = ip->dstIp;
        inet_ntop(AF_INET, &addr, dstBuf, sizeof(dstBuf));

        if (protocol == 6) {
            int tcpOffset = offset + ipHdrLen;
            if (tcpOffset + (int)sizeof(TcpHeader) > (int)header->caplen) return;
            const TcpHeader *tcp = (const TcpHeader *)(data + tcpOffset);
            srcPort = ntohs(tcp->srcPort);
            dstPort = ntohs(tcp->dstPort);

            // Process TCP packet
            processTcpPacket(header, data, tcp, srcBuf, dstBuf, srcPort, dstPort);
        } else {
            int udpOffset = offset + ipHdrLen;
            if (udpOffset + (int)sizeof(UdpHeader) > (int)header->caplen) return;
            const UdpHeader *udp = (const UdpHeader *)(data + udpOffset);
            srcPort = ntohs(udp->srcPort);
            dstPort = ntohs(udp->dstPort);

            processUdpPacket(header, data, udp, srcBuf, dstBuf, srcPort, dstPort);
        }
        return;

    } else if (etherType == 0x86DD) {
        // IPv6
        if (offset + (int)sizeof(Ip6Header) > (int)header->caplen) return;
        const Ip6Header *ip6 = (const Ip6Header *)(data + offset);
        u_char nextHeader = ip6->nextHeader;
        int ip6HdrLen = 40;  // Fixed IPv6 header size

        // Walk extension headers to find TCP/UDP
        int extOffset = offset + ip6HdrLen;
        while (nextHeader != 6 && nextHeader != 17 && extOffset + 2 <= (int)header->caplen) {
            if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 ||
                nextHeader == 135 || nextHeader == 139 || nextHeader == 140) {
                if (extOffset + 2 > (int)header->caplen) return;
                nextHeader = data[extOffset];
                int extLen = (data[extOffset + 1] + 1) * 8;
                extOffset += extLen;
            } else if (nextHeader == 44) {
                if (extOffset + 8 > (int)header->caplen) return;
                nextHeader = data[extOffset];
                extOffset += 8;
            } else {
                break;
            }
        }

        inet_ntop(AF_INET6, ip6->srcAddr, srcBuf, sizeof(srcBuf));
        inet_ntop(AF_INET6, ip6->dstAddr, dstBuf, sizeof(dstBuf));

        if (nextHeader == 6) {
            if (extOffset + (int)sizeof(TcpHeader) > (int)header->caplen) return;
            const TcpHeader *tcp = (const TcpHeader *)(data + extOffset);
            srcPort = ntohs(tcp->srcPort);
            dstPort = ntohs(tcp->dstPort);
            processTcpPacket(header, data, tcp, srcBuf, dstBuf, srcPort, dstPort);
        } else if (nextHeader == 17) {
            if (extOffset + (int)sizeof(UdpHeader) > (int)header->caplen) return;
            const UdpHeader *udp = (const UdpHeader *)(data + extOffset);
            srcPort = ntohs(udp->srcPort);
            dstPort = ntohs(udp->dstPort);
            processUdpPacket(header, data, udp, srcBuf, dstBuf, srcPort, dstPort);
        }
        return;
    } else {
        return;  // Not IPv4 or IPv6
    }
}

void CaptureThread::processTcpPacket(const struct pcap_pkthdr *header, const u_char *data,
                                      const TcpHeader *tcp,
                                      const char *srcBuf, const char *dstBuf,
                                      u_short srcPort, u_short dstPort)
{
    // Skip our own proxy traffic (localhost:9527)
    if (srcPort == 9527 || dstPort == 9527) {
        if (strcmp(srcBuf, "127.0.0.1") == 0 || strcmp(dstBuf, "127.0.0.1") == 0 ||
            strcmp(srcBuf, "::1") == 0 || strcmp(dstBuf, "::1") == 0) {
            return;
        }
    }

    bool isHttps = (dstPort == 443 || srcPort == 443 || dstPort == 8443 || srcPort == 8443 || dstPort == 9443 || srcPort == 9443);

    // Use canonical key so both directions map to the same stream
    ConnKey key = ConnKey::canonical(QString(srcBuf), srcPort, QString(dstBuf), dstPort);

    // Determine direction: data flows from src to dst in this packet
    bool clientToServer = (key.clientIp == QString(srcBuf) && key.clientPort == srcPort);

    int tcpHdrLen = ((tcp->dataOffset >> 4) & 0x0F) * 4;
    int payloadOffset = (int)((const u_char *)tcp - data) + tcpHdrLen;
    int payloadLen = (int)header->caplen - payloadOffset;

    // Periodically emit stale streams
    if ((m_packetCount & 0x1F) == 0) {
        emitStaleStreams();
    }

    if (payloadLen <= 0) {
        if (tcp->flags & (TH_FIN | TH_RST)) {
            QMutexLocker lock(&m_mutex);
            auto it = m_streams.find(key);
            if (it != m_streams.end()) {
                checkStreamComplete(key, it.value());
            }
        }
        return;
    }

    const u_char *payload = data + payloadOffset;
    quint32 seqNum = ntohl(tcp->seqNum);

    QMutexLocker lock(&m_mutex);
    TcpStream &stream = m_streams[key];

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
            stream.sniHost = extractSNI(payload, payloadLen);
        }

        if (!stream.clientSeqInit) {
            stream.clientSeq = seqNum;
            stream.clientSeqInit = true;
            stream.requestData.append((const char *)payload, payloadLen);
        } else {
            // TCP sequence comparison (RFC 793): handles quint32 wrap-around
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
            // TCP sequence comparison (RFC 793): handles quint32 wrap-around
            quint32 expected = stream.serverSeq + (quint32)stream.responseData.size();
            quint32 diff = seqNum - expected;
            if (diff < 0x80000000u || seqNum == stream.serverSeq) {
                stream.responseData.append((const char *)payload, payloadLen);
            }
        }
    }

    checkStreamComplete(key, stream);

    // Handle FIN/RST - only emit if there's actual data
    if (tcp->flags & (TH_FIN | TH_RST)) {
        if (stream.requestData.isEmpty() && stream.responseData.isEmpty() && stream.sniHost.isEmpty()) {
            m_streams.remove(key);
            return;
        }
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
            if (!stream.requestData.isEmpty()) {
                HttpParser::parseRequest(stream.requestData, item);
                if (!stream.responseData.isEmpty()) {
                    HttpParser::parseResponse(stream.responseData, item);
                }
            }
            if (item.host.isEmpty()) item.host = stream.dstIp;
            if (item.url.isEmpty()) item.url = stream.dstIp + ":" + QString::number(stream.dstPort);
            if (item.method.isEmpty()) item.method = "TCP";
            if (item.protocol.isEmpty()) item.protocol = "TCP";
        }
        logToFile("EMIT FIN/RST: " + item.url + " proto=" + item.protocol +
                  " req=" + QString::number(item.requestSize) + "B resp=" + QString::number(item.responseSize) + "B");
        emit httpCaptured(item);
        m_streams.remove(key);
    }
}

void CaptureThread::processUdpPacket(const struct pcap_pkthdr *header, const u_char *data,
                                      const UdpHeader *udp,
                                      const char *srcBuf, const char *dstBuf,
                                      u_short srcPort, u_short dstPort)
{
    // Skip our own proxy traffic
    if (srcPort == 9527 || dstPort == 9527) {
        if (strcmp(srcBuf, "127.0.0.1") == 0 || strcmp(dstBuf, "127.0.0.1") == 0 ||
            strcmp(srcBuf, "::1") == 0 || strcmp(dstBuf, "::1") == 0) {
            return;
        }
    }

    // Skip common UDP noise: DNS, mDNS, LLMNR, NetBIOS, SSDP, DHCP
    if (srcPort == 53 || dstPort == 53 ||
        srcPort == 5353 || dstPort == 5353 ||
        srcPort == 5355 || dstPort == 5355 ||
        srcPort == 137 || dstPort == 137 ||
        srcPort == 138 || dstPort == 138 ||
        srcPort == 1900 || dstPort == 1900 ||
        srcPort == 67 || dstPort == 67 ||
        srcPort == 68 || dstPort == 68 ||
        srcPort == 69 || dstPort == 69) {
        return;
    }

    int payloadOffset = (int)((const u_char *)udp - data) + sizeof(UdpHeader);
    int payloadLen = (int)header->caplen - payloadOffset;
    if (payloadLen <= 0) return;

    // Emit each UDP packet as a separate item (UDP is connectionless)
    RequestItem item;
    item.id = m_nextId++;
    item.timestamp = QDateTime::currentDateTime();
    item.host = dstBuf;
    item.method = "UDP";
    item.path = QString::number(dstPort);
    item.url = QString(dstBuf) + ":" + QString::number(dstPort);
    item.protocol = "UDP";
    item.requestSize = payloadLen;
    item.responseSize = 0;

    logToFile("EMIT UDP: " + item.url + " size=" + QString::number(payloadLen));
    emit httpCaptured(item);
}

void CaptureThread::emitStaleStreams()
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    constexpr qint64 STALE_TIMEOUT_MS = 3000;  // 3 seconds

    auto it = m_streams.begin();
    while (it != m_streams.end()) {
        TcpStream &stream = it.value();
        if (stream.startTime > 0 && (now - stream.startTime) > STALE_TIMEOUT_MS
            && (stream.requestData.isEmpty() == false || stream.responseData.isEmpty() == false
                || !stream.sniHost.isEmpty())) {
            RequestItem item;
            item.id = m_nextId++;
            item.timestamp = QDateTime::fromMSecsSinceEpoch(stream.startTime);
            item.duration = now - stream.startTime;
            item.requestSize = stream.requestData.size();
            item.responseSize = stream.responseData.size();

            if (stream.isHttps) {
                item.host = stream.sniHost.isEmpty() ? stream.dstIp : stream.sniHost;
                item.method = "CONNECT";
                item.path = item.host + ":" + QString::number(stream.dstPort);
                item.url = "https://" + item.host;
                item.protocol = "HTTPS";
            } else {
                // Try to parse as HTTP first
                if (!stream.requestData.isEmpty()) {
                    HttpParser::parseRequest(stream.requestData, item);
                    if (!stream.responseData.isEmpty()) {
                        HttpParser::parseResponse(stream.responseData, item);
                    }
                }
                if (item.host.isEmpty()) item.host = stream.dstIp;
                if (item.url.isEmpty()) item.url = stream.dstIp + ":" + QString::number(stream.dstPort);
                if (item.method.isEmpty()) item.method = "TCP";
                if (item.protocol.isEmpty()) item.protocol = "TCP";
            }

            logToFile("EMIT STALE: " + item.url + " proto=" + item.protocol +
                      " req=" + QString::number(item.requestSize) + "B resp=" + QString::number(item.responseSize) + "B");
            emit httpCaptured(item);
            it = m_streams.erase(it);
            continue;
        }
        // Also clean up very old empty streams (30s) to prevent memory leaks
        if (stream.startTime > 0 && (now - stream.startTime) > 30000) {
            it = m_streams.erase(it);
            continue;
        }
        ++it;
    }
}

void CaptureThread::checkStreamComplete(const ConnKey &key, TcpStream &stream)
{
    if (stream.requestData.isEmpty() && stream.sniHost.isEmpty()) return;

    // For HTTPS, emit on FIN/RST or stale timeout (not every packet)
    if (stream.isHttps) {
        return;
    }

    // For HTTP, check if we have a complete request
    int reqHeaderEnd = stream.requestData.indexOf("\r\n\r\n");
    if (reqHeaderEnd < 0) {
        // Not HTTP - will be emitted by stale timeout or FIN/RST
        return;
    }

    // Check if request body is complete
    QByteArray reqHeaders = stream.requestData.left(reqHeaderEnd).toLower();
    int reqContentLength = -1;
    int clIdx = reqHeaders.indexOf("content-length:");
    if (clIdx >= 0) {
        int clEnd = reqHeaders.indexOf("\r\n", clIdx);
        if (clEnd < 0) clEnd = reqHeaders.size();
        QByteArray clValue = reqHeaders.mid(clIdx + 15, clEnd - clIdx - 15).trimmed();
        reqContentLength = clValue.toInt();
    }

    int reqBodyStart = reqHeaderEnd + 4;
    int reqBodySize = stream.requestData.size() - reqBodyStart;

    if (reqContentLength >= 0 && reqBodySize < reqContentLength) return;  // Body incomplete

    // Check if we have a complete response
    int respHeaderEnd = stream.responseData.indexOf("\r\n\r\n");
    if (respHeaderEnd < 0) return;  // Response headers not complete yet

    int respContentLength = -1;
    QByteArray respHeaders = stream.responseData.left(respHeaderEnd).toLower();
    int respClIdx = respHeaders.indexOf("content-length:");
    if (respClIdx >= 0) {
        int respClEnd = respHeaders.indexOf("\r\n", respClIdx);
        if (respClEnd < 0) respClEnd = respHeaders.size();
        QByteArray respClValue = respHeaders.mid(respClIdx + 15, respClEnd - respClIdx - 15).trimmed();
        respContentLength = respClValue.toInt();
    }

    int respBodyStart = respHeaderEnd + 4;
    int respBodySize = stream.responseData.size() - respBodyStart;

    if (respContentLength >= 0 && respBodySize < respContentLength) return;  // Response body incomplete

    // We have a complete request+response pair
    RequestItem item;
    item.id = m_nextId++;
    item.timestamp = QDateTime::fromMSecsSinceEpoch(stream.startTime);
    item.duration = QDateTime::currentMSecsSinceEpoch() - stream.startTime;

    HttpParser::parseRequest(stream.requestData, item);
    HttpParser::parseResponse(stream.responseData, item);

    // Fix host if needed
    if (item.host.isEmpty()) {
        item.host = stream.dstIp;
    }

    qDebug() << "PacketCapture: captured" << item.method << item.host << item.path << item.statusCode;

    emit httpCaptured(item);

    // Remove completed stream
    m_streams.remove(key);
}

// ============================================================================
// PacketCapture
// ============================================================================

PacketCapture::PacketCapture(QObject *parent)
    : QObject(parent)
{
}

PacketCapture::~PacketCapture()
{
    stop();
}

bool PacketCapture::isNpcapInstalled()
{
    // macOS: libpcap is always available
    return QFile::exists("/usr/lib/libpcap.dylib")
        || QFile::exists("/opt/homebrew/opt/libpcap/lib/libpcap.dylib");
}

QStringList PacketCapture::availableInterfaces()
{
    QStringList names;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qWarning() << "PacketCapture: pcap_findalldevs failed:" << errbuf;
        return names;
    }

    for (pcap_if_t *d = alldevs; d; d = d->next) {
        if (d->name) {
            QString name = QString::fromLocal8Bit(d->name);
            QString desc = d->description ? QString::fromLocal8Bit(d->description) : name;
            names << name + " | " + desc;
        }
    }

    pcap_freealldevs(alldevs);
    return names;
}

bool PacketCapture::start()
{
    if (!m_captures.isEmpty()) {
        stop();
    }

    // Check libpcap availability
    if (!isNpcapInstalled()) {
        QString msg = "libpcap not found. Install via: brew install libpcap";
        qWarning() << "PacketCapture:" << msg;
        logToFile("ERROR: " + msg);
        emit captureStatusChanged(msg);
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qWarning() << "PacketCapture: pcap_findalldevs failed:" << errbuf;
        logToFile("ERROR: pcap_findalldevs failed: " + QString(errbuf));
        emit captureStatusChanged(QString("pcap_findalldevs failed: %1").arg(errbuf));
        return false;
    }

    // Log all available interfaces
    logToFile("=== PacketCapture::start() ===");
    qDebug() << "PacketCapture: available interfaces:";
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        QString desc = d->description ? QString::fromLocal8Bit(d->description) : "no desc";
        QString name = d->name ? QString::fromLocal8Bit(d->name) : "?";
        qDebug() << "  " << d->name << "|" << desc << "flags:" << d->flags
                 << "addrs:" << (d->addresses ? "yes" : "no");
        logToFile("  IF: " + name + " | " + desc + " flags=" + QString::number(d->flags));
    }

    // Collect all suitable interfaces
    QList<pcap_if_t*> candidates;
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        if (!d->addresses) continue;
#ifdef PCAP_IF_LOOPBACK
        if (d->flags & PCAP_IF_LOOPBACK) continue;
#else
        if (d->flags & 0x00000001) continue;
#endif
        QString name = QString::fromLocal8Bit(d->name);
        QString desc = d->description ? QString::fromLocal8Bit(d->description) : "";
        if (name.contains("NPCAP", Qt::CaseInsensitive) || name.contains("Loopback", Qt::CaseInsensitive))
            continue;
        if (desc.contains("Bluetooth", Qt::CaseInsensitive) ||
            desc.contains("WAN Miniport", Qt::CaseInsensitive) ||
            desc.contains("VMware", Qt::CaseInsensitive) ||
            desc.contains("VirtualBox", Qt::CaseInsensitive) ||
            desc.contains("Hyper-V", Qt::CaseInsensitive) ||
            desc.contains("Teredo", Qt::CaseInsensitive) ||
            desc.contains("isatap", Qt::CaseInsensitive)) {
            continue;
        }
        candidates.append(d);
    }

    // Fallback: if no candidates, try all non-loopback interfaces
    if (candidates.isEmpty()) {
        logToFile("No preferred interfaces found, trying all non-loopback");
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            if (!d->addresses) continue;
#ifdef PCAP_IF_LOOPBACK
            if (d->flags & PCAP_IF_LOOPBACK) continue;
#else
            if (d->flags & 0x00000001) continue;
#endif
            candidates.append(d);
        }
    }

    if (candidates.isEmpty()) {
        qWarning() << "PacketCapture: no suitable interfaces found";
        logToFile("ERROR: no suitable interfaces found");
        pcap_freealldevs(alldevs);
        emit captureStatusChanged("No suitable network interfaces found.");
        return false;
    }

    // Start capture on all suitable interfaces
    bool anyStarted = false;
    for (pcap_if_t *d : candidates) {
        if (startCaptureOnInterface(d)) {
            anyStarted = true;
        }
    }

    pcap_freealldevs(alldevs);

    if (anyStarted) {
        logToFile(QString("Packet capture started on %1 interface(s)").arg(m_captures.size()));
        emit captureStatusChanged(QString("Capturing on %1 interface(s)").arg(m_captures.size()));
    }

    return anyStarted;
}

bool PacketCapture::startCaptureOnInterface(pcap_if_t *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    QString devName = QString::fromLocal8Bit(dev->name);
    QString devDesc = dev->description ? QString::fromLocal8Bit(dev->description) : devName;

    pcap_t *handle = pcap_open_live(dev->name, 65536, 1, 100, errbuf);
    if (!handle) {
        qWarning() << "PacketCapture: pcap_open_live failed for" << devName << ":" << errbuf;
        logToFile("WARNING: pcap_open_live failed for " + devName + ": " + QString(errbuf));
        return false;
    }

    logToFile("Opened: " + devName + " | " + devDesc + " link=" + QString::number(pcap_datalink(handle)));

    // Set BPF filter: capture all TCP and UDP except our proxy port
    struct bpf_program fp;
    const char *filter = "(tcp or udp) and not port 9527";
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        qWarning() << "PacketCapture: pcap_compile failed for" << devName << ":" << pcap_geterr(handle);
        logToFile("ERROR: pcap_compile failed for " + devName + ": " + QString(pcap_geterr(handle)));
        pcap_close(handle);
        return false;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        qWarning() << "PacketCapture: pcap_setfilter failed for" << devName << ":" << pcap_geterr(handle);
        logToFile("ERROR: pcap_setfilter failed for " + devName + ": " + QString(pcap_geterr(handle)));
        pcap_freecode(&fp);
        pcap_close(handle);
        return false;
    }
    pcap_freecode(&fp);

    // Create capture thread
    CaptureThread *thread = new CaptureThread(handle, this);
    connect(thread, &CaptureThread::httpCaptured,
            this, &PacketCapture::requestCaptured, Qt::QueuedConnection);
    connect(thread, &CaptureThread::finished, thread, &QObject::deleteLater);
    thread->start();

    InterfaceCapture ic;
    ic.handle = handle;
    ic.thread = thread;
    ic.name = devName;
    ic.description = devDesc;
    m_captures.append(ic);

    logToFile("Capture thread started for: " + devName);
    qDebug() << "PacketCapture: capturing on" << devName;

    return true;
}

void PacketCapture::stop()
{
    for (auto &ic : m_captures) {
        if (ic.thread) {
            ic.thread->requestStop();
            ic.thread->wait(5000);
            ic.thread = nullptr;
        }
        if (ic.handle) {
            pcap_close(ic.handle);
            ic.handle = nullptr;
        }
    }
    m_captures.clear();
    qDebug() << "PacketCapture: stopped";
}

bool PacketCapture::isRunning() const
{
    for (const auto &ic : m_captures) {
        if (ic.thread && ic.thread->isRunning()) {
            return true;
        }
    }
    return false;
}

void PacketCapture::setMitmActive(bool active)
{
    // macOS: pcap doesn't need MITM state (no duplicate filtering)
    Q_UNUSED(active);
}

#endif // Q_OS_WIN / macOS pcap implementation
