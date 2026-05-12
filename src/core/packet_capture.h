#pragma once

#include <QObject>
#include <QThread>
#include <QByteArray>
#include <QMap>
#include <QMutex>
#include <QDateTime>
#include "model/request_item.h"

#ifdef Q_OS_WIN
#include <winsock2.h>
#endif

// Forward declarations for pcap types
typedef struct pcap pcap_t;
struct pcap_pkthdr;

// TCP stream reassembly buffer
struct TcpStream {
    QByteArray requestData;
    QByteArray responseData;
    quint32 clientSeq = 0;
    quint32 serverSeq = 0;
    bool clientSeqInit = false;
    bool serverSeqInit = false;
    qint64 startTime = 0;
    QString srcIp;
    quint16 srcPort = 0;
    QString dstIp;
    quint16 dstPort = 0;
    bool isHttps = false;
    QString sniHost;
};

// Key for identifying a TCP connection
struct ConnKey {
    QString clientIp;
    quint16 clientPort = 0;
    QString serverIp;
    quint16 serverPort = 0;

    bool operator==(const ConnKey &o) const {
        return clientIp == o.clientIp && clientPort == o.clientPort
            && serverIp == o.serverIp && serverPort == o.serverPort;
    }
    bool operator<(const ConnKey &o) const {
        if (clientIp != o.clientIp) return clientIp < o.clientIp;
        if (clientPort != o.clientPort) return clientPort < o.clientPort;
        if (serverIp != o.serverIp) return serverIp < o.serverIp;
        return serverPort < o.serverPort;
    }

    // Create a canonical key where the "lower" endpoint is always the client
    static ConnKey canonical(const QString &ip1, quint16 port1, const QString &ip2, quint16 port2) {
        if (ip1 < ip2 || (ip1 == ip2 && port1 <= port2))
            return {ip1, port1, ip2, port2};
        else
            return {ip2, port2, ip1, port1};
    }
};

class CaptureThread : public QThread {
    Q_OBJECT
public:
    CaptureThread(pcap_t *handle, QObject *parent = nullptr);
    void run() override;
    void requestStop();

signals:
    void httpCaptured(const RequestItem &item);

private:
    static void packetHandler(u_char *user, const pcap_pkthdr *header, const u_char *data);
    void processPacket(const pcap_pkthdr *header, const u_char *data);
    void processTcpPacket(const pcap_pkthdr *header, const u_char *data, const struct TcpHeader *tcp,
                          const char *srcBuf, const char *dstBuf, u_short srcPort, u_short dstPort);
    void processUdpPacket(const pcap_pkthdr *header, const u_char *data, const struct UdpHeader *udp,
                          const char *srcBuf, const char *dstBuf, u_short srcPort, u_short dstPort);
    void checkStreamComplete(const ConnKey &key, TcpStream &stream);
    void emitStaleStreams();

    pcap_t *m_handle;
    volatile bool m_stopRequested = false;

    QMap<ConnKey, TcpStream> m_streams;
    QMutex m_mutex;
    int m_nextId = 1;
    int m_packetCount = 0;
};

class PacketCapture : public QObject
{
    Q_OBJECT
public:
    explicit PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();

    bool start();
    void stop();
    bool isRunning() const;

    static QStringList availableInterfaces();

signals:
    void requestCaptured(const RequestItem &item);

private:
    CaptureThread *m_thread = nullptr;
    pcap_t *m_handle = nullptr;
};
