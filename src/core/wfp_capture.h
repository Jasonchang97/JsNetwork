#pragma once

#ifdef Q_OS_WIN

#include <QObject>
#include <QThread>
#include <QByteArray>
#include <QMap>
#include <QMutex>
#include <QDateTime>
#include "model/request_item.h"

#include <winsock2.h>
#include <windows.h>

// Forward declarations for WinDivert types
struct _WINDIVERT_IPHDR;
struct _WINDIVERT_IPV6HDR;
struct _WINDIVERT_TCPHDR;
struct _WINDIVERT_UDPHDR;
struct _WINDIVERT_ADDRESS;

// TCP stream reassembly buffer (shared with PacketCapture)
struct WfpTcpStream {
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

struct WfpConnKey {
    QString clientIp;
    quint16 clientPort = 0;
    QString serverIp;
    quint16 serverPort = 0;

    bool operator==(const WfpConnKey &o) const {
        return clientIp == o.clientIp && clientPort == o.clientPort
            && serverIp == o.serverIp && serverPort == o.serverPort;
    }
    bool operator<(const WfpConnKey &o) const {
        if (clientIp != o.clientIp) return clientIp < o.clientIp;
        if (clientPort != o.clientPort) return clientPort < o.clientPort;
        if (serverIp != o.serverIp) return serverIp < o.serverIp;
        return serverPort < o.serverPort;
    }

    static WfpConnKey canonical(const QString &ip1, quint16 port1,
                                const QString &ip2, quint16 port2) {
        if (ip1 < ip2 || (ip1 == ip2 && port1 <= port2))
            return {ip1, port1, ip2, port2};
        else
            return {ip2, port2, ip1, port1};
    }
};

// Forward declare WinDivertApi (defined below)
struct WinDivertApi;

class WfpCaptureThread : public QThread {
    Q_OBJECT
public:
    WfpCaptureThread(void *handle, const WinDivertApi *api, QObject *parent = nullptr);
    void run() override;
    void requestStop();

signals:
    void httpCaptured(const RequestItem &item);

private:
    void processTcpPacket(const _WINDIVERT_IPHDR *ipHdr, const _WINDIVERT_TCPHDR *tcpHdr,
                          const quint8 *payload, UINT payloadLen, bool outbound);
    void processTcpPacketV6(const _WINDIVERT_IPV6HDR *ip6Hdr, const _WINDIVERT_TCPHDR *tcpHdr,
                            const quint8 *payload, UINT payloadLen, bool outbound);
    void checkStreamComplete(const WfpConnKey &key, WfpTcpStream &stream);
    void emitStaleStreams();
    static QString extractSniFromClientHello(const QByteArray &data);

    void *m_handle;  // HANDLE (WinDivert handle)
    const WinDivertApi *m_api;
    volatile bool m_stopRequested = false;

    QMap<WfpConnKey, WfpTcpStream> m_streams;
    QMutex m_mutex;
    int m_nextId = 1;
    int m_packetCount = 0;
};

// WinDivert function pointer types
typedef void* HANDLE_WD;
typedef INT16 WINDIVERT_LAYER_T;
typedef UINT64 WINDIVERT_FLAGS_T;

typedef HANDLE_WD (WINAPI *WinDivertOpenFn)(const char *, WINDIVERT_LAYER_T, INT16, UINT64);
typedef BOOL (WINAPI *WinDivertRecvFn)(HANDLE_WD, void *, UINT, UINT *, _WINDIVERT_ADDRESS *);
typedef BOOL (WINAPI *WinDivertCloseFn)(HANDLE_WD);
typedef BOOL (WINAPI *WinDivertShutdownFn)(HANDLE_WD, int);
typedef BOOL (WINAPI *WinDivertHelperParsePacketFn)(const void *, UINT,
    _WINDIVERT_IPHDR **, _WINDIVERT_IPV6HDR **, UINT8 *,
    void *, void *, _WINDIVERT_TCPHDR **, _WINDIVERT_UDPHDR **,
    void **, UINT *, void **, UINT *);
typedef BOOL (WINAPI *WinDivertHelperFormatIPv4AddressFn)(UINT32, char *, UINT);
typedef BOOL (WINAPI *WinDivertHelperFormatIPv6AddressFn)(const UINT32 *, char *, UINT);

struct WinDivertApi {
    WinDivertOpenFn open = nullptr;
    WinDivertRecvFn recv = nullptr;
    WinDivertCloseFn close = nullptr;
    WinDivertShutdownFn shutdown = nullptr;
    WinDivertHelperParsePacketFn parsePacket = nullptr;
    WinDivertHelperFormatIPv4AddressFn formatIPv4 = nullptr;
    WinDivertHelperFormatIPv6AddressFn formatIPv6 = nullptr;
    bool loaded = false;
};

class WfpCapture : public QObject
{
    Q_OBJECT
public:
    explicit WfpCapture(QObject *parent = nullptr);
    ~WfpCapture();

    bool start();
    void stop();
    bool isRunning() const;
    bool isAvailable() const;

signals:
    void requestCaptured(const RequestItem &item);
    void captureStatusChanged(const QString &message);

private:
    bool loadWinDivert();

    WinDivertApi m_api;
    void *m_dllHandle = nullptr;
    WfpCaptureThread *m_thread = nullptr;
    void *m_wdHandle = nullptr;  // WinDivert HANDLE
};

#endif // Q_OS_WIN
