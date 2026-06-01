#pragma once

#include <QObject>
#include <QThread>
#include <QByteArray>
#include <QMap>
#include <QMutex>
#include <QDateTime>
#include "model/request_item.h"

// TCP stream reassembly buffer
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

// WinDivert function pointer types (no WinDivert types in signatures)
#ifndef WINAPI
#define WINAPI __stdcall
#endif

typedef void* HANDLE_WD;

typedef HANDLE_WD (WINAPI *WinDivertOpenFn)(const char *, int, short, unsigned long long);
typedef int (WINAPI *WinDivertRecvFn)(HANDLE_WD, void *, unsigned int, unsigned int *, void *);
typedef int (WINAPI *WinDivertCloseFn)(HANDLE_WD);
typedef int (WINAPI *WinDivertShutdownFn)(HANDLE_WD, int);
typedef int (WINAPI *WinDivertHelperParsePacketFn)(const void *, unsigned int,
    void **, void **, unsigned char *,
    void *, void *, void **, void **,
    void **, unsigned int *, void **, unsigned int *);
typedef int (WINAPI *WinDivertHelperFormatIPv4AddressFn)(unsigned int, char *, unsigned int);
typedef int (WINAPI *WinDivertHelperFormatIPv6AddressFn)(const unsigned int *, char *, unsigned int);

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

class WfpCaptureThread : public QThread {
    Q_OBJECT
public:
    WfpCaptureThread(void *handle, const WinDivertApi *api, QObject *parent = nullptr);
    void run() override;
    void requestStop();

signals:
    void httpCaptured(const RequestItem &item);

private:
    void processTcpPacket(void *ipHdr, void *tcpHdr,
                          const quint8 *payload, unsigned int payloadLen, bool outbound, bool isIpv6);
    void checkStreamComplete(const WfpConnKey &key, WfpTcpStream &stream);
    void emitStaleStreams();
    static QString extractSniFromClientHello(const QByteArray &data);

    void *m_handle;
    const WinDivertApi *m_api;
    volatile bool m_stopRequested = false;

    QMap<WfpConnKey, WfpTcpStream> m_streams;
    QMutex m_mutex;
    int m_nextId = 1;
    int m_packetCount = 0;
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
    void *m_wdHandle = nullptr;
};
