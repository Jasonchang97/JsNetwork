#pragma once

#include <QObject>
#include <QThread>
#include <QMap>
#include <QMutex>
#include <QPair>
#include <winsock2.h>
#include "wfp_capture.h"

// Tracks a redirected connection's original destination
struct RedirectConn {
    quint32 origDstIp = 0;
    quint16 origDstPort = 0;
    qint64 timestamp = 0;
};

// WinDivert packet redirect thread — intercepts outgoing SYN to port 443,
// rewrites destination to local transparent proxy, and rewrites return traffic.
class WfpRedirectThread : public QThread {
    Q_OBJECT
public:
    WfpRedirectThread(const WinDivertApi *api, void *handle, quint16 proxyPort, QObject *parent = nullptr);
    void run() override;
    void requestStop();

    // Look up original destination for a redirected connection
    bool lookupOriginal(quint32 clientIp, quint16 clientPort,
                        quint32 &origDstIp, quint16 &origDstPort);

private:
    void cleanupStale();

    const WinDivertApi *m_api;
    void *m_handle;
    quint16 m_proxyPort;
    volatile bool m_stopRequested = false;

    // clientIp:clientPort → original destination
    QMap<QPair<quint32, quint16>, RedirectConn> m_connections;
    QMutex m_mutex;
    int m_packetCount = 0;
};

// Manages WinDivert transparent proxy redirect
class WfpRedirect : public QObject {
    Q_OBJECT
public:
    explicit WfpRedirect(QObject *parent = nullptr);
    ~WfpRedirect();

    bool start(quint16 proxyPort);
    void stop();
    bool isRunning() const;
    bool isAvailable() const;

    // Look up original destination for a redirected connection
    bool lookupOriginal(quint32 clientIp, quint16 clientPort,
                        quint32 &origDstIp, quint16 &origDstPort);

private:
    bool loadWinDivert();

    WinDivertApi m_api;
    void *m_dllHandle = nullptr;
    WfpRedirectThread *m_thread = nullptr;
    void *m_wdHandle = nullptr;
};
