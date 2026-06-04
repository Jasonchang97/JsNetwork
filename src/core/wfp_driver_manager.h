#pragma once

#include <QObject>
#include <QThread>
#include <QMutex>
#include <QStringList>
#include <QAtomicInt>

#ifdef Q_OS_WIN

// Forward declarations for Windows types
typedef void *HANDLE;
typedef unsigned long DWORD;

// Shared with driver (same structures as driver/jsnetwork_wfp.h)
#define JSNWFP_PORT_NAME        L"\\JsNetworkWfpPort"
#define JSNWFP_MAX_PATH         260
#define JSNWFP_MAX_SNI          256
#define JSNWFP_CMD_START_CAPTURE    1
#define JSNWFP_CMD_STOP_CAPTURE     2
#define JSNWFP_CMD_SET_FILTER       3
#define JSNWFP_EVENT_CONNECT        1
#define JSNWFP_EVENT_DISCONNECT     2

// FILTER_MESSAGE_HEADER from fltUser.h
typedef struct _JSNWFP_MSG_HEADER {
    unsigned long  ReplyLength;
    unsigned long long MessageId;
} JSNWFP_MSG_HEADER;

#pragma pack(push, 8)
typedef struct _JSNWFP_EVENT {
    unsigned int   eventType;
    unsigned int   processId;
    unsigned long long timestamp;
    unsigned int   localAddr;
    unsigned int   remoteAddr;
    unsigned short localPort;
    unsigned short remotePort;
    unsigned short direction;
    unsigned short padding;
    wchar_t        processPath[JSNWFP_MAX_PATH];
    char           sniName[JSNWFP_MAX_SNI];
} JSNWFP_EVENT;

typedef struct _JSNWFP_COMMAND {
    unsigned int   command;
    unsigned int   param;
    wchar_t        filterPath[JSNWFP_MAX_PATH];
} JSNWFP_COMMAND;
#pragma pack(pop)

// Background thread that listens for events from the kernel driver
class WfpDriverListenThread : public QThread {
    Q_OBJECT
public:
    typedef long (*FilterGetMessageFn)(void *, void *, unsigned long, void *);

    explicit WfpDriverListenThread(HANDLE port, FilterGetMessageFn getMessageFn, QObject *parent = nullptr);
    void requestStop();

signals:
    void connectionDetected(quint32 pid, const QString &processPath,
                           quint32 localAddr, quint16 localPort,
                           quint32 remoteAddr, quint16 remotePort);

protected:
    void run() override;

private:
    HANDLE m_port;
    FilterGetMessageFn m_getMessageFn;
    QAtomicInt m_stopRequested;
};

// Manages the WFP callout driver lifecycle and event reception
class WfpDriverManager : public QObject {
    Q_OBJECT
public:
    explicit WfpDriverManager(QObject *parent = nullptr);
    ~WfpDriverManager();

    // Driver lifecycle
    bool install();
    bool uninstall();
    bool start();
    void stop();
    bool isRunning() const;
    bool isAvailable() const;

    // Send command to driver
    bool sendCommand(quint32 command, quint32 param = 0);

signals:
    void connectionDetected(quint32 pid, const QString &processPath,
                           quint32 localAddr, quint16 localPort,
                           quint32 remoteAddr, quint16 remotePort);
    void driverError(const QString &error);
    void driverStatusChanged(const QString &status);

private:
    bool loadFltLib();
    void unloadFltLib();

    // FilterCommunicationPort function pointers
    typedef long (*FilterConnectCommunicationPortFn)(
        const wchar_t *portName, unsigned long options,
        const void *context, unsigned short sizeOfContext,
        void *securityAttributes, void **port);
    typedef long (*FilterGetMessageFn)(
        void *port, void *messageBuffer,
        unsigned long messageBufferSize,
        void *overlapped);
    typedef long (*FilterSendMessageFn)(
        void *port, void *inBuffer,
        unsigned long inBufferSize, void *outBuffer,
        unsigned long outBufferSize, unsigned long *bytesReturned);
    typedef long (*FilterCloseFn)(void *port);

    FilterConnectCommunicationPortFn m_connectFn = nullptr;
    FilterGetMessageFn m_getMessageFn = nullptr;
    FilterSendMessageFn m_sendMessageFn = nullptr;
    FilterCloseFn m_closeFn = nullptr;

    void *m_fltLibHandle = nullptr;
    HANDLE m_port = nullptr;
    WfpDriverListenThread *m_listenThread = nullptr;
    QString m_driverPath;
};

#endif // Q_OS_WIN
