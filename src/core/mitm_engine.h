#pragma once

#include <QObject>
#include <QTcpSocket>
#include <QByteArray>

struct ssl_st;
struct ssl_ctx_st;
struct bio_st;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;

class CertManager;

class MitmConnection : public QObject
{
    Q_OBJECT
public:
    explicit MitmConnection(QTcpSocket *clientSocket, const QString &targetHost,
                            quint16 targetPort, CertManager *certMgr,
                            QObject *parent = nullptr);
    ~MitmConnection();

    void start();

signals:
    void finished();
    void requestCaptured(const QByteArray &requestData,
                         const QByteArray &responseData,
                         const QString &host, quint16 port,
                         qint64 durationMs);

private slots:
    void onServerConnected();
    void onClientReadyRead();
    void onServerReadyRead();

private:
    void doClientHandshake();
    bool flushClientWriteBIO();
    bool flushServerWrite();
    bool isResponseComplete() const;
    void emitCapturedAndReset();
    void cleanup();

    QTcpSocket *m_clientSocket;
    QTcpSocket *m_serverSocket;
    QString m_targetHost;
    quint16 m_targetPort;
    CertManager *m_certMgr;

    // Server TLS (socket BIO, accessed from server handshake thread)
    SSL *m_serverSsl = nullptr;
    SSL_CTX *m_serverCtx = nullptr;
    int m_serverFd = -1;

    // Client TLS (memory BIO, accessed from main thread event loop)
    SSL *m_clientSsl = nullptr;
    BIO *m_clientRbio = nullptr;
    BIO *m_clientWbio = nullptr;

    QByteArray m_requestBuffer;
    QByteArray m_responseBuffer;
    QByteArray m_pendingServerWrite;  // Buffered data when SSL_write returns WANT_WRITE
    qint64 m_startTime = 0;  // For timing diagnostics

    enum State { Connecting, ServerHandshake, ClientHandshake, Relaying, Done };
    State m_state = Connecting;
};

class MitmEngine : public QObject
{
    Q_OBJECT
public:
    explicit MitmEngine(CertManager *certMgr, QObject *parent = nullptr);
    ~MitmEngine();

    MitmConnection *intercept(QTcpSocket *clientSocket,
                              const QString &targetHost,
                              quint16 targetPort);

signals:
    void requestCaptured(const QByteArray &requestData,
                         const QByteArray &responseData,
                         const QString &host, quint16 port,
                         qint64 durationMs);

private:
    CertManager *m_certMgr;
};
