#include "mitm_engine.h"
#include "cert_manager.h"
#include "compat.h"
#include <QDebug>
#include <QTimer>
#include <QDateTime>
#include <QStandardPaths>
#include <QFile>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <QThread>
#include <cstring>

static WinsockInit winsockInit2;

static void logMsg(const QString &msg) {
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/debug.log";
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        f.write(QDateTime::currentDateTime().toString("hh:mm:ss.zzz").toUtf8());
        f.write(" ");
        f.write(msg.toUtf8());
        f.write("\n");
    }
}

// ============================================================================
// ServerHandshakeThread - server TLS handshake in background thread
// ============================================================================

class ServerHandshakeThread : public QThread {
    Q_OBJECT
public:
    ServerHandshakeThread(const QString &host, quint16 port, QObject *parent = nullptr)
        : QThread(parent), m_host(host), m_port(port) {
        PIPE(m_wakePipe);
    }
    ~ServerHandshakeThread() {
        // Interrupt select() so the thread can exit
        char c = 1;
        WRITE(m_wakePipe[1], &c, 1);
        wait(15000); // Wait up to 15s for thread to finish
        CLOSE(m_wakePipe[0]);
        CLOSE(m_wakePipe[1]);
        // Close server fd if thread left it open
        if (m_serverFd >= 0) {
            CLOSE(m_serverFd);
            m_serverFd = -1;
        }
    }

    void run() override {
        m_serverFd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_serverFd < 0) return;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(m_port);
        struct hostent *he = gethostbyname(m_host.toLatin1().data());
        if (!he) { CLOSE(m_serverFd); m_serverFd = -1; return; }
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);

        if (::connect(m_serverFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            CLOSE(m_serverFd); m_serverFd = -1; return;
        }

        m_ctx = SSL_CTX_new(TLS_method());
        SSL_CTX_set_default_verify_paths(m_ctx);

        // Force HTTP/1.1 only - MITM proxy only handles plaintext HTTP parsing
        static const unsigned char alpnProtos[] = {
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'  // "http/1.1"
        };
        SSL_CTX_set_alpn_protos(m_ctx, alpnProtos, sizeof(alpnProtos));

        m_ssl = SSL_new(m_ctx);
        SSL_set_connect_state(m_ssl);
        SSL_set_fd(m_ssl, m_serverFd);
        SSL_set_tlsext_host_name(m_ssl, m_host.toLatin1().data());

        int attempts = 0;
        while (true) {
            int ret = SSL_do_handshake(m_ssl);
            if (ret == 1) { m_ok = true; return; }
            int err = SSL_get_error(m_ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(m_serverFd, &fds);
                FD_SET(m_wakePipe[0], &fds);
                int maxfd = (m_serverFd > m_wakePipe[0] ? m_serverFd : m_wakePipe[0]) + 1;
                struct timeval tv = {10, 0};
                if (err == SSL_ERROR_WANT_READ)
                    select(maxfd, &fds, nullptr, nullptr, &tv);
                else
                    select(maxfd, nullptr, &fds, nullptr, &tv);
                if (FD_ISSET(m_wakePipe[0], &fds)) return; // Shutdown requested
                if (++attempts > 200) return;
                continue;
            }
            return;
        }
    }

    bool m_ok = false;
    int m_serverFd = -1;
    SSL *m_ssl = nullptr;
    SSL_CTX *m_ctx = nullptr;

private:
    QString m_host;
    quint16 m_port;
    int m_wakePipe[2];
};

// ============================================================================
// CertGenThread - generate domain cert in background thread (RSA key gen ~30-200ms)
// ============================================================================

class CertGenThread : public QThread {
    Q_OBJECT
public:
    CertGenThread(const QString &domain, CertManager *certMgr, QObject *parent = nullptr)
        : QThread(parent), m_domain(domain), m_certMgr(certMgr) {}

    void run() override {
        m_ctx = m_certMgr->createSslContextForDomain(m_domain);
    }

    SSL_CTX *m_ctx = nullptr;

private:
    QString m_domain;
    CertManager *m_certMgr;
};

// ============================================================================
// MitmConnection - hybrid approach: server in thread, client in main event loop
// Uses memory BIOs for client TLS to avoid socket fd conflicts
// ============================================================================

MitmConnection::MitmConnection(QTcpSocket *clientSocket, const QString &targetHost,
                                 quint16 targetPort, CertManager *certMgr,
                                 QObject *parent)
    : QObject(parent)
    , m_clientSocket(clientSocket)
    , m_serverSocket(new QTcpSocket(this))
    , m_targetHost(targetHost)
    , m_targetPort(targetPort)
    , m_certMgr(certMgr)
{
}

MitmConnection::~MitmConnection()
{
    cleanup();
}

void MitmConnection::start()
{
    m_startTime = QDateTime::currentMSecsSinceEpoch();
    logMsg(QString("MITM start: %1:%2 clientBytesAvail=%3 clientState=%4")
           .arg(m_targetHost).arg(m_targetPort)
           .arg(m_clientSocket->bytesAvailable())
           .arg((int)m_clientSocket->state()));

    // Detect when browser closes the connection
    connect(m_clientSocket, &QTcpSocket::disconnected, this, [this]() {
        cleanup();
    });

    // Start server TLS handshake in background thread (NOT a child of this, to avoid crash on cleanup)
    auto *serverThread = new ServerHandshakeThread(m_targetHost, m_targetPort);
    connect(serverThread, &QThread::finished, this, [this, serverThread]() {
        if (!serverThread->m_ok) {
            logMsg("MITM: server TLS FAILED for " + m_targetHost);
            serverThread->deleteLater();
            cleanup();
            return;
        }

        logMsg("MITM: server TLS OK for " + m_targetHost);
        m_serverSsl = serverThread->m_ssl;
        m_serverCtx = serverThread->m_ctx;
        m_serverFd = serverThread->m_serverFd;
        serverThread->m_ssl = nullptr;
        serverThread->m_ctx = nullptr;
        serverThread->m_serverFd = -1;
        serverThread->deleteLater();

        // Make server socket non-blocking for event-loop relay
#ifdef Q_OS_WIN
        u_long mode = 1;
        ioctlsocket(m_serverFd, FIONBIO, &mode);
#else
        int sflags = fcntl(m_serverFd, F_GETFL, 0);
        fcntl(m_serverFd, F_SETFL, sflags | O_NONBLOCK);
#endif

        // Generate domain cert in background thread (RSA key gen ~30-200ms)
        auto *certThread = new CertGenThread(m_targetHost, m_certMgr);
        connect(certThread, &QThread::finished, this, [this, certThread]() {
            SSL_CTX *clientCtx = certThread->m_ctx;
            certThread->deleteLater();

            if (!clientCtx) {
                logMsg("MITM: cert gen FAILED for " + m_targetHost);
                cleanup();
                return;
            }

            logMsg("MITM: cert OK for " + m_targetHost);

            // Set up client SSL with memory BIOs
            m_clientSsl = SSL_new(clientCtx);
            m_clientRbio = BIO_new(BIO_s_mem());
            m_clientWbio = BIO_new(BIO_s_mem());
            SSL_set_bio(m_clientSsl, m_clientRbio, m_clientWbio);
            SSL_set_accept_state(m_clientSsl);

            m_state = ClientHandshake;

            // Timeout: if client handshake doesn't complete in 30s, give up
            QTimer::singleShot(30000, this, [this]() {
                if (m_state == ClientHandshake) {
                    logMsg("MITM: client handshake TIMEOUT for " + m_targetHost);
                    cleanup();
                }
            });

            // Feed any already-buffered Qt data to the read BIO
            if (m_clientSocket->bytesAvailable() > 0) {
                QByteArray data = m_clientSocket->readAll();
                BIO_write(m_clientRbio, data.constData(), data.size());
            }

            doClientHandshake();
        });
        certThread->start();
    });
    serverThread->start();
}

void MitmConnection::doClientHandshake()
{
    while (true) {
        int ret = SSL_do_handshake(m_clientSsl);
        if (ret == 1) {
            logMsg("MITM: client TLS OK for " + m_targetHost);
            // Flush any remaining output
            flushClientWriteBIO();
            m_state = Relaying;
            // Connect client readyRead for relay
            connect(m_clientSocket, &QTcpSocket::readyRead,
                    this, &MitmConnection::onClientReadyRead);
            // Poll server socket
            auto *timer = new QTimer(this);
            connect(timer, &QTimer::timeout, this, &MitmConnection::onServerReadyRead);
            timer->start(50);
            return;
        }

        int err = SSL_get_error(m_clientSsl, ret);

        if (err == SSL_ERROR_WANT_WRITE) {
            // SSL wants to write data to client
            if (!flushClientWriteBIO()) {
                qDebug() << "MITM: client write failed for" << m_targetHost;
                cleanup();
                return;
            }
            continue;
        }

        if (err == SSL_ERROR_WANT_READ) {
            // Flush output first (e.g., ServerHello)
            if (!flushClientWriteBIO()) {
                qDebug() << "MITM: client write failed for" << m_targetHost;
                cleanup();
                return;
            }
            // Check if Qt has buffered data
            if (m_clientSocket->bytesAvailable() > 0) {
                QByteArray data = m_clientSocket->readAll();
                BIO_write(m_clientRbio, data.constData(), data.size());
                continue;
            }
            // Wait for more data from client
            connect(m_clientSocket, &QTcpSocket::readyRead,
                    this, &MitmConnection::doClientHandshake, Qt::UniqueConnection);
            return;
        }

        qDebug() << "MITM: client handshake fatal err=" << err << "errno=" << errno;
        cleanup();
        return;
    }
}

bool MitmConnection::flushClientWriteBIO()
{
    char buf[16384];
    int n;
    while ((n = BIO_read(m_clientWbio, buf, sizeof(buf))) > 0) {
        m_clientSocket->write(buf, n);
    }
    m_clientSocket->flush();
    return true;
}

void MitmConnection::onClientReadyRead()
{
    if (m_state == ClientHandshake) {
        QByteArray data = m_clientSocket->readAll();
        if (!data.isEmpty()) {
            BIO_write(m_clientRbio, data.constData(), data.size());
        }
        doClientHandshake();
        return;
    }

    if (m_state != Relaying) return;

    // Read raw TLS data from client, feed to memory read BIO
    QByteArray rawData = m_clientSocket->readAll();
    if (rawData.isEmpty()) return;
    BIO_write(m_clientRbio, rawData.constData(), rawData.size());

    // Decrypt all available records and forward to server
    char plainBuf[16384];
    int n;
    while ((n = SSL_read(m_clientSsl, plainBuf, sizeof(plainBuf))) > 0) {
        m_requestBuffer.append(plainBuf, n);

        // IMPORTANT: must flush pending data BEFORE writing new data
        // OpenSSL requires retrying with the same args after WANT_WRITE
        if (!m_pendingServerWrite.isEmpty()) {
            if (!flushServerWrite()) {
                cleanup();
                return;
            }
        }

        if (m_pendingServerWrite.isEmpty()) {
            // No pending data, safe to write new data
            m_pendingServerWrite.append(plainBuf, n);
            if (!flushServerWrite()) {
                cleanup();
                return;
            }
        } else {
            // Pending data couldn't be flushed, buffer new data too
            m_pendingServerWrite.append(plainBuf, n);
        }
    }
}

bool MitmConnection::flushServerWrite()
{
    if (m_pendingServerWrite.isEmpty() || !m_serverSsl) return true;

    const char *data = m_pendingServerWrite.constData();
    int remaining = m_pendingServerWrite.size();
    int offset = 0;

    while (offset < remaining) {
        int w = SSL_write(m_serverSsl, data + offset, remaining - offset);
        if (w > 0) {
            offset += w;
        } else {
            int err = SSL_get_error(m_serverSsl, w);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                // Keep remaining data in buffer
                m_pendingServerWrite = m_pendingServerWrite.mid(offset);
                return true;
            }
            return false;  // Fatal error
        }
    }

    m_pendingServerWrite.clear();
    return true;
}

bool MitmConnection::isResponseComplete() const
{
    // Need at least headers
    int headerEnd = m_responseBuffer.indexOf("\r\n\r\n");
    if (headerEnd < 0) return false;

    // Check Content-Length
    int contentLength = -1;
    QByteArray headers = m_responseBuffer.left(headerEnd).toLower();
    int clIdx = headers.indexOf("content-length:");
    if (clIdx >= 0) {
        int clEnd = headers.indexOf("\r\n", clIdx);
        if (clEnd < 0) clEnd = headers.size();
        QByteArray clValue = headers.mid(clIdx + 15, clEnd - clIdx - 15).trimmed();
        contentLength = clValue.toInt();
    }

    int bodyStart = headerEnd + 4;
    int bodySize = m_responseBuffer.size() - bodyStart;

    if (contentLength >= 0) {
        return bodySize >= contentLength;
    }

    // Check chunked transfer encoding
    if (headers.contains("transfer-encoding:") && headers.contains("chunked")) {
        // Look for terminating chunk: "\r\n0\r\n" followed by optional trailers and final "\r\n"
        QByteArray body = m_responseBuffer.mid(bodyStart);
        int termIdx = body.indexOf("\r\n0\r\n");
        if (termIdx >= 0) {
            // Found "0" chunk, check for trailing \r\n\r\n after it
            int afterZero = termIdx + 5; // past "\r\n0\r\n"
            int trailEnd = body.indexOf("\r\n", afterZero);
            return trailEnd >= 0;
        }
        // Also handle case where body starts with "0\r\n" (empty chunked body)
        if (body.startsWith("0\r\n\r\n") || body.startsWith("0\r\n")) {
            return body.indexOf("\r\n\r\n") >= 0;
        }
        return false;
    }

    // No Content-Length and not chunked: wait for connection close
    return false;
}

void MitmConnection::emitCapturedAndReset()
{
    if (m_requestBuffer.isEmpty()) return;

    logMsg(QString("MITM: captured %1 req=%2 resp=%3")
           .arg(m_targetHost).arg(m_requestBuffer.size()).arg(m_responseBuffer.size()));

    qint64 duration = QDateTime::currentMSecsSinceEpoch() - m_startTime;
    emit requestCaptured(m_requestBuffer, m_responseBuffer, m_targetHost, m_targetPort, duration);

    m_requestBuffer.clear();
    m_responseBuffer.clear();
    // Don't clear m_pendingServerWrite - it may contain data not yet flushed to server
}

void MitmConnection::onServerReadyRead()
{
    if (m_state != Relaying || !m_serverSsl) return;

    // Flush any pending client->server data that was buffered due to WANT_WRITE
    if (!m_pendingServerWrite.isEmpty()) {
        if (!flushServerWrite()) {
            cleanup();
            return;
        }
    }

    char plainBuf[16384];
    int n;
    bool serverClosed = false;
    while ((n = SSL_read(m_serverSsl, plainBuf, sizeof(plainBuf))) > 0) {
        m_responseBuffer.append(plainBuf, n);
        SSL_write(m_clientSsl, plainBuf, n);
        flushClientWriteBIO();
    }

    if (n <= 0) {
        int err = SSL_get_error(m_serverSsl, n);
        if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL ||
            err == SSL_ERROR_SSL) {
            serverClosed = true;
        }
    }

    // Check if HTTP response is complete - emit immediately instead of waiting for connection close
    if (isResponseComplete()) {
        emitCapturedAndReset();
    } else if (serverClosed && !m_responseBuffer.isEmpty()) {
        // Server closed connection - treat accumulated data as complete response
        // (common for HTTP/1.0 or responses without Content-Length)
        emitCapturedAndReset();
        cleanup();
    }
}

void MitmConnection::onServerConnected() {}

void MitmConnection::cleanup()
{
    if (m_state == Done) return;

    logMsg(QString("MITM: cleanup %1 state=%2 req=%3 resp=%4 serverSsl=%5 clientSsl=%6")
           .arg(m_targetHost).arg((int)m_state)
           .arg(m_requestBuffer.size()).arg(m_responseBuffer.size())
           .arg(m_serverSsl != nullptr).arg(m_clientSsl != nullptr));

    m_state = Done;

    if (m_clientSsl) {
        SSL_shutdown(m_clientSsl);
        SSL_free(m_clientSsl);
        m_clientSsl = nullptr;
        m_clientRbio = nullptr;
        m_clientWbio = nullptr;
    }
    if (m_serverSsl) {
        SSL_shutdown(m_serverSsl);
        SSL_free(m_serverSsl);
        m_serverSsl = nullptr;
    }
    if (m_serverCtx) {
        SSL_CTX_free(m_serverCtx);
        m_serverCtx = nullptr;
    }
    // Close server fd (thread's copy was set to -1 after transfer)
    if (m_serverFd >= 0) {
        CLOSE(m_serverFd);
        m_serverFd = -1;
    }

    if (!m_requestBuffer.isEmpty()) {
        qint64 duration = QDateTime::currentMSecsSinceEpoch() - m_startTime;
        emit requestCaptured(m_requestBuffer, m_responseBuffer, m_targetHost, m_targetPort, duration);
    }
    emit finished();
}

// ============================================================================
// MitmEngine
// ============================================================================

MitmEngine::MitmEngine(CertManager *certMgr, QObject *parent)
    : QObject(parent)
    , m_certMgr(certMgr)
{
}

MitmEngine::~MitmEngine() = default;

MitmConnection *MitmEngine::intercept(QTcpSocket *clientSocket,
                                       const QString &targetHost,
                                       quint16 targetPort)
{
    auto *conn = new MitmConnection(clientSocket, targetHost, targetPort,
                                     m_certMgr, this);

    connect(conn, &MitmConnection::requestCaptured,
            this, &MitmEngine::requestCaptured);
    connect(conn, &MitmConnection::finished, conn, &QObject::deleteLater);

    conn->start();
    return conn;
}

#include "mitm_engine.moc"
