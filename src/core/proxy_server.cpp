#include "proxy_server.h"
#include "http_parser.h"
#include "cert_manager.h"
#include "mitm_engine.h"
#include <QUrl>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QNetworkProxy>
#include <QThread>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <cstring>

// Background thread for blocking DNS + TCP connect only
class ConnectThread : public QThread {
public:
    ConnectThread(int clientFd, const QString &host, quint16 port, QObject *parent = nullptr)
        : QThread(parent)
        , m_clientFd(clientFd)
        , m_host(host)
        , m_port(port)
    {}

    int takeClientFd() { int fd = m_clientFd; m_clientFd = -1; return fd; }
    int takeServerFd() { int fd = m_serverFd; m_serverFd = -1; return fd; }
    bool success() const { return m_success; }

protected:
    void run() override {
        m_serverFd = socket(AF_INET, SOCK_STREAM, 0);
        if (m_serverFd < 0) { m_success = false; return; }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(m_port);

        struct hostent *he = gethostbyname(m_host.toLatin1().data());
        if (!he) { ::close(m_serverFd); m_serverFd = -1; m_success = false; return; }
        memcpy(&addr.sin_addr, he->h_addr, he->h_length);

        if (::connect(m_serverFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            ::close(m_serverFd); m_serverFd = -1; m_success = false; return;
        }
        m_success = true;
    }

private:
    int m_clientFd;
    int m_serverFd = -1;
    QString m_host;
    quint16 m_port;
    bool m_success = false;
};

// Bidirectional TCP tunnel using blocking I/O in a separate thread
class TunnelThread : public QThread {
public:
    TunnelThread(int fd1, int fd2, QObject *parent = nullptr)
        : QThread(parent), m_fd1(fd1), m_fd2(fd2) {
        // Self-pipe to interrupt select() on shutdown
        pipe(m_wakePipe);
    }
    ~TunnelThread() {
        // Interrupt the select() loop
        char c = 1;
        write(m_wakePipe[1], &c, 1);
        wait(3000); // Wait up to 3s for thread to finish
        ::close(m_wakePipe[0]);
        ::close(m_wakePipe[1]);
    }

    void run() override {
        fd_set fds;
        char buf[8192];
        int maxfd = (m_fd1 > m_fd2 ? m_fd1 : m_fd2) + 1;
        if (m_wakePipe[0] >= maxfd) maxfd = m_wakePipe[0] + 1;

        while (true) {
            FD_ZERO(&fds);
            FD_SET(m_fd1, &fds);
            FD_SET(m_fd2, &fds);
            FD_SET(m_wakePipe[0], &fds);

            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;

            int ret = select(maxfd, &fds, nullptr, nullptr, &tv);
            if (ret <= 0) break;
            if (FD_ISSET(m_wakePipe[0], &fds)) break; // Shutdown requested

            if (FD_ISSET(m_fd1, &fds)) {
                ssize_t n = read(m_fd1, buf, sizeof(buf));
                if (n <= 0) break;
                write(m_fd2, buf, n);
            }
            if (FD_ISSET(m_fd2, &fds)) {
                ssize_t n = read(m_fd2, buf, sizeof(buf));
                if (n <= 0) break;
                write(m_fd1, buf, n);
            }
        }
        ::close(m_fd1);
        ::close(m_fd2);
    }

private:
    int m_fd1, m_fd2;
    int m_wakePipe[2];
};

ProxyServer::ProxyServer(QObject *parent)
    : QObject(parent)
    , m_server(new QTcpServer(this))
    , m_nam(new QNetworkAccessManager(this))
{
    // Don't use system proxy for outgoing requests (avoids loop)
    m_nam->setProxy(QNetworkProxy::NoProxy);
    connect(m_server, &QTcpServer::newConnection,
            this, &ProxyServer::onNewConnection);
}

ProxyServer::~ProxyServer()
{
    stop();
}

bool ProxyServer::start(quint16 port)
{
    if (m_server->isListening()) {
        m_server->close();
    }
    return m_server->listen(QHostAddress::LocalHost, port);
}

void ProxyServer::stop()
{
    m_server->close();
    for (auto *conn : qAsConst(m_connections)) {
        cleanup(conn);
    }
    m_connections.clear();
}

bool ProxyServer::isRunning() const
{
    return m_server->isListening();
}

quint16 ProxyServer::port() const
{
    return m_server->serverPort();
}

void ProxyServer::enableMitm(CertManager *certMgr)
{
    m_certMgr = certMgr;
    m_mitmEngine = new MitmEngine(certMgr, this);

    connect(m_mitmEngine, &MitmEngine::requestCaptured,
            this, &ProxyServer::onMitmCaptured);

    m_mitmEnabled = true;
}

void ProxyServer::disableMitm()
{
    m_mitmEnabled = false;
    if (m_mitmEngine) {
        m_mitmEngine->deleteLater();
        m_mitmEngine = nullptr;
    }
    m_certMgr = nullptr;
}

bool ProxyServer::isMitmEnabled() const
{
    return m_mitmEnabled;
}

void ProxyServer::onNewConnection()
{
    while (m_server->hasPendingConnections()) {
        QTcpSocket *client = m_server->nextPendingConnection();
        auto *conn = new Connection;
        conn->client = client;
        conn->item.id = m_nextId++;
        conn->item.timestamp = QDateTime::currentDateTime();
        conn->startTime = QDateTime::currentMSecsSinceEpoch();
        m_connections[client] = conn;

        connect(client, &QTcpSocket::readyRead, this, &ProxyServer::onClientReadyRead);
        connect(client, &QTcpSocket::disconnected, this, &ProxyServer::onClientDisconnected);
    }
}

void ProxyServer::onClientReadyRead()
{
    auto *client = qobject_cast<QTcpSocket*>(sender());
    if (!client || !m_connections.contains(client)) return;

    Connection *conn = m_connections[client];

    // CONNECT tunnel: forward client data to server
    if (conn->server) {
        QByteArray data = client->readAll();
        if (conn->server->isWritable()) {
            conn->server->write(data);
            conn->server->flush();
        }
        return;
    }

    conn->requestBuffer.append(client->readAll());

    // Wait for complete headers
    if (!conn->requestBuffer.contains("\r\n\r\n")) return;

    // Parse the first line to determine method
    QByteArray firstLine = conn->requestBuffer.left(conn->requestBuffer.indexOf("\r\n"));
    QList<QByteArray> parts = firstLine.split(' ');
    if (parts.size() < 2) return;

    QString method = QString::fromLatin1(parts[0]);
    QString target = QString::fromLatin1(parts[1]);

    if (method == "CONNECT") {
        // HTTPS: host:port format
        conn->isConnect = true;
        conn->item.method = method;
        QStringList hostPort = target.split(':');
        conn->item.host = hostPort.value(0);
        conn->item.path = target;
        conn->item.protocol = "HTTPS";
        handleConnect(conn);
    } else {
        // Plain HTTP
        if (!HttpParser::parseRequest(conn->requestBuffer, conn->item)) return;
        // Fix host if it includes port
        QUrl url(conn->item.url);
        if (!url.host().isEmpty()) {
            conn->item.host = url.host();
        }
        handlePlainHttp(conn);
    }
}

void ProxyServer::handleConnect(Connection *conn)
{
    quint16 targetPort = 443;
    QStringList hostPort = conn->item.path.split(':');
    if (hostPort.size() > 1) {
        targetPort = hostPort[1].toUShort();
    }
    QString targetHost = hostPort[0];

    // Send 200 to client first (non-blocking)
    QByteArray response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    conn->client->write(response);
    conn->client->flush();

    if (m_mitmEnabled && m_mitmEngine && targetPort == 443) {
        // MITM mode: ServerHandshakeThread does DNS+connect+TLS in background (already non-blocking)
        qDebug() << "MITM: intercepting" << targetHost;

        QTcpSocket *client = conn->client;
        m_connections.remove(conn->client);
        conn->client = nullptr;

        MitmConnection *mitmConn = m_mitmEngine->intercept(client, targetHost, targetPort);
        connect(mitmConn, &MitmConnection::finished, this, [conn, client]() {
            client->disconnectFromHost();
            client->deleteLater();
            delete conn;
        });
    } else {
        // Pass-through: DNS + connect in background thread (avoids blocking main thread)
        qDebug() << "Proxy: pass-through" << targetHost << ":" << targetPort;

        int clientFd = dup(conn->client->socketDescriptor());
        m_connections.remove(conn->client);
        conn->client->deleteLater();
        conn->client = nullptr;

        auto *connector = new ConnectThread(clientFd, targetHost, targetPort);
        connect(connector, &QThread::finished, this, [this, connector, conn]() {
            if (!connector->success()) {
                qDebug() << "Connect failed to" << conn->item.host;
                ::close(connector->takeClientFd());
                delete conn;
                connector->deleteLater();
                return;
            }

            int clientFd = connector->takeClientFd();
            int serverFd = connector->takeServerFd();
            connector->deleteLater();

            // Start bidirectional tunnel now that connect succeeded
            auto *tunnel = new TunnelThread(clientFd, serverFd, this);
            connect(tunnel, &QThread::finished, this, [conn, tunnel]() {
                delete conn;
                tunnel->deleteLater();
            });
            tunnel->start();
        });
        connector->start();
    }
}

void ProxyServer::handlePlainHttp(Connection *conn)
{
    QUrl url(conn->item.url);
    QNetworkRequest request(url);
    request.setAttribute(QNetworkRequest::FollowRedirectsAttribute, false);
    request.setRawHeader("Host", conn->item.host.toUtf8());
    // Copy request headers (skip Host and Proxy-Connection)
    for (auto it = conn->item.requestHeaders.constBegin();
         it != conn->item.requestHeaders.constEnd(); ++it) {
        QString key = it.key().toLower();
        if (key != "host" && key != "proxy-connection") {
            request.setRawHeader(it.key().toUtf8(), it.value().toUtf8());
        }
    }

    QNetworkReply *reply = nullptr;
    QString method = conn->item.method;
    if (method == "GET") {
        reply = m_nam->get(request);
    } else if (method == "POST") {
        reply = m_nam->post(request, conn->item.requestBody);
    } else if (method == "PUT") {
        reply = m_nam->put(request, conn->item.requestBody);
    } else if (method == "DELETE") {
        reply = m_nam->deleteResource(request);
    } else if (method == "HEAD") {
        reply = m_nam->head(request);
    } else {
        reply = m_nam->sendCustomRequest(request, method.toUtf8(), conn->item.requestBody);
    }

    if (!reply) {
        // Remove client from tracking and cleanup
        if (conn->client) m_connections.remove(conn->client);
        conn->client->deleteLater();
        delete conn;
        return;
    }

    // Remove client from tracking (reply owns the connection now)
    if (conn->client) m_connections.remove(conn->client);

    connect(reply, &QNetworkReply::finished, this, [this, reply, conn]() {
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            QByteArray errResp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            if (conn->client && conn->client->isWritable()) {
                conn->client->write(errResp);
                conn->client->flush();
            }
            conn->client->deleteLater();
            delete conn;
            return;
        }

        // Build HTTP response
        int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QString reason = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toString();
        QByteArray respData = "HTTP/1.1 " + QByteArray::number(status) + " " + reason.toUtf8() + "\r\n";

        QList<QByteArray> skipHeaders = {"connection", "transfer-encoding", "content-encoding"};
        for (const auto &hdr : reply->rawHeaderPairs()) {
            QByteArray key = hdr.first.toLower();
            if (!skipHeaders.contains(key)) {
                respData += hdr.first + ": " + hdr.second + "\r\n";
            }
        }
        QByteArray body = reply->readAll();
        respData += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
        respData += "Connection: close\r\n";
        respData += "\r\n";
        respData += body;

        // Parse response for RequestItem
        HttpParser::parseResponse(respData, conn->item);

        // Calculate duration
        if (conn->startTime > 0) {
            conn->item.duration = QDateTime::currentMSecsSinceEpoch() - conn->startTime;
        }

        if (conn->client && conn->client->isWritable()) {
            conn->client->write(respData);
            conn->client->flush();
        }

        emit requestCaptured(conn->item);
        conn->client->deleteLater();
        delete conn;
    });
}

void ProxyServer::onServerReadyRead()
{
    auto *server = qobject_cast<QTcpSocket*>(sender());
    if (!server || !m_connections.contains(server)) return;

    Connection *conn = m_connections[server];
    QByteArray data = server->readAll();
    conn->responseBuffer.append(data);

    if (conn->client && conn->client->isWritable()) {
        conn->client->write(data);
        conn->client->flush();
    }
}

void ProxyServer::onServerDisconnected()
{
    auto *server = qobject_cast<QTcpSocket*>(sender());
    if (!server || !m_connections.contains(server)) return;

    Connection *conn = m_connections[server];

    if (!conn->mitmActive && !conn->responseBuffer.isEmpty()) {
        HttpParser::parseResponse(conn->responseBuffer, conn->item);
        emit requestCaptured(conn->item);
    }

    cleanup(conn);
}

void ProxyServer::onClientDisconnected()
{
    auto *client = qobject_cast<QTcpSocket*>(sender());
    if (!client || !m_connections.contains(client)) return;

    Connection *conn = m_connections[client];
    if (conn->server) {
        conn->server->disconnectFromHost();
    } else {
        cleanup(conn);
    }
}

void ProxyServer::onMitmCaptured(const QByteArray &requestData,
                                  const QByteArray &responseData,
                                  const QString &host, quint16 port,
                                  qint64 durationMs)
{
    RequestItem item;
    item.id = m_nextId++;
    item.timestamp = QDateTime::currentDateTime();
    item.host = host;
    item.protocol = "HTTPS";
    item.duration = durationMs;

    qDebug() << "MITM: captured" << host
             << "req=" << requestData.size()
             << "resp=" << responseData.size();

    // Parse HTTP request from decrypted data
    if (requestData.contains("\r\n\r\n")) {
        HttpParser::parseRequest(requestData, item);
    }

    // Parse HTTP response from decrypted data
    if (responseData.contains("\r\n\r\n")) {
        HttpParser::parseResponse(responseData, item);
    }

    qDebug() << "MITM:" << item.method << host << item.path << item.statusCode;

    emit requestCaptured(item);
}

void ProxyServer::cleanup(Connection *conn)
{
    if (conn->client) {
        m_connections.remove(conn->client);
        conn->client->deleteLater();
    }
    if (conn->server) {
        m_connections.remove(conn->server);
        conn->server->deleteLater();
    }
    delete conn;
}
