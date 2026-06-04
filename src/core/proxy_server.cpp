#include "proxy_server.h"
#include "http_parser.h"
#include "cert_manager.h"
#include "mitm_engine.h"
#ifdef Q_OS_WIN
#include "wfp_redirect.h"
#endif
#include "compat.h"
#include <QUrl>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QNetworkProxy>
#include <QThread>
#include <QStandardPaths>
#include <QFile>
#include <QDateTime>
#include <cstring>

static WinsockInit winsockInit;

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
        struct addrinfo hints = {}, *result = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        QByteArray hostAscii = m_host.toLatin1();
        QByteArray portStr = QByteArray::number(m_port);
        if (getaddrinfo(hostAscii.constData(), portStr.constData(), &hints, &result) != 0 || !result) {
            m_success = false;
            return;
        }

        m_serverFd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (m_serverFd < 0) { freeaddrinfo(result); m_success = false; return; }

        if (::connect(m_serverFd, result->ai_addr, (int)result->ai_addrlen) < 0) {
            CLOSE(m_serverFd); m_serverFd = -1;
        }
        freeaddrinfo(result);

        if (m_serverFd < 0) { m_success = false; return; }
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
        PIPE(m_wakePipe);
    }
    ~TunnelThread() {
        // Interrupt the select() loop
        char c = 1;
        WRITE(m_wakePipe[1], &c, 1);
        wait(3000); // Wait up to 3s for thread to finish
        CLOSE(m_wakePipe[0]);
        CLOSE(m_wakePipe[1]);
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
                int n = READ(m_fd1, buf, sizeof(buf));
                if (n <= 0) break;
                WRITE(m_fd2, buf, n);
            }
            if (FD_ISSET(m_fd2, &fds)) {
                int n = READ(m_fd2, buf, sizeof(buf));
                if (n <= 0) break;
                WRITE(m_fd1, buf, n);
            }
        }
        CLOSE(m_fd1);
        CLOSE(m_fd2);
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
    bool ok = m_server->listen(QHostAddress::LocalHost, port);
    if (ok) {
        qDebug() << "ProxyServer: listening on 127.0.0.1:" << port;
    } else {
        qWarning() << "ProxyServer: FAILED to listen on 127.0.0.1:" << port
                    << "error:" << m_server->errorString();
    }
    return ok;
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

    // Detect direct TLS ClientHello (no CONNECT header, e.g. from system proxy)
    // TLS record: ContentType=0x16, Version=0x03xx
    // Use peek() to inspect without consuming - MitmConnection needs the data
    if (conn->requestBuffer.isEmpty() && client->bytesAvailable() >= 2) {
        QByteArray peekData = client->peek(512);
        if (peekData.size() >= 2
            && (unsigned char)peekData[0] == 0x16
            && (unsigned char)peekData[1] == 0x03) {
            QString sniHost = extractSniFromClientHello(peekData);
            if (sniHost.isEmpty()) {
                sniHost = "(unknown-SNI)";
            }

            logMsg(QString("Direct TLS detected: host=%1 bytes=%2 mitmEnabled=%3")
                   .arg(sniHost).arg(peekData.size()).arg(m_mitmEnabled));

            if (m_mitmEnabled && m_mitmEngine) {
                // MITM mode: intercept and decrypt
                logMsg("Direct TLS MITM: intercepting " + sniHost);
                handleDirectTls(conn, sniHost);
            } else {
                // Pass-through: connect to real server and tunnel raw TLS
                logMsg("Direct TLS pass-through: " + sniHost);
                conn->item.host = sniHost;
                conn->item.method = "CONNECT";
                conn->item.path = sniHost + ":443";
                conn->item.protocol = "HTTPS";
                conn->item.url = "https://" + sniHost;
                conn->item.duration = 0;
                emit requestCaptured(conn->item);

                // Build raw initial data from peek + read
                QByteArray initialData = client->readAll();
                int clientFd = DUP(client->socketDescriptor());
                m_connections.remove(client);
                client->deleteLater();
                conn->client = nullptr;

                auto *connector = new ConnectThread(clientFd, sniHost, 443);
                connect(connector, &QThread::finished, this, [this, connector, conn, initialData]() {
                    if (!connector->success()) {
                        qDebug() << "Direct TLS: connect failed to" << conn->item.host;
                        CLOSE(connector->takeClientFd());
                        delete conn;
                        connector->deleteLater();
                        return;
                    }
                    int clientFd = connector->takeClientFd();
                    int serverFd = connector->takeServerFd();
                    connector->deleteLater();

                    // Send initial ClientHello to server
                    if (!initialData.isEmpty()) {
                        WRITE(serverFd, initialData.constData(), initialData.size());
                    }

                    // Start bidirectional tunnel
                    auto *tunnel = new TunnelThread(clientFd, serverFd, this);
                    connect(tunnel, &QThread::finished, this, [conn, tunnel]() {
                        delete conn;
                        tunnel->deleteLater();
                    });
                    tunnel->start();
                });
                connector->start();
            }
            return;
        }
    }

    conn->requestBuffer.append(client->readAll());

    // Wait for complete headers (HTTP CONNECT or plain HTTP)
    int headerEnd = conn->requestBuffer.indexOf("\r\n\r\n");
    if (headerEnd < 0) return;

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
        // Plain HTTP: wait for full request body before processing
        // Check Content-Length to determine if we have the complete body
        QByteArray headerBlock = conn->requestBuffer.left(headerEnd);
        QByteArray headersLower = headerBlock.toLower();
        int clIdx = headersLower.indexOf("content-length:");
        if (clIdx >= 0) {
            int clEnd = headersLower.indexOf("\r\n", clIdx);
            if (clEnd < 0) clEnd = headersLower.size();
            int contentLength = headersLower.mid(clIdx + 15, clEnd - clIdx - 15).trimmed().toInt();
            int bodyStart = headerEnd + 4;
            int bodyReceived = conn->requestBuffer.size() - bodyStart;
            if (bodyReceived < contentLength) {
                // Body not fully received yet, wait for more data
                return;
            }
        }
        // Also handle chunked transfer encoding for requests
        if (headersLower.contains("transfer-encoding:") && headersLower.contains("chunked")) {
            QByteArray body = conn->requestBuffer.mid(headerEnd + 4);
            if (!body.contains("\r\n0\r\n\r\n") && !body.startsWith("0\r\n\r\n")) {
                return;
            }
        }

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
        logMsg("CONNECT MITM: intercepting " + targetHost);

        QTcpSocket *client = conn->client;
        m_connections.remove(conn->client);
        conn->client = nullptr;

        MitmConnection *mitmConn = m_mitmEngine->intercept(client, targetHost, targetPort);
        connect(mitmConn, &MitmConnection::finished, this, [mitmConn, conn, client]() {
            client->disconnectFromHost();
            client->deleteLater();
            delete conn;
            mitmConn->deleteLater();
        });
    } else {
        // Pass-through: DNS + connect in background thread (avoids blocking main thread)
        qDebug() << "Proxy: pass-through" << targetHost << ":" << targetPort;

        // Emit CONNECT request metadata so it shows up in traffic list
        conn->item.protocol = "HTTPS";
        conn->item.url = "https://" + targetHost;
        conn->item.duration = 0;
        emit requestCaptured(conn->item);

        // DUP creates an independent socket handle (WSADuplicateSocket on Windows,
        // dup() on Unix). The QTcpSocket can be safely deleted afterward.
        int clientFd = DUP(conn->client->socketDescriptor());
        m_connections.remove(conn->client);
        conn->client->deleteLater();
        conn->client = nullptr;

        auto *connector = new ConnectThread(clientFd, targetHost, targetPort);
        connect(connector, &QThread::finished, this, [this, connector, conn]() {
            if (!connector->success()) {
                qDebug() << "Connect failed to" << conn->item.host;
                CLOSE(connector->takeClientFd());
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
        if (conn->client) m_connections.remove(conn->client);
        conn->client->deleteLater();
        delete conn;
        return;
    }

    // Remove client from tracking (reply owns the connection now)
    if (conn->client) m_connections.remove(conn->client);

    // Forward response data incrementally to avoid blocking on streaming responses.
    // Use readyRead to send data as it arrives; only parse for RequestItem on finished.
    bool *headersSent = new bool(false);
    QByteArray *respBuf = new QByteArray();
    bool *headerParsed = new bool(false);

    connect(reply, &QNetworkReply::readyRead, this, [this, reply, conn, headersSent, respBuf, headerParsed]() {
        if (!conn->client || !conn->client->isWritable()) return;

        if (!*headersSent) {
            int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (status == 0) return; // Headers not yet available
            QString reason = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toString();

            QByteArray respHeaders = "HTTP/1.1 " + QByteArray::number(status) + " " + reason.toUtf8() + "\r\n";
            QList<QByteArray> skipHeaders = {"connection", "transfer-encoding", "content-encoding"};
            for (const auto &hdr : reply->rawHeaderPairs()) {
                QByteArray key = hdr.first.toLower();
                if (!skipHeaders.contains(key)) {
                    respHeaders += hdr.first + ": " + hdr.second + "\r\n";
                }
            }
            respHeaders += "Connection: close\r\n";
            respHeaders += "\r\n";
            conn->client->write(respHeaders);
            *headersSent = true;
        }

        QByteArray chunk = reply->readAll();
        if (!chunk.isEmpty()) {
            respBuf->append(chunk);
            conn->client->write(chunk);
            conn->client->flush();
        }
    });

    connect(reply, &QNetworkReply::finished, this, [this, reply, conn, headersSent, respBuf, headerParsed]() {
        reply->deleteLater();

        if (reply->error() != QNetworkReply::NoError) {
            if (!*headersSent) {
                QByteArray errResp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                if (conn->client && conn->client->isWritable()) {
                    conn->client->write(errResp);
                    conn->client->flush();
                }
            }
        } else {
            // If no readyRead was emitted (e.g. empty body), send headers now
            if (!*headersSent && conn->client && conn->client->isWritable()) {
                int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
                QString reason = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toString();
                QByteArray respHeaders = "HTTP/1.1 " + QByteArray::number(status) + " " + reason.toUtf8() + "\r\n";
                QList<QByteArray> skipHeaders = {"connection", "transfer-encoding", "content-encoding"};
                for (const auto &hdr : reply->rawHeaderPairs()) {
                    QByteArray key = hdr.first.toLower();
                    if (!skipHeaders.contains(key)) {
                        respHeaders += hdr.first + ": " + hdr.second + "\r\n";
                    }
                }
                QByteArray body = reply->readAll();
                respHeaders += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
                respHeaders += "Connection: close\r\n";
                respHeaders += "\r\n";
                conn->client->write(respHeaders);
                if (!body.isEmpty()) conn->client->write(body);
                conn->client->flush();
                *respBuf = body;
            }

            // Build a full response for parsing
            int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            QString reason = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute).toString();
            QByteArray fullResp = "HTTP/1.1 " + QByteArray::number(status) + " " + reason.toUtf8() + "\r\n";
            for (const auto &hdr : reply->rawHeaderPairs()) {
                fullResp += hdr.first + ": " + hdr.second + "\r\n";
            }
            fullResp += "\r\n";
            fullResp += *respBuf;
            HttpParser::parseResponse(fullResp, conn->item);
        }

        if (conn->startTime > 0) {
            conn->item.duration = QDateTime::currentMSecsSinceEpoch() - conn->startTime;
        }
        emit requestCaptured(conn->item);

        delete headersSent;
        delete respBuf;
        delete headerParsed;
        conn->client->deleteLater();
        delete conn;
    });
}

QString ProxyServer::extractSniFromClientHello(const QByteArray &data)
{
    // TLS record: 5-byte header
    //   byte 0: ContentType (0x16 = Handshake)
    //   byte 1-2: Version (0x0301..0x0304)
    //   byte 3-4: Length
    // Handshake header:
    //   byte 5: HandshakeType (0x01 = ClientHello)
    //   byte 6-8: Length
    // ClientHello:
    //   byte 9-10: ClientVersion
    //   byte 11-42: Random (32 bytes)
    //   byte 43: SessionIdLength
    //   ... then cipher suites, compression, extensions

    if (data.size() < 44) return QString();

    int pos = 5;  // Skip TLS record header
    if ((unsigned char)data[pos] != 0x01) return QString();  // Not ClientHello

    pos += 4;  // Skip handshake header (type + 3-byte length)
    pos += 2;  // Skip client version
    pos += 32; // Skip random

    if (pos >= data.size()) return QString();

    // Session ID
    int sessionIdLen = (unsigned char)data[pos++];
    pos += sessionIdLen;

    if (pos + 2 > data.size()) return QString();

    // Cipher suites
    int cipherSuitesLen = ((unsigned char)data[pos] << 8) | (unsigned char)data[pos + 1];
    pos += 2 + cipherSuitesLen;

    if (pos >= data.size()) return QString();

    // Compression methods
    int compLen = (unsigned char)data[pos++];
    pos += compLen;

    if (pos + 2 > data.size()) return QString();

    // Extensions
    int extTotalLen = ((unsigned char)data[pos] << 8) | (unsigned char)data[pos + 1];
    pos += 2;
    int extEnd = pos + extTotalLen;

    while (pos + 4 <= extEnd && pos + 4 <= data.size()) {
        int extType = ((unsigned char)data[pos] << 8) | (unsigned char)data[pos + 1];
        int extLen = ((unsigned char)data[pos + 2] << 8) | (unsigned char)data[pos + 3];
        pos += 4;

        if (extType == 0x0000) {
            // server_name extension
            // inner list length (2 bytes) + server_name_type (1 byte) + name length (2 bytes)
            if (pos + 5 > data.size()) return QString();
            int nameLen = ((unsigned char)data[pos + 3] << 8) | (unsigned char)data[pos + 4];
            if (pos + 5 + nameLen > data.size()) return QString();
            return QString::fromLatin1(data.constData() + pos + 5, nameLen);
        }
        pos += extLen;
    }
    return QString();
}

void ProxyServer::handleDirectTls(Connection *conn, const QString &host)
{
    logMsg(QString("handleDirectTls: host=%1 mitmEnabled=%2 mitmEngine=%3")
           .arg(host).arg(m_mitmEnabled).arg(m_mitmEngine != nullptr));

    QTcpSocket *client = conn->client;

    // Remove from connection map (MitmConnection will manage the socket)
    m_connections.remove(client);
    conn->client = nullptr;

    // ClientHello data is still in the socket buffer (we used peek()).
    // MitmConnection::start() will read it via clientSocket->bytesAvailable()
    // and feed it to the SSL BIO for the client TLS handshake.

    MitmConnection *mitmConn = m_mitmEngine->intercept(client, host, 443);

    connect(mitmConn, &MitmConnection::finished, this, [mitmConn, conn, client]() {
        client->disconnectFromHost();
        client->deleteLater();
        delete conn;
        mitmConn->deleteLater();
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

    logMsg(QString("MITM captured: host=%1 req=%2 resp=%3")
           .arg(host).arg(requestData.size()).arg(responseData.size()));

    // Parse HTTP request from decrypted data
    if (requestData.contains("\r\n\r\n")) {
        HttpParser::parseRequest(requestData, item);
    }

    // Fix URL to use https:// since this was MITM-decrypted HTTPS traffic
    if (!item.path.isEmpty()) {
        item.url = "https://" + host + item.path;
    }

    // Parse HTTP response from decrypted data
    if (responseData.contains("\r\n\r\n")) {
        HttpParser::parseResponse(responseData, item);
    }

    logMsg(QString("MITM parsed: %1 %2%3 status=%4")
           .arg(item.method, host, item.path).arg(item.statusCode));

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

// ============================================================================
// Transparent proxy — intercepts WinDivert-redirected connections (Windows only)
// ============================================================================

#ifdef Q_OS_WIN
bool ProxyServer::startTransparent(quint16 port, WfpRedirect *redirect)
{
    if (m_transparentServer) {
        m_transparentServer->close();
        m_transparentServer->deleteLater();
    }

    m_redirect = redirect;
    m_transparentServer = new QTcpServer(this);
    connect(m_transparentServer, &QTcpServer::newConnection,
            this, &ProxyServer::onTransparentConnection);

    bool ok = m_transparentServer->listen(QHostAddress::LocalHost, port);
    if (ok) {
        logMsg("Transparent proxy listening on 127.0.0.1:" + QString::number(port));
    } else {
        logMsg("Transparent proxy FAILED to listen on 127.0.0.1:" + QString::number(port)
               + " error: " + m_transparentServer->errorString());
    }
    return ok;
}

void ProxyServer::onTransparentConnection()
{
    while (m_transparentServer->hasPendingConnections()) {
        QTcpSocket *client = m_transparentServer->nextPendingConnection();

        // Look up original destination from the redirect table
        quint32 clientIp = client->peerAddress().toIPv4Address();
        quint16 clientPort = client->peerPort();
        quint32 origDstIp = 0;
        quint16 origDstPort = 0;

        if (!m_redirect || !m_redirect->lookupOriginal(clientIp, clientPort, origDstIp, origDstPort)) {
            logMsg(QString("Transparent: no redirect info for %1:%2")
                   .arg(clientIp).arg(clientPort));
            client->disconnectFromHost();
            client->deleteLater();
            continue;
        }

        // Convert original destination IP to string (fallback hostname)
        struct in_addr a;
        a.s_addr = htonl(origDstIp);
        QString origDstIpStr = QString::fromLatin1(inet_ntoa(a));

        logMsg(QString("Transparent: new connection %1:%2 → %3:%4")
               .arg(clientIp).arg(clientPort)
               .arg(origDstIpStr).arg(origDstPort));

        // Wait for the first data from the client to extract SNI from TLS ClientHello.
        // Reverse DNS on the IP rarely returns the actual hostname, so we must parse
        // the ClientHello to get the real server name for MITM certificate generation.
        connect(client, &QTcpSocket::readyRead, this, [this, client, origDstIpStr, origDstPort]() {
            // Peek at the data without consuming (MitmConnection needs it)
            QByteArray peekData = client->peek(512);

            QString host;
            bool isTls = false;

            // Check for TLS ClientHello: ContentType=0x16, Version=0x03xx
            if (peekData.size() >= 2
                && (unsigned char)peekData[0] == 0x16
                && (unsigned char)peekData[1] == 0x03) {
                isTls = true;
                host = extractSniFromClientHello(peekData);
                if (!host.isEmpty()) {
                    logMsg("Transparent TLS: SNI=" + host);
                }
            }

            // Fallback to IP if SNI extraction failed
            if (host.isEmpty()) {
                host = origDstIpStr;
                logMsg("Transparent: no SNI, using IP " + host);
            }

            // Emit request metadata for traffic list
            RequestItem item;
            item.id = m_nextId++;
            item.timestamp = QDateTime::currentDateTime();
            item.host = host;
            item.method = "CONNECT";
            item.path = host + ":" + QString::number(origDstPort);
            item.protocol = "HTTPS";
            item.url = "https://" + host;
            item.duration = 0;
            emit requestCaptured(item);

            // Perform MITM if enabled, otherwise tunnel through
            if (m_mitmEnabled && m_mitmEngine) {
                logMsg("Transparent MITM: intercepting " + host + ":" + QString::number(origDstPort));
                handleTransparentMitm(client, host, origDstPort);
            } else {
                handleTransparentTunnel(client, host, origDstPort);
            }
        });
    }
}

void ProxyServer::handleTransparentMitm(QTcpSocket *client, const QString &host, quint16 port)
{
    logMsg("Transparent MITM: intercepting " + host + ":" + QString::number(port));

    // Remove from connection map (MitmConnection manages the socket)
    m_connections.remove(client);

    MitmConnection *mitmConn = m_mitmEngine->intercept(client, host, port);
    connect(mitmConn, &MitmConnection::finished, this, [mitmConn, client]() {
        client->disconnectFromHost();
        client->deleteLater();
        mitmConn->deleteLater();
    });
}

void ProxyServer::handleTransparentTunnel(QTcpSocket *client, const QString &host, quint16 port)
{
    logMsg("Transparent tunnel: " + host + ":" + QString::number(port));

    // Connect to the real server in a background thread
    auto *connector = new ConnectThread(-1, host, port, this);
    connect(connector, &QThread::finished, this, [this, client, connector, host, port]() {
        if (!connector->success()) {
            logMsg("Transparent tunnel: connect failed for " + host + ":" + QString::number(port));
            client->disconnectFromHost();
            client->deleteLater();
            connector->deleteLater();
            return;
        }

        // Get the server fd from the connector
        int serverFd = connector->takeServerFd();
        if (serverFd < 0) {
            client->disconnectFromHost();
            client->deleteLater();
            connector->deleteLater();
            return;
        }

        // Create a QTcpSocket from the server fd
        auto *server = new QTcpSocket(this);
        server->setSocketDescriptor(serverFd);

        // Set up bidirectional forwarding
        connect(client, &QTcpSocket::readyRead, server, [client, server]() {
            server->write(client->readAll());
        });
        connect(server, &QTcpSocket::readyRead, client, [client, server]() {
            client->write(server->readAll());
        });
        connect(client, &QTcpSocket::disconnected, server, &QTcpSocket::disconnectFromHost);
        connect(server, &QTcpSocket::disconnected, client, &QTcpSocket::disconnectFromHost);

        // Cleanup when done
        connect(client, &QTcpSocket::disconnected, this, [client, server]() {
            server->deleteLater();
            client->deleteLater();
        });

        connector->deleteLater();
    });
    connector->start();
}
#endif // Q_OS_WIN
