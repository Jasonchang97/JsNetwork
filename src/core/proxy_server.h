#pragma once

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QMap>
#include "model/request_item.h"

class CertManager;
class MitmEngine;
class MitmConnection;
class WfpRedirect;

class ProxyServer : public QObject
{
    Q_OBJECT
public:
    explicit ProxyServer(QObject *parent = nullptr);
    ~ProxyServer();

    bool start(quint16 port);
    void stop();
    bool isRunning() const;
    quint16 port() const;

    // MITM support
    void enableMitm(CertManager *certMgr);
    void disableMitm();
    bool isMitmEnabled() const;

    // Transparent proxy (WinDivert redirect)
    bool startTransparent(quint16 port, WfpRedirect *redirect);

signals:
    void requestCaptured(const RequestItem &item);
    void mitmError(const QString &error);

private slots:
    void onNewConnection();
    void onClientReadyRead();
    void onServerReadyRead();
    void onClientDisconnected();
    void onServerDisconnected();

private:
    struct Connection {
        QTcpSocket *client = nullptr;
        QTcpSocket *server = nullptr;
        QByteArray requestBuffer;
        QByteArray responseBuffer;
        RequestItem item;
        bool isConnect = false;
        bool mitmActive = false;
        qint64 startTime = 0;  // ms since epoch
    };

    void handleConnect(Connection *conn);
    void handlePlainHttp(Connection *conn);
    void handleDirectTls(Connection *conn, const QString &host);
    static QString extractSniFromClientHello(const QByteArray &data);
    void onMitmCaptured(const QByteArray &requestData, const QByteArray &responseData,
                        const QString &host, quint16 port, qint64 durationMs);
    void cleanup(Connection *conn);

    // Transparent proxy
    void onTransparentConnection();
    void handleTransparentMitm(QTcpSocket *client, const QString &host, quint16 port);

    QTcpServer *m_server;
    QNetworkAccessManager *m_nam;
    QMap<QTcpSocket*, Connection*> m_connections;
    int m_nextId = 1;

    // MITM
    CertManager *m_certMgr = nullptr;
    MitmEngine *m_mitmEngine = nullptr;
    bool m_mitmEnabled = false;

    // Transparent proxy
    QTcpServer *m_transparentServer = nullptr;
    WfpRedirect *m_redirect = nullptr;
};
