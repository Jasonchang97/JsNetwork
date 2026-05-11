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
    void onMitmCaptured(const QByteArray &requestData, const QByteArray &responseData,
                        const QString &host, quint16 port, qint64 durationMs);
    void cleanup(Connection *conn);

    QTcpServer *m_server;
    QNetworkAccessManager *m_nam;
    QMap<QTcpSocket*, Connection*> m_connections;
    int m_nextId = 1;

    // MITM
    CertManager *m_certMgr = nullptr;
    MitmEngine *m_mitmEngine = nullptr;
    bool m_mitmEnabled = false;
};
