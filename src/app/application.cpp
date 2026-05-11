#include "application.h"
#include "ui/mainwindow.h"
#include "ui/theme.h"
#include "core/proxy_server.h"
#include "core/cert_manager.h"
#include "core/mock_engine.h"
#include "core/traffic_storage.h"
#include "core/har_exporter.h"
#include "platform/cert_installer.h"
#include "platform/proxy_config.h"
#include <QStandardPaths>
#include <QDir>
#include <QDebug>
#include <QTimer>

Application::Application(QObject *parent)
    : QObject(parent)
    , m_proxyServer(std::make_unique<ProxyServer>())
    , m_certManager(std::make_unique<CertManager>())
    , m_certInstaller(std::make_unique<CertInstaller>())
    , m_mockEngine(std::make_unique<MockEngine>())
    , m_theme(std::make_unique<Theme>())
    , m_storage(std::make_unique<TrafficStorage>())
    , m_harExporter(std::make_unique<HarExporter>())
    , m_mainWindow(std::make_unique<MainWindow>(m_mockEngine.get(), m_theme.get(),
                                                 m_storage.get(), m_harExporter.get()))
{
    connect(m_proxyServer.get(), &ProxyServer::requestCaptured,
            m_mainWindow.get(), &MainWindow::onRequestCaptured);
    connect(m_proxyServer.get(), &ProxyServer::requestCaptured,
            this, [this](const RequestItem &item) {
        if (m_storage->isOpen()) {
            m_storage->saveRequest(item);
        }
    });
    connect(m_proxyServer.get(), &ProxyServer::mitmError,
            this, [](const QString &err) {
                qWarning() << "MITM Error:" << err;
            });

    // MITM toggle from UI
    connect(m_mainWindow.get(), &MainWindow::mitmToggled,
            this, [this](bool enabled) {
        qDebug() << "MITM toggle requested:" << enabled
                 << "certReady:" << m_certManager->isReady();
        if (enabled && m_certManager->isReady()) {
            // Pre-generate certs for common domains (runs in background thread)
            m_certManager->preGenerateCerts({
                // Google
                "www.google.com", "google.com",
                "accounts.google.com", "apis.google.com",
                "mail.google.com", "drive.google.com",
                "translate.google.com", "maps.google.com",
                "play.google.com", "scholar.google.com",
                "clients1.google.com", "clients2.google.com",
                "clients3.google.com", "clients4.google.com",
                "clients5.google.com",
                "www.gstatic.com", "fonts.gstatic.com",
                "ssl.gstatic.com", "encrypted.gstatic.com",
                "ajax.googleapis.com", "fonts.googleapis.com",
                "www.googleapis.com", "storage.googleapis.com",
                "lh1.googleusercontent.com", "lh2.googleusercontent.com",
                "lh3.googleusercontent.com", "lh4.googleusercontent.com",
                "lh5.googleusercontent.com", "lh6.googleusercontent.com",
                // YouTube
                "www.youtube.com", "youtube.com",
                "i.ytimg.com", "s.ytimg.com",
                "yt3.ggpht.com", "yt3.googleusercontent.com",
                // GitHub
                "github.com", "api.github.com",
                "raw.githubusercontent.com", "gist.githubusercontent.com",
                "avatars.githubusercontent.com",
                // Microsoft
                "www.bing.com", "login.microsoftonline.com",
                "outlook.office.com", "login.live.com",
                // Common CDNs & APIs
                "cdn.jsdelivr.net", "unpkg.com",
                "cdnjs.cloudflare.com", "www.cloudflare.com",
                "ajax.cloudflare.com", "cdn.bootcdn.net",
                // Baidu / Chinese sites
                "www.baidu.com", "baidu.com",
                "m.baidu.com", "map.baidu.com",
                "passport.baidu.com", "pan.baidu.com",
                "www.bilibili.com", "api.bilibili.com",
                "static.hdslb.com",
                "www.zhihu.com", "zhuanlan.zhihu.com",
                // Social
                "twitter.com", "x.com", "abs.twimg.com",
                "pbs.twimg.com", "t.co",
                "www.facebook.com", "static.xx.fbcdn.net",
                "www.instagram.com", "static.cdninstagram.com",
                // News / misc
                "www.wikipedia.org", "en.wikipedia.org",
                "upload.wikimedia.org",
                "www.apple.com", "developer.apple.com",
                "stackoverflow.com", "cdn.sstatic.net",
                "npmjs.com", "registry.npmjs.org",
                // Amazon
                "www.amazon.com", "images-na.ssl-images-amazon.com",
                "fls-na.amazon.com",
                // Apple services
                "xp.apple.com", "gs.apple.com",
                "swcdn.apple.com", "swdist.apple.com",
            });
            m_proxyServer->enableMitm(m_certManager.get());
            m_mainWindow->setMitmStatus(true);
            qDebug() << "MITM enabled";
        } else {
            m_proxyServer->disableMitm();
            m_mainWindow->setMitmStatus(false);
            qDebug() << "MITM disabled";
        }
    });
}

Application::~Application()
{
    ProxyConfig::disableSystemProxy();
    qDebug() << "System proxy restored";
}

void Application::start()
{
    m_theme->loadPreference();

    // Open SQLite database
    QString dbPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                     + "/traffic.db";
    QDir().mkpath(QFileInfo(dbPath).absolutePath());
    m_storage->open(dbPath);

    initCertificate();

    if (m_certManager->isReady()) {
        qDebug() << "Certificate ready - MITM available (toggle via UI)";
    } else {
        qWarning() << "Certificate not ready - MITM unavailable";
    }

    m_proxyServer->start(9527);

    // Configure system proxy to route traffic through our proxy
    if (ProxyConfig::enableSystemProxy(9527)) {
        qDebug() << "System proxy configured to 127.0.0.1:9527";
    } else {
        qWarning() << "Failed to configure system proxy";
    }

    m_mainWindow->show();
}

void Application::initCertificate()
{
    QString certDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                      + "/certificates";
    QDir().mkpath(certDir);

    if (!m_certManager->initialize(certDir)) {
        qWarning() << "Failed to initialize certificate manager";
        return;
    }

    if (!m_certInstaller->isInstalled()) {
        qInfo() << "CA certificate not installed in system trust store.";
        qInfo() << "CA cert path:" << m_certManager->caCertPath();

        if (m_certInstaller->installCaCert(m_certManager->caCertPath())) {
            qInfo() << "CA certificate installed successfully";
        } else {
            qWarning() << "Failed to install CA certificate:"
                       << m_certInstaller->lastError();
            qWarning() << "Please install manually:" << m_certManager->caCertPath();
        }
    } else {
        qInfo() << "CA certificate already installed";
    }
}
