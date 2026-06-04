#include "application.h"
#include "version.h"
#include "ui/mainwindow.h"
#include "ui/theme.h"
#include "core/proxy_server.h"
#include "core/cert_manager.h"
#include "core/mock_engine.h"
#include "core/traffic_storage.h"
#include "core/har_exporter.h"
#include "core/packet_capture.h"
#ifdef Q_OS_WIN
#include "core/wfp_redirect.h"
#endif
#include "platform/cert_installer.h"
#include "platform/proxy_config.h"
#include <QStandardPaths>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QDebug>
#include <QTimer>
#include <QProcess>
#include <QMetaType>
#include <cstdlib>
#include <csignal>

#ifndef Q_OS_WIN
#include <unistd.h>
#endif

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <windows.h>
#endif

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

// Crash-safe cleanup: ensure system proxy is restored even on abnormal exit
static void cleanupProxy()
{
    ProxyConfig::disableSystemProxy();
}

static void signalHandler(int sig)
{
    cleanupProxy();
    _exit(128 + sig);
}

static void installCleanupHandlers()
{
    std::atexit(cleanupProxy);
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGINT, signalHandler);
    std::signal(SIGABRT, signalHandler);
#ifndef Q_OS_WIN
    std::signal(SIGSEGV, signalHandler);
    std::signal(SIGQUIT, signalHandler);
    std::signal(SIGHUP, signalHandler);
#endif
    // On Windows, SIGSEGV is NOT handled here so the SEH handler in main.cpp
    // (detailedCrashHandler) can catch it and write a minidump + crash log.
}

Application::Application(QObject *parent)
    : QObject(parent)
    , m_proxyServer(std::make_unique<ProxyServer>())
    , m_certManager(std::make_unique<CertManager>())
    , m_certInstaller(std::make_unique<CertInstaller>())
    , m_mockEngine(std::make_unique<MockEngine>())
    , m_theme(std::make_unique<Theme>())
    , m_storage(std::make_unique<TrafficStorage>())
    , m_harExporter(std::make_unique<HarExporter>())
    , m_packetCapture(std::make_unique<PacketCapture>())
    , m_mainWindow(std::make_unique<MainWindow>(m_mockEngine.get(), m_theme.get(),
                                                 m_storage.get(), m_harExporter.get()))
{
    // Register RequestItem for queued signal/slot connections across threads.
    // Without this, Qt does a shallow memcpy instead of proper copy construction,
    // causing use-after-free when the original goes out of scope.
    qRegisterMetaType<RequestItem>("RequestItem");

    connect(m_proxyServer.get(), &ProxyServer::requestCaptured,
            m_mainWindow.get(), &MainWindow::onRequestCaptured);
    connect(m_proxyServer.get(), &ProxyServer::requestCaptured,
            this, [this](const RequestItem &item) {
        if (m_storage->isOpen()) {
            m_storage->saveRequest(item);
        }
    });

    // Packet capture (WinDivert on Windows, pcap on macOS) - captures all traffic at network level
    connect(m_packetCapture.get(), &PacketCapture::requestCaptured,
            m_mainWindow.get(), &MainWindow::onRequestCaptured);
    connect(m_packetCapture.get(), &PacketCapture::requestCaptured,
            this, [this](const RequestItem &item) {
        if (m_storage->isOpen()) {
            m_storage->saveRequest(item);
        }
    });
    connect(m_packetCapture.get(), &PacketCapture::captureStatusChanged,
            this, [](const QString &msg) {
        logMsg("PacketCapture: " + msg);
    });
    connect(m_proxyServer.get(), &ProxyServer::mitmError,
            this, [](const QString &err) {
                qWarning() << "MITM Error:" << err;
            });

    // Register crash-safe cleanup handlers (atexit + signals)
    installCleanupHandlers();

}

Application::~Application()
{
    logMsg("Application shutting down...");

    m_packetCapture->stop();
    logMsg("Packet capture stopped");

#ifdef Q_OS_WIN
    m_packetCapture->stopWfpDriver();
    logMsg("WFP driver stopped");

    if (m_wfpRedirect) {
        m_wfpRedirect->stop();
        logMsg("Transparent proxy redirect stopped");
    }
#endif

    m_proxyServer->stop();
    logMsg("Proxy server stopped");

    if (ProxyConfig::isSystemProxyEnabled()) {
        if (ProxyConfig::disableSystemProxy()) {
            logMsg("System proxy disabled successfully");
        } else {
            logMsg("WARNING: Failed to disable system proxy");
        }
    } else {
        logMsg("System proxy was not enabled, no need to disable");
    }

    logMsg("Application shutdown complete");
}

void Application::checkPreviousCrashCleanup()
{
    // Check if proxy was left enabled from a previous crash
    if (ProxyConfig::isSystemProxyEnabled()) {
        logMsg("Startup: detected stale proxy settings from previous session - clearing");
        if (ProxyConfig::disableSystemProxy()) {
            logMsg("Startup: stale proxy settings cleared successfully");
        } else {
            logMsg("Startup: WARNING - failed to clear stale proxy settings");
        }
    } else {
        logMsg("Startup: no stale proxy settings detected");
    }
}

void Application::start()
{
    logMsg(QString("=== JsNetwork v%1 starting ===").arg(JSNETWORK_VERSION));

    // Clean up any stale proxy settings from previous crash
    checkPreviousCrashCleanup();

    m_theme->loadPreference();

    // Open SQLite database
    QString dbPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                     + "/traffic.db";
    QDir().mkpath(QFileInfo(dbPath).absolutePath());
    m_storage->open(dbPath);

    initCertificate();

    if (m_certManager->isReady()) {
        // NOTE: preGenerateCerts disabled for crash diagnosis — background RSA key gen
        // may corrupt OpenSSL state when concurrent with MITM connections
#if 0
        m_certManager->preGenerateCerts({
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
            "www.youtube.com", "youtube.com",
            "i.ytimg.com", "s.ytimg.com",
            "yt3.ggpht.com", "yt3.googleusercontent.com",
            "github.com", "api.github.com",
            "raw.githubusercontent.com", "gist.githubusercontent.com",
            "avatars.githubusercontent.com",
            "www.bing.com", "login.microsoftonline.com",
            "outlook.office.com", "login.live.com",
            "cdn.jsdelivr.net", "unpkg.com",
            "cdnjs.cloudflare.com", "www.cloudflare.com",
            "ajax.cloudflare.com", "cdn.bootcdn.net",
            "www.baidu.com", "baidu.com",
            "m.baidu.com", "map.baidu.com",
            "passport.baidu.com", "pan.baidu.com",
            "www.bilibili.com", "api.bilibili.com",
            "static.hdslb.com",
            "www.zhihu.com", "zhuanlan.zhihu.com",
            "twitter.com", "x.com", "abs.twimg.com",
            "pbs.twimg.com", "t.co",
            "www.facebook.com", "static.xx.fbcdn.net",
            "www.instagram.com", "static.cdninstagram.com",
            "www.wikipedia.org", "en.wikipedia.org",
            "upload.wikimedia.org",
            "www.apple.com", "developer.apple.com",
            "stackoverflow.com", "cdn.sstatic.net",
            "npmjs.com", "registry.npmjs.org",
            "www.amazon.com", "images-na.ssl-images-amazon.com",
            "fls-na.amazon.com",
            "xp.apple.com", "gs.apple.com",
            "swcdn.apple.com", "swdist.apple.com",
        });
#endif
        m_proxyServer->enableMitm(m_certManager.get());
        m_packetCapture->setMitmActive(true);
        logMsg("MITM auto-enabled (HTTPS decrypt active)");
    } else {
        logMsg("Certificate NOT ready - HTTPS decrypt unavailable");
    }

    m_proxyServer->start(9527);

    if (ProxyConfig::enableSystemProxy(9527)) {
        logMsg("System proxy enabled: 127.0.0.1:9527");
    } else {
        logMsg("Failed to set system proxy");
    }

    // Start WinDivert transparent proxy for apps that bypass system proxy
#ifdef Q_OS_WIN
    {
        quint16 transparentPort = 9529;
        m_wfpRedirect = std::make_unique<WfpRedirect>();
        if (m_wfpRedirect->start(transparentPort)) {
            m_proxyServer->startTransparent(transparentPort, m_wfpRedirect.get());
            logMsg("Transparent proxy active on port " + QString::number(transparentPort));
        } else {
            logMsg("Transparent proxy failed to start");
        }
    }

    // WFP callout driver disabled — FltSendMessage blocks outbound connections
    // causing browser hangs. Needs non-blocking approach before re-enabling.
    // m_packetCapture->startWfpDriver();
#endif

    // Save m_mainWindow pointer to a volatile stack local BEFORE any calls
    // that clobber the callee-saved EBX register (which holds `this` on x86 MSVC).
    // A callee between here and show() violates the x86 ABI by corrupting EBX.
    // By reading the pointer now (while EBX is valid) and storing it volatile,
    // the compiler emits a stack spill that survives the corruption.
    MainWindow *volatile mainWin = m_mainWindow.get();

    if (m_packetCapture->start()) {
        logMsg("Packet capture started");
    } else {
        logMsg("Packet capture failed to start");
    }

    logMsg("About to show main window...");
    mainWin->show();
    logMsg("Main window shown, entering event loop");
}

void Application::initCertificate()
{
    QString certDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                      + "/certificates";
    QDir().mkpath(certDir);

    if (!m_certManager->initialize(certDir)) {
        logMsg("ERROR: Failed to initialize certificate manager");
        return;
    }

    QString certPath = m_certManager->caCertPath();
    logMsg(QString("CA cert path: %1").arg(certPath));

    if (!QFile::exists(certPath)) {
        logMsg("ERROR: CA cert file missing: " + certPath);
        return;
    }

    // Only install if not already present in the trust store
    if (m_certInstaller->isInstalled()) {
        logMsg("CA cert already installed - skipping installation");
        return;
    }

    logMsg("CA cert not in trust store - installing...");
    if (m_certInstaller->installCaCert(certPath)) {
        if (m_certInstaller->isInstalled()) {
            logMsg("CA cert installed and verified");
        } else {
            logMsg("WARNING: install returned success but cert not found in trust store");
        }
    } else {
        logMsg("WARNING: CA cert install failed: " + m_certInstaller->lastError());
    }
}

