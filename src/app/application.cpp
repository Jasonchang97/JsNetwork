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
#include <cstdlib>
#include <csignal>

#ifndef Q_OS_WIN
#include <unistd.h>
#endif

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <ws2spi.h>
#include <windows.h>
#include <shellapi.h>
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
#ifndef Q_OS_WIN
    std::signal(SIGQUIT, signalHandler);
    std::signal(SIGHUP, signalHandler);
#endif
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
    connect(m_proxyServer.get(), &ProxyServer::requestCaptured,
            m_mainWindow.get(), &MainWindow::onRequestCaptured);
    connect(m_proxyServer.get(), &ProxyServer::requestCaptured,
            this, [this](const RequestItem &item) {
        if (m_storage->isOpen()) {
            m_storage->saveRequest(item);
        }
    });

    // Packet capture (Npcap) - captures all traffic at network level
    connect(m_packetCapture.get(), &PacketCapture::requestCaptured,
            m_mainWindow.get(), &MainWindow::onRequestCaptured);
    connect(m_packetCapture.get(), &PacketCapture::requestCaptured,
            this, [this](const RequestItem &item) {
        if (m_storage->isOpen()) {
            m_storage->saveRequest(item);
        }
    });
    connect(m_proxyServer.get(), &ProxyServer::mitmError,
            this, [](const QString &err) {
                qWarning() << "MITM Error:" << err;
            });

    // Register crash-safe cleanup handlers (atexit + signals)
    installCleanupHandlers();

    // MITM toggle from UI
    connect(m_mainWindow.get(), &MainWindow::mitmToggled,
            this, [this](bool enabled) {
        logMsg(QString("MITM toggle requested: enabled=%1 certReady=%2")
               .arg(enabled).arg(m_certManager->isReady()));
        if (enabled && m_certManager->isReady()) {
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
            m_proxyServer->enableMitm(m_certManager.get());
            m_mainWindow->setMitmStatus(true);
            logMsg("MITM enabled");
        } else {
            m_proxyServer->disableMitm();
            m_mainWindow->setMitmStatus(false);
            logMsg("MITM disabled");
        }
    });
}

Application::~Application()
{
    logMsg("Application shutting down...");
    m_packetCapture->stop();
    m_proxyServer->stop();

#ifdef Q_OS_WIN
    if (m_proxyActiveEvent) {
        CloseHandle(m_proxyActiveEvent);
        m_proxyActiveEvent = nullptr;
        logMsg("Named Event closed - LSP will pass through directly");
    }
#endif

    if (ProxyConfig::disableSystemProxy()) {
        logMsg("System proxy disabled successfully");
    } else {
        logMsg("WARNING: Failed to disable system proxy");
    }
}

bool Application::isRunningAsAdmin()
{
#ifdef Q_OS_WIN
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
#else
    return geteuid() == 0;
#endif
}

void Application::checkPreviousCrashLsp()
{
    // Always clear system proxy on startup in case previous session crashed
    ProxyConfig::disableSystemProxy();
    logMsg("Startup: cleared any stale proxy settings");
}

void Application::start()
{
    logMsg(QString("=== JsNetwork v%1 starting ===").arg(JSNETWORK_VERSION));

    // Clean up any stale proxy settings from previous crash
    checkPreviousCrashLsp();

    m_theme->loadPreference();

    // Open SQLite database
    QString dbPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                     + "/traffic.db";
    QDir().mkpath(QFileInfo(dbPath).absolutePath());
    m_storage->open(dbPath);

    initCertificate();

    if (m_certManager->isReady()) {
        logMsg("Certificate ready - MITM available (toggle via UI)");
    } else {
        logMsg("Certificate NOT ready - MITM unavailable");
    }

#ifdef Q_OS_WIN
    m_proxyActiveEvent = CreateEventW(nullptr, TRUE, TRUE,
                                       L"Global\\JsNetwork_ProxyActive_9527");
    if (m_proxyActiveEvent) {
        SetEvent((HANDLE)m_proxyActiveEvent);
        logMsg("Named Event created (signaled) - LSP will redirect traffic");
    } else {
        logMsg(QString("Failed to create Named Event, error=%1").arg(GetLastError()));
    }
#endif

    m_proxyServer->start(9527);

    if (ProxyConfig::enableSystemProxy(9527)) {
        logMsg("System proxy enabled: 127.0.0.1:9527");
    } else {
        logMsg("Failed to set system proxy");
    }

#ifdef Q_OS_WIN
    installLspIfNeeded();
#endif

    if (m_packetCapture->start()) {
        logMsg("Packet capture started (Npcap)");
    } else {
        logMsg("Packet capture failed to start - Npcap may not be installed");
    }

    m_mainWindow->show();
}

void Application::initCertificate()
{
    QString certDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                      + "/certificates";
    QDir().mkpath(certDir);

    if (!m_certManager->initialize(certDir)) {
        logMsg("ERROR: Failed to initialize certificate manager");
        qWarning() << "Failed to initialize certificate manager";
        return;
    }

    logMsg(QString("CA cert path: %1").arg(m_certManager->caCertPath()));

    if (!m_certInstaller->isInstalled()) {
        logMsg("CA certificate not in system trust store - installing...");
        qInfo() << "CA certificate not installed in system trust store.";

        if (m_certInstaller->installCaCert(m_certManager->caCertPath())) {
            logMsg("CA certificate installed successfully");
            qInfo() << "CA certificate installed successfully";
        } else {
            QString err = m_certInstaller->lastError();
            logMsg("WARNING: CA cert install failed: " + err);
            logMsg("HTTPS decryption will not work until certificate is trusted");
            qWarning() << "Failed to install CA certificate:" << err;
        }
    } else {
        logMsg("CA certificate already installed in trust store");
        qInfo() << "CA certificate already installed";
    }
}

void Application::installLspIfNeeded()
{
#ifdef Q_OS_WIN
    // Check LSP status directly via Winsock API (no external process needed)
    {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        int err = 0;
        DWORD bufLen = 0;
        WSCEnumProtocols(NULL, NULL, &bufLen, &err);
        if (bufLen > 0) {
            WSAPROTOCOL_INFOW *infos = (WSAPROTOCOL_INFOW *)malloc(bufLen);
            int n = WSCEnumProtocols(NULL, infos, &bufLen, &err);
            // {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
            static const GUID lspGuid =
                {0xa1b2c3d4, 0xe5f6, 0x7890, {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90}};
            for (int i = 0; i < n; i++) {
                if (IsEqualGUID(infos[i].ProviderId, lspGuid)) {
                    free(infos);
                    WSACleanup();
                    logMsg("LSP already installed (with Named Event control)");
                    return;
                }
            }
            free(infos);
        }
        WSACleanup();
    }

    logMsg("LSP not installed, requesting elevated installation...");

    QString appDir = QCoreApplication::applicationDirPath();
    QString installer64Path = appDir + "/lsp_installer64.exe";
    QString lspDll64Path = appDir + "/x64/jsnetwork_lsp.dll";
    QString lspDll32Path = appDir + "/jsnetwork_lsp.dll";

    bool have64 = QFile::exists(installer64Path) && QFile::exists(lspDll64Path);

    if (have64) {
        QString nativeInstallerPath = QDir::toNativeSeparators(installer64Path);
        QString params = QString("install \"%1\" \"%2\"").arg(
            QDir::toNativeSeparators(lspDll64Path),
            QDir::toNativeSeparators(lspDll32Path));

        SHELLEXECUTEINFOW sei = {};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = (LPCWSTR)nativeInstallerPath.utf16();
        sei.lpParameters = (LPCWSTR)params.utf16();
        sei.nShow = SW_HIDE;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, 30000);
            DWORD exitCode = 0;
            GetExitCodeProcess(sei.hProcess, &exitCode);
            CloseHandle(sei.hProcess);

            if (exitCode == 0) {
                logMsg("LSP installed successfully (64-bit installer, both catalogs)");
            } else {
                logMsg(QString("LSP install failed, exit code=%1").arg(exitCode));
            }
        } else {
            logMsg(QString("Failed to launch elevated installer, error=%1").arg(GetLastError()));
        }
    } else {
        QString installerPath = appDir + "/lsp_installer.exe";
        if (!QFile::exists(lspDll32Path)) {
            logMsg("LSP DLL not found at: " + lspDll32Path);
            return;
        }

        QString nativeInstallerPath = QDir::toNativeSeparators(installerPath);
        QString params = QString("install \"%1\"").arg(
            QDir::toNativeSeparators(lspDll32Path));

        SHELLEXECUTEINFOW sei = {};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = (LPCWSTR)nativeInstallerPath.utf16();
        sei.lpParameters = (LPCWSTR)params.utf16();
        sei.nShow = SW_HIDE;

        if (ShellExecuteExW(&sei)) {
            WaitForSingleObject(sei.hProcess, 30000);
            DWORD exitCode = 0;
            GetExitCodeProcess(sei.hProcess, &exitCode);
            CloseHandle(sei.hProcess);

            if (exitCode == 0) {
                logMsg("LSP 32-bit installed successfully");
            } else {
                logMsg(QString("LSP 32-bit install failed, exit code=%1").arg(exitCode));
            }
        } else {
            logMsg(QString("Failed to launch elevated installer, error=%1").arg(GetLastError()));
        }
    }
#endif
}
