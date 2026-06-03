#pragma once

#include <QObject>
#include <memory>

class MainWindow;
class ProxyServer;
class CertManager;
class CertInstaller;
class MockEngine;
class Theme;
class TrafficStorage;
class HarExporter;
class ProxyConfig;
class PacketCapture;
#ifdef Q_OS_WIN
class WfpRedirect;
#endif

class Application : public QObject
{
    Q_OBJECT
public:
    explicit Application(QObject *parent = nullptr);
    ~Application();

    void start();
    void setAutoEnableMitm(bool enable) { m_autoEnableMitm = enable; }

private:
    void initCertificate();
    void checkPreviousCrashCleanup();

    std::unique_ptr<ProxyServer> m_proxyServer;
    std::unique_ptr<CertManager> m_certManager;
    std::unique_ptr<CertInstaller> m_certInstaller;
    std::unique_ptr<MockEngine> m_mockEngine;
    std::unique_ptr<Theme> m_theme;
    std::unique_ptr<TrafficStorage> m_storage;
    std::unique_ptr<HarExporter> m_harExporter;
    std::unique_ptr<MainWindow> m_mainWindow;
    std::unique_ptr<PacketCapture> m_packetCapture;
#ifdef Q_OS_WIN
    std::unique_ptr<WfpRedirect> m_wfpRedirect;
#endif
    bool m_autoEnableMitm = false;
};
