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

class Application : public QObject
{
    Q_OBJECT
public:
    explicit Application(QObject *parent = nullptr);
    ~Application();

    void start();

private:
    void initCertificate();

    std::unique_ptr<ProxyServer> m_proxyServer;
    std::unique_ptr<CertManager> m_certManager;
    std::unique_ptr<CertInstaller> m_certInstaller;
    std::unique_ptr<MockEngine> m_mockEngine;
    std::unique_ptr<Theme> m_theme;
    std::unique_ptr<TrafficStorage> m_storage;
    std::unique_ptr<HarExporter> m_harExporter;
    std::unique_ptr<MainWindow> m_mainWindow;
};
