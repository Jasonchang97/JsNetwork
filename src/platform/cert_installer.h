#pragma once

#include <QObject>
#include <QString>

class CertInstaller : public QObject
{
    Q_OBJECT
public:
    explicit CertInstaller(QObject *parent = nullptr);

    // Install CA certificate into system trust store
    // Requires admin/root privileges
    bool installCaCert(const QString &certPath);

    // Remove CA certificate from system trust store
    bool uninstallCaCert();

    // Check if our CA cert is installed
    bool isInstalled() const;

    // Get last error message
    QString lastError() const;

private:
    bool installMac(const QString &certPath);
    bool installWin(const QString &certPath);
    bool uninstallMac();
    bool uninstallWin();
    bool isInstalledMac() const;
    bool isInstalledWin() const;

    QString m_lastError;
    static constexpr const char *CA_CN = "JsNetwork CA";
};
