#include "proxy_config.h"

#ifdef Q_OS_MAC
#include <QProcess>
#endif

#ifdef Q_OS_WIN
#include <QSettings>
#endif

QString ProxyConfig::m_originalProxy;

bool ProxyConfig::enableSystemProxy(quint16 port)
{
    QString proxyAddr = QString("127.0.0.1:%1").arg(port);

#ifdef Q_OS_MAC
    // Get current Wi-Fi service name
    QProcess proc;
    proc.start("networksetup", {"-listallnetworkservices"});
    proc.waitForFinished();
    QString output = QString::fromUtf8(proc.readAllStandardOutput());
    QStringList services = output.split('\n', QString::SkipEmptyParts);

    QString wifiService;
    for (const QString &s : services) {
        if (s.contains("Wi-Fi") || s.contains("AirPort")) {
            wifiService = s.trimmed();
            break;
        }
    }

    if (wifiService.isEmpty()) return false;

    // Save current settings
    proc.start("networksetup", {"-getwebproxy", wifiService});
    proc.waitForFinished();
    m_originalProxy = QString::fromUtf8(proc.readAllStandardOutput());

    // Set HTTP proxy
    proc.start("networksetup", {"-setwebproxy", wifiService, "127.0.0.1", QString::number(port)});
    proc.waitForFinished();

    // Set HTTPS proxy
    proc.start("networksetup", {"-setsecurewebproxy", wifiService, "127.0.0.1", QString::number(port)});
    proc.waitForFinished();

    return true;
#endif

#ifdef Q_OS_WIN
    QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                       QSettings::NativeFormat);
    m_originalProxy = settings.value("ProxyServer").toString();
    settings.setValue("ProxyEnable", 1);
    settings.setValue("ProxyServer", proxyAddr);
    return true;
#endif

    return false;
}

bool ProxyConfig::disableSystemProxy()
{
#ifdef Q_OS_MAC
    QProcess proc;
    proc.start("networksetup", {"-listallnetworkservices"});
    proc.waitForFinished();
    QString output = QString::fromUtf8(proc.readAllStandardOutput());
    QStringList services = output.split('\n', QString::SkipEmptyParts);

    QString wifiService;
    for (const QString &s : services) {
        if (s.contains("Wi-Fi") || s.contains("AirPort")) {
            wifiService = s.trimmed();
            break;
        }
    }

    if (wifiService.isEmpty()) return false;

    proc.start("networksetup", {"-setwebproxystate", wifiService, "off"});
    proc.waitForFinished();
    proc.start("networksetup", {"-setsecurewebproxystate", wifiService, "off"});
    proc.waitForFinished();

    return true;
#endif

#ifdef Q_OS_WIN
    QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                       QSettings::NativeFormat);
    settings.setValue("ProxyEnable", 0);
    return true;
#endif

    return false;
}

bool ProxyConfig::isSystemProxyEnabled()
{
#ifdef Q_OS_MAC
    QProcess proc;
    proc.start("networksetup", {"-listallnetworkservices"});
    proc.waitForFinished();
    QString output = QString::fromUtf8(proc.readAllStandardOutput());
    QStringList services = output.split('\n', QString::SkipEmptyParts);

    QString wifiService;
    for (const QString &s : services) {
        if (s.contains("Wi-Fi") || s.contains("AirPort")) {
            wifiService = s.trimmed();
            break;
        }
    }
    if (wifiService.isEmpty()) return false;

    proc.start("networksetup", {"-getwebproxy", wifiService});
    proc.waitForFinished();
    QString proxyOutput = QString::fromUtf8(proc.readAllStandardOutput());
    return proxyOutput.contains("Enabled: Yes");
#endif

#ifdef Q_OS_WIN
    QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                       QSettings::NativeFormat);
    return settings.value("ProxyEnable", 0).toInt() == 1;
#endif

    return false;
}
