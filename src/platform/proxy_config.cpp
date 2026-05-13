#include "proxy_config.h"

#ifdef Q_OS_MAC
#include <QProcess>
#endif

#ifdef Q_OS_WIN
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

static const wchar_t *kInternetSettingsKey =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

static void notifyProxyChange()
{
    InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
    InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
}
#endif

#ifdef Q_OS_MAC
// Get all active network service names (not just Wi-Fi)
static QStringList macNetworkServices()
{
    QProcess proc;
    proc.start("networksetup", {"-listallnetworkservices"});
    proc.waitForFinished();
    QString output = QString::fromUtf8(proc.readAllStandardOutput());
    QStringList services;
    for (const QString &line : output.split('\n', QString::SkipEmptyParts)) {
        QString s = line.trimmed();
        // Skip header line ("An asterisk denotes...")
        if (s.startsWith("*") || s.startsWith("An asterisk")) continue;
        if (!s.isEmpty()) services.append(s);
    }
    return services;
}
#endif

bool ProxyConfig::enableSystemProxy(quint16 port)
{
#ifdef Q_OS_MAC
    QStringList services = macNetworkServices();
    bool anyOk = false;

    for (const QString &svc : services) {
        QProcess proc;
        proc.start("networksetup", {"-setwebproxy", svc, "127.0.0.1", QString::number(port)});
        proc.waitForFinished();
        bool ok1 = (proc.exitCode() == 0);

        proc.start("networksetup", {"-setsecurewebproxy", svc, "127.0.0.1", QString::number(port)});
        proc.waitForFinished();
        bool ok2 = (proc.exitCode() == 0);

        if (ok1 || ok2) anyOk = true;
    }
    return anyOk;
#endif

#ifdef Q_OS_WIN
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kInternetSettingsKey, 0,
                      KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD enable = 1;
    RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD,
                   (const BYTE *)&enable, sizeof(enable));

    char proxyServer[64];
    int len = wsprintfA(proxyServer, "127.0.0.1:%d", (int)port);
    RegSetValueExA(hKey, "ProxyServer", 0, REG_SZ,
                   (const BYTE *)proxyServer, len + 1);

    const char *bypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;"
                         "172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;"
                         "172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;"
                         "172.29.*;172.30.*;172.31.*;192.168.*;<local>";
    RegSetValueExA(hKey, "ProxyOverride", 0, REG_SZ,
                   (const BYTE *)bypass, (DWORD)strlen(bypass) + 1);

    RegCloseKey(hKey);
    notifyProxyChange();
    return true;
#endif

    return false;
}

bool ProxyConfig::disableSystemProxy()
{
#ifdef Q_OS_MAC
    QStringList services = macNetworkServices();
    bool anyOk = false;

    for (const QString &svc : services) {
        QProcess proc;
        proc.start("networksetup", {"-setwebproxystate", svc, "off"});
        proc.waitForFinished();
        bool ok1 = (proc.exitCode() == 0);

        proc.start("networksetup", {"-setsecurewebproxystate", svc, "off"});
        proc.waitForFinished();
        bool ok2 = (proc.exitCode() == 0);

        if (ok1 || ok2) anyOk = true;
    }
    return anyOk;
#endif

#ifdef Q_OS_WIN
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kInternetSettingsKey, 0,
                      KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD enable = 0;
    RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD,
                   (const BYTE *)&enable, sizeof(enable));

    RegDeleteValueA(hKey, "ProxyServer");
    RegDeleteValueA(hKey, "ProxyOverride");

    RegCloseKey(hKey);
    notifyProxyChange();
    return true;
#endif

    return false;
}

bool ProxyConfig::isSystemProxyEnabled()
{
#ifdef Q_OS_MAC
    // Check if any network service has proxy enabled pointing to our port
    QStringList services = macNetworkServices();
    for (const QString &svc : services) {
        QProcess proc;
        proc.start("networksetup", {"-getwebproxy", svc});
        proc.waitForFinished();
        QString output = QString::fromUtf8(proc.readAllStandardOutput());
        if (output.contains("Enabled: Yes") && output.contains("127.0.0.1")) {
            return true;
        }
    }
    return false;
#endif

#ifdef Q_OS_WIN
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kInternetSettingsKey, 0,
                      KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD enable = 0;
    DWORD size = sizeof(enable);
    RegQueryValueExW(hKey, L"ProxyEnable", nullptr, nullptr,
                     (BYTE *)&enable, &size);
    RegCloseKey(hKey);
    return enable != 0;
#endif

    return false;
}
