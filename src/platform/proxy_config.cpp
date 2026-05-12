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

bool ProxyConfig::enableSystemProxy(quint16 port)
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

    proc.start("networksetup", {"-setwebproxy", wifiService, "127.0.0.1", QString::number(port)});
    proc.waitForFinished();
    proc.start("networksetup", {"-setsecurewebproxy", wifiService, "127.0.0.1", QString::number(port)});
    proc.waitForFinished();

    return true;
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

    // Bypass list: don't proxy localhost and private networks
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
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kInternetSettingsKey, 0,
                      KEY_SET_VALUE, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD enable = 0;
    RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD,
                   (const BYTE *)&enable, sizeof(enable));

    // Clear ProxyServer value entirely
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
