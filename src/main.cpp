#include "app/application.h"
#include <QApplication>
#include <QCoreApplication>
#include <csignal>
#include <cstdlib>

#ifdef Q_OS_MAC
#include <unistd.h>

static void cleanupSystemProxy()
{
    system("networksetup -setwebproxystate Wi-Fi off 2>/dev/null");
    system("networksetup -setsecurewebproxystate Wi-Fi off 2>/dev/null");
}
#endif

#ifdef Q_OS_WIN
#include <windows.h>
#include <shellapi.h>

static void cleanupLspOnCrash()
{
    // Emergency: clear system proxy via registry (no elevation needed, immediate effect)
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD zero = 0;
        RegSetValueExW(hKey, L"ProxyEnable", 0, REG_DWORD, (const BYTE *)&zero, sizeof(zero));
        RegDeleteValueW(hKey, L"ProxyServer");
        RegDeleteValueW(hKey, L"ProxyOverride");
        RegCloseKey(hKey);
    }
}

static LONG WINAPI crashHandler(EXCEPTION_POINTERS *)
{
    cleanupLspOnCrash();
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

static void signalHandler(int)
{
#ifdef Q_OS_MAC
    cleanupSystemProxy();
#endif
#ifdef Q_OS_WIN
    cleanupLspOnCrash();
#endif
    _exit(1);
}

int main(int argc, char *argv[])
{
#ifdef Q_OS_MAC
    atexit(cleanupSystemProxy);
#endif

#ifdef Q_OS_WIN
    SetUnhandledExceptionFilter(crashHandler);
#endif

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
#ifdef Q_OS_MAC
    signal(SIGHUP, signalHandler);
    signal(SIGQUIT, signalHandler);
#endif
    signal(SIGSEGV, signalHandler);
    signal(SIGABRT, signalHandler);

    QApplication app(argc, argv);
    app.setApplicationName("JsNetwork");
    app.setApplicationVersion("0.1.0");
    app.setOrganizationName("JsNetwork");

    Application jsn;
    jsn.start();

    return app.exec();
}
