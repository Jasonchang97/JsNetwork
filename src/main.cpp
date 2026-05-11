#include "app/application.h"
#include <QApplication>
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

static void signalHandler(int)
{
#ifdef Q_OS_MAC
    cleanupSystemProxy();
#endif
    _exit(1);
}

int main(int argc, char *argv[])
{
#ifdef Q_OS_MAC
    atexit(cleanupSystemProxy);
#endif

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGHUP, signalHandler);
    signal(SIGQUIT, signalHandler);
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
