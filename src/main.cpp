#include "app/application.h"
#include "app/version.h"
#include <QApplication>
#include <QFile>
#include <QStandardPaths>
#include <QDateTime>
#include <QDir>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

static void crashLog(const QString &msg) {
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/crash.log";
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        f.write(QDateTime::currentDateTime().toString("hh:mm:ss.zzz").toUtf8());
        f.write(" ");
        f.write(msg.toUtf8());
        f.write("\n");
    }
}

static void qtMessageHandler(QtMsgType type, const QMessageLogContext &ctx, const QString &msg) {
    QByteArray localMsg = msg.toLocal8Bit();
    const char *file = ctx.file ? ctx.file : "";
    const char *function = ctx.function ? ctx.function : "";
    QString logLine;

    switch (type) {
    case QtDebugMsg:
        logLine = QString("DEBUG: %1 (%2:%3, %4)").arg(localMsg.constData()).arg(file).arg(ctx.line).arg(function);
        break;
    case QtInfoMsg:
        logLine = QString("INFO: %1").arg(localMsg.constData());
        break;
    case QtWarningMsg:
        logLine = QString("WARN: %1").arg(localMsg.constData());
        break;
    case QtCriticalMsg:
        logLine = QString("CRITICAL: %1").arg(localMsg.constData());
        break;
    case QtFatalMsg:
        logLine = QString("FATAL: %1").arg(localMsg.constData());
        break;
    }
    crashLog(logLine);

    // Also write to stderr for debugging
    fprintf(stderr, "%s\n", localMsg.constData());

    if (type == QtFatalMsg)
        abort();
}

#ifdef Q_OS_WIN
static LONG WINAPI detailedCrashHandler(EXCEPTION_POINTERS *exInfo) {
    if (exInfo && exInfo->ExceptionRecord) {
        DWORD code = exInfo->ExceptionRecord->ExceptionCode;
        ULONG_PTR addr = (ULONG_PTR)exInfo->ExceptionRecord->ExceptionAddress;
        crashLog(QString("CRASH: ExceptionCode=0x%1 Address=0x%2")
                 .arg(code, 8, 16, QChar('0'))
                 .arg(addr, 16, 16, QChar('0')));

        // Write minidump
        QString dumpPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/crash.dmp";
        HANDLE hFile = CreateFileW((LPCWSTR)dumpPath.utf16(), GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            // Dynamically load MiniDumpWriteDump to avoid linking dbghelp
            typedef BOOL (WINAPI *MiniDumpWriteDumpFn)(HANDLE, DWORD, HANDLE, int, void*, void*, void*);
            HMODULE dbghelp = LoadLibraryW(L"dbghelp.dll");
            if (dbghelp) {
                auto pMiniDump = (MiniDumpWriteDumpFn)GetProcAddress(dbghelp, "MiniDumpWriteDump");
                if (pMiniDump) {
                    MINIDUMP_EXCEPTION_INFORMATION mei;
                    mei.ThreadId = GetCurrentThreadId();
                    mei.ExceptionPointers = exInfo;
                    mei.ClientPointers = FALSE;
                    pMiniDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                              2 /* MiniDumpWithFullMemory */, &mei, nullptr, nullptr);
                }
                FreeLibrary(dbghelp);
            }
            CloseHandle(hFile);
        }
    }
    // Terminate after writing dump - can't safely continue after access violation
    TerminateProcess(GetCurrentProcess(), 139);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

int main(int argc, char *argv[])
{
    // Initialize OpenSSL before any threads or crypto operations
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    // Install Qt message handler early to capture all output
    qInstallMessageHandler(qtMessageHandler);

    crashLog("=== main() starting ===");

    QApplication app(argc, argv);
    app.setApplicationName("JsNetwork");
    app.setApplicationVersion(JSNETWORK_VERSION);
    app.setOrganizationName("JsNetwork");

    crashLog("QApplication created");

#ifdef Q_OS_WIN
    SetUnhandledExceptionFilter(detailedCrashHandler);
#endif

    Application jsn;
    crashLog("Application object created");

    jsn.start();
    crashLog("Application::start() returned, entering event loop");

    int ret = app.exec();

    crashLog(QString("Event loop exited with code: %1").arg(ret));
    return ret;
}
