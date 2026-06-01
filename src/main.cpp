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
#include <dbghelp.h>
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
// Raw Win32 log helper — safe to call in crash handler (no heap allocation)
static void rawCrashLog(const wchar_t *path, const char *msg) {
    HANDLE h = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written;
        SetFilePointer(h, 0, nullptr, FILE_END);
        WriteFile(h, msg, (DWORD)strlen(msg), &written, nullptr);
        CloseHandle(h);
    }
}

static LONG WINAPI detailedCrashHandler(EXCEPTION_POINTERS *exInfo) {
    // Use raw Win32 APIs only — Qt/QString are unsafe after a crash
    if (!exInfo || !exInfo->ExceptionRecord) {
        TerminateProcess(GetCurrentProcess(), 139);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    DWORD code = exInfo->ExceptionRecord->ExceptionCode;
    ULONG_PTR addr = (ULONG_PTR)exInfo->ExceptionRecord->ExceptionAddress;

    // Determine log/dump paths
    wchar_t appDataPath[MAX_PATH] = {0};
    bool hasAppData = GetEnvironmentVariableW(L"APPDATA", appDataPath, MAX_PATH) > 0;

    wchar_t logPath[MAX_PATH];
    wchar_t dumpPath[MAX_PATH];
    if (hasAppData) {
        _snwprintf_s(logPath, MAX_PATH, _TRUNCATE,
            L"%s\\JsNetwork\\JsNetwork\\crash.log", appDataPath);
        _snwprintf_s(dumpPath, MAX_PATH, _TRUNCATE,
            L"%s\\JsNetwork\\JsNetwork\\crash.dmp", appDataPath);
    } else {
        wcscpy_s(logPath, L"crash.log");
        wcscpy_s(dumpPath, L"crash.dmp");
    }

    // Log crash info
    char logBuf[256];
    _snprintf_s(logBuf, sizeof(logBuf), _TRUNCATE,
        "CRASH: ExceptionCode=0x%08lx Address=0x%016llx\r\n",
        (unsigned long)code, (unsigned long long)addr);
    rawCrashLog(logPath, logBuf);

    // Write minidump
    typedef BOOL (WINAPI *MiniDumpWriteDumpFn)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
                                                PMINIDUMP_EXCEPTION_INFORMATION,
                                                PMINIDUMP_USER_STREAM_INFORMATION,
                                                PMINIDUMP_CALLBACK_INFORMATION);
    HMODULE dbghelp = LoadLibraryW(L"dbghelp.dll");
    if (dbghelp) {
        auto pMiniDump = (MiniDumpWriteDumpFn)GetProcAddress(dbghelp, "MiniDumpWriteDump");
        if (pMiniDump) {
            MINIDUMP_EXCEPTION_INFORMATION mei;
            mei.ThreadId = GetCurrentThreadId();
            mei.ExceptionPointers = exInfo;
            mei.ClientPointers = FALSE;

            HANDLE hFile = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                BOOL ok = pMiniDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                                    MiniDumpNormal, &mei, nullptr, nullptr);
                if (!ok) {
                    DWORD err = GetLastError();
                    char errBuf[128];
                    _snprintf_s(errBuf, sizeof(errBuf), _TRUNCATE,
                        "MiniDumpWriteDump FAILED, GetLastError=%lu\r\n", err);
                    rawCrashLog(logPath, errBuf);
                }
                FlushFileBuffers(hFile);
                CloseHandle(hFile);
            } else {
                rawCrashLog(logPath, "CreateFile for crash.dmp FAILED\r\n");
            }
        } else {
            rawCrashLog(logPath, "GetProcAddress(MiniDumpWriteDump) FAILED\r\n");
        }
    } else {
        rawCrashLog(logPath, "LoadLibrary(dbghelp.dll) FAILED\r\n");
    }

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
