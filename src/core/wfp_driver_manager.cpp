#include "wfp_driver_manager.h"

#ifdef Q_OS_WIN

#include <QDebug>
#include <QFile>
#include <QCoreApplication>
#include <QDateTime>

// Windows headers
#include <windows.h>

// fltUser.h for FilterCommunicationPort APIs
#include <fltUser.h>
#pragma comment(lib, "fltLib.lib")

// ============================================================================
// WfpDriverListenThread
// ============================================================================

WfpDriverListenThread::WfpDriverListenThread(HANDLE port, QObject *parent)
    : QThread(parent), m_port(port), m_stopRequested(0)
{
}

void WfpDriverListenThread::requestStop()
{
    m_stopRequested = 1;
}

void WfpDriverListenThread::run()
{
    JSNWFP_EVENT event;
    DWORD bytesReturned;
    HRESULT hr;

    qDebug() << "WfpDriverListenThread: started";

    while (!m_stopRequested) {
        memset(&event, 0, sizeof(event));
        bytesReturned = 0;

        // FilterGetMessage blocks until a message arrives or the port is closed
        hr = FilterGetMessage(m_port,
                              &event, sizeof(event),
                              &bytesReturned, NULL);

        if (m_stopRequested) break;

        if (SUCCEEDED(hr)) {
            QString processPath = QString::fromWCharArray(event.processPath);

            emit connectionDetected(
                event.processId,
                processPath,
                event.localAddr,
                event.localPort,
                event.remoteAddr,
                event.remotePort
            );
        } else if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {
            // Port was closed
            break;
        } else if (hr == HRESULT_FROM_WIN32(ERROR_FLT_DELETING_OBJECT)) {
            // Filter is being deleted
            break;
        } else {
            // Other error, brief sleep before retrying
            qDebug() << "WfpDriverListenThread: FilterGetMessage failed"
                     << QString::number(hr, 16);
            msleep(100);
        }
    }

    qDebug() << "WfpDriverListenThread: stopped";
}

// ============================================================================
// WfpDriverManager
// ============================================================================

WfpDriverManager::WfpDriverManager(QObject *parent)
    : QObject(parent)
{
    m_driverPath = QCoreApplication::applicationDirPath() + "/jsnetwork_wfp.sys";
}

WfpDriverManager::~WfpDriverManager()
{
    stop();
    unloadFltLib();
}

bool WfpDriverManager::loadFltLib()
{
    if (m_fltLibHandle) return true;

    m_fltLibHandle = LoadLibraryW(L"fltLib.dll");
    if (!m_fltLibHandle) {
        DWORD err = GetLastError();
        emit driverError(QString("Failed to load fltLib.dll, error=%1").arg(err));
        return false;
    }

    m_connectFn = (FilterConnectCommunicationPortFn)
        GetProcAddress((HMODULE)m_fltLibHandle, "FilterConnectCommunicationPort");
    m_getMessageFn = (FilterGetMessageFn)
        GetProcAddress((HMODULE)m_fltLibHandle, "FilterGetMessage");
    m_sendMessageFn = (FilterSendMessageFn)
        GetProcAddress((HMODULE)m_fltLibHandle, "FilterSendMessage");
    m_closeFn = (FilterCloseFn)
        GetProcAddress((HMODULE)m_fltLibHandle, "FilterClose");

    if (!m_connectFn || !m_getMessageFn || !m_sendMessageFn || !m_closeFn) {
        emit driverError("fltLib.dll missing required functions");
        unloadFltLib();
        return false;
    }

    return true;
}

void WfpDriverManager::unloadFltLib()
{
    if (m_fltLibHandle) {
        FreeLibrary((HMODULE)m_fltLibHandle);
        m_fltLibHandle = nullptr;
        m_connectFn = nullptr;
        m_getMessageFn = nullptr;
        m_sendMessageFn = nullptr;
        m_closeFn = nullptr;
    }
}

bool WfpDriverManager::install()
{
    if (!QFile::exists(m_driverPath)) {
        emit driverError("Driver file not found: " + m_driverPath);
        return false;
    }

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            emit driverError("Administrator privileges required to install driver");
        } else {
            emit driverError(QString("OpenSCManager failed, error=%1").arg(err));
        }
        return false;
    }

    // Check if service already exists
    SC_HANDLE svc = OpenServiceW(scm, L"JsNetworkWfp", SERVICE_ALL_ACCESS);
    if (svc) {
        // Service exists, check if it needs update
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        qDebug() << "WfpDriverManager: driver service already installed";
        return true;
    }

    // Create new service
    svc = CreateServiceW(scm,
                         L"JsNetworkWfp",
                         L"JsNetwork WFP Driver",
                         SERVICE_ALL_ACCESS,
                         SERVICE_KERNEL_DRIVER,
                         SERVICE_DEMAND_START,
                         SERVICE_ERROR_NORMAL,
                         (LPCWSTR)m_driverPath.utf16(),
                         NULL, NULL, NULL, NULL, NULL);

    if (!svc) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);
        emit driverError(QString("CreateService failed, error=%1").arg(err));
        return false;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    qDebug() << "WfpDriverManager: driver service installed";
    return true;
}

bool WfpDriverManager::uninstall()
{
    stop();

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return false;

    SC_HANDLE svc = OpenServiceW(scm, L"JsNetworkWfp", SERVICE_ALL_ACCESS);
    if (!svc) {
        CloseServiceHandle(scm);
        return true;  // Already gone
    }

    // Stop the service first
    SERVICE_STATUS status;
    ControlService(svc, SERVICE_CONTROL_STOP, &status);

    // Delete the service
    BOOL deleted = DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    qDebug() << "WfpDriverManager: driver service uninstalled"
             << (deleted ? "ok" : "failed");
    return deleted != 0;
}

bool WfpDriverManager::start()
{
    if (m_port) {
        qDebug() << "WfpDriverManager: already running";
        return true;
    }

    if (!loadFltLib()) return false;

    // Start the driver service
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        DWORD err = GetLastError();
        emit driverError(QString("OpenSCManager failed, error=%1").arg(err));
        return false;
    }

    SC_HANDLE svc = OpenServiceW(scm, L"JsNetworkWfp", SERVICE_START);
    if (!svc) {
        CloseServiceHandle(scm);
        emit driverError("Driver service not found. Run install() first.");
        return false;
    }

    BOOL started = StartServiceW(svc, 0, NULL);
    DWORD err = GetLastError();
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (!started && err != ERROR_SERVICE_ALREADY_RUNNING) {
        if (err == ERROR_PATH_NOT_FOUND || err == ERROR_FILE_NOT_FOUND) {
            emit driverError("Driver file not found. The .sys file must be in the application directory.");
        } else if (err == ERROR_INVALID_IMAGE_HASH) {
            emit driverError("Driver not signed. Enable test signing: bcdedit /set testsigning on");
        } else if (err == ERROR_ACCESS_DENIED) {
            emit driverError("Administrator privileges required to start driver");
        } else {
            emit driverError(QString("StartService failed, error=%1").arg(err));
        }
        return false;
    }

    // Connect to the communication port
    HRESULT hr = m_connectFn(JSNWFP_PORT_NAME, 0, NULL, 0, NULL, &m_port);
    if (FAILED(hr)) {
        emit driverError(QString("FilterConnectCommunicationPort failed, hr=%1")
                        .arg(QString::number(hr, 16)));
        return false;
    }

    // Start listening thread
    m_listenThread = new WfpDriverListenThread(m_port, this);
    connect(m_listenThread, &WfpDriverListenThread::connectionDetected,
            this, &WfpDriverManager::connectionDetected);
    connect(m_listenThread, &QThread::finished,
            m_listenThread, &QObject::deleteLater);
    m_listenThread->start();

    emit driverStatusChanged("WFP driver active");
    qDebug() << "WfpDriverManager: started, connected to driver";
    return true;
}

void WfpDriverManager::stop()
{
    if (m_listenThread) {
        m_listenThread->requestStop();
        m_listenThread->quit();
        m_listenThread->wait(3000);
        delete m_listenThread;
        m_listenThread = nullptr;
    }

    if (m_port && m_closeFn) {
        m_closeFn(m_port);
        m_port = nullptr;
    }

    // Stop the driver service
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, L"JsNetworkWfp", SERVICE_STOP);
        if (svc) {
            SERVICE_STATUS status;
            ControlService(svc, SERVICE_CONTROL_STOP, &status);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }

    emit driverStatusChanged("WFP driver stopped");
    qDebug() << "WfpDriverManager: stopped";
}

bool WfpDriverManager::isRunning() const
{
    return m_port != nullptr && m_listenThread && m_listenThread->isRunning();
}

bool WfpDriverManager::isAvailable() const
{
    return QFile::exists(m_driverPath);
}

bool WfpDriverManager::sendCommand(quint32 command, quint32 param)
{
    if (!m_port || !m_sendMessageFn) return false;

    JSNWFP_COMMAND cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.command = command;
    cmd.param = param;

    DWORD bytesReturned = 0;
    HRESULT hr = m_sendMessageFn(m_port, &cmd, sizeof(cmd), NULL, 0, &bytesReturned);
    return SUCCEEDED(hr);
}

#endif // Q_OS_WIN
