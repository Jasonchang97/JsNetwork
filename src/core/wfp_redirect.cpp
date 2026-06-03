#include "wfp_redirect.h"

#ifdef Q_OS_WIN

#include "wfp_capture.h"
#include <QDebug>
#include <QFile>
#include <QStandardPaths>
#include <QDateTime>
#include <QCoreApplication>
#include <QTextStream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define WINDIVERTEXPORT
#include "WinDivert.h"

static void redirectLog(const QString &msg) {
    QString path = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/wfp_redirect.log";
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        QTextStream ts(&f);
        ts << QDateTime::currentDateTime().toString("hh:mm:ss.zzz") << " " << msg << "\n";
    }
}

// ============================================================================
// WfpRedirectThread
// ============================================================================

WfpRedirectThread::WfpRedirectThread(const WinDivertApi *api, quint16 proxyPort, QObject *parent)
    : QThread(parent), m_api(api), m_proxyPort(proxyPort)
{
}

void WfpRedirectThread::requestStop()
{
    m_stopRequested = true;
}

bool WfpRedirectThread::lookupOriginal(quint32 clientIp, quint16 clientPort,
                                        quint32 &origDstIp, quint16 &origDstPort)
{
    QMutexLocker lock(&m_mutex);
    auto it = m_connections.find({clientIp, clientPort});
    if (it != m_connections.end()) {
        origDstIp = it->origDstIp;
        origDstPort = it->origDstPort;
        return true;
    }
    return false;
}

void WfpRedirectThread::cleanupStale()
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    for (auto it = m_connections.begin(); it != m_connections.end(); ) {
        if (now - it->timestamp > 60000) {
            it = m_connections.erase(it);
        } else {
            ++it;
        }
    }
}

void WfpRedirectThread::run()
{
    if (!m_handle || !m_api || !m_api->send) return;

    redirectLog("WfpRedirectThread::run() started, proxyPort=" + QString::number(m_proxyPort));

    UINT8 packet[65535];
    UINT recvLen = 0;
    WINDIVERT_ADDRESS addr;

    while (!m_stopRequested) {
        memset(&addr, 0, sizeof(addr));
        recvLen = 0;

        int ok = m_api->recv(m_handle, packet, sizeof(packet), &recvLen, &addr);
        if (!ok) {
            if (m_stopRequested) break;
            DWORD err = GetLastError();
            if (err == 995 || err == 1229) break;
            continue;
        }
        if (recvLen == 0) continue;

        m_packetCount++;
        if ((m_packetCount & 0xFF) == 0) {
            cleanupStale();
        }

        WINDIVERT_IPHDR *ipHdr = nullptr;
        WINDIVERT_IPV6HDR *ip6Hdr = nullptr;
        WINDIVERT_TCPHDR *tcpHdr = nullptr;
        UINT8 protocol = 0;
        PVOID payload = nullptr;
        UINT payloadLen = 0;

        m_api->parsePacket(packet, recvLen,
                (void **)&ipHdr, (void **)&ip6Hdr, &protocol,
                nullptr, nullptr, (void **)&tcpHdr, nullptr,
                &payload, &payloadLen, nullptr, nullptr);

        if (!tcpHdr) continue;
        if (!ipHdr) continue; // Only support IPv4 for redirect

        UINT16 srcPort = ntohs(tcpHdr->SrcPort);
        UINT16 dstPort = ntohs(tcpHdr->DstPort);
        bool isSyn = tcpHdr->Syn && !tcpHdr->Ack;
        bool isFinRst = tcpHdr->Fin || tcpHdr->Rst;
        bool isOutbound = (addr.Outbound != 0);
        quint32 srcIp = ipHdr->SrcAddr;
        quint32 dstIp = ipHdr->DstAddr;

        bool modified = false;

        if (isSyn && dstPort == 443) {
            if (!isOutbound) {
                // Inbound SYN to 443: new client connection → redirect to proxy
                QMutexLocker lock(&m_mutex);
                m_connections[{srcIp, srcPort}] = {dstIp, dstPort, QDateTime::currentMSecsSinceEpoch()};

                ipHdr->DstAddr = htonl(INADDR_LOOPBACK);
                tcpHdr->DstPort = htons(m_proxyPort);
                modified = true;

                redirectLog(QString("REDIRECT: %1:%2 → %3:%4 (orig dst %5:%6)")
                    .arg(srcIp & 0xFF).arg(srcPort)
                    .arg("127.0.0.1").arg(m_proxyPort)
                    .arg(dstIp & 0xFF).arg(dstPort));
            }
            // Outbound SYN to 443: proxy's own connection → pass through
        } else {
            // Check if this is a tracked connection that needs address rewriting
            if (isOutbound) {
                // Outbound packet (server → client direction after rewrite)
                // src = 127.0.0.1:proxyPort (proxy responding to client)
                // Need to rewrite src to original destination
                if (srcPort == m_proxyPort) {
                    QMutexLocker lock(&m_mutex);
                    auto it = m_connections.find({dstIp, dstPort});
                    if (it != m_connections.end()) {
                        ipHdr->SrcAddr = htonl(it->origDstIp);
                        tcpHdr->SrcPort = htons(it->origDstPort);
                        modified = true;
                    }
                }
            } else {
                // Inbound packet (client → server direction after redirect)
                // dst = 127.0.0.1:proxyPort (client sending to proxy)
                // Need to keep dst as proxy (kernel handles it)
                if (dstPort == m_proxyPort) {
                    // This is client data going to the proxy — no rewrite needed
                    // The kernel TCP stack handles delivery to the proxy
                } else if (srcPort == 443) {
                    // Response from real server to proxy's ephemeral port
                    // This is proxy ↔ server traffic, not tracked — pass through
                }
            }

            // Clean up tracked connection on FIN/RST
            if (isFinRst) {
                QMutexLocker lock(&m_mutex);
                // Check both directions
                m_connections.remove({srcIp, srcPort});
                m_connections.remove({dstIp, dstPort});
            }
        }

        // Recalculate checksums if modified
        if (modified && m_api->calcChecksums) {
            m_api->calcChecksums(packet, recvLen, &addr, 0);
        }

        // Always re-inject the packet (modified or original)
        UINT sendLen = 0;
        if (!m_api->send(m_handle, packet, recvLen, &sendLen, &addr)) {
            // Send failed — packet lost
        }
    }

    QMutexLocker lock(&m_mutex);
    m_connections.clear();
    redirectLog("WfpRedirectThread::run() stopped, packets=" + QString::number(m_packetCount));
}

// ============================================================================
// WfpRedirect
// ============================================================================

WfpRedirect::WfpRedirect(QObject *parent)
    : QObject(parent)
{
}

WfpRedirect::~WfpRedirect()
{
    stop();
}

bool WfpRedirect::loadWinDivert()
{
    if (m_dllHandle) return true;

    // Reuse the same DLL already loaded by WfpCapture
    m_dllHandle = GetModuleHandleW(L"WinDivert.dll");
    if (!m_dllHandle) {
        QString appDir = QCoreApplication::applicationDirPath();
        QString dllPath = appDir + "/WinDivert.dll";
        if (!QFile::exists(dllPath)) {
            redirectLog("WinDivert.dll not found at: " + dllPath);
            return false;
        }
        m_dllHandle = LoadLibraryW((LPCWSTR)dllPath.utf16());
        if (!m_dllHandle) {
            DWORD err = GetLastError();
            redirectLog(QString("Failed to load WinDivert.dll, error=%1").arg(err));
            return false;
        }
    }

    m_api.open = (WinDivertOpenFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertOpen");
    m_api.recv = (WinDivertRecvFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertRecv");
    m_api.close = (WinDivertCloseFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertClose");
    m_api.shutdown = (WinDivertShutdownFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertShutdown");
    m_api.send = (WinDivertSendFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertSend");
    m_api.parsePacket = (WinDivertHelperParsePacketFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperParsePacket");
    m_api.formatIPv4 = (WinDivertHelperFormatIPv4AddressFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperFormatIPv4Address");
    m_api.formatIPv6 = (WinDivertHelperFormatIPv6AddressFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperFormatIPv6Address");
    m_api.calcChecksums = (WinDivertHelperCalcChecksumsFn)GetProcAddress((HMODULE)m_dllHandle, "WinDivertHelperCalcChecksums");

    if (!m_api.open || !m_api.recv || !m_api.send || !m_api.close) {
        redirectLog("WinDivert.dll missing required functions (need send)");
        if (!GetModuleHandleW(L"WinDivert.dll")) {
            FreeLibrary((HMODULE)m_dllHandle);
        }
        m_dllHandle = nullptr;
        return false;
    }

    m_api.loaded = true;
    redirectLog("WinDivert.dll loaded for redirect");
    return true;
}

bool WfpRedirect::start(quint16 proxyPort)
{
    if (m_thread) stop();

    if (!loadWinDivert()) return false;

    // Filter: TCP to port 443, not loopback, not proxy's own port
    QString filter = QString("tcp and !loopback and !tcp.SrcPort == %1 and !tcp.DstPort == %1")
                     .arg(proxyPort);
    QByteArray filterUtf8 = filter.toLatin1();

    // Open WITHOUT SNIFF — packets are blocked until we re-inject them.
    // This lets us modify and re-inject, or re-inject unchanged.
    m_wdHandle = m_api.open(filterUtf8.constData(), 0, 0, 0);
    if (!m_wdHandle || m_wdHandle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        redirectLog(QString("WinDivertOpen for redirect failed, error=%1").arg(err));

        if (err == 5) {
            redirectLog("WinDivert redirect requires Administrator privileges");
        }
        return false;
    }

    m_thread = new WfpRedirectThread(&m_api, proxyPort, this);
    m_thread->m_handle = m_wdHandle;
    m_thread->start();

    redirectLog("WinDivert redirect started on port " + QString::number(proxyPort));
    return true;
}

void WfpRedirect::stop()
{
    if (m_wdHandle && m_wdHandle != INVALID_HANDLE_VALUE) {
        if (m_api.shutdown) {
            m_api.shutdown(m_wdHandle, 3);
        }
    }

    if (m_thread) {
        m_thread->requestStop();
        m_thread->wait(3000);
        delete m_thread;
        m_thread = nullptr;
    }

    if (m_wdHandle && m_wdHandle != INVALID_HANDLE_VALUE) {
        if (m_api.close) {
            m_api.close(m_wdHandle);
        }
        m_wdHandle = nullptr;
    }
}

bool WfpRedirect::isRunning() const
{
    return m_thread && m_thread->isRunning();
}

bool WfpRedirect::isAvailable() const
{
    QString appDir = QCoreApplication::applicationDirPath();
    return QFile::exists(appDir + "/WinDivert.dll");
}

bool WfpRedirect::lookupOriginal(quint32 clientIp, quint16 clientPort,
                                  quint32 &origDstIp, quint16 &origDstPort)
{
    if (m_thread) return m_thread->lookupOriginal(clientIp, clientPort, origDstIp, origDstPort);
    return false;
}

#endif // Q_OS_WIN
