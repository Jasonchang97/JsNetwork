// JsNetwork LSP (Layered Service Provider)
// Intercepts WSPConnect to redirect HTTP (80) and HTTPS (443) connections
// to 127.0.0.1:9527 so the JsNetwork proxy can capture and decrypt traffic.

#include "lsp_provider.h"
#include <wchar.h>

Provider gProvider = {};

// GUID for this LSP provider
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
static const GUID gProviderGuid =
    {0xa1b2c3d4, 0xe5f6, 0x7890, {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90}};

void *LspAlloc(size_t size, int *err) {
    void *ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!ptr && err) *err = WSAENOBUFS;
    return ptr;
}

void LspFree(void *ptr) {
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

SocketContext *FindSocketCtx(SOCKET s) {
    SocketContext *ctx = gProvider.SocketList;
    while (ctx) {
        if (ctx->Socket == s) return ctx;
        ctx = ctx->Next;
    }
    return NULL;
}

// Check if current process is JsNetwork (to avoid redirecting proxy's own connections)
static BOOL IsProxyProcess() {
    WCHAR path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    // Check if the exe name contains "JsNetwork" (case-insensitive)
    WCHAR *name = wcsrchr(path, L'\\');
    if (!name) name = path; else name++;
    return (_wcsicmp(name, L"JsNetwork.exe") == 0);
}

// Check if the proxy is currently running by testing the named event
static BOOL IsProxyRunning() {
    HANDLE hEvent = OpenEventW(SYNCHRONIZE, FALSE, LSP_PROXY_ACTIVE_EVENT);
    if (hEvent == NULL) return FALSE;
    DWORD result = WaitForSingleObject(hEvent, 0);
    CloseHandle(hEvent);
    return (result == WAIT_OBJECT_0);
}

// Check if port is HTTP or HTTPS (should be intercepted)
static BOOL IsInterceptedPort(u_short port) {
    return port == htons(80) || port == htons(443);
}

// ===========================================================================
// Custom WSPConnect - redirects HTTP/HTTPS connections to 127.0.0.1:9527
// ===========================================================================
int WSPAPI WSPConnect(
    SOCKET s, const struct sockaddr FAR *name, int namelen,
    LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
    LPQOS lpSQOS, LPQOS lpGQOS, LPINT lpErrno)
{
    SocketContext *ctx = FindSocketCtx(s);

    if (!gProvider.SkipRedirect && ctx
        && name && namelen >= (int)sizeof(struct sockaddr_in)
        && ctx->AddressFamily == AF_INET
        && ctx->SocketType == SOCK_STREAM)
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)name;
        if (IsInterceptedPort(addr->sin_port) && IsProxyRunning()) {
            struct sockaddr_in redirect;
            memcpy(&redirect, name, sizeof(redirect));
            redirect.sin_addr.s_addr = inet_addr("127.0.0.1");
            redirect.sin_port = htons(LSP_PROXY_PORT);
            ctx->Redirected = TRUE;
            return gProvider.NextProcTable.lpWSPConnect(
                s, (const struct sockaddr *)&redirect, sizeof(redirect),
                lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
        }
    }

    return gProvider.NextProcTable.lpWSPConnect(
        s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
}

// ===========================================================================
// WSPSocket - track socket creation
// ===========================================================================
SOCKET WSPAPI WSPSocket(
    int af, int type, int protocol,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    GROUP g, DWORD dwFlags, LPINT lpErrno)
{
    SOCKET s = gProvider.NextProcTable.lpWSPSocket(
        af, type, protocol, lpProtocolInfo, g, dwFlags, lpErrno);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    SocketContext *ctx = (SocketContext *)LspAlloc(sizeof(SocketContext), lpErrno);
    if (!ctx) {
        gProvider.NextProcTable.lpWSPCloseSocket(s, lpErrno);
        return INVALID_SOCKET;
    }
    ctx->Socket = s;
    ctx->AddressFamily = af;
    ctx->SocketType = type;
    ctx->Protocol = protocol;

    EnterCriticalSection(&gProvider.Lock);
    ctx->Next = gProvider.SocketList;
    gProvider.SocketList = ctx;
    LeaveCriticalSection(&gProvider.Lock);

    return s;
}

// ===========================================================================
// WSPCloseSocket - cleanup socket context
// ===========================================================================
int WSPAPI WSPCloseSocket(SOCKET s, LPINT lpErrno) {
    EnterCriticalSection(&gProvider.Lock);
    SocketContext **pp = &gProvider.SocketList;
    while (*pp) {
        if ((*pp)->Socket == s) {
            SocketContext *toFree = *pp;
            *pp = toFree->Next;
            LspFree(toFree);
            break;
        }
        pp = &(*pp)->Next;
    }
    LeaveCriticalSection(&gProvider.Lock);

    return gProvider.NextProcTable.lpWSPCloseSocket(s, lpErrno);
}

// ===========================================================================
// Forwarding wrappers for all other 27 WSP functions
// ===========================================================================

SOCKET WSPAPI WSPAccept(SOCKET s, struct sockaddr *addr, int *addrlen,
    LPCONDITIONPROC fn, DWORD cbData, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPAccept(s, addr, addrlen, fn, cbData, lpErrno);
}

int WSPAPI WSPAddressToString(LPSOCKADDR addr, int addrlen, LPWSAPROTOCOL_INFOW proto,
    LPWSTR str, LPDWORD len, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPAddressToString(addr, addrlen, proto, str, len, lpErrno);
}

int WSPAPI WSPAsyncSelect(SOCKET s, HWND hWnd, unsigned int msg, long events, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPAsyncSelect(s, hWnd, msg, events, lpErrno);
}

int WSPAPI WSPBind(SOCKET s, const struct sockaddr *name, int namelen, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPBind(s, name, namelen, lpErrno);
}

int WSPAPI WSPCancelBlockingCall(LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPCancelBlockingCall(lpErrno);
}

int WSPAPI WSPCleanup(LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPCleanup(lpErrno);
}

int WSPAPI WSPDuplicateSocket(SOCKET s, DWORD pid, LPWSAPROTOCOL_INFOW proto, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPDuplicateSocket(s, pid, proto, lpErrno);
}

int WSPAPI WSPEnumNetworkEvents(SOCKET s, WSAEVENT hEvent, LPWSANETWORKEVENTS events, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPEnumNetworkEvents(s, hEvent, events, lpErrno);
}

int WSPAPI WSPEventSelect(SOCKET s, WSAEVENT hEvent, long events, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPEventSelect(s, hEvent, events, lpErrno);
}

int WSPAPI WSPGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED ov, LPDWORD bytes,
    BOOL wait, LPDWORD flags, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPGetOverlappedResult(s, ov, bytes, wait, flags, lpErrno);
}

int WSPAPI WSPGetPeerName(SOCKET s, struct sockaddr *name, int *namelen, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPGetPeerName(s, name, namelen, lpErrno);
}

int WSPAPI WSPGetSockName(SOCKET s, struct sockaddr *name, int *namelen, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPGetSockName(s, name, namelen, lpErrno);
}

int WSPAPI WSPGetSockOpt(SOCKET s, int level, int optname, char *optval, int *optlen, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPGetSockOpt(s, level, optname, optval, optlen, lpErrno);
}

int WSPAPI WSPGetQOSByName(SOCKET s, LPWSABUF qosName, LPQOS qos, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPGetQOSByName(s, qosName, qos, lpErrno);
}

int WSPAPI WSPIoctl(SOCKET s, DWORD code, LPVOID inBuf, DWORD inLen,
    LPVOID outBuf, DWORD outLen, LPDWORD retBytes,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE fn,
    LPWSATHREADID tid, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPIoctl(s, code, inBuf, inLen,
        outBuf, outLen, retBytes, ov, fn, tid, lpErrno);
}

SOCKET WSPAPI WSPJoinLeaf(SOCKET s, const struct sockaddr *name, int namelen,
    LPWSABUF callerData, LPWSABUF calleeData, LPQOS sqos, LPQOS gqos,
    DWORD flags, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPJoinLeaf(s, name, namelen,
        callerData, calleeData, sqos, gqos, flags, lpErrno);
}

int WSPAPI WSPListen(SOCKET s, int backlog, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPListen(s, backlog, lpErrno);
}

int WSPAPI WSPRecv(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvBytes,
    LPDWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE fn,
    LPWSATHREADID tid, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPRecv(s, bufs, count, recvBytes,
        flags, ov, fn, tid, lpErrno);
}

int WSPAPI WSPRecvDisconnect(SOCKET s, LPWSABUF disconnectData, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPRecvDisconnect(s, disconnectData, lpErrno);
}

int WSPAPI WSPRecvFrom(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvBytes,
    LPDWORD flags, struct sockaddr *from, int *fromLen,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE fn,
    LPWSATHREADID tid, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPRecvFrom(s, bufs, count, recvBytes,
        flags, from, fromLen, ov, fn, tid, lpErrno);
}

int WSPAPI WSPSelect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    const struct timeval *timeout, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPSelect(nfds, readfds, writefds, exceptfds, timeout, lpErrno);
}

int WSPAPI WSPSend(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sentBytes,
    DWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE fn,
    LPWSATHREADID tid, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPSend(s, bufs, count, sentBytes,
        flags, ov, fn, tid, lpErrno);
}

int WSPAPI WSPSendDisconnect(SOCKET s, LPWSABUF disconnectData, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPSendDisconnect(s, disconnectData, lpErrno);
}

int WSPAPI WSPSendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sentBytes,
    DWORD flags, const struct sockaddr *to, int toLen,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE fn,
    LPWSATHREADID tid, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPSendTo(s, bufs, count, sentBytes,
        flags, to, toLen, ov, fn, tid, lpErrno);
}

int WSPAPI WSPSetSockOpt(SOCKET s, int level, int optname, const char *optval, int optlen, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPSetSockOpt(s, level, optname, optval, optlen, lpErrno);
}

int WSPAPI WSPShutdown(SOCKET s, int how, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPShutdown(s, how, lpErrno);
}

int WSPAPI WSPStringToAddress(LPWSTR addrStr, int af, LPWSAPROTOCOL_INFOW proto,
    LPSOCKADDR addr, int *addrLen, LPINT lpErrno) {
    return gProvider.NextProcTable.lpWSPStringToAddress(addrStr, af, proto, addr, addrLen, lpErrno);
}

// ===========================================================================
// WSPStartup - Chain to the base TCP provider
// ===========================================================================

// Exported via .def file
int WSPAPI WSPStartup(
    WORD wVersionRequested, LPWSPDATA lpWSPData,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    WSPUPCALLTABLE UpcallTable,
    LPWSPPROC_TABLE lpProcTable)
{
    int err;

    EnterCriticalSection(&gProvider.Lock);
    gProvider.UpcallTable = UpcallTable;

    // Already initialized - bump refcount and return cached table
    if (gProvider.StartupCount > 0) {
        gProvider.StartupCount++;
        memcpy(lpProcTable, &gProvider.NextProcTable, sizeof(WSPPROC_TABLE));
        lpWSPData->wVersion = MAKEWORD(2, 2);
        lpWSPData->wHighVersion = MAKEWORD(2, 2);
        LeaveCriticalSection(&gProvider.Lock);
        return 0;
    }

    // Find the base provider in the protocol chain
    if (lpProtocolInfo->ProtocolChain.ChainLen <= 1) {
        LeaveCriticalSection(&gProvider.Lock);
        return WSAVERNOTSUPPORTED;
    }
    DWORD baseId = lpProtocolInfo->ProtocolChain.ChainEntries[
        lpProtocolInfo->ProtocolChain.ChainLen - 1];

    // Enumerate protocols to find the base provider's info
    DWORD bufLen = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &err);
    WSAPROTOCOL_INFOW *infos = (WSAPROTOCOL_INFOW *)LspAlloc(bufLen, &err);
    if (!infos) { LeaveCriticalSection(&gProvider.Lock); return WSAENOBUFS; }
    int nProtos = WSCEnumProtocols(NULL, infos, &bufLen, &err);

    WSAPROTOCOL_INFOW baseInfo = {};
    for (int i = 0; i < nProtos; i++) {
        if (infos[i].dwCatalogEntryId == baseId) {
            baseInfo = infos[i];
            break;
        }
    }
    LspFree(infos);

    // Get base provider's DLL path
    WCHAR dllPath[MAX_PATH];
    int pathLen = MAX_PATH;
    WSCGetProviderPath(&baseInfo.ProviderId, dllPath, &pathLen, &err);
    WCHAR expanded[MAX_PATH];
    ExpandEnvironmentStringsW(dllPath, expanded, MAX_PATH);

    // Load base provider and call its WSPStartup
    gProvider.hModule = LoadLibraryW(expanded);
    if (!gProvider.hModule) { LeaveCriticalSection(&gProvider.Lock); return WSASYSNOTREADY; }

    LPWSPSTARTUP baseStartup = (LPWSPSTARTUP)GetProcAddress(gProvider.hModule, "WSPStartup");
    if (!baseStartup) {
        FreeLibrary(gProvider.hModule); gProvider.hModule = NULL;
        LeaveCriticalSection(&gProvider.Lock);
        return WSASYSNOTREADY;
    }

    WSPDATA wspData;
    WSPPROC_TABLE nextTable = {};
    // CRITICAL: pass base provider's own WSAPROTOCOL_INFO (not chain entry)
    err = baseStartup(wVersionRequested, &wspData, &baseInfo, UpcallTable, &nextTable);
    if (err != 0) {
        FreeLibrary(gProvider.hModule); gProvider.hModule = NULL;
        LeaveCriticalSection(&gProvider.Lock);
        return err;
    }

    gProvider.NextProcTable = nextTable;
    gProvider.ProtocolInfo = *lpProtocolInfo;
    gProvider.StartupCount = 1;
    gProvider.SkipRedirect = IsProxyProcess();

    // Return base provider's table with our overrides
    *lpProcTable = nextTable;
    lpProcTable->lpWSPConnect = WSPConnect;
    lpProcTable->lpWSPSocket = WSPSocket;
    lpProcTable->lpWSPCloseSocket = WSPCloseSocket;

    lpWSPData->wVersion = wspData.wVersion;
    lpWSPData->wHighVersion = wspData.wHighVersion;

    LeaveCriticalSection(&gProvider.Lock);
    return 0;
}

// ===========================================================================
// DllMain
// ===========================================================================
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&gProvider.Lock);
    } else if (reason == DLL_PROCESS_DETACH) {
        DeleteCriticalSection(&gProvider.Lock);
    }
    return TRUE;
}
