#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2spi.h>
#include <sporder.h>
#include <windows.h>

// Proxy port that the LSP redirects HTTPS connections to
#define LSP_PROXY_PORT 9527

// Named event that signals the proxy is running and accepting connections
// LSP checks this before redirecting; if not signaled, traffic passes through directly
#define LSP_PROXY_ACTIVE_EVENT L"Global\\JsNetwork_ProxyActive_9527"

// Per-socket context
struct SocketContext {
    SOCKET Socket;
    int AddressFamily;
    int SocketType;
    int Protocol;
    BOOL Redirected;
    SocketContext *Next;
};

// Global provider state
struct Provider {
    WSPPROC_TABLE NextProcTable;
    HMODULE hModule;
    WSPUPCALLTABLE UpcallTable;
    WSAPROTOCOL_INFOW ProtocolInfo;
    int StartupCount;
    CRITICAL_SECTION Lock;
    SocketContext *SocketList;
    BOOL SkipRedirect;  // TRUE if this is the proxy process itself
};

extern Provider gProvider;

void *LspAlloc(size_t size, int *err);
void LspFree(void *ptr);
SocketContext *FindSocketCtx(SOCKET s);
