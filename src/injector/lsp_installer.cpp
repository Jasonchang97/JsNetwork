// LSP Installer/Uninstaller for JsNetwork
// Usage: lsp_installer.exe install <path_to_lsp.dll>
//        lsp_installer.exe uninstall
//        lsp_installer.exe status
// Must run as Administrator.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2spi.h>
#include <sporder.h>
#include <windows.h>
#include <stdio.h>
#include <cstdlib>

// Same GUID as in lsp_provider.cpp
static GUID gProviderGuid =
    {0xa1b2c3d4, 0xe5f6, 0x7890, {0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90}};

static wchar_t PROVIDER_NAME[] = L"JsNetwork Traffic Interceptor";
static wchar_t TCP_PROTOCOL[] = L"JsNetwork LSP (TCP)";

static BOOL CopyDllWithRetry(const wchar_t *src, const wchar_t *dest) {
    if (CopyFileW(src, dest, FALSE))
        return TRUE;

    DWORD err = GetLastError();
    if (err != ERROR_SHARING_VIOLATION && err != ERROR_ACCESS_DENIED)
        return FALSE;

    // File is locked (loaded by other processes). If it already exists,
    // it's likely already our DLL from a previous install - skip the copy.
    if (GetFileAttributesW(dest) != INVALID_FILE_ATTRIBUTES) {
        wprintf(L"DLL locked but already exists at %s - using existing\n", dest);
        return TRUE;
    }

    wprintf(L"File locked (error %d), trying rename...\n", err);
    WCHAR backup[MAX_PATH];
    wsprintfW(backup, L"%s.old", dest);
    DeleteFileW(backup);
    if (MoveFileExW(dest, backup, MOVEFILE_REPLACE_EXISTING)) {
        wprintf(L"Renamed to %s\n", backup);
        if (CopyFileW(src, dest, FALSE))
            return TRUE;
    }
    return FALSE;
}

static void CleanOldProvider() {
    int err = 0;
    WSCDeinstallProvider(&gProviderGuid, &err);
#ifdef _WIN64
    WSCDeinstallProvider32(&gProviderGuid, &err);
#endif
}

static BOOL FindBaseTcpProvider(DWORD *outServiceFlags) {
    int err = 0;
    DWORD bufLen = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &err);
    if (bufLen == 0) return FALSE;
    WSAPROTOCOL_INFOW *infos = (WSAPROTOCOL_INFOW *)malloc(bufLen);
    int n = WSCEnumProtocols(NULL, infos, &bufLen, &err);

    for (int i = 0; i < n; i++) {
        if (infos[i].iAddressFamily == AF_INET &&
            infos[i].iSocketType == SOCK_STREAM &&
            infos[i].iProtocol == IPPROTO_TCP &&
            infos[i].ProtocolChain.ChainLen == 1) {
            wprintf(L"Base TCP: catalog=%u flags=0x%08X chain=%d name=%s\n",
                    infos[i].dwCatalogEntryId, infos[i].dwServiceFlags1,
                    infos[i].ProtocolChain.ChainLen, infos[i].szProtocol);
            *outServiceFlags = infos[i].dwServiceFlags1;
            free(infos);
            return TRUE;
        }
    }
    free(infos);
    return FALSE;
}

int InstallLSP(const wchar_t *dllPath, const wchar_t *dll32Path) {
    int err = 0;

    // Only clean residual entries that may prevent re-installation
    int dummy = 0;
    WSCDeinstallProvider(&gProviderGuid, &dummy);
#ifdef _WIN64
    WSCDeinstallProvider32(&gProviderGuid, &dummy);
#endif

    WCHAR sys32[MAX_PATH];
    GetSystemDirectoryW(sys32, MAX_PATH);
    WCHAR dest[MAX_PATH];
    wsprintfW(dest, L"%s\\jsnetwork_lsp.dll", sys32);

    if (!CopyDllWithRetry(dllPath, dest)) {
        wprintf(L"Failed to copy DLL to %s (error %d)\n", dest, GetLastError());
        wprintf(L"Make sure you're running as Administrator.\n");
        return 1;
    }
    wprintf(L"Copied DLL to %s\n", dest);

    DWORD baseTcpFlags = 0;
    if (FindBaseTcpProvider(&baseTcpFlags)) {
        wprintf(L"Using base TCP service flags: 0x%08X\n", baseTcpFlags);
    } else {
        wprintf(L"Warning: no base TCP provider found!\n");
    }

    WSAPROTOCOL_INFOW proto = {};
    proto.dwServiceFlags1 = baseTcpFlags;
    proto.dwProviderFlags = 0;
    memcpy(&proto.ProviderId, &gProviderGuid, sizeof(GUID));
    proto.iAddressFamily = AF_INET;
    proto.iMaxSockAddr = 16;
    proto.iMinSockAddr = 16;
    proto.iSocketType = SOCK_STREAM;
    proto.iProtocol = IPPROTO_TCP;
    proto.iProtocolMaxOffset = 0;
    proto.iNetworkByteOrder = BIGENDIAN;
    proto.iSecurityScheme = SECURITY_PROTOCOL_NONE;
    proto.dwMessageSize = 0;
    wcscpy_s(proto.szProtocol, WSAPROTOCOL_LEN, TCP_PROTOCOL);

    DWORD catalogId = 0;
#ifdef _WIN64
    WCHAR syswow64[MAX_PATH];
    GetSystemWow64DirectoryW(syswow64, MAX_PATH);
    WCHAR dest32[MAX_PATH];
    wsprintfW(dest32, L"%s\\jsnetwork_lsp.dll", syswow64);
    if (dll32Path && dll32Path[0]) {
        if (!CopyDllWithRetry(dll32Path, dest32)) {
            wprintf(L"Failed to copy 32-bit DLL to %s (error %d)\n", dest32, GetLastError());
        } else {
            wprintf(L"Copied 32-bit DLL to %s\n", dest32);
        }
    }
    wprintf(L"64-bit DLL: %s\n32-bit DLL: %s\n", dest, dest32);
    int ret = WSCInstallProviderAndChains64_32(
        &gProviderGuid, dest, dest32, PROVIDER_NAME,
        0, &proto, 1, &catalogId, &err);
#else
    (void)dll32Path;
    wprintf(L"DLL path: %s\n", dest);
    int ret = WSCInstallProviderAndChains(
        &gProviderGuid, dest, PROVIDER_NAME,
        0, &proto, 1, &catalogId, &err);
#endif

    if (ret == SOCKET_ERROR) {
        wprintf(L"WSCInstallProviderAndChains failed: err=%d WSAErr=%d\n", err, WSAGetLastError());
        return 1;
    }
    wprintf(L"LSP installed. Catalog entry ID: %u\n", catalogId);

    // Reorder: put our chain entries first so they take priority
    DWORD bufLen = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &err);
    WSAPROTOCOL_INFOW *infos = (WSAPROTOCOL_INFOW *)malloc(bufLen);
    int n = WSCEnumProtocols(NULL, infos, &bufLen, &err);

    DWORD *ids = (DWORD *)malloc(n * sizeof(DWORD));
    int count = 0;

    // Our chain entries first
    for (int i = 0; i < n; i++) {
        if (infos[i].ProtocolChain.ChainLen > 1) {
            for (int j = 0; j < infos[i].ProtocolChain.ChainLen; j++) {
                if (infos[i].ProtocolChain.ChainEntries[j] == catalogId) {
                    ids[count++] = infos[i].dwCatalogEntryId;
                    break;
                }
            }
        }
    }
    // Then everything else
    for (int i = 0; i < n; i++) {
        BOOL found = FALSE;
        for (int j = 0; j < count; j++) {
            if (ids[j] == infos[i].dwCatalogEntryId) { found = TRUE; break; }
        }
        if (!found) ids[count++] = infos[i].dwCatalogEntryId;
    }

    WSCWriteProviderOrder(ids, count);
    free(ids);
    free(infos);

    wprintf(L"LSP catalog reordered. Reboot or restart apps to take effect.\n");
    return 0;
}

int UninstallLSP() {
    int err = 0;
    int ret = WSCDeinstallProvider(&gProviderGuid, &err);
    if (ret == SOCKET_ERROR) {
        wprintf(L"WSCDeinstallServiceProvider failed: %d\n", err);
        return 1;
    }

    // Remove DLL from System32
    WCHAR sys32[MAX_PATH];
    GetSystemDirectoryW(sys32, MAX_PATH);
    WCHAR path[MAX_PATH];
    wsprintfW(path, L"%s\\jsnetwork_lsp.dll", sys32);
    DeleteFileW(path);

    wprintf(L"LSP uninstalled. Run 'netsh winsock reset' and reboot for clean state.\n");
    return 0;
}

int ShowStatus() {
    int err = 0;
    DWORD bufLen = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &err);
    WSAPROTOCOL_INFOW *infos = (WSAPROTOCOL_INFOW *)malloc(bufLen);
    int n = WSCEnumProtocols(NULL, infos, &bufLen, &err);

    BOOL found = FALSE;
    for (int i = 0; i < n; i++) {
        if (IsEqualGUID(infos[i].ProviderId, gProviderGuid)) {
            wprintf(L"Found LSP: %s (catalog %u, chain len %d)\n",
                infos[i].szProtocol, infos[i].dwCatalogEntryId,
                infos[i].ProtocolChain.ChainLen);
            found = TRUE;
        }
    }

    if (!found) {
        wprintf(L"LSP is not installed.\n");
    }

    free(infos);
    return found ? 0 : 1;
}

int wmain(int argc, wchar_t *argv[]) {
    // Init Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  lsp_installer.exe install <dll_path> [32bit_dll_path]\n");
        wprintf(L"  lsp_installer.exe uninstall\n");
        wprintf(L"  lsp_installer.exe status\n");
        WSACleanup();
        return 1;
    }

    int ret = 1;
    if (_wcsicmp(argv[1], L"install") == 0) {
        if (argc < 3) {
            wprintf(L"Missing DLL path.\n");
        } else {
            const wchar_t *dll32 = (argc >= 4) ? argv[3] : NULL;
            ret = InstallLSP(argv[2], dll32);
        }
    } else if (_wcsicmp(argv[1], L"uninstall") == 0) {
        ret = UninstallLSP();
    } else if (_wcsicmp(argv[1], L"status") == 0) {
        ret = ShowStatus();
    } else {
        wprintf(L"Unknown command: %s\n", argv[1]);
    }

    WSACleanup();
    return ret;
}
