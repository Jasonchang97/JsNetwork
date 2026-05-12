#pragma once

#include <QString>

class ProxyConfig
{
public:
    // Set system proxy to point to our proxy server (macOS only; no-op on Windows)
    static bool enableSystemProxy(quint16 port);

    // Restore original system proxy settings (macOS only; no-op on Windows)
    static bool disableSystemProxy();

    // Check if system proxy is currently enabled (macOS only; returns false on Windows)
    static bool isSystemProxyEnabled();
};
