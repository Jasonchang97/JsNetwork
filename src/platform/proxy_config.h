#pragma once

#include <QString>

class ProxyConfig
{
public:
    // Set system proxy to point to our proxy server
    static bool enableSystemProxy(quint16 port);

    // Restore original system proxy settings
    static bool disableSystemProxy();

    // Check if system proxy is currently enabled
    static bool isSystemProxyEnabled();

private:
    static QString m_originalProxy;
};
