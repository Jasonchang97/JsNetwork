#ifndef JSNETWORK_WFP_H
#define JSNETWORK_WFP_H

//
// Shared definitions between kernel driver and user-mode application.
// This header is included by both the driver (C) and the Qt app (C++).
//

// Communication port name
#define JSNWFP_PORT_NAME        L"\\JsNetworkWfpPort"

// Maximum sizes
#define JSNWFP_MAX_PATH         260
#define JSNWFP_MAX_SNI          256

// User-mode -> Driver commands
#define JSNWFP_CMD_START_CAPTURE    1
#define JSNWFP_CMD_STOP_CAPTURE     2
#define JSNWFP_CMD_SET_FILTER       3   // Filter by process name
#define JSNWFP_CMD_QUERY_ORIG_DST   4   // Query original destination for redirected connection

// Driver -> User-mode event types
#define JSNWFP_EVENT_CONNECT        1   // New outbound TCP connection
#define JSNWFP_EVENT_DISCONNECT     2   // Connection closed

// Event structure (driver -> user-mode)
// Aligned to 8 bytes for cross-mode compatibility
typedef struct _JSNWFP_EVENT {
    UINT32 eventType;                           // JSNWFP_EVENT_*
    UINT32 processId;                           // PID of the connecting process
    UINT64 timestamp;                           // 100ns ticks since 1601-01-01
    UINT32 localAddr;                           // IPv4 local address (network byte order)
    UINT32 remoteAddr;                          // IPv4 remote address (network byte order)
    UINT16 localPort;                           // Local port (host byte order)
    UINT16 remotePort;                          // Remote port (host byte order)
    UINT16 direction;                           // 0=outbound, 1=inbound
    UINT16 padding;                             // Alignment padding
    WCHAR  processPath[JSNWFP_MAX_PATH];        // Full process image path
    CHAR   sniName[JSNWFP_MAX_SNI];             // TLS SNI hostname (empty if not HTTPS)
} JSNWFP_EVENT;

// Command structure (user-mode -> driver)
typedef struct _JSNWFP_COMMAND {
    UINT32 command;                             // JSNWFP_CMD_*
    UINT32 param;                               // Command-specific parameter
    WCHAR  filterPath[JSNWFP_MAX_PATH];         // Process path filter (for SET_FILTER)
} JSNWFP_COMMAND;

// Query request (user-mode -> driver, via FilterSendMessage)
typedef struct _JSNWFP_QUERY {
    UINT32 clientAddr;                          // Client IP (network byte order)
    UINT16 clientPort;                          // Client port (host byte order)
    UINT16 padding;
} JSNWFP_QUERY;

// Query response (driver -> user-mode)
typedef struct _JSNWFP_ORIG_DST {
    UINT32 origAddr;                            // Original destination IP (network byte order)
    UINT16 origPort;                            // Original destination port (host byte order)
    UINT16 found;                               // 1=found, 0=not found
} JSNWFP_ORIG_DST;

#endif // JSNETWORK_WFP_H
