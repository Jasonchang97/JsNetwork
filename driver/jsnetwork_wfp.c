/*++
jsnetwork_wfp.c

WFP Callout Driver for JsNetwork.
Captures outbound TCP connections at the ALE Connect layer,
extracting process PID, path, and connection metadata.

Communication with user-mode via FilterCommunicationPort.
--*/

#include <fltKernel.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#include "jsnetwork_wfp.h"

// ============================================================================
// Globals
// ============================================================================

static PDEVICE_OBJECT  g_DeviceObject   = NULL;
static PFLT_FILTER      g_Filter         = NULL;
static PFLT_PORT        g_ServerPort     = NULL;
static PFLT_PORT        g_ClientPort     = NULL;
static BOOLEAN          g_Capturing      = FALSE;

// WFP registration state
static UINT32           g_AleConnectCalloutId4 = 0;
static UINT32           g_AleConnectCalloutId6 = 0;
static UINT32           g_AleConnectFilterId4  = 0;
static UINT32           g_AleConnectFilterId6  = 0;
static HANDLE           g_EngineHandle         = NULL;

// WFP provider and sublayer GUIDs
// {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
DEFINE_GUID(JSNWFP_PROVIDER_GUID,
    0xa1b2c3d4, 0xe5f6, 0x7890, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

// {B2C3D4E5-F6A7-8901-BCDE-F12345678901}
DEFINE_GUID(JSNWFP_SUBLAYER_GUID,
    0xb2c3d4e5, 0xf6a7, 0x8901, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0x01);

// {C3D4E5F6-A7B8-9012-CDEF-123456789012}
DEFINE_GUID(JSNWFP_ALE_CONNECT_CALLOUT_GUID,
    0xc3d4e5f6, 0xa7b8, 0x9012, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12);

// ============================================================================
// Forward declarations
// ============================================================================

DRIVER_INITIALIZE DriverEntry;
static VOID     DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
static NTSTATUS FilterUnload(_In_ ULONG Flags);

static NTSTATUS RegisterWfpCallouts(_In_ PDEVICE_OBJECT deviceObject);
static VOID     UnregisterWfpCallouts(VOID);

static VOID NTAPI AleConnectClassify(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut);

static NTSTATUS AleConnectNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER *filter);

static NTSTATUS SetupCommunicationPort(VOID);
static VOID     CleanupCommunicationPort(VOID);

// ============================================================================
// Minifilter callbacks for communication port
// ============================================================================

static NTSTATUS PortConnect(
    _In_ PFLT_PORT clientPort,
    _In_opt_ void *serverPortCookie,
    _In_reads_bytes_opt_(contextLength) void *context,
    _In_ ULONG contextLength,
    _Outptr_result_maybenull_ void **connectionCookie)
{
    UNREFERENCED_PARAMETER(serverPortCookie);
    UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(contextLength);
    UNREFERENCED_PARAMETER(connectionCookie);

    g_ClientPort = clientPort;
    DbgPrint("JsNetworkWfp: Client connected\n");
    return STATUS_SUCCESS;
}

static VOID PortDisconnect(_In_opt_ void *connectionCookie)
{
    UNREFERENCED_PARAMETER(connectionCookie);

    FltCloseClientPort(g_Filter, &g_ClientPort);
    g_ClientPort = NULL;
    DbgPrint("JsNetworkWfp: Client disconnected\n");
}

// ============================================================================
// Driver entry / unload
// ============================================================================

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath)
{
    NTSTATUS status;
    FLT_REGISTRATION filterReg = {0};
    UNICODE_STRING deviceName;

    UNREFERENCED_PARAMETER(registryPath);

    DbgPrint("JsNetworkWfp: DriverEntry\n");

    // Create device object for cleanup tracking
    RtlInitUnicodeString(&deviceName, L"\\Device\\JsNetworkWfp");
    status = IoCreateDevice(driverObject, 0, &deviceName,
                            FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    // Register minifilter (needed for FilterCommunicationPort)
    filterReg.Size = sizeof(FLT_REGISTRATION);
    filterReg.Version = FLT_REGISTRATION_VERSION;
    filterReg.FilterUnloadCallback = FilterUnload;

    status = FltRegisterFilter(driverObject, &filterReg, &g_Filter);
    if (!NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: FltRegisterFilter failed: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set up communication port
    status = SetupCommunicationPort();
    if (!NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: SetupCommunicationPort failed: 0x%08X\n", status);
        FltUnregisterFilter(g_Filter);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Start minifilter (required for communication port to work)
    status = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: FltStartFiltering failed: 0x%08X\n", status);
        CleanupCommunicationPort();
        FltUnregisterFilter(g_Filter);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Register WFP callouts
    status = RegisterWfpCallouts(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: RegisterWfpCallouts failed: 0x%08X\n", status);
        CleanupCommunicationPort();
        FltUnregisterFilter(g_Filter);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Set unload routine
    driverObject->DriverUnload = DriverUnload;

    DbgPrint("JsNetworkWfp: Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

static VOID DriverUnload(_In_ PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
    DbgPrint("JsNetworkWfp: DriverUnload\n");

    UnregisterWfpCallouts();
    CleanupCommunicationPort();

    if (g_Filter) {
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
    }

    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

static NTSTATUS FilterUnload(_In_ ULONG flags)
{
    UNREFERENCED_PARAMETER(flags);
    DbgPrint("JsNetworkWfp: FilterUnload\n");

    UnregisterWfpCallouts();
    CleanupCommunicationPort();

    if (g_Filter) {
        FltUnregisterFilter(g_Filter);
        g_Filter = NULL;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// Communication port setup
// ============================================================================

static NTSTATUS SetupCommunicationPort(VOID)
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES objAttr;
    PSECURITY_DESCRIPTOR sd;

    RtlInitUnicodeString(&portName, JSNWFP_PORT_NAME);

    // Build security descriptor allowing all access
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(&objAttr, &portName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, sd);

    // Kernel-mode FltCreateCommunicationPort takes callbacks directly
    status = FltCreateCommunicationPort(g_Filter, &g_ServerPort,
                                         &objAttr, NULL,
                                         PortConnect, PortDisconnect, NULL,
                                         1); // MaxConnections

    FltFreeSecurityDescriptor(sd);

    if (NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: Communication port created\n");
    }

    return status;
}

static VOID CleanupCommunicationPort(VOID)
{
    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }
}

// ============================================================================
// WFP callout registration
// ============================================================================

static NTSTATUS RegisterWfpCallouts(_In_ PDEVICE_OBJECT deviceObject)
{
    NTSTATUS status;
    FWPM_SESSION session = {0};
    FWPM_PROVIDER provider = {0};
    FWPM_SUBLAYER sublayer = {0};
    FWPS_CALLOUT callout = {0};
    FWPM_CALLOUT mCallout = {0};
    FWPM_FILTER filter = {0};

    UNREFERENCED_PARAMETER(deviceObject);

    // Open WFP engine session
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: FwpmEngineOpen failed: 0x%08X\n", status);
        return status;
    }

    // Begin transaction
    status = FwpmTransactionBegin(g_EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    // Register provider
    memset(&provider, 0, sizeof(provider));
    provider.providerKey = JSNWFP_PROVIDER_GUID;
    provider.displayData.name = L"JsNetwork WFP Provider";
    provider.displayData.description = L"Network traffic capture provider for JsNetwork";
    status = FwpmProviderAdd(g_EngineHandle, &provider, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto abort;
    }

    // Register sublayer
    memset(&sublayer, 0, sizeof(sublayer));
    sublayer.subLayerKey = JSNWFP_SUBLAYER_GUID;
    sublayer.displayData.name = L"JsNetwork WFP Sublayer";
    sublayer.displayData.description = L"Network traffic capture sublayer";
    sublayer.providerKey = (GUID *)&JSNWFP_PROVIDER_GUID;
    sublayer.weight = 0xFFFF;  // Highest weight to classify first
    status = FwpmSubLayerAdd(g_EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto abort;
    }

    // Register ALE Connect callout (IPv4)
    memset(&callout, 0, sizeof(callout));
    callout.calloutKey = JSNWFP_ALE_CONNECT_CALLOUT_GUID;
    callout.classifyFn = AleConnectClassify;
    callout.notifyFn = AleConnectNotify;

    status = FwpsCalloutRegister(g_DeviceObject, &callout, &g_AleConnectCalloutId4);
    if (!NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: FwpsCalloutRegister (v4) failed: 0x%08X\n", status);
        goto abort;
    }

    // Register management callout (IPv4)
    memset(&mCallout, 0, sizeof(mCallout));
    mCallout.calloutKey = JSNWFP_ALE_CONNECT_CALLOUT_GUID;
    mCallout.displayData.name = L"JsNetwork ALE Connect Callout";
    mCallout.displayData.description = L"Captures outbound TCP connections";
    mCallout.providerKey = (GUID *)&JSNWFP_PROVIDER_GUID;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd(g_EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        goto abort;
    }

    // Add filter for ALE Connect (IPv4) - capture all outbound TCP
    memset(&filter, 0, sizeof(filter));
    filter.filterKey = JSNWFP_ALE_CONNECT_CALLOUT_GUID;
    filter.displayData.name = L"JsNetwork ALE Connect Filter";
    filter.displayData.description = L"Outbound TCP connection filter";
    filter.providerKey = (GUID *)&JSNWFP_PROVIDER_GUID;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = JSNWFP_SUBLAYER_GUID;
    filter.weight.type = FWP_EMPTY;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = JSNWFP_ALE_CONNECT_CALLOUT_GUID;

    status = FwpmFilterAdd(g_EngineHandle, &filter, NULL, &g_AleConnectFilterId4);
    if (!NT_SUCCESS(status)) {
        DbgPrint("JsNetworkWfp: FwpmFilterAdd (v4) failed: 0x%08X\n", status);
        goto abort;
    }

    // Commit transaction
    status = FwpmTransactionCommit(g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    g_Capturing = TRUE;
    DbgPrint("JsNetworkWfp: WFP callouts registered\n");
    return STATUS_SUCCESS;

abort:
    FwpmTransactionAbort(g_EngineHandle);
cleanup:
    if (g_AleConnectCalloutId4) {
        FwpsCalloutUnregisterById(g_AleConnectCalloutId4);
        g_AleConnectCalloutId4 = 0;
    }
    if (g_EngineHandle) {
        FwpmEngineClose(g_EngineHandle);
        g_EngineHandle = NULL;
    }
    return status;
}

static VOID UnregisterWfpCallouts(VOID)
{
    g_Capturing = FALSE;

    if (g_AleConnectCalloutId4) {
        FwpsCalloutUnregisterById(g_AleConnectCalloutId4);
        g_AleConnectCalloutId4 = 0;
    }
    if (g_AleConnectCalloutId6) {
        FwpsCalloutUnregisterById(g_AleConnectCalloutId6);
        g_AleConnectCalloutId6 = 0;
    }

    if (g_EngineHandle) {
        // Remove filter and callout from WFP engine
        FwpmTransactionBegin(g_EngineHandle, 0);
        FwpmFilterDeleteById(g_EngineHandle, g_AleConnectFilterId4);
        FwpmCalloutDeleteById(g_EngineHandle, g_AleConnectCalloutId4);
        FwpmTransactionCommit(g_EngineHandle);

        FwpmEngineClose(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    DbgPrint("JsNetworkWfp: WFP callouts unregistered\n");
}

// ============================================================================
// ALE Connect Callout
// ============================================================================

static VOID NTAPI AleConnectClassify(
    _In_ const FWPS_INCOMING_VALUES *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
    _Inout_opt_ void *layerData,
    _In_opt_ const void *classifyContext,
    _In_ const FWPS_FILTER *filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
    JSNWFP_EVENT event;
    NTSTATUS status;
    UINT64 processId;
    WCHAR imagePath[JSNWFP_MAX_PATH];

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Always allow the connection (we're just observing)
    classifyOut->actionType = FWP_ACTION_CONTINUE;

    if (!g_Capturing || !g_ClientPort) {
        return;
    }

    // Get process ID from metadata
    processId = inMetaValues->processId;

    // Skip system process (PID 4) and idle process (PID 0)
    if (processId == 0 || processId == 4) {
        return;
    }

    // Get process image path
    memset(imagePath, 0, sizeof(imagePath));
    {
        PEPROCESS process = NULL;
        status = PsLookupProcessByProcessId((HANDLE)processId, &process);
        if (NT_SUCCESS(status) && process) {
            PUNICODE_STRING pImageName = NULL;
            status = SeLocateProcessImageName(process, &pImageName);
            if (NT_SUCCESS(status) && pImageName) {
                RtlStringCbCopyW(imagePath, sizeof(imagePath), pImageName->Buffer);
                ExFreePool(pImageName);
            }
            ObDereferenceObject(process);
        }
    }

    if (!NT_SUCCESS(status)) {
        // Use empty path if we can't resolve
        imagePath[0] = L'\0';
    }

    // Build event
    memset(&event, 0, sizeof(event));
    event.eventType = JSNWFP_EVENT_CONNECT;
    event.processId = (UINT32)processId;
    event.timestamp = 0;  // Will be filled by user-mode
    event.localAddr = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    event.localPort = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    event.remoteAddr = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    event.remotePort = inFixedValues->incomingValue[
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    event.direction = 0;  // outbound

    // Copy process path (safe copy with null termination)
    RtlStringCbCopyW(event.processPath, sizeof(event.processPath), imagePath);

    // Send to user-mode with zero timeout (non-blocking, drop if busy)
    __try {
        LARGE_INTEGER timeout;
        timeout.QuadPart = 0;  // Non-blocking: return immediately if no client or busy
        status = FltSendMessage(g_Filter, &g_ClientPort,
                                &event, sizeof(event),
                                NULL, &timeout, NULL);
        if (!NT_SUCCESS(status)) {
            // Client may have disconnected or buffer full — not critical
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Swallow exceptions from message sending
    }
}

static NTSTATUS AleConnectNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID *filterKey,
    _Inout_ FWPS_FILTER *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}
