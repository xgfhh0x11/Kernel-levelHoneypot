#pragma once

#include <ntddk.h>

// Control Layer: Management and configuration

// Config path matches the install location documented in README.md / BUILD.md
// (`mkdir C:\Release` ; `copy config\honey.conf C:\Release\`).
// `\??\` is the kernel-mode object-manager prefix that resolves DOS-style paths.
#define CONFIG_FILE_PATH L"\\??\\C:\\Release\\honey.conf"
#define MAX_CONFIG_LINE_SIZE 512
#define MAX_CONFIG_ENTRIES 256

typedef struct _HONEYPOT_CONFIG {
    BOOLEAN TriggerLayerEnabled;
    BOOLEAN DetectionLayerEnabled;
    BOOLEAN DeceptionLayerEnabled;
    BOOLEAN LoggingLayerEnabled;
    BOOLEAN ExtractionLayerEnabled;
    
    // Trigger layer config
    ULONG MaxFakeRegistryKeys;
    ULONG MaxHookedFunctions;
    
    // Detection layer config
    ULONG MaxSyscallLogEntries;
    BOOLEAN StackFingerprintingEnabled;
    BOOLEAN MemoryTrackingEnabled;
    
    // Deception layer config
    ULONG MaxFakeProcesses;
    ULONG MaxFakeThreads;
    ULONG FakeStructureUpdateInterval;
    
    // Logging layer config
    ULONG LogBufferSize;
    BOOLEAN EncryptionEnabled;
    ULONG ExportIntervalSeconds;
    
    // Extraction layer config
    BOOLEAN DisassemblerEnabled;
    BOOLEAN ExploitFingerprintingEnabled;
    
    // Remote update config
    BOOLEAN RemoteUpdateEnabled;
    UNICODE_STRING RemoteUpdateUrl;
} HONEYPOT_CONFIG, *PHONEYPOT_CONFIG;

typedef struct _CONTROL_LAYER_STATE {
    BOOLEAN Initialized;
    
    // Configuration
    HONEYPOT_CONFIG Config;
    BOOLEAN ConfigLoaded;
    
    // Remote update (covert channel - placeholder)
    BOOLEAN RemoteUpdateEnabled;
    
    // Statistics
    LARGE_INTEGER LastConfigUpdate;
    ULONG ConfigUpdateCount;
} CONTROL_LAYER_STATE, *PCONTROL_LAYER_STATE;

// Function declarations
NTSTATUS InitializeControlLayer(VOID);
VOID CleanupControlLayer(VOID);
NTSTATUS LoadConfiguration(PUNICODE_STRING ConfigFilePath);
NTSTATUS ParseConfigLine(PCHAR Line, PHONEYPOT_CONFIG Config);
NTSTATUS ApplyConfiguration(PHONEYPOT_CONFIG Config);
NTSTATUS ReloadConfiguration(VOID);
NTSTATUS RemoteUpdateCheck(VOID); // Placeholder for covert channel

// =================================================================
// IOCTL interface — kept in sync with UserModeApp/HoneyPotControl.h
// =================================================================

#define HANDSHAKE_SECRET_SIZE 32
#define SESSION_ID_SIZE       16

#define KMOD_DRIVER_VERSION_MAJOR 1
#define KMOD_DRIVER_VERSION_MINOR 0
#define KMOD_DRIVER_VERSION       ((KMOD_DRIVER_VERSION_MAJOR << 16) | KMOD_DRIVER_VERSION_MINOR)

// Handshake response status codes
#define HONEYPOT_HANDSHAKE_OK           0x00000000
#define HONEYPOT_HANDSHAKE_BAD_SECRET   0x00000001
#define HONEYPOT_HANDSHAKE_BAD_VERSION  0x00000002

#pragma pack(push, 1)
typedef struct _HONEYPOT_HANDSHAKE_REQUEST {
    UCHAR Secret[HANDSHAKE_SECRET_SIZE];
    ULONG Version;
} HONEYPOT_HANDSHAKE_REQUEST, *PHONEYPOT_HANDSHAKE_REQUEST;

typedef struct _HONEYPOT_HANDSHAKE_RESPONSE {
    UCHAR SessionId[SESSION_ID_SIZE];
    ULONG Status;
    ULONG DriverVersion;
} HONEYPOT_HANDSHAKE_RESPONSE, *PHONEYPOT_HANDSHAKE_RESPONSE;
#pragma pack(pop)

// IOCTL codes — numbering matches UserModeApp/HoneyPotControl.h byte-for-byte.
// Function codes 0x800-0x804.
#define IOCTL_HONEYPOT_HANDSHAKE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HONEYPOT_GET_STATS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HONEYPOT_GET_LOGS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HONEYPOT_RELOAD_CONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HONEYPOT_EXPORT_LOGS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Shared handshake secret — must match UserModeApp/HoneyPotControl.c g_HandshakeSecret.
extern const UCHAR g_HoneyPotHandshakeSecret[HANDSHAKE_SECRET_SIZE];

// Validates the request secret, generates a session ID, and fills Response.
// Returns STATUS_SUCCESS even when the secret/version is wrong; the failure
// is reported in Response->Status so the IRP completes cleanly.
NTSTATUS HandleHandshake(PHONEYPOT_HANDSHAKE_REQUEST Request,
                         PHONEYPOT_HANDSHAKE_RESPONSE Response);

