#include "FakeNetFilter.h"
#include <string.h>

// Make the RtlRandomEx prototype visible (returns ULONG, not the implicit int)
// so the session-id generation below is not truncated through an int return.
NTSYSAPI ULONG NTAPI RtlRandomEx(_Inout_ PULONG Seed);

extern HONEYPOT_GLOBAL_STATE g_HoneyPotState;

NTSTATUS InitializeControlLayer(VOID)
{
    PCONTROL_LAYER_STATE state = &g_HoneyPotState.ControlState;
    UNICODE_STRING configPath = RTL_CONSTANT_STRING(CONFIG_FILE_PATH);
    
    DbgPrint("[ControlLayer] Initializing...\n");
    
    RtlZeroMemory(state, sizeof(CONTROL_LAYER_STATE));
    
    // Set default configuration
    state->Config.TriggerLayerEnabled = TRUE;
    state->Config.DetectionLayerEnabled = TRUE;
    state->Config.DeceptionLayerEnabled = TRUE;
    state->Config.LoggingLayerEnabled = TRUE;
    state->Config.ExtractionLayerEnabled = TRUE;
    
    state->Config.MaxFakeRegistryKeys = 16;
    state->Config.MaxHookedFunctions = MAX_HOOKED_FUNCTIONS;
    state->Config.MaxSyscallLogEntries = MAX_SYSCALL_LOG_ENTRIES;
    state->Config.StackFingerprintingEnabled = TRUE;
    state->Config.MemoryTrackingEnabled = TRUE;
    state->Config.MaxFakeProcesses = MAX_FAKE_EPROCESS;
    state->Config.MaxFakeThreads = MAX_FAKE_ETHREAD;
    state->Config.FakeStructureUpdateInterval = 60;
    state->Config.LogBufferSize = LOG_BUFFER_SIZE;
    state->Config.EncryptionEnabled = TRUE;
    state->Config.ExportIntervalSeconds = 300;
    state->Config.DisassemblerEnabled = TRUE;
    state->Config.ExploitFingerprintingEnabled = TRUE;
    state->Config.RemoteUpdateEnabled = FALSE;
    
    // Load configuration from file
    LoadConfiguration(&configPath);
    
    // Apply configuration
    ApplyConfiguration(&state->Config);
    
    state->Initialized = TRUE;
    DbgPrint("[ControlLayer] Initialized successfully\n");
    
    return STATUS_SUCCESS;
}

VOID CleanupControlLayer(VOID)
{
    PCONTROL_LAYER_STATE state = &g_HoneyPotState.ControlState;
    
    DbgPrint("[ControlLayer] Cleaning up...\n");
    
    if (state->Config.RemoteUpdateUrl.Buffer) {
        ExFreePoolWithTag(state->Config.RemoteUpdateUrl.Buffer, 'CTRL');
    }
    
    state->Initialized = FALSE;
    DbgPrint("[ControlLayer] Cleanup complete\n");
}

NTSTATUS LoadConfiguration(PUNICODE_STRING ConfigFilePath)
{
    PCONTROL_LAYER_STATE state = &g_HoneyPotState.ControlState;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttribs;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    PUCHAR fileBuffer = NULL;
    ULONG fileSize = 0;
    ULONG bytesRead = 0;
    PCHAR line = NULL;
    PCHAR nextLine = NULL;
    
    DbgPrint("[ControlLayer] Loading configuration from %wZ\n", ConfigFilePath);
    
    // Open config file
    InitializeObjectAttributes(&objAttribs, ConfigFilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
                               NULL, NULL);
    
    status = ZwOpenFile(&fileHandle, FILE_READ_DATA, &objAttribs, &ioStatus, 
                       FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ControlLayer] Failed to open config file: 0x%08X (using defaults)\n", status);
        return STATUS_SUCCESS; // Use defaults
    }
    
    // Get file size
    FILE_STANDARD_INFORMATION fileInfo;
    status = ZwQueryInformationFile(fileHandle, &ioStatus, &fileInfo, sizeof(fileInfo), 
                                    FileStandardInformation);
    
    if (NT_SUCCESS(status) && fileInfo.EndOfFile.QuadPart > 0) {
        fileSize = (ULONG)fileInfo.EndOfFile.QuadPart;
        fileBuffer = ExAllocatePoolWithTag(NonPagedPool, fileSize + 1, 'CTRL');
        
        if (fileBuffer) {
            // Read file
            status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatus, 
                               fileBuffer, fileSize, NULL, NULL);
            
            if (NT_SUCCESS(status)) {
                fileBuffer[fileSize] = '\0';
                
                // Parse lines
                line = (PCHAR)fileBuffer;
                while (line && *line) {
                    // Find next line
                    nextLine = NULL;
                    for (PCHAR p = line; *p; p++) {
                        if (*p == '\n' || *p == '\r') {
                            nextLine = p + 1;
                            *p = '\0';
                            break;
                        }
                    }
                    
                    // Skip whitespace
                    while (*line == ' ' || *line == '\t') line++;
                    
                    // Skip comments and empty lines
                    if (*line != '#' && *line != '\0') {
                        ParseConfigLine(line, &state->Config);
                    }
                    
                    line = nextLine;
                }
                
                state->ConfigLoaded = TRUE;
                DbgPrint("[ControlLayer] Configuration loaded successfully\n");
            }
            
            ExFreePoolWithTag(fileBuffer, 'CTRL');
        }
    }
    
    ZwClose(fileHandle);
    
    return STATUS_SUCCESS;
}

NTSTATUS ParseConfigLine(PCHAR Line, PHONEYPOT_CONFIG Config)
{
    PCHAR key, value;
    PCHAR equals;
    ULONG i;
    
    // Find '=' separator
    equals = NULL;
    for (i = 0; Line[i] != '\0'; i++) {
        if (Line[i] == '=') {
            equals = Line + i;
            break;
        }
    }
    
    if (!equals) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *equals = '\0';
    key = Line;
    value = equals + 1;
    
    // Trim whitespace
    while (*key == ' ' || *key == '\t') key++;
    while (*value == ' ' || *value == '\t') value++;
    
    // Parse key-value pairs (simplified case-insensitive comparison)
    ULONG keyLen = (ULONG)(equals - key);
    ULONG valueInt = 0;
    
    // Convert value to integer
    for (i = 0; value[i] >= '0' && value[i] <= '9'; i++) {
        valueInt = valueInt * 10 + (value[i] - '0');
    }
    
    // Compare keys (case-insensitive, simplified)
    if (keyLen == 19 && RtlCompareMemory(key, "TriggerLayerEnabled", 19) == 19) {
        Config->TriggerLayerEnabled = (valueInt != 0);
    } else if (keyLen == 21 && RtlCompareMemory(key, "DetectionLayerEnabled", 21) == 21) {
        Config->DetectionLayerEnabled = (valueInt != 0);
    } else if (keyLen == 21 && RtlCompareMemory(key, "DeceptionLayerEnabled", 21) == 21) {
        Config->DeceptionLayerEnabled = (valueInt != 0);
    } else if (keyLen == 20 && RtlCompareMemory(key, "LoggingLayerEnabled", 20) == 20) {
        Config->LoggingLayerEnabled = (valueInt != 0);
    } else if (keyLen == 22 && RtlCompareMemory(key, "ExtractionLayerEnabled", 22) == 22) {
        Config->ExtractionLayerEnabled = (valueInt != 0);
    } else if (keyLen == 25 && RtlCompareMemory(key, "StackFingerprintingEnabled", 25) == 25) {
        Config->StackFingerprintingEnabled = (valueInt != 0);
    } else if (keyLen == 21 && RtlCompareMemory(key, "MemoryTrackingEnabled", 21) == 21) {
        Config->MemoryTrackingEnabled = (valueInt != 0);
    } else if (keyLen == 18 && RtlCompareMemory(key, "EncryptionEnabled", 18) == 18) {
        Config->EncryptionEnabled = (valueInt != 0);
    } else if (keyLen == 19 && RtlCompareMemory(key, "DisassemblerEnabled", 19) == 19) {
        Config->DisassemblerEnabled = (valueInt != 0);
    } else if (keyLen == 21 && RtlCompareMemory(key, "ExportIntervalSeconds", 21) == 21) {
        Config->ExportIntervalSeconds = valueInt;
    } else if (keyLen == 28 && RtlCompareMemory(key, "FakeStructureUpdateInterval", 28) == 28) {
        Config->FakeStructureUpdateInterval = valueInt;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS ApplyConfiguration(PHONEYPOT_CONFIG Config)
{
    // Apply configuration to layers
    g_HoneyPotState.DetectionState.StackFingerprintingEnabled = Config->StackFingerprintingEnabled;
    g_HoneyPotState.DetectionState.MemoryTrackingEnabled = Config->MemoryTrackingEnabled;
    g_HoneyPotState.LoggingState.EncryptionEnabled = Config->EncryptionEnabled;
    g_HoneyPotState.ExtractionState.DisassemblerEnabled = Config->DisassemblerEnabled;
    
    DbgPrint("[ControlLayer] Configuration applied\n");
    
    return STATUS_SUCCESS;
}

NTSTATUS ReloadConfiguration(VOID)
{
    PCONTROL_LAYER_STATE state = &g_HoneyPotState.ControlState;
    UNICODE_STRING configPath = RTL_CONSTANT_STRING(CONFIG_FILE_PATH);
    NTSTATUS status;
    
    DbgPrint("[ControlLayer] Reloading configuration...\n");
    
    status = LoadConfiguration(&configPath);
    if (NT_SUCCESS(status)) {
        ApplyConfiguration(&state->Config);
        state->ConfigUpdateCount++;
        KeQuerySystemTime(&state->LastConfigUpdate);
    }
    
    return status;
}

NTSTATUS RemoteUpdateCheck(VOID)
{
    // Placeholder for remote update via covert channel
    // In real implementation, this would establish a covert communication channel
    // and check for updates

    DbgPrint("[ControlLayer] Remote update check (not implemented)\n");

    return STATUS_NOT_IMPLEMENTED;
}

// =================================================================
// Handshake — paired with UserModeApp/HoneyPotControl.c
// =================================================================

const UCHAR g_HoneyPotHandshakeSecret[HANDSHAKE_SECRET_SIZE] = {
    0x4B, 0x52, 0x4E, 0x4C, 0x48, 0x4F, 0x4E, 0x45,  // "KRNLHONE"
    0x59, 0x50, 0x4F, 0x54, 0x53, 0x45, 0x43, 0x52,  // "YPOTSECR"
    0x45, 0x54, 0x4B, 0x45, 0x59, 0x31, 0x32, 0x33,  // "ETKEY123"
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31   // "45678901"
};

NTSTATUS HandleHandshake(PHONEYPOT_HANDSHAKE_REQUEST Request,
                         PHONEYPOT_HANDSHAKE_RESPONSE Response)
{
    LARGE_INTEGER counter;
    ULONG seed;
    ULONG i;

    if (!Request || !Response) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Response, sizeof(*Response));
    Response->DriverVersion = KMOD_DRIVER_VERSION;

    // Constant-size secret check. RtlEqualMemory is not constant-time, but
    // the handshake is a defensive lab gate, not a cryptographic protocol.
    if (!RtlEqualMemory(Request->Secret,
                        g_HoneyPotHandshakeSecret,
                        HANDSHAKE_SECRET_SIZE)) {
        Response->Status = HONEYPOT_HANDSHAKE_BAD_SECRET;
        DbgPrint("[ControlLayer] Handshake rejected: bad secret\n");
        return STATUS_SUCCESS;
    }

    // Major version must match; minor differences are accepted.
    if ((Request->Version >> 16) != KMOD_DRIVER_VERSION_MAJOR) {
        Response->Status = HONEYPOT_HANDSHAKE_BAD_VERSION;
        DbgPrint("[ControlLayer] Handshake rejected: bad version 0x%08X\n",
                 Request->Version);
        return STATUS_SUCCESS;
    }

    // Session ID = sequence of RtlRandomEx outputs seeded by perfcounter.
    counter = KeQueryPerformanceCounter(NULL);
    seed = (ULONG)counter.QuadPart;
    for (i = 0; i < SESSION_ID_SIZE; i++) {
        Response->SessionId[i] = (UCHAR)(RtlRandomEx(&seed) & 0xFF);
    }

    Response->Status = HONEYPOT_HANDSHAKE_OK;
    DbgPrint("[ControlLayer] Handshake accepted; session opened\n");
    return STATUS_SUCCESS;
}

