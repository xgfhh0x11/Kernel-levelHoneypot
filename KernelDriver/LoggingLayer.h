#pragma once

#include <ntddk.h>

// Logging Layer: Hidden recording module with encrypted export

#define LOG_BUFFER_SIZE (1024 * 1024) // 1MB
#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define MAX_LOG_ENTRIES 100000

typedef struct _LOG_ENTRY {
    LARGE_INTEGER Timestamp;
    ULONG EntryType;
    ULONG_PTR ProcessId;
    ULONG_PTR ThreadId;
    UCHAR Data[256];
    ULONG DataSize;
    UCHAR StackHash[32]; // SHA-256 hash of stack
} LOG_ENTRY, *PLOG_ENTRY;

typedef enum _LOG_ENTRY_TYPE {
    LogEntrySyscall,
    LogEntryMemoryAccess,
    LogEntryRegistryAccess,
    LogEntryFileAccess,
    LogEntryDeception,
    LogEntryExtraction
} LOG_ENTRY_TYPE;

typedef struct _LOGGING_LAYER_STATE {
    BOOLEAN Initialized;
    
    // Ring0 log buffer (non-paged pool)
    PLOG_ENTRY LogBuffer;
    ULONG LogBufferSize;
    ULONG LogIndex;
    ULONG LogCount;
    KSPIN_LOCK LogLock;
    
    // AES-XTS encryption
    UCHAR EncryptionKey[AES_KEY_SIZE];
    UCHAR EncryptionTweak[AES_BLOCK_SIZE];
    BOOLEAN EncryptionEnabled;
    
    // Export mechanism
    BOOLEAN ExportPending;
    LARGE_INTEGER LastExportTime;
    ULONG ExportIntervalSeconds;
    
    // Statistics
    ULONG64 TotalLogEntries;
    ULONG64 EncryptedExports;
} LOGGING_LAYER_STATE, *PLOGGING_LAYER_STATE;

// Function declarations
NTSTATUS InitializeLoggingLayer(VOID);
VOID CleanupLoggingLayer(VOID);
NTSTATUS LogEntry(LOG_ENTRY_TYPE EntryType, ULONG_PTR ProcessId, ULONG_PTR ThreadId, PVOID Data, ULONG DataSize);
NTSTATUS CalculateStackHash(PUCHAR HashBuffer);
NTSTATUS EncryptLogBuffer(PUCHAR Buffer, ULONG BufferSize, PUCHAR EncryptedBuffer, PULONG EncryptedSize);
NTSTATUS ExportLogsToFile(PUNICODE_STRING FilePath);
NTSTATUS InitializeAESEncryption(VOID);

