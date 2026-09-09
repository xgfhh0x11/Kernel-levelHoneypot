#include "FakeNetFilter.h"

extern HONEYPOT_GLOBAL_STATE g_HoneyPotState;

// Simple SHA-256 implementation (simplified for kernel mode)
// NOTE: This is a placeholder - NOT cryptographically secure!
VOID SimpleSHA256(PUCHAR Data, ULONG DataSize, PUCHAR Hash)
{
    // In real implementation, use proper crypto library
    // For now, create a simple hash
    ULONG i, j;
    RtlZeroMemory(Hash, 32);
    
    for (i = 0; i < DataSize; i++) {
        Hash[i % 32] ^= Data[i];
        Hash[(i + 1) % 32] ^= (Data[i] << 1) | (Data[i] >> 7);
    }
}

NTSTATUS InitializeLoggingLayer(VOID)
{
    PLOGGING_LAYER_STATE state = &g_HoneyPotState.LoggingState;
    
    DbgPrint("[LoggingLayer] Initializing...\n");
    
    RtlZeroMemory(state, sizeof(LOGGING_LAYER_STATE));
    
    // Allocate log buffer (non-paged pool)
    state->LogBufferSize = LOG_BUFFER_SIZE;
    state->LogBuffer = ExAllocatePoolWithTag(NonPagedPool, 
                                             sizeof(LOG_ENTRY) * MAX_LOG_ENTRIES, 
                                             'LOGG');
    if (!state->LogBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(state->LogBuffer, sizeof(LOG_ENTRY) * MAX_LOG_ENTRIES);
    
    // Initialize spinlock
    KeInitializeSpinLock(&state->LogLock);
    
    // Initialize AES encryption
    NTSTATUS status = InitializeAESEncryption();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[LoggingLayer] Warning: Failed to initialize encryption: 0x%08X\n", status);
        state->EncryptionEnabled = FALSE;
    } else {
        state->EncryptionEnabled = TRUE;
    }
    
    // Set export interval
    state->ExportIntervalSeconds = 300; // 5 minutes
    KeQuerySystemTime(&state->LastExportTime);
    
    state->Initialized = TRUE;
    DbgPrint("[LoggingLayer] Initialized successfully\n");
    
    return STATUS_SUCCESS;
}

VOID CleanupLoggingLayer(VOID)
{
    PLOGGING_LAYER_STATE state = &g_HoneyPotState.LoggingState;
    
    DbgPrint("[LoggingLayer] Cleaning up...\n");
    
    // Export logs before cleanup
    if (state->LogCount > 0) {
        UNICODE_STRING exportPath = RTL_CONSTANT_STRING(L"\\SystemRoot\\Release\\honeypot_logs.enc");
        ExportLogsToFile(&exportPath);
    }
    
    if (state->LogBuffer) {
        ExFreePoolWithTag(state->LogBuffer, 'LOGG');
        state->LogBuffer = NULL;
    }
    
    // Clear encryption keys
    RtlZeroMemory(state->EncryptionKey, AES_KEY_SIZE);
    RtlZeroMemory(state->EncryptionTweak, AES_BLOCK_SIZE);
    
    state->Initialized = FALSE;
    DbgPrint("[LoggingLayer] Cleanup complete\n");
}

NTSTATUS LogEntry(LOG_ENTRY_TYPE EntryType, ULONG_PTR ProcessId, ULONG_PTR ThreadId, 
                 PVOID Data, ULONG DataSize)
{
    PLOGGING_LAYER_STATE state = &g_HoneyPotState.LoggingState;
    PLOG_ENTRY entry;
    KIRQL oldIrql;
    
    if (!state->Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeAcquireSpinLock(&state->LogLock, &oldIrql);
    
    if (state->LogCount >= MAX_LOG_ENTRIES) {
        // Overwrite oldest entry (circular buffer)
        state->LogIndex = (state->LogIndex + 1) % MAX_LOG_ENTRIES;
        state->LogCount = MAX_LOG_ENTRIES;
    }
    
    entry = &state->LogBuffer[(state->LogIndex + state->LogCount) % MAX_LOG_ENTRIES];
    
    // Fill entry
    KeQuerySystemTime(&entry->Timestamp);
    entry->EntryType = EntryType;
    entry->ProcessId = ProcessId;
    entry->ThreadId = ThreadId;
    
    // Copy data (truncate if necessary)
    entry->DataSize = min(DataSize, sizeof(entry->Data));
    if (Data && DataSize > 0) {
        RtlCopyMemory(entry->Data, Data, entry->DataSize);
    }
    
    // Calculate stack hash
    CalculateStackHash(entry->StackHash);
    
    state->LogCount++;
    state->TotalLogEntries++;
    
    KeReleaseSpinLock(&state->LogLock, oldIrql);
    
    // Check if export is needed
    LARGE_INTEGER currentTime;
    LARGE_INTEGER interval;
    KeQuerySystemTime(&currentTime);
    interval.QuadPart = state->ExportIntervalSeconds * -10000000LL;
    
    if (currentTime.QuadPart - state->LastExportTime.QuadPart >= interval.QuadPart) {
        state->ExportPending = TRUE;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS CalculateStackHash(PUCHAR HashBuffer)
{
    ULONG_PTR stackBase;
    ULONG_PTR stackLimit;
    UCHAR stackData[256];
    ULONG stackDataSize;
    
    // Get current stack limits. _KTHREAD is opaque, so its StackBase/StackLimit
    // members cannot be read directly; IoGetStackLimits() is the documented way
    // to obtain the kernel stack bounds (high limit = base, low limit = limit).
    IoGetStackLimits(&stackLimit, &stackBase);
    
    stackDataSize = min(sizeof(stackData), (ULONG)(stackBase - stackLimit));
    stackDataSize = min(stackDataSize, 256);
    
    // Read stack (simplified - in real implementation use proper memory access)
    RtlZeroMemory(stackData, sizeof(stackData));
    
    // Create hash of stack
    SimpleSHA256(stackData, stackDataSize, HashBuffer);
    
    return STATUS_SUCCESS;
}

NTSTATUS InitializeAESEncryption(VOID)
{
    PLOGGING_LAYER_STATE state = &g_HoneyPotState.LoggingState;
    
    // Generate encryption key (in real implementation, use proper key derivation)
    // For demonstration, use a fixed key (NOT SECURE - replace in production)
    RtlZeroMemory(state->EncryptionKey, AES_KEY_SIZE);
    RtlFillMemory(state->EncryptionKey, AES_KEY_SIZE, 0x42); // Placeholder
    
    // Generate tweak (for XTS mode)
    RtlZeroMemory(state->EncryptionTweak, AES_BLOCK_SIZE);
    RtlFillMemory(state->EncryptionTweak, AES_BLOCK_SIZE, 0x24); // Placeholder
    
    DbgPrint("[LoggingLayer] AES encryption initialized\n");
    
    return STATUS_SUCCESS;
}

NTSTATUS EncryptLogBuffer(PUCHAR Buffer, ULONG BufferSize, PUCHAR EncryptedBuffer, PULONG EncryptedSize)
{
    PLOGGING_LAYER_STATE state = &g_HoneyPotState.LoggingState;
    ULONG i;
    
    if (!state->EncryptionEnabled) {
        RtlCopyMemory(EncryptedBuffer, Buffer, BufferSize);
        *EncryptedSize = BufferSize;
        return STATUS_SUCCESS;
    }
    
    // Simplified AES-XTS encryption (in real implementation, use proper crypto library)
    // For demonstration, use XOR with key (NOT SECURE - replace in production)
    for (i = 0; i < BufferSize && i < (MAX_LOG_ENTRIES * sizeof(LOG_ENTRY)); i++) {
        EncryptedBuffer[i] = Buffer[i] ^ state->EncryptionKey[i % AES_KEY_SIZE];
    }
    
    *EncryptedSize = BufferSize;
    
    DbgPrint("[LoggingLayer] Encrypted %lu bytes\n", BufferSize);
    
    return STATUS_SUCCESS;
}

NTSTATUS ExportLogsToFile(PUNICODE_STRING FilePath)
{
    PLOGGING_LAYER_STATE state = &g_HoneyPotState.LoggingState;
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttribs;
    IO_STATUS_BLOCK ioStatus;
    HANDLE fileHandle = NULL;
    PUCHAR encryptedBuffer = NULL;
    ULONG encryptedSize = 0;
    KIRQL oldIrql;
    
    DbgPrint("[LoggingLayer] Exporting logs to file...\n");
    
    if (!state->Initialized || state->LogCount == 0) {
        return STATUS_SUCCESS;
    }
    
    // Allocate buffer for encrypted logs
    encryptedBuffer = ExAllocatePoolWithTag(NonPagedPool, 
                                            state->LogCount * sizeof(LOG_ENTRY) + 1024, 
                                            'LOGG');
    if (!encryptedBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Copy logs to buffer
    KeAcquireSpinLock(&state->LogLock, &oldIrql);
    RtlCopyMemory(encryptedBuffer, state->LogBuffer, state->LogCount * sizeof(LOG_ENTRY));
    KeReleaseSpinLock(&state->LogLock, oldIrql);
    
    // Encrypt buffer
    status = EncryptLogBuffer(encryptedBuffer, state->LogCount * sizeof(LOG_ENTRY), 
                             encryptedBuffer, &encryptedSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(encryptedBuffer, 'LOGG');
        return status;
    }
    
    // Open file for writing
    InitializeObjectAttributes(&objAttribs, FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
                               NULL, NULL);
    
    status = ZwCreateFile(&fileHandle, FILE_WRITE_DATA, &objAttribs, &ioStatus, NULL,
                         FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, 
                         FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    
    if (NT_SUCCESS(status)) {
        // Write encrypted logs
        status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, 
                            encryptedBuffer, encryptedSize, NULL, NULL);
        
        ZwClose(fileHandle);
    }
    
    if (NT_SUCCESS(status)) {
        state->EncryptedExports++;
        state->ExportPending = FALSE;
        KeQuerySystemTime(&state->LastExportTime);
        DbgPrint("[LoggingLayer] Exported %lu log entries\n", state->LogCount);
    }
    
    if (encryptedBuffer) {
        ExFreePoolWithTag(encryptedBuffer, 'LOGG');
    }
    
    return status;
}

