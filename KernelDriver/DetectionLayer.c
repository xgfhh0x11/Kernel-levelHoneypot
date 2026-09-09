#include "FakeNetFilter.h"

// Process access-right masks live in winnt.h (user mode); provide the one the
// suspicious-access heuristic needs since the WDK headers do not declare it.
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif

extern HONEYPOT_GLOBAL_STATE g_HoneyPotState;

NTSTATUS InitializeDetectionLayer(VOID)
{
    PDETECTION_LAYER_STATE state = &g_HoneyPotState.DetectionState;
    
    DbgPrint("[DetectionLayer] Initializing...\n");
    
    RtlZeroMemory(state, sizeof(DETECTION_LAYER_STATE));
    
    // Allocate syscall log buffer
    state->SyscallLogBuffer = ExAllocatePoolWithTag(NonPagedPool, 
                                                     sizeof(SYSCALL_LOG_ENTRY) * MAX_SYSCALL_LOG_ENTRIES, 
                                                     'DETC');
    if (!state->SyscallLogBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(state->SyscallLogBuffer, sizeof(SYSCALL_LOG_ENTRY) * MAX_SYSCALL_LOG_ENTRIES);
    
    // Allocate memory pattern buffer
    state->MemoryPatterns = ExAllocatePoolWithTag(NonPagedPool, 
                                                   sizeof(MEMORY_ACCESS_PATTERN) * MAX_MEMORY_PATTERNS, 
                                                   'DETC');
    if (!state->MemoryPatterns) {
        ExFreePoolWithTag(state->SyscallLogBuffer, 'DETC');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(state->MemoryPatterns, sizeof(MEMORY_ACCESS_PATTERN) * MAX_MEMORY_PATTERNS);
    
    // Initialize spinlocks
    KeInitializeSpinLock(&state->SyscallLogLock);
    KeInitializeSpinLock(&state->MemoryPatternLock);
    
    // Enable stack fingerprinting
    state->StackFingerprintingEnabled = TRUE;
    
    state->Initialized = TRUE;
    DbgPrint("[DetectionLayer] Initialized successfully\n");
    
    return STATUS_SUCCESS;
}

VOID CleanupDetectionLayer(VOID)
{
    PDETECTION_LAYER_STATE state = &g_HoneyPotState.DetectionState;
    
    DbgPrint("[DetectionLayer] Cleaning up...\n");
    
    if (state->SyscallLogBuffer) {
        ExFreePoolWithTag(state->SyscallLogBuffer, 'DETC');
        state->SyscallLogBuffer = NULL;
    }
    
    if (state->MemoryPatterns) {
        ExFreePoolWithTag(state->MemoryPatterns, 'DETC');
        state->MemoryPatterns = NULL;
    }
    
    state->Initialized = FALSE;
    DbgPrint("[DetectionLayer] Cleanup complete\n");
}

NTSTATUS LogSyscall(SYSCALL_TYPE SyscallType, ULONG_PTR ProcessId, ULONG_PTR ThreadId, 
                   ULONG_PTR ReturnAddress, PULONG_PTR Parameters)
{
    PDETECTION_LAYER_STATE state = &g_HoneyPotState.DetectionState;
    PSYSCALL_LOG_ENTRY entry;
    KIRQL oldIrql;
    
    if (!state->Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeAcquireSpinLock(&state->SyscallLogLock, &oldIrql);
    
    entry = &state->SyscallLogBuffer[state->SyscallLogIndex];
    
    // Fill entry
    KeQuerySystemTime(&entry->Timestamp);
    entry->SyscallType = SyscallType;
    entry->ProcessId = ProcessId;
    entry->ThreadId = ThreadId;
    entry->ReturnAddress = ReturnAddress;
    
    // Capture stack fingerprint
    if (state->StackFingerprintingEnabled) {
        CaptureStackFingerprint(entry->StackFingerprint, STACK_FINGERPRINT_SIZE, 
                               &entry->StackFingerprintSize);
    }
    
    // Copy parameters
    if (Parameters) {
        RtlCopyMemory(entry->Parameters, Parameters, sizeof(ULONG_PTR) * 8);
    }
    
    // Analyze for suspicious behavior
    entry->IsSuspicious = AnalyzeSuspiciousBehavior(entry);
    
    // Update indices
    state->SyscallLogIndex = (state->SyscallLogIndex + 1) % MAX_SYSCALL_LOG_ENTRIES;
    if (state->SyscallLogCount < MAX_SYSCALL_LOG_ENTRIES) {
        state->SyscallLogCount++;
    }
    
    state->TotalSyscallsLogged++;
    if (entry->IsSuspicious) {
        state->SuspiciousSyscallsDetected++;
    }
    
    KeReleaseSpinLock(&state->SyscallLogLock, oldIrql);
    
    // Log to logging layer
    if (g_HoneyPotState.LoggingState.Initialized) {
        LogEntry(LogEntrySyscall, ProcessId, ThreadId, entry, sizeof(SYSCALL_LOG_ENTRY));
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS CaptureStackFingerprint(PUCHAR Buffer, ULONG BufferSize, PULONG CapturedSize)
{
    ULONG_PTR stackBase;
    ULONG_PTR stackLimit;
    ULONG bytesToCapture;
    ULONG i;
    
    // Get current stack limits. _KTHREAD is opaque, so its StackBase/StackLimit
    // members cannot be read directly; IoGetStackLimits() is the documented way
    // to obtain the kernel stack bounds (high limit = base, low limit = limit).
    IoGetStackLimits(&stackLimit, &stackBase);

    // Capture a portion of the stack
    bytesToCapture = min(BufferSize, (ULONG)(stackBase - stackLimit));
    bytesToCapture = min(bytesToCapture, STACK_FINGERPRINT_SIZE);
    
    // Read stack memory (in real implementation, we'd use proper memory access)
    // For now, we'll create a hash of return addresses
    RtlZeroMemory(Buffer, BufferSize);
    
    // Simple fingerprint: hash of return addresses on stack
    for (i = 0; i < bytesToCapture && i < BufferSize; i += sizeof(ULONG_PTR)) {
        ULONG_PTR stackValue = *(PULONG_PTR)(stackBase - i);
        Buffer[i % BufferSize] ^= (UCHAR)(stackValue & 0xFF);
        Buffer[(i + 1) % BufferSize] ^= (UCHAR)((stackValue >> 8) & 0xFF);
    }
    
    *CapturedSize = bytesToCapture;
    
    return STATUS_SUCCESS;
}

// NOT CURRENTLY INVOKED: no call sites anywhere in this driver -- memory
// access is not tracked by any hook (the syscall hooks that would feed this
// are themselves never installed; see TriggerLayer.c).
NTSTATUS TrackMemoryAccess(ULONG_PTR BaseAddress, SIZE_T RegionSize, ULONG Protection,
                          ULONG_PTR ProcessId)
{
    PDETECTION_LAYER_STATE state = &g_HoneyPotState.DetectionState;
    PMEMORY_ACCESS_PATTERN pattern;
    KIRQL oldIrql;
    
    if (!state->Initialized || !state->MemoryTrackingEnabled) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (state->MemoryPatternCount >= MAX_MEMORY_PATTERNS) {
        // Overwrite oldest entry
        state->MemoryPatternCount = 0;
    }
    
    KeAcquireSpinLock(&state->MemoryPatternLock, &oldIrql);
    
    pattern = &state->MemoryPatterns[state->MemoryPatternCount];
    pattern->BaseAddress = BaseAddress;
    pattern->RegionSize = RegionSize;
    pattern->Protection = Protection;
    pattern->ProcessId = ProcessId;
    KeQuerySystemTime(&pattern->AccessTime);
    
    // Analyze for suspicious patterns (e.g., RWX memory)
    pattern->IsSuspicious = (Protection == PAGE_EXECUTE_READWRITE);
    
    state->MemoryPatternCount++;
    
    KeReleaseSpinLock(&state->MemoryPatternLock, oldIrql);
    
    // Log to logging layer
    if (g_HoneyPotState.LoggingState.Initialized) {
        LogEntry(LogEntryMemoryAccess, ProcessId, 0, pattern, sizeof(MEMORY_ACCESS_PATTERN));
    }
    
    return STATUS_SUCCESS;
}

BOOLEAN AnalyzeSuspiciousBehavior(PSYSCALL_LOG_ENTRY Entry)
{
    BOOLEAN isSuspicious = FALSE;
    
    // Heuristic: suspicious patterns
    switch (Entry->SyscallType) {
        case SyscallNtAllocateVirtualMemory:
            // Check for RWX allocation
            if (Entry->Parameters[2] == PAGE_EXECUTE_READWRITE) {
                isSuspicious = TRUE;
            }
            break;
            
        case SyscallNtProtectVirtualMemory:
            // Check for making memory executable
            if (Entry->Parameters[2] == PAGE_EXECUTE_READWRITE || 
                Entry->Parameters[2] == PAGE_EXECUTE_READ) {
                isSuspicious = TRUE;
            }
            break;
            
        case SyscallNtCreateThreadEx:
            // Creating threads is often part of exploits
            isSuspicious = TRUE;
            break;
            
        case SyscallNtOpenProcess:
            // Opening processes with high privileges
            if (Entry->Parameters[1] & (PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION)) {
                isSuspicious = TRUE;
            }
            break;
            
        default:
            break;
    }
    
    // Check stack fingerprint for ROP patterns
    // In real implementation, we'd analyze the stack fingerprint more thoroughly
    
    return isSuspicious;
}

