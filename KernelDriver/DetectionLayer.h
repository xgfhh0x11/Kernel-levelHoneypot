#pragma once

#include <ntddk.h>

// Detection Layer: Stealth sensor for observing attacker behavior

#define MAX_SYSCALL_LOG_ENTRIES 10000
#define STACK_FINGERPRINT_SIZE 64
#define MAX_MEMORY_PATTERNS 1000

typedef enum _SYSCALL_TYPE {
    SyscallNtOpenProcess,
    SyscallZwQuerySystemInformation,
    SyscallNtReadVirtualMemory,
    SyscallNtWriteVirtualMemory,
    SyscallNtAllocateVirtualMemory,
    SyscallNtProtectVirtualMemory,
    SyscallNtCreateThreadEx,
    SyscallNtResumeThread,
    SyscallUnknown
} SYSCALL_TYPE;

typedef struct _SYSCALL_LOG_ENTRY {
    LARGE_INTEGER Timestamp;
    SYSCALL_TYPE SyscallType;
    ULONG_PTR ProcessId;
    ULONG_PTR ThreadId;
    ULONG_PTR ReturnAddress;
    UCHAR StackFingerprint[STACK_FINGERPRINT_SIZE];
    ULONG StackFingerprintSize;
    ULONG_PTR Parameters[8];
    BOOLEAN IsSuspicious;
} SYSCALL_LOG_ENTRY, *PSYSCALL_LOG_ENTRY;

typedef struct _MEMORY_ACCESS_PATTERN {
    ULONG_PTR BaseAddress;
    SIZE_T RegionSize;
    ULONG Protection;
    ULONG_PTR ProcessId;
    LARGE_INTEGER AccessTime;
    BOOLEAN IsSuspicious;
} MEMORY_ACCESS_PATTERN, *PMEMORY_ACCESS_PATTERN;

typedef struct _DETECTION_LAYER_STATE {
    BOOLEAN Initialized;
    
    // Syscall logging
    PSYSCALL_LOG_ENTRY SyscallLogBuffer;
    ULONG SyscallLogIndex;
    ULONG SyscallLogCount;
    KSPIN_LOCK SyscallLogLock;
    
    // Stack fingerprinting
    BOOLEAN StackFingerprintingEnabled;
    
    // Memory access tracking
    BOOLEAN MemoryTrackingEnabled;
    PMEMORY_ACCESS_PATTERN MemoryPatterns;
    ULONG MemoryPatternCount;
    KSPIN_LOCK MemoryPatternLock;
    
    // Statistics
    ULONG64 TotalSyscallsLogged;
    ULONG64 SuspiciousSyscallsDetected;
} DETECTION_LAYER_STATE, *PDETECTION_LAYER_STATE;

// Function declarations
NTSTATUS InitializeDetectionLayer(VOID);
VOID CleanupDetectionLayer(VOID);
NTSTATUS LogSyscall(SYSCALL_TYPE SyscallType, ULONG_PTR ProcessId, ULONG_PTR ThreadId, ULONG_PTR ReturnAddress, PULONG_PTR Parameters);
NTSTATUS CaptureStackFingerprint(PUCHAR Buffer, ULONG BufferSize, PULONG CapturedSize);
NTSTATUS TrackMemoryAccess(ULONG_PTR BaseAddress, SIZE_T RegionSize, ULONG Protection, ULONG_PTR ProcessId); // NOT CURRENTLY INVOKED, see DetectionLayer.c
BOOLEAN AnalyzeSuspiciousBehavior(PSYSCALL_LOG_ENTRY Entry);

