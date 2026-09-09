#pragma once

#include <ntddk.h>

// Deception Layer: Manipulation module to redirect attacker to fake universe

#define MAX_FAKE_EPROCESS 128
#define MAX_FAKE_ETHREAD 256
#define MAX_FAKE_MEMORY_REGIONS 512

typedef struct _FAKE_EPROCESS {
    ULONG_PTR FakeProcessId;
    ULONG_PTR FakeParentProcessId;
    UNICODE_STRING FakeImageName;
    LARGE_INTEGER CreationTime;
    BOOLEAN IsActive;
    PVOID FakePebAddress;
} FAKE_EPROCESS, *PFAKE_EPROCESS;

typedef struct _FAKE_ETHREAD {
    ULONG_PTR FakeThreadId;
    ULONG_PTR FakeProcessId;
    ULONG_PTR FakeStartAddress;
    ULONG FakeThreadState;
    BOOLEAN IsActive;
} FAKE_ETHREAD, *PFAKE_ETHREAD;

typedef struct _FAKE_MEMORY_REGION {
    ULONG_PTR FakeBaseAddress;
    SIZE_T FakeRegionSize;
    ULONG FakeProtection;
    ULONG_PTR FakeProcessId;
    BOOLEAN IsNonCanonical;
    BOOLEAN IsActive;
} FAKE_MEMORY_REGION, *PFAKE_MEMORY_REGION;

typedef struct _DECEPTION_LAYER_STATE {
    BOOLEAN Initialized;
    
    // Fake kernel objects
    FAKE_EPROCESS FakeProcesses[MAX_FAKE_EPROCESS];
    ULONG FakeProcessCount;
    KSPIN_LOCK FakeProcessLock;
    
    FAKE_ETHREAD FakeThreads[MAX_FAKE_ETHREAD];
    ULONG FakeThreadCount;
    KSPIN_LOCK FakeThreadLock;
    
    // Fake memory layout
    FAKE_MEMORY_REGION FakeMemoryRegions[MAX_FAKE_MEMORY_REGIONS];
    ULONG FakeMemoryRegionCount;
    KSPIN_LOCK FakeMemoryLock;
    
    // Anti-fingerprint: time-varying fake structures
    LARGE_INTEGER LastStructureUpdate;
    ULONG UpdateIntervalSeconds;
    
    // Statistics
    ULONG64 DeceptionCount;
    ULONG64 FakeObjectAccessCount;
} DECEPTION_LAYER_STATE, *PDECEPTION_LAYER_STATE;

// Function declarations
NTSTATUS InitializeDeceptionLayer(VOID);
VOID CleanupDeceptionLayer(VOID);
NTSTATUS CreateFakeProcess(PUNICODE_STRING ImageName, ULONG_PTR ProcessId, ULONG_PTR ParentProcessId, PFAKE_EPROCESS* FakeProcess);
NTSTATUS CreateFakeThread(ULONG_PTR ThreadId, ULONG_PTR ProcessId, ULONG_PTR StartAddress, PFAKE_ETHREAD* FakeThread);
NTSTATUS CreateFakeMemoryRegion(ULONG_PTR BaseAddress, SIZE_T RegionSize, ULONG Protection, ULONG_PTR ProcessId, BOOLEAN NonCanonical);
PFAKE_EPROCESS FindFakeProcess(ULONG_PTR ProcessId);
PFAKE_ETHREAD FindFakeThread(ULONG_PTR ThreadId);
PFAKE_MEMORY_REGION FindFakeMemoryRegion(ULONG_PTR BaseAddress, ULONG_PTR ProcessId);
VOID UpdateFakeStructures(VOID); // Anti-fingerprint mechanism

