#include "FakeNetFilter.h"

extern HONEYPOT_GLOBAL_STATE g_HoneyPotState;

NTSTATUS InitializeDeceptionLayer(VOID)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    
    DbgPrint("[DeceptionLayer] Initializing...\n");
    
    RtlZeroMemory(state, sizeof(DECEPTION_LAYER_STATE));
    
    // Initialize spinlocks
    KeInitializeSpinLock(&state->FakeProcessLock);
    KeInitializeSpinLock(&state->FakeThreadLock);
    KeInitializeSpinLock(&state->FakeMemoryLock);
    
    // Set update interval (anti-fingerprint)
    state->UpdateIntervalSeconds = 60; // Update every 60 seconds
    KeQuerySystemTime(&state->LastStructureUpdate);
    
    // Create some initial fake processes
    UNICODE_STRING fakeImage1 = RTL_CONSTANT_STRING(L"svchost.exe");
    UNICODE_STRING fakeImage2 = RTL_CONSTANT_STRING(L"explorer.exe");
    
    CreateFakeProcess(&fakeImage1, 1000, 4, NULL);
    CreateFakeProcess(&fakeImage2, 2000, 4, NULL);
    
    state->Initialized = TRUE;
    DbgPrint("[DeceptionLayer] Initialized successfully\n");
    
    return STATUS_SUCCESS;
}

VOID CleanupDeceptionLayer(VOID)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    ULONG i;
    KIRQL oldIrql;

    DbgPrint("[DeceptionLayer] Cleaning up...\n");

    // Free fake process resources
    KeAcquireSpinLock(&state->FakeProcessLock, &oldIrql);
    for (i = 0; i < state->FakeProcessCount; i++) {
        if (state->FakeProcesses[i].FakeImageName.Buffer) {
            ExFreePoolWithTag(state->FakeProcesses[i].FakeImageName.Buffer, 'DECP');
        }
    }
    KeReleaseSpinLock(&state->FakeProcessLock, oldIrql);
    
    state->Initialized = FALSE;
    DbgPrint("[DeceptionLayer] Cleanup complete\n");
}

NTSTATUS CreateFakeProcess(PUNICODE_STRING ImageName, ULONG_PTR ProcessId, 
                          ULONG_PTR ParentProcessId, PFAKE_EPROCESS* FakeProcess)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    PFAKE_EPROCESS fakeProcess;
    KIRQL oldIrql;
    
    if (state->FakeProcessCount >= MAX_FAKE_EPROCESS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    KeAcquireSpinLock(&state->FakeProcessLock, &oldIrql);
    
    fakeProcess = &state->FakeProcesses[state->FakeProcessCount];
    
    fakeProcess->FakeProcessId = ProcessId;
    fakeProcess->FakeParentProcessId = ParentProcessId;
    KeQuerySystemTime(&fakeProcess->CreationTime);
    
    // Allocate and copy image name
    fakeProcess->FakeImageName.Buffer = ExAllocatePoolWithTag(NonPagedPool, ImageName->Length, 'DECP');
    if (!fakeProcess->FakeImageName.Buffer) {
        KeReleaseSpinLock(&state->FakeProcessLock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyUnicodeString(&fakeProcess->FakeImageName, ImageName);
    
    // Generate fake PEB address (non-canonical to make it more interesting)
    fakeProcess->FakePebAddress = (PVOID)(0xFFFF800000000000ULL + (ProcessId * 0x1000));
    
    fakeProcess->IsActive = TRUE;
    state->FakeProcessCount++;
    state->DeceptionCount++;
    
    KeReleaseSpinLock(&state->FakeProcessLock, oldIrql);
    
    if (FakeProcess) {
        *FakeProcess = fakeProcess;
    }
    
    DbgPrint("[DeceptionLayer] Created fake process: %wZ (PID: %lu)\n", ImageName, ProcessId);
    
    return STATUS_SUCCESS;
}

NTSTATUS CreateFakeThread(ULONG_PTR ThreadId, ULONG_PTR ProcessId, ULONG_PTR StartAddress, 
                         PFAKE_ETHREAD* FakeThread)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    PFAKE_ETHREAD fakeThread;
    KIRQL oldIrql;
    
    if (state->FakeThreadCount >= MAX_FAKE_ETHREAD) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    KeAcquireSpinLock(&state->FakeThreadLock, &oldIrql);
    
    fakeThread = &state->FakeThreads[state->FakeThreadCount];
    fakeThread->FakeThreadId = ThreadId;
    fakeThread->FakeProcessId = ProcessId;
    fakeThread->FakeStartAddress = StartAddress;
    fakeThread->FakeThreadState = 2; // Running
    fakeThread->IsActive = TRUE;
    
    state->FakeThreadCount++;
    state->DeceptionCount++;
    
    KeReleaseSpinLock(&state->FakeThreadLock, oldIrql);
    
    if (FakeThread) {
        *FakeThread = fakeThread;
    }
    
    DbgPrint("[DeceptionLayer] Created fake thread: TID %lu in PID %lu\n", ThreadId, ProcessId);
    
    return STATUS_SUCCESS;
}

NTSTATUS CreateFakeMemoryRegion(ULONG_PTR BaseAddress, SIZE_T RegionSize, ULONG Protection, 
                                ULONG_PTR ProcessId, BOOLEAN NonCanonical)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    PFAKE_MEMORY_REGION region;
    KIRQL oldIrql;
    
    if (state->FakeMemoryRegionCount >= MAX_FAKE_MEMORY_REGIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    KeAcquireSpinLock(&state->FakeMemoryLock, &oldIrql);
    
    region = &state->FakeMemoryRegions[state->FakeMemoryRegionCount];
    region->FakeBaseAddress = BaseAddress;
    region->FakeRegionSize = RegionSize;
    region->FakeProtection = Protection;
    region->FakeProcessId = ProcessId;
    region->IsNonCanonical = NonCanonical;
    region->IsActive = TRUE;
    
    state->FakeMemoryRegionCount++;
    state->DeceptionCount++;
    
    KeReleaseSpinLock(&state->FakeMemoryLock, oldIrql);
    
    DbgPrint("[DeceptionLayer] Created fake memory region: 0x%p (Size: %Iu)\n", 
             (PVOID)BaseAddress, RegionSize);
    
    return STATUS_SUCCESS;
}

PFAKE_EPROCESS FindFakeProcess(ULONG_PTR ProcessId)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    PFAKE_EPROCESS fakeProcess = NULL;
    ULONG i;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&state->FakeProcessLock, &oldIrql);
    
    for (i = 0; i < state->FakeProcessCount; i++) {
        if (state->FakeProcesses[i].FakeProcessId == ProcessId && 
            state->FakeProcesses[i].IsActive) {
            fakeProcess = &state->FakeProcesses[i];
            state->FakeObjectAccessCount++;
            break;
        }
    }
    
    KeReleaseSpinLock(&state->FakeProcessLock, oldIrql);
    
    return fakeProcess;
}

PFAKE_ETHREAD FindFakeThread(ULONG_PTR ThreadId)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    PFAKE_ETHREAD fakeThread = NULL;
    ULONG i;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&state->FakeThreadLock, &oldIrql);
    
    for (i = 0; i < state->FakeThreadCount; i++) {
        if (state->FakeThreads[i].FakeThreadId == ThreadId && 
            state->FakeThreads[i].IsActive) {
            fakeThread = &state->FakeThreads[i];
            state->FakeObjectAccessCount++;
            break;
        }
    }
    
    KeReleaseSpinLock(&state->FakeThreadLock, oldIrql);
    
    return fakeThread;
}

PFAKE_MEMORY_REGION FindFakeMemoryRegion(ULONG_PTR BaseAddress, ULONG_PTR ProcessId)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    PFAKE_MEMORY_REGION region = NULL;
    ULONG i;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&state->FakeMemoryLock, &oldIrql);
    
    for (i = 0; i < state->FakeMemoryRegionCount; i++) {
        if (state->FakeMemoryRegions[i].FakeBaseAddress == BaseAddress &&
            state->FakeMemoryRegions[i].FakeProcessId == ProcessId &&
            state->FakeMemoryRegions[i].IsActive) {
            region = &state->FakeMemoryRegions[i];
            state->FakeObjectAccessCount++;
            break;
        }
    }
    
    KeReleaseSpinLock(&state->FakeMemoryLock, oldIrql);
    
    return region;
}

VOID UpdateFakeStructures(VOID)
{
    PDECEPTION_LAYER_STATE state = &g_HoneyPotState.DeceptionState;
    LARGE_INTEGER currentTime;
    LARGE_INTEGER interval;
    ULONG i;
    KIRQL oldIrql;

    KeQuerySystemTime(&currentTime);
    interval.QuadPart = state->UpdateIntervalSeconds * -10000000LL; // Convert to 100-ns intervals
    
    // Check if update interval has passed
    if (currentTime.QuadPart - state->LastStructureUpdate.QuadPart < interval.QuadPart) {
        return;
    }
    
    DbgPrint("[DeceptionLayer] Updating fake structures (anti-fingerprint)\n");
    
    // Modify fake process attributes slightly (anti-fingerprint)
    KeAcquireSpinLock(&state->FakeProcessLock, &oldIrql);
    for (i = 0; i < state->FakeProcessCount; i++) {
        if (state->FakeProcesses[i].IsActive) {
            // Slightly modify PEB address
            state->FakeProcesses[i].FakePebAddress = (PVOID)((ULONG_PTR)state->FakeProcesses[i].FakePebAddress + 0x100);
        }
    }
    KeReleaseSpinLock(&state->FakeProcessLock, oldIrql);
    
    state->LastStructureUpdate = currentTime;
}

