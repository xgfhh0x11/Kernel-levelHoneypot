#include "FakeNetFilter.h"

extern HONEYPOT_GLOBAL_STATE g_HoneyPotState;

NTSTATUS InitializeTriggerLayer(VOID)
{
    NTSTATUS status;
    PTRIGGER_LAYER_STATE state = &g_HoneyPotState.TriggerState;
    
    DbgPrint("[TriggerLayer] Initializing...\n");
    
    RtlZeroMemory(state, sizeof(TRIGGER_LAYER_STATE));
    
    // Create fake registry keys
    UNICODE_STRING fakeKeyPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\FakeService");
    UNICODE_STRING fakeValueName = RTL_CONSTANT_STRING(L"ServicePath");
    CHAR fakeValueData[] = "C:\\Windows\\System32\\FakeService.exe";
    
    status = CreateFakeRegistryKey(&fakeKeyPath, &fakeValueName, REG_SZ, 
                                   fakeValueData, sizeof(fakeValueData));
    if (!NT_SUCCESS(status)) {
        DbgPrint("[TriggerLayer] Failed to create fake registry key: 0x%08X\n", status);
    }
    
    // EXPERIMENTAL / NOT WIRED: inline syscall hooking is implemented below
    // (InstallInlineHook / HookedNtOpenProcess / HookedZwQuerySystemInformation)
    // but InitializeTriggerLayer() deliberately never calls InstallInlineHook.
    // Resolving NtOpenProcess/ZwQuerySystemInformation addresses and wiring
    // the hooks up requires a privileged test VM to validate safely -- the
    // hook stubs as written do not call through to the original function
    // (see the comments on HookedNtOpenProcess below), so installing them
    // as-is would break every real process-handle-open on the system. This
    // driver currently observes nothing; see README.md / ARCHITECTURE.md
    // for the honest status of this feature.

    state->Initialized = TRUE;
    DbgPrint("[TriggerLayer] Initialized successfully\n");
    
    return STATUS_SUCCESS;
}

VOID CleanupTriggerLayer(VOID)
{
    PTRIGGER_LAYER_STATE state = &g_HoneyPotState.TriggerState;
    ULONG i;
    
    DbgPrint("[TriggerLayer] Cleaning up...\n");
    
    // Remove all hooks
    for (i = 0; i < state->HookedFunctionCount; i++) {
        if (state->HookedFunctions[i].IsActive) {
            RemoveInlineHook(state->HookedFunctions[i].OriginalFunction);
        }
    }
    
    state->Initialized = FALSE;
    DbgPrint("[TriggerLayer] Cleanup complete\n");
}

NTSTATUS CreateFakeRegistryKey(PUNICODE_STRING KeyPath, PUNICODE_STRING ValueName, 
                               ULONG ValueType, PVOID ValueData, ULONG ValueDataSize)
{
    PTRIGGER_LAYER_STATE state = &g_HoneyPotState.TriggerState;
    PFAKE_REGISTRY_KEY fakeKey;
    
    if (state->FakeRegistryKeyCount >= 16) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    fakeKey = &state->FakeRegistryKeys[state->FakeRegistryKeyCount];
    
    // Allocate and copy key path
    fakeKey->KeyPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, KeyPath->Length, 'TRIG');
    if (!fakeKey->KeyPath.Buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyUnicodeString(&fakeKey->KeyPath, KeyPath);
    
    // Allocate and copy value name
    fakeKey->ValueName.Buffer = ExAllocatePoolWithTag(NonPagedPool, ValueName->Length, 'TRIG');
    if (!fakeKey->ValueName.Buffer) {
        ExFreePoolWithTag(fakeKey->KeyPath.Buffer, 'TRIG');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyUnicodeString(&fakeKey->ValueName, ValueName);
    
    // Allocate and copy value data
    fakeKey->ValueData = ExAllocatePoolWithTag(NonPagedPool, ValueDataSize, 'TRIG');
    if (!fakeKey->ValueData) {
        ExFreePoolWithTag(fakeKey->KeyPath.Buffer, 'TRIG');
        ExFreePoolWithTag(fakeKey->ValueName.Buffer, 'TRIG');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(fakeKey->ValueData, ValueData, ValueDataSize);
    
    fakeKey->ValueType = ValueType;
    fakeKey->ValueDataSize = ValueDataSize;
    fakeKey->IsActive = TRUE;
    
    state->FakeRegistryKeyCount++;
    state->TriggerCount++;
    
    DbgPrint("[TriggerLayer] Created fake registry key: %wZ\n", KeyPath);
    
    return STATUS_SUCCESS;
}

// EXPERIMENTAL / NOT WIRED: no call sites anywhere in this driver.
// InitializeTriggerLayer() (see above) does not call this function, so the
// entire inline-hook pipeline is dead code in the shipped driver. Do not
// wire this up without first fixing HookedNtOpenProcess /
// HookedZwQuerySystemInformation to call through to the original function
// and without cross-CPU synchronization (this only patches the current
// core); see BUILD_AND_VERIFY.md for the full list of prerequisites.
NTSTATUS InstallInlineHook(PVOID TargetFunction, PVOID HookFunction, PCHAR FunctionName)
{
    PTRIGGER_LAYER_STATE state = &g_HoneyPotState.TriggerState;
    PHOOKED_FUNCTION hook;
    KIRQL oldIrql;
    UCHAR jmpCode[14] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, address
                          0xFF, 0xE0 };  // jmp rax
    
    if (state->HookedFunctionCount >= MAX_HOOKED_FUNCTIONS) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    hook = &state->HookedFunctions[state->HookedFunctionCount];
    
    // Save original function address
    hook->OriginalFunction = TargetFunction;
    hook->HookFunction = HookFunction;
    RtlStringCbCopyA(hook->FunctionName, sizeof(hook->FunctionName), FunctionName);
    
    // Save original bytes (first 14 bytes for x64)
    RtlCopyMemory(hook->OriginalBytes, TargetFunction, 14);
    hook->HookedBytes = 14;
    
    // Raise IRQL to prevent context switches
    KeRaiseIrql(HIGH_LEVEL, &oldIrql);
    
    // Disable write protection
    __writecr0(__readcr0() & ~0x10000);
    
    // Install jump to hook function
    *(PVOID*)(jmpCode + 2) = HookFunction;
    RtlCopyMemory(TargetFunction, jmpCode, 14);
    
    // Flush instruction cache
    __wbinvd();
    
    // Re-enable write protection
    __writecr0(__readcr0() | 0x10000);
    
    // Lower IRQL
    KeLowerIrql(oldIrql);
    
    hook->IsActive = TRUE;
    state->HookedFunctionCount++;
    state->HookCallCount++;
    
    DbgPrint("[TriggerLayer] Installed inline hook: %s\n", FunctionName);
    
    return STATUS_SUCCESS;
}

NTSTATUS RemoveInlineHook(PVOID TargetFunction)
{
    PTRIGGER_LAYER_STATE state = &g_HoneyPotState.TriggerState;
    PHOOKED_FUNCTION hook = NULL;
    ULONG i;
    KIRQL oldIrql;
    
    // Find the hook
    for (i = 0; i < state->HookedFunctionCount; i++) {
        if (state->HookedFunctions[i].OriginalFunction == TargetFunction) {
            hook = &state->HookedFunctions[i];
            break;
        }
    }
    
    if (!hook || !hook->IsActive) {
        return STATUS_NOT_FOUND;
    }
    
    // Raise IRQL
    KeRaiseIrql(HIGH_LEVEL, &oldIrql);
    
    // Disable write protection
    __writecr0(__readcr0() & ~0x10000);
    
    // Restore original bytes
    RtlCopyMemory(TargetFunction, hook->OriginalBytes, hook->HookedBytes);
    
    // Flush instruction cache
    __wbinvd();
    
    // Re-enable write protection
    __writecr0(__readcr0() | 0x10000);
    
    // Lower IRQL
    KeLowerIrql(oldIrql);
    
    hook->IsActive = FALSE;
    
    DbgPrint("[TriggerLayer] Removed inline hook\n");
    
    return STATUS_SUCCESS;
}

// Hook function implementations.
//
// EXPERIMENTAL / NOT WIRED: never installed (InstallInlineHook has no call
// sites), never invoked except by their own header declaration. This stub
// also never calls the real NtOpenProcess -- it always returns
// STATUS_SUCCESS with either a fake handle or (for non-fake targets) no
// handle at all. If this were hooked in as-is, every real process-handle
// request on the system (Task Manager, AV, the test harness itself) would
// get a broken/fake handle instead of the real one, which would hang or
// crash a live test VM almost immediately. A real trampoline that preserves
// the original bytes and calls through for non-deception-target requests
// is required before this can ever be wired up.
NTSTATUS HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                             POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    PTRIGGER_LAYER_STATE state = &g_HoneyPotState.TriggerState;
    NTSTATUS status;
    
    // Log the syscall
    if (g_HoneyPotState.DetectionState.Initialized) {
        ULONG_PTR params[4] = { (ULONG_PTR)ProcessHandle, DesiredAccess, 
                               (ULONG_PTR)ObjectAttributes, (ULONG_PTR)ClientId };
        LogSyscall(SyscallNtOpenProcess, PsGetCurrentProcessId(), 
                   PsGetCurrentThreadId(), (ULONG_PTR)_ReturnAddress(), params);
    }
    
    // Call original function (in real implementation, we'd call the original)
    // For now, we'll just return a fake success
    state->HookCallCount++;
    
    // Deception: potentially redirect to fake process
    if (ClientId && g_HoneyPotState.DeceptionState.Initialized) {
        PFAKE_EPROCESS fakeProcess = FindFakeProcess((ULONG_PTR)ClientId->UniqueProcess);
        if (fakeProcess) {
            // Return fake process handle
            *ProcessHandle = (HANDLE)0x12345678; // Fake handle
            return STATUS_SUCCESS;
        }
    }
    
    // In real implementation, we'd call the original NtOpenProcess
    // For demonstration, return success
    return STATUS_SUCCESS;
}

// EXPERIMENTAL / NOT WIRED: same status as HookedNtOpenProcess above -- never
// installed, never called through to the real ZwQuerySystemInformation.
NTSTATUS HookedZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                        PVOID SystemInformation, ULONG SystemInformationLength, 
                                        PULONG ReturnLength)
{
    PTRIGGER_LAYER_STATE state = &g_HoneyPotState.TriggerState;
    
    // Log the syscall
    if (g_HoneyPotState.DetectionState.Initialized) {
        ULONG_PTR params[4] = { SystemInformationClass, (ULONG_PTR)SystemInformation, 
                               SystemInformationLength, (ULONG_PTR)ReturnLength };
        LogSyscall(SyscallZwQuerySystemInformation, PsGetCurrentProcessId(), 
                   PsGetCurrentThreadId(), (ULONG_PTR)_ReturnAddress(), params);
    }
    
    state->HookCallCount++;
    
    // Deception: potentially return fake system information
    // In real implementation, we'd call the original and modify the response
    
    return STATUS_SUCCESS;
}

