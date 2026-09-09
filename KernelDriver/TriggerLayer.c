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
    
    // Install inline hooks (passive hooks)
    // Note: In real implementation, we'd resolve these from ntdll.dll exports
    // For now, we'll use placeholder addresses that would be resolved at runtime
    
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

// Hook function implementations
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

