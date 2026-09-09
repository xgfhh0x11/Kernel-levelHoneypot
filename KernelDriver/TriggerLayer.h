#pragma once

#include <ntddk.h>

// SYSTEM_INFORMATION_CLASS lives in ntexapi.h, which ntddk.h does not pull in.
// Declare it (guarded) so the ZwQuerySystemInformation hook prototype parses.
#ifndef _SYSTEM_INFORMATION_CLASS_DEFINED
#define _SYSTEM_INFORMATION_CLASS_DEFINED
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
#endif

// Trigger Layer: Entrypoint for attacker interaction

typedef struct _FAKE_REGISTRY_KEY {
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValueName;
    ULONG ValueType;
    PVOID ValueData;
    ULONG ValueDataSize;
    BOOLEAN IsActive;
} FAKE_REGISTRY_KEY, *PFAKE_REGISTRY_KEY;

typedef struct _HOOKED_FUNCTION {
    PVOID OriginalFunction;
    PVOID HookFunction;
    UCHAR OriginalBytes[16];
    ULONG HookedBytes;
    BOOLEAN IsActive;
    CHAR FunctionName[64];
} HOOKED_FUNCTION, *PHOOKED_FUNCTION;

typedef struct _TRIGGER_LAYER_STATE {
    BOOLEAN Initialized;
    
    // Fake registry keys
    FAKE_REGISTRY_KEY FakeRegistryKeys[16];
    ULONG FakeRegistryKeyCount;
    
    // Inline hooks
    HOOKED_FUNCTION HookedFunctions[MAX_HOOKED_FUNCTIONS];
    ULONG HookedFunctionCount;
    
    // Statistics
    ULONG64 TriggerCount;
    ULONG64 HookCallCount;
} TRIGGER_LAYER_STATE, *PTRIGGER_LAYER_STATE;

// Function declarations
NTSTATUS InitializeTriggerLayer(VOID);
VOID CleanupTriggerLayer(VOID);
NTSTATUS CreateFakeRegistryKey(PUNICODE_STRING KeyPath, PUNICODE_STRING ValueName, ULONG ValueType, PVOID ValueData, ULONG ValueDataSize);

// EXPERIMENTAL / NOT WIRED -- see TriggerLayer.c. InstallInlineHook has no
// call sites in this driver; InitializeTriggerLayer() never installs the
// hooks below. Do not wire these up without first fixing the hook stubs to
// call through to the original function (see HookedNtOpenProcess).
NTSTATUS InstallInlineHook(PVOID TargetFunction, PVOID HookFunction, PCHAR FunctionName);
NTSTATUS RemoveInlineHook(PVOID TargetFunction);

// Hook functions (passive inline hooks) -- EXPERIMENTAL / NOT WIRED, never
// installed and never called through to the real syscalls. See TriggerLayer.c.
NTSTATUS HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS HookedZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

