#pragma once

#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdf.h>

// Version information
#define DRIVER_VERSION_MAJOR 1
#define DRIVER_VERSION_MINOR 0
#define DRIVER_NAME L"FakeNetFilter"
#define DEVICE_NAME L"\\Device\\FakeNetFilter"
#define SYMBOLIC_NAME L"\\DosDevices\\FakeNetFilter"

// Configuration
#define MAX_LOG_BUFFER_SIZE (1024 * 1024) // 1MB
#define MAX_HOOKED_FUNCTIONS 32
#define MAX_FAKE_OBJECTS 256

// Layer includes
#include "TriggerLayer.h"
#include "DetectionLayer.h"
#include "DeceptionLayer.h"
#include "LoggingLayer.h"
#include "ExtractionLayer.h"
#include "ControlLayer.h"

// Statistics structure (for IOCTL)
typedef struct _HONEYPOT_STATISTICS {
    ULONG64 TotalSyscallsLogged;
    ULONG64 SuspiciousSyscallsDetected;
    ULONG64 DeceptionCount;
    ULONG64 FakeObjectAccessCount;
    ULONG64 PayloadsAnalyzed;
    ULONG64 ExploitsDetected;
    ULONG64 TotalLogEntries;
    ULONG64 EncryptedExports;
} HONEYPOT_STATISTICS, *PHONEYPOT_STATISTICS;

// Global state
typedef struct _HONEYPOT_GLOBAL_STATE {
    BOOLEAN Initialized;
    BOOLEAN Active;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING RegistryPath;
    
    // Layer states
    TRIGGER_LAYER_STATE TriggerState;
    DETECTION_LAYER_STATE DetectionState;
    DECEPTION_LAYER_STATE DeceptionState;
    LOGGING_LAYER_STATE LoggingState;
    EXTRACTION_LAYER_STATE ExtractionState;
    CONTROL_LAYER_STATE ControlState;
} HONEYPOT_GLOBAL_STATE, *PHONEYPOT_GLOBAL_STATE;

extern HONEYPOT_GLOBAL_STATE g_HoneyPotState;

// Function declarations
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS InitializeHoneyPot(VOID);
VOID CleanupHoneyPot(VOID);

