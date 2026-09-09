#include "FakeNetFilter.h"

HONEYPOT_GLOBAL_STATE g_HoneyPotState = { 0 };

NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION ioStack;
    ULONG ioControlCode;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    
    ioStack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    
    switch (ioControlCode) {
        case IOCTL_HONEYPOT_HANDSHAKE: {
            PHONEYPOT_HANDSHAKE_REQUEST request =
                (PHONEYPOT_HANDSHAKE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
            PHONEYPOT_HANDSHAKE_RESPONSE response =
                (PHONEYPOT_HANDSHAKE_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

            if (ioStack->Parameters.DeviceIoControl.InputBufferLength <
                    sizeof(HONEYPOT_HANDSHAKE_REQUEST) ||
                ioStack->Parameters.DeviceIoControl.OutputBufferLength <
                    sizeof(HONEYPOT_HANDSHAKE_RESPONSE) ||
                !request) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            // METHOD_BUFFERED reuses SystemBuffer for input and output. Copy
            // the request out before HandleHandshake zeros the buffer.
            HONEYPOT_HANDSHAKE_REQUEST localRequest;
            RtlCopyMemory(&localRequest, request, sizeof(localRequest));

            status = HandleHandshake(&localRequest, response);
            if (NT_SUCCESS(status)) {
                information = sizeof(HONEYPOT_HANDSHAKE_RESPONSE);
            }
            break;
        }

        case IOCTL_HONEYPOT_GET_STATS: {
            // METHOD_BUFFERED: SystemBuffer is the only valid buffer here
            // (Irp->MdlAddress is never set for METHOD_BUFFERED requests --
            // see the EXPORT_LOGS case below for the bug that pattern caused).
            PHONEYPOT_STATISTICS stats = (PHONEYPOT_STATISTICS)Irp->AssociatedIrp.SystemBuffer;

            if (stats && ioStack->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(HONEYPOT_STATISTICS)) {
                // Fill statistics from global state
                stats->TotalSyscallsLogged = g_HoneyPotState.DetectionState.TotalSyscallsLogged;
                stats->SuspiciousSyscallsDetected = g_HoneyPotState.DetectionState.SuspiciousSyscallsDetected;
                stats->DeceptionCount = g_HoneyPotState.DeceptionState.DeceptionCount;
                stats->FakeObjectAccessCount = g_HoneyPotState.DeceptionState.FakeObjectAccessCount;
                stats->PayloadsAnalyzed = g_HoneyPotState.ExtractionState.PayloadsAnalyzed;
                stats->ExploitsDetected = g_HoneyPotState.ExtractionState.ExploitsDetected;
                stats->TotalLogEntries = g_HoneyPotState.LoggingState.TotalLogEntries;
                stats->EncryptedExports = g_HoneyPotState.LoggingState.EncryptedExports;
                
                information = sizeof(HONEYPOT_STATISTICS);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }
        
        case IOCTL_HONEYPOT_GET_LOGS:
            // Log retrieval is reserved for a future revision; the export
            // path (IOCTL_HONEYPOT_EXPORT_LOGS) is the supported way to
            // pull encrypted logs to disk today.
            status = STATUS_NOT_IMPLEMENTED;
            break;

        case IOCTL_HONEYPOT_RELOAD_CONFIG:
            status = ReloadConfiguration();
            break;

        case IOCTL_HONEYPOT_EXPORT_LOGS: {
            // This IOCTL is declared METHOD_BUFFERED (see ControlLayer.h), so
            // the I/O manager never populates Irp->MdlAddress -- that field is
            // exclusive to METHOD_IN_DIRECT/METHOD_OUT_DIRECT. The buffered
            // path (like HANDSHAKE/GET_STATS above) must read the path string
            // from Irp->AssociatedIrp.SystemBuffer instead.
            ULONG inputLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
            PWCHAR pathBuffer = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;

            if (pathBuffer && inputLength >= sizeof(WCHAR)) {
                UNICODE_STRING path;
                SIZE_T maxChars = inputLength / sizeof(WCHAR);

                // Ensure the buffer is NUL-terminated within the bytes the
                // caller actually supplied before trusting wcslen() on it.
                pathBuffer[maxChars - 1] = L'\0';

                path.Buffer = pathBuffer;
                path.Length = (USHORT)(wcslen(pathBuffer) * sizeof(WCHAR));
                path.MaximumLength = (USHORT)inputLength;
                status = ExportLogsToFile(&path);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        }
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

NTSTATUS DeviceCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

NTSTATUS CreateDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_NAME);
    
    status = IoCreateDevice(DriverObject,
                           0,
                           &deviceName,
                           FILE_DEVICE_UNKNOWN,
                           FILE_DEVICE_SECURE_OPEN,
                           FALSE,
                           &deviceObject);
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    
    g_HoneyPotState.DeviceObject = deviceObject;
    
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    
    DbgPrint("[FakeNetFilter] DriverEntry called\n");
    
    // Initialize global state
    RtlZeroMemory(&g_HoneyPotState, sizeof(HONEYPOT_GLOBAL_STATE));
    g_HoneyPotState.RegistryPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, RegistryPath->Length, 'HONE');
    if (!g_HoneyPotState.RegistryPath.Buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyUnicodeString(&g_HoneyPotState.RegistryPath, RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    
    // Set up dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;
    
    // Create device object
    status = CreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FakeNetFilter] Failed to create device: 0x%08X\n", status);
        ExFreePoolWithTag(g_HoneyPotState.RegistryPath.Buffer, 'HONE');
        return status;
    }
    
    // Initialize honeypot system
    status = InitializeHoneyPot();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FakeNetFilter] Failed to initialize honeypot: 0x%08X\n", status);
        CleanupHoneyPot();
        return status;
    }
    
    g_HoneyPotState.Initialized = TRUE;
    g_HoneyPotState.Active = TRUE;
    
    DbgPrint("[FakeNetFilter] Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLink;
    
    UNREFERENCED_PARAMETER(DriverObject);
    
    DbgPrint("[FakeNetFilter] DriverUnload called\n");
    
    g_HoneyPotState.Active = FALSE;
    CleanupHoneyPot();
    
    // Delete symbolic link
    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symbolicLink);
    
    // Delete device object
    if (g_HoneyPotState.DeviceObject) {
        IoDeleteDevice(g_HoneyPotState.DeviceObject);
    }
    
    if (g_HoneyPotState.RegistryPath.Buffer) {
        ExFreePoolWithTag(g_HoneyPotState.RegistryPath.Buffer, 'HONE');
    }
    
    DbgPrint("[FakeNetFilter] Driver unloaded\n");
}

NTSTATUS InitializeHoneyPot(VOID)
{
    NTSTATUS status;
    
    DbgPrint("[FakeNetFilter] Initializing honeypot layers...\n");
    
    // Initialize layers in order: Control -> Trigger -> Detection -> Deception -> Logging -> Extraction
    status = InitializeControlLayer();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FakeNetFilter] Failed to initialize Control Layer: 0x%08X\n", status);
        return status;
    }
    
    status = InitializeTriggerLayer();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FakeNetFilter] Failed to initialize Trigger Layer: 0x%08X\n", status);
        return status;
    }
    
    status = InitializeDetectionLayer();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FakeNetFilter] Failed to initialize Detection Layer: 0x%08X\n", status);
        return status;
    }
    
    status = InitializeDeceptionLayer();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FakeNetFilter] Failed to initialize Deception Layer: 0x%08X\n", status);
        return status;
    }
    
    status = InitializeLoggingLayer();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FakeNetFilter] Failed to initialize Logging Layer: 0x%08X\n", status);
        return status;
    }
    
    status = InitializeExtractionLayer();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[FakeNetFilter] Failed to initialize Extraction Layer: 0x%08X\n", status);
        return status;
    }
    
    DbgPrint("[FakeNetFilter] All layers initialized successfully\n");
    return STATUS_SUCCESS;
}

VOID CleanupHoneyPot(VOID)
{
    DbgPrint("[FakeNetFilter] Cleaning up honeypot layers...\n");
    
    // Cleanup in reverse order
    CleanupExtractionLayer();
    CleanupLoggingLayer();
    CleanupDeceptionLayer();
    CleanupDetectionLayer();
    CleanupTriggerLayer();
    CleanupControlLayer();
    
    g_HoneyPotState.Initialized = FALSE;
    DbgPrint("[FakeNetFilter] Cleanup complete\n");
}

