#include "HoneyPotControl.h"
#include <stdio.h>
#include <string.h>

// Handshake secret (must match kernel driver)
// In production, this should be loaded from secure storage or encrypted config
static const UCHAR g_HandshakeSecret[HANDSHAKE_SECRET_SIZE] = {
    0x4B, 0x52, 0x4E, 0x4C, 0x48, 0x4F, 0x4E, 0x45,  // "KRNLHONE"
    0x59, 0x50, 0x4F, 0x54, 0x53, 0x45, 0x43, 0x52,  // "YPOTSECR"
    0x45, 0x54, 0x4B, 0x45, 0x59, 0x31, 0x32, 0x33,  // "ETKEY123"
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31   // "45678901"
};

HANDLE OpenHoneyPotDevice(VOID)
{
    HANDLE hDevice;

    hDevice = CreateFileW(DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        wprintf(L"Failed to open device: %lu\n", error);
        return NULL;
    }

    return hDevice;
}

VOID CloseHoneyPotDevice(HANDLE hDevice)
{
    if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
    }
}

BOOL PerformHandshake(HANDLE hDevice, PUCHAR SessionId)
{
    DWORD bytesReturned;
    BOOL result;
    HONEYPOT_HANDSHAKE_REQUEST request = { 0 };
    HONEYPOT_HANDSHAKE_RESPONSE response = { 0 };

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Prepare handshake request
    for (size_t i = 0; i < HANDSHAKE_SECRET_SIZE; i++) {
        request.Secret[i] = g_HandshakeSecret[i];
    }
    request.Version = APP_VERSION;

    // Send handshake request
    result = DeviceIoControl(hDevice,
        IOCTL_HONEYPOT_HANDSHAKE,
        &request,
        sizeof(HONEYPOT_HANDSHAKE_REQUEST),
        &response,
        sizeof(HONEYPOT_HANDSHAKE_RESPONSE),
        &bytesReturned,
        NULL);

    if (!result) {
        DWORD error = GetLastError();
        wprintf(L"Handshake failed: %lu\n", error);
        return FALSE;
    }

    // Check response status
    if (response.Status != 0) {
        wprintf(L"Handshake failed with status: 0x%08X\n", response.Status);
        return FALSE;
    }

    // Copy session ID if provided
    if (SessionId) {
        for (size_t i = 0; i < SESSION_ID_SIZE; i++) {
            SessionId[i] = response.SessionId[i];
        }
    }

    // Display driver version
    ULONG driverMajor = (response.DriverVersion >> 16) & 0xFFFF;
    ULONG driverMinor = response.DriverVersion & 0xFFFF;
    wprintf(L"Handshake successful! Driver version: %lu.%lu\n", driverMajor, driverMinor);

    return TRUE;
}

BOOL GetHoneyPotStatistics(HANDLE hDevice, PHONEYPOT_STATISTICS Stats)
{
    DWORD bytesReturned;
    BOOL result;

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE || !Stats) {
        return FALSE;
    }

    result = DeviceIoControl(hDevice,
        IOCTL_HONEYPOT_GET_STATS,
        NULL,
        0,
        Stats,
        sizeof(HONEYPOT_STATISTICS),
        &bytesReturned,
        NULL);

    if (!result) {
        DWORD error = GetLastError();
        wprintf(L"Failed to get statistics: %lu\n", error);
        return FALSE;
    }

    return TRUE;
}

BOOL ExportLogs(HANDLE hDevice, LPCWSTR FilePath)
{
    DWORD bytesReturned;
    BOOL result;
    WCHAR filePathBuffer[MAX_PATH];

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (FilePath) {
        wcscpy_s(filePathBuffer, MAX_PATH, FilePath);
    }
    else {
        wcscpy_s(filePathBuffer, MAX_PATH, L"C:\\Release\\honeypot_logs.enc");
    }

    result = DeviceIoControl(hDevice,
        IOCTL_HONEYPOT_EXPORT_LOGS,
        filePathBuffer,
        (DWORD)(wcslen(filePathBuffer) * sizeof(WCHAR)),
        NULL,
        0,
        &bytesReturned,
        NULL);

    if (!result) {
        DWORD error = GetLastError();
        wprintf(L"Failed to export logs: %lu\n", error);
        return FALSE;
    }

    wprintf(L"Logs exported to: %s\n", filePathBuffer);
    return TRUE;
}

BOOL ReloadConfiguration(HANDLE hDevice)
{
    DWORD bytesReturned;
    BOOL result;

    if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    result = DeviceIoControl(hDevice,
        IOCTL_HONEYPOT_RELOAD_CONFIG,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL);

    if (!result) {
        DWORD error = GetLastError();
        wprintf(L"Failed to reload configuration: %lu\n", error);
        return FALSE;
    }

    wprintf(L"Configuration reloaded successfully\n");
    return TRUE;
}

int wmain(int argc, WCHAR* argv[])
{
    HANDLE hDevice = NULL;
    HONEYPOT_STATISTICS stats = { 0 };

    wprintf(L"HoneyPot Control Application\n");
    wprintf(L"============================\n\n");

    // Help is answerable without the driver — handle it before opening the
    // device so `HoneyPotControl.exe help` works on any host (and in CI).
    if (argc > 1 && (_wcsicmp(argv[1], L"help") == 0 || _wcsicmp(argv[1], L"/?") == 0)) {
        wprintf(L"Usage:\n");
        wprintf(L"  HoneyPotControl.exe [command]\n\n");
        wprintf(L"Commands:\n");
        wprintf(L"  (no args)  - Display statistics\n");
        wprintf(L"  export     - Export logs to file\n");
        wprintf(L"  reload     - Reload configuration\n");
        wprintf(L"  help       - Show this help\n");
        return 0;
    }

    // Open device
    hDevice = OpenHoneyPotDevice();
    if (!hDevice) {
        wprintf(L"Error: Could not connect to FakeNetFilter driver.\n");
        wprintf(L"Make sure the driver is loaded and running.\n");
        return 1;
    }

    wprintf(L"Connected to FakeNetFilter driver.\n");

    // Perform handshake
    UCHAR sessionId[SESSION_ID_SIZE] = { 0 };
    if (!PerformHandshake(hDevice, sessionId)) {
        wprintf(L"Error: Handshake failed. Cannot establish secure session.\n");
        CloseHoneyPotDevice(hDevice);
        return 1;
    }

    wprintf(L"\n");

    // Get statistics
    if (GetHoneyPotStatistics(hDevice, &stats)) {
        wprintf(L"Statistics:\n");
        wprintf(L"  Total Syscalls Logged: %llu\n", stats.TotalSyscallsLogged);
        wprintf(L"  Suspicious Syscalls: %llu\n", stats.SuspiciousSyscallsDetected);
        wprintf(L"  Deception Count: %llu\n", stats.DeceptionCount);
        wprintf(L"  Fake Object Accesses: %llu\n", stats.FakeObjectAccessCount);
        wprintf(L"  Payloads Analyzed: %llu\n", stats.PayloadsAnalyzed);
        wprintf(L"  Exploits Detected: %llu\n", stats.ExploitsDetected);
        wprintf(L"  Total Log Entries: %llu\n", stats.TotalLogEntries);
        wprintf(L"  Encrypted Exports: %llu\n", stats.EncryptedExports);
        wprintf(L"\n");
    }

    // Handle command line arguments
    if (argc > 1) {
        if (_wcsicmp(argv[1], L"export") == 0) {
            LPCWSTR filePath = (argc > 2) ? argv[2] : NULL;
            ExportLogs(hDevice, filePath);
        }
        else if (_wcsicmp(argv[1], L"reload") == 0) {
            ReloadConfiguration(hDevice);
        }
        // `help` / `/?` is handled earlier, before the device is opened.
    }

    CloseHoneyPotDevice(hDevice);

    return 0;
}

