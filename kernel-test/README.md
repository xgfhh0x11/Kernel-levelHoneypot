# Kernel-levelHoneypot — dynamic kernel-test harness

Runbook for exercising the `FakeNetFilter.sys` WDM driver on a **disposable**
Hyper-V kdnet guest. Read the safety section first. This is a defensive
deception (honeypot) driver; these scripts test the driver's control/IOCTL
surface, they do not enable any offensive capability.

## Target / channel

- Guest: a throwaway Hyper-V VM (here: `WinKDbg`), kernel-debugged over the
  network with `kd.exe` / `kdnet.exe` from the host.
- Attach template (host; key/port from the guest's `bcdedit /dbgsettings`):

  ```
  kd -k net:port=<PORT>,key=<KEY>
  ```

## Prerequisites

1. **Take a Hyper-V checkpoint first** — loading can bugcheck the guest.
2. Guest test-signing on, then reboot:

   ```
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```

3. The driver must build (WDM; `build.ps1`). Note: this dev host may lack the
   WDM kernel headers (`ntifs.h`) — if `build.ps1` fails on missing headers,
   build inside the guest or on a full WDK box.

## Scope note (from code review)

- The inline syscall hooks (`InstallInlineHook`, `HookedNtOpenProcess`,
  `HookedZwQuerySystemInformation`) are **experimental / NOT WIRED** — they have
  no call sites and the stubs do not chain to the original syscall. Do **not**
  enable them; wiring them as-is would hang the guest. These scripts only
  exercise the driver's load + IOCTL control surface, which is the live path.
- `IOCTL_HONEYPOT_EXPORT_LOGS` was fixed to read its path from the buffered
  system buffer (it previously no-opped under METHOD_BUFFERED); `smoke-test.ps1`
  confirms it now actually acts.

## Files

| File | Purpose |
|------|---------|
| `build.ps1` | Build `FakeNetFilter.sys` (Release, x64) with the host WDK. Prints exact errors and exits non-zero on failure. |
| `load.ps1` | `sc create` + `sc start` inside the guest. Dry-run unless `-Arm`. |
| `unload.ps1` | `sc stop` + `sc delete`. |
| `kd-triage.txt` | `kd` crash-triage / Driver Verifier commands. |
| `smoke-test.ps1` | Opens `\\.\FakeNetFilter`, issues the 5 IOCTLs (incl. HANDSHAKE first, and EXPORT_LOGS to confirm the buffered-IOCTL fix). Dry-run unless `-Arm`. |

## Device / IOCTL surface

- User-mode path: `\\.\FakeNetFilter` (symlink `\DosDevices\FakeNetFilter`).
- Service name used by the scripts: `FakeNetFilter`.
- IOCTLs (`METHOD_BUFFERED`, `FILE_DEVICE_UNKNOWN`):
  HANDSHAKE (0x800), GET_STATS (0x801), GET_LOGS (0x802),
  RELOAD_CONFIG (0x803), EXPORT_LOGS (0x804).
- Several IOCTLs (GET_STATS, RELOAD_CONFIG) gate on a prior successful
  HANDSHAKE — `smoke-test.ps1` sends HANDSHAKE first.

## SAFETY

- **Checkpoint the guest before loading; revert on any bugcheck.**
- Enable **Driver Verifier** (`verifier /standard /driver FakeNetFilter.sys`)
  on the guest before load.
- Disposable guest only. The scripts touch the guest **only** with `-Arm`;
  the default is a dry-run that prints the exact commands.
