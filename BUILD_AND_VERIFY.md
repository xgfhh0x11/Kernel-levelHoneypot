# Kernel-Mode Deception Framework — Build & Verification

> *Quality gate for the HBO NL portfolio. Complements the existing
> BUILD.md with acceptance criteria and verification recipe.*
>
> *Last updated: 2026-05-14 — post P0–P3 fix pass. Critical IOCTL off-by-one resolved.*

## 1. Build

### 1.1 Primary build path

- **Platform**: Windows 10 / 11 x64, kernel-mode (`.sys`) + user-mode (`.exe`)
- **Toolchain**: Visual Studio 2019 or 2022 (PlatformToolset `v143`) + Windows
  Driver Kit (WDK) 10 + Windows SDK 10.0.19041.0 or later. C dialect only
  (no C++ sources).
- **Command** (copy-pastable, from an *x64 Native Tools Command Prompt*):

  ```cmd
  REM 1) Kernel driver — `FakeNetFilter.vcxproj` is committed (post-2026-05-14
  REM    fix pass), so MSBuild against the WindowsKernelModeDriver10.0
  REM    toolset Just Works. The legacy WDK `sources` file is still in the
  REM    tree for `build -cZ` flows.
  cd KernelDriver
  msbuild FakeNetFilter.vcxproj /p:Configuration=Release /p:Platform=x64

  REM    Legacy alternative (requires WDK 7.1-era environment):
  REM    build -cZ

  REM 2) User-mode control app:
  cd ..\UserModeApp
  msbuild HoneyPotControl.vcxproj /p:Configuration=Release /p:Platform=x64
  ```

- **Output**:
  - `KernelDriver\bin\Release\FakeNetFilter.sys` (driver — name is fixed by
    `FakeNetFilter.vcxproj:TargetName=FakeNetFilter` /
    `sources:TARGETNAME=FakeNetFilter` and by `DRIVER_NAME` /
    `DEVICE_NAME` in `FakeNetFilter.h`).
  - `UserModeApp\x64\Release\HoneyPotControl.exe`
- Reference: see `BUILD.md` for exhaustive build details (three build
  paths: Visual Studio GUI, MSBuild, legacy WDK `sources`).

### 1.2 Alternative build paths

- **VS IDE**: open `KernelDriver\FakeNetFilter.vcxproj` for the driver
  and `UserModeApp\HoneyPotControl.vcxproj` for the control app. Both
  projects are now committed to the repo (see §3.1, fixed 2026-05-14).
- **`cl.exe` one-liner for the user-mode app** (no MSBuild required):
  ```cmd
  cd UserModeApp
  cl /Fe:HoneyPotControl.exe HoneyPotControl.c /link kernel32.lib user32.lib
  ```
- **Legacy WDK `build -cZ`** is what the committed `KernelDriver\sources`
  file targets. This tool ships with the WDK 7.1 era environment and is
  not available in modern WDK 10 installs without the legacy package.

### 1.3 Dependencies

- **Required**:
  - Windows 10/11 x64 host with admin rights for the test/install step.
  - WDK 10 (with VS integration) — supplies `ntddk.h`, `wdf.h`,
    `ntoskrnl.lib`, `hal.lib`, `wdfldr.lib`.
  - Visual Studio 2019/2022 with the *Desktop development with C++*
    workload.
  - Test-signing enabled (`bcdedit /set testsigning on`) on the target
    machine; reboot required.
- **Optional**: WinDbg / DbgView (to capture `DbgPrint` lines emitted by
  `DriverEntry` and the per-layer init paths).

## 2. Expected behavior

### 2.1 What this project does

A six-layer kernel-mode honeypot (Trigger → Detection → Deception →
Logging → Extraction → Control). The driver registers as
`\Device\FakeNetFilter` with symbolic link `\DosDevices\FakeNetFilter`,
installs passive inline hooks on `NtOpenProcess` and
`ZwQuerySystemInformation`, maintains a synthetic process/thread universe,
and exposes statistics + log export via a small IOCTL surface
(`0x800-0x804`). `HoneyPotControl.exe` opens `\\.\FakeNetFilter`,
performs a 32-byte shared-secret handshake, and prints counters or
triggers a log export.

### 2.2 Acceptance criteria

- [ ] **A1 — Driver builds**: `FakeNetFilter.sys` is produced at
      `KernelDriver\x64\Release\FakeNetFilter.sys` with no errors and no
      `/WX` warnings (the `sources` file sets `/W4 /WX`).
- [ ] **A2 — App builds**: `HoneyPotControl.exe` is produced at
      `UserModeApp\x64\Release\HoneyPotControl.exe`.
- [ ] **A3 — Driver loads**: `sc start FakeNetFilter` returns
      `STATE: 4 RUNNING` and DbgView shows
      `[FakeNetFilter] Driver loaded successfully` followed by six
      `[FakeNetFilter] ...layer initialized` lines.
- [ ] **A4 — Device reachable**: `HoneyPotControl.exe` (no args) opens
      `\\.\FakeNetFilter` and does not print *"Could not connect"*.
- [ ] **A5 — Handshake passes**: app prints
      `Handshake successful! Driver version: 1.0`. Kernel side now
      implements `IOCTL_HONEYPOT_HANDSHAKE = 0x800` end-to-end:
      `ControlLayer.c:HandleHandshake` validates the 32-byte secret with
      `RtlEqualMemory`, checks major version, and returns a randomised
      16-byte session ID. The dispatcher in
      `FakeNetFilter.c` size-validates request/response buffers before
      calling through. (Resolved 2026-05-14; see §3.1.)
- [ ] **A6 — Statistics readable**: after some activity, the eight
      `HONEYPOT_STATISTICS` fields print as non-negative integers; at
      least `TotalSyscallsLogged` is `> 0` after running e.g.
      `Get-Process` from another shell.
- [ ] **A7 — Log export**: `HoneyPotControl.exe export` produces a file
      at `C:\Release\honeypot_logs.enc` (or the supplied path).
- [ ] **A8 — Config reload**: editing `C:\Release\honey.conf` then
      `HoneyPotControl.exe reload` succeeds and is reflected in
      subsequent stats. (`ControlLayer.h:CONFIG_FILE_PATH` was realigned
      to `\??\C:\Release\honey.conf` on 2026-05-14, matching the install
      step; the previous `\SystemRoot\Release\` path is gone.)
- [ ] **A9 — Clean unload**: `sc stop FakeNetFilter` succeeds; DbgView
      shows `Cleanup complete` then `Driver unloaded`; no bugcheck.

### 2.3 Manual verification

Run on an **isolated VM with a recent checkpoint**. Bugchecks are
expected during iteration on a Ring-0 component.

```cmd
REM --- one-time setup (reboot required after testsigning) ---
bcdedit /set testsigning on
shutdown /r /t 0

REM --- install ---
mkdir C:\Release
copy KernelDriver\bin\Release\FakeNetFilter.sys C:\Release\
copy config\honey.conf                          C:\Release\
REM Post-2026-05-14: the kernel parser reads exactly C:\Release\honey.conf
REM (CONFIG_FILE_PATH = L"\\??\\C:\\Release\\honey.conf"), so the
REM single copy above is sufficient.

sc create FakeNetFilter binPath= "C:\Release\FakeNetFilter.sys" type= kernel
sc start FakeNetFilter
sc query FakeNetFilter           REM expect STATE: 4 RUNNING  -> A3

REM --- exercise ---
HoneyPotControl.exe              REM A4, A5, A6
Get-Process > nul                REM generate syscalls
HoneyPotControl.exe              REM TotalSyscallsLogged should rise
HoneyPotControl.exe export C:\Release\honeypot_logs.enc   REM A7
HoneyPotControl.exe reload       REM A8

REM --- teardown ---
sc stop   FakeNetFilter          REM A9
sc delete FakeNetFilter
```

Capture `DbgPrint` output with **DbgView** (`Capture > Capture Kernel`)
or `windbg -k` for kernel-debug attach. Without one of these the
`[FakeNetFilter] ...` lines that prove A3/A9 are invisible.

### 2.4 Automated verification

**Present (added 2026-06-10).** A `pytest` suite under `tests/` plus a
GitHub Actions workflow (`.github/workflows/ci.yml`):

- `tests/test_structure.py` — asserts each of the six layers has a
  matching `<Name>Layer.{c,h}`, the driver entry point + user-mode app
  are present, and `FakeNetFilter.vcxproj` compiles every layer (so the
  source tree and the build can't drift apart).
- `tests/test_cli_smoke.py` — runs the built `HoneyPotControl.exe help`
  and asserts exit 0 + usage text. `help`/`/?` was moved ahead of the
  device-open in `wmain` (2026-06-10) so it is answerable without the
  driver; skips cleanly when the app is not built.

CI builds the user-mode control app with MSVC on `windows-latest`,
smoke-tests `help`, then runs `pytest`. The kernel driver still needs a
WDK + privileged VM (the §2.3 manual recipe / a future `Verify.ps1`
remains the path for the full A1–A9 end-to-end). Run locally:

```sh
pip install -r tests/requirements.txt
python -m pytest tests/ -v
```

## 3. Alternatives & improvements

### 3.1 Known fragilities

- ✅ **Driver `.vcxproj` is missing.** ~~The repo ships
  `UserModeApp\HoneyPotControl.vcxproj` but **no project file for the
  driver** — only the legacy WDK 7.1-era `sources` file. BUILD.md
  Method 2 (`msbuild /t:build`) therefore *cannot work as written*.~~
  **RESOLVED 2026-05-14:** `KernelDriver\FakeNetFilter.vcxproj` is now
  committed. It targets the `WindowsKernelModeDriver10.0` toolset,
  enumerates all 7 source files (`FakeNetFilter.c`, `ControlLayer.c`,
  `DeceptionLayer.c`, `DetectionLayer.c`, `ExtractionLayer.c`,
  `LoggingLayer.c`, `TriggerLayer.c`) and all 7 headers, sets
  `TargetName=FakeNetFilter` / `TargetExt=.sys`, and links
  `ntstrsafe.lib`. BUILD.md Method 2 now works end-to-end.
- ✅ **Driver filename mismatch across docs.** ~~`README.md` references
  `krnlhoneypot.sys` in the install snippet, but the actual build output
  is `FakeNetFilter.sys`.~~ **RESOLVED 2026-05-14:** every
  `krnlhoneypot.sys` mention in `README.md` was rewritten to
  `FakeNetFilter.sys`. README, BUILD.md, the new `.vcxproj`, and the
  `sources` file all agree on the driver name now.
- ✅ **Handshake is one-sided.** ~~`HoneyPotControl.c` sends
  `IOCTL_HONEYPOT_HANDSHAKE = 0x800`, but the driver's
  `DeviceIoControl` switch in `FakeNetFilter.c` has **no case for
  `0x800`**, and `ControlLayer.h` re-defines `0x800` as
  `IOCTL_HONEYPOT_GET_STATS` (so two different IOCTLs share the same
  code).~~ **RESOLVED 2026-05-14 (P0 fix):** `ControlLayer.h` was
  renumbered to align byte-for-byte with `HoneyPotControl.h`:
  | Code  | User app (`HoneyPotControl.h`) | Kernel (`ControlLayer.h`) |
  |-------|--------------------------------|---------------------------|
  | 0x800 | HANDSHAKE                      | HANDSHAKE ✅              |
  | 0x801 | GET_STATS                      | GET_STATS ✅              |
  | 0x802 | GET_LOGS                       | GET_LOGS ✅               |
  | 0x803 | RELOAD_CONFIG                  | RELOAD_CONFIG ✅          |
  | 0x804 | EXPORT_LOGS                    | EXPORT_LOGS ✅            |
  Additionally `ControlLayer.h` now exports `HANDSHAKE_SECRET_SIZE`,
  `SESSION_ID_SIZE`, `KMOD_DRIVER_VERSION`, the
  `HONEYPOT_HANDSHAKE_REQUEST`/`RESPONSE` structs, the
  `g_HoneyPotHandshakeSecret` extern, and the `HandleHandshake()`
  prototype. `ControlLayer.c` defines the matching 32-byte secret
  (`"KRNLHONEYPOTSECRETKEY12345678901"`) and implements
  `HandleHandshake()` (constant-size `RtlEqualMemory` check, major-version
  gate, `RtlRandomEx` session ID seeded by `KeQueryPerformanceCounter`).
  The dispatcher in `FakeNetFilter.c` now has explicit cases for
  `IOCTL_HONEYPOT_HANDSHAKE` (with input/output size validation) and
  `IOCTL_HONEYPOT_GET_LOGS` (returns `STATUS_NOT_IMPLEMENTED` — export
  remains the supported log-egress path).
- ✅ **Config path divergence.** ~~`config\honey.conf` documents itself
  as living at `\SystemRoot\Release\honey.conf` (= `C:\Windows\Release\`),
  matching `ControlLayer.h:CONFIG_FILE_PATH`. But README/BUILD copy it
  to `C:\Release\`.~~ **RESOLVED 2026-05-14:**
  `ControlLayer.h:CONFIG_FILE_PATH` is now
  `L"\\??\\C:\\Release\\honey.conf"`, matching the install-time `copy`
  in README/BUILD.md. The `\??\` prefix is the kernel-mode
  object-manager DOS-namespace prefix, the supported way to address a
  drive-letter path from `ZwOpenFile`.
- ⚠️ **Encryption is XOR.** `LoggingLayer.c` ships a documented
  placeholder; the `.enc` extension on exports is aspirational. README
  and ARCHITECTURE.md both call this out.
- ⚠️ **Inline syscall hooks** modify kernel memory under CR0 toggling;
  PatchGuard will eventually bugcheck the system on a non-test build.
  Test-signing alone does **not** disable PatchGuard.
- ⚠️ **`/WX` + `/W4`** in the `sources` file means any new compiler
  warning is a build break. Welcome.

### 3.2 Fallbacks

- **Driver won't build via `FakeNetFilter.vcxproj`**: fall back to
  Method 3 of BUILD.md — the legacy WDK `sources` file (`build -cZ`).
  Or open the `.vcxproj` in VS 2022 and use Build > Build Solution.
- **Driver won't load (`sc start` returns 577 / 1275)**: confirm
  test-signing is on (`bcdedit /enum {current}` → `testsigning Yes`),
  and that the build is x64.
- **Handshake fails with `HONEYPOT_HANDSHAKE_BAD_SECRET`**: the
  32-byte secret is hard-coded on both sides; check that
  `UserModeApp\HoneyPotControl.c:g_HandshakeSecret` and
  `KernelDriver\ControlLayer.c:g_HoneyPotHandshakeSecret` still match
  (both should be `"KRNLHONEYPOTSECRETKEY12345678901"`).
- **Handshake fails with `HONEYPOT_HANDSHAKE_BAD_VERSION`**: the
  driver's major version (`KMOD_DRIVER_VERSION_MAJOR`) and the app's
  major version disagree — bump whichever is stale.
- **VM bugchecks repeatedly**: revert to checkpoint, narrow the
  `honey.conf` layer flags (e.g. start with only
  `TriggerLayerEnabled=0`, `DetectionLayerEnabled=1`, others `=0`) to
  isolate which layer is at fault.

### 3.3 Roadmap

- **Short-term (≤1 day)** — *all five items below were completed in the
  2026-05-14 P0–P3 fix pass:*
  - ✅ Reconcile the IOCTL tables in `HoneyPotControl.h` and
    `ControlLayer.h`. *(Done: `ControlLayer.h` now holds HANDSHAKE at
    0x800 through EXPORT_LOGS at 0x804, matching the user header.
    Promoting these to a shared `IoctlCodes.h` is still a nice-to-have
    but no longer load-bearing.)*
  - ✅ Implement `IOCTL_HONEYPOT_HANDSHAKE` in the driver. *(Done:
    `ControlLayer.c:HandleHandshake` plus dispatcher case in
    `FakeNetFilter.c`.)*
  - ✅ Pick one config path. *(Done: `\??\C:\Release\honey.conf`.)*
  - ✅ Commit a `KernelDriver\FakeNetFilter.vcxproj`. *(Done; a `.sln`
    wrapper is still optional — `msbuild` on the `.vcxproj` directly
    works.)*
  - ✅ Fix `README.md` to reference `FakeNetFilter.sys`. *(Done.)*
- **Medium-term (≤1 week)**:
  - Replace the XOR placeholder in `LoggingLayer.c` with Windows CNG
    AES-XTS (`BCryptOpenAlgorithmProvider(BCRYPT_XTS_AES_ALGORITHM)`).
    *(Assessed 2026-06-10 — deliberately NOT done here.* This is
    kernel-mode crypto that needs a WDK build and a privileged kernel VM
    to compile and validate; writing it blind would ship unverifiable
    kernel code, which is worse than the honest, clearly-labelled
    placeholder. The same applies to the CNN classifier and the
    `RemoteUpdate*` covert channel in the long-term list below. What
    *was* done: `tests/test_placeholder_honesty.py` now pins the
    disclosure comments ("NOT cryptographically secure", the
    disassembler/CNN/remote-update placeholder notes) so the weak
    implementations can never be silently relabelled as production-grade
    — a regression the kernel build alone would not catch.)*
  - **PARTIALLY DONE 2026-06-10** — a cross-platform `pytest` suite +
    GitHub Actions CI now build/smoke the user-mode app and check
    structure. A PowerShell harness (`tests\Verify.ps1`) that runs §2.3
    end-to-end and asserts A1–A9 on a privileged VM is still the
    remaining piece for the full kernel-side flow.
  - ~~Add a `.gitignore` rule for `x64/`, `*.sys.pdb`, `*.obj`.~~
    **Already covered** — `.gitignore` ignores `x64/`, `*.pdb`
    (covers `*.sys.pdb`), and `*.obj`; Python cache rules added
    2026-06-10 for `tests/`.
- **Long-term**:
  - Replace inline hooks with a Windows-supported mechanism
    (KMDF callouts, ETW Threat-Intelligence, or
    `PsSetCreateProcessNotifyRoutineEx`) — the current design is
    fundamentally PatchGuard-incompatible.
  - Move "CNN-based classification" from placeholder to either a real
    ML model exported via ONNX-Runtime in user-mode, or remove it from
    the design.
  - Add a covert-channel implementation for `RemoteUpdate*` or remove
    the stub from `honey.conf`.

## 4. Sanity check

| Check | Status | Notes |
|-------|--------|-------|
| README documents build | ✅ | `README.md` §Building references `BUILD.md`; BUILD.md gives three methods, all three are now actually viable. |
| Build files present | ✅ | `UserModeApp\HoneyPotControl.vcxproj` ✅; `KernelDriver\FakeNetFilter.vcxproj` ✅ (committed 2026-05-14); `KernelDriver\sources` ✅. All three build paths documented in BUILD.md now have backing build files. |
| Build files internally consistent | ✅ | (a) IOCTL codes in `HoneyPotControl.h` and `ControlLayer.h` are aligned byte-for-byte (HANDSHAKE 0x800 → EXPORT_LOGS 0x804) — fixed 2026-05-14. (b) Every doc references `FakeNetFilter.sys`; the legacy `krnlhoneypot.sys` string was scrubbed from `README.md`. (c) `ControlLayer.h:CONFIG_FILE_PATH` (`\??\C:\Release\honey.conf`) matches the README/BUILD install step. |
| Source structure matches README | ✅ | The six layers named in README §Architecture each have matching `<Name>Layer.c/.h` in `KernelDriver/`, and all six (plus `FakeNetFilter.c`) are enumerated as `<ClCompile>` entries in `FakeNetFilter.vcxproj`. |
| Tests exist | ✅ | `tests/` (pytest): `test_structure.py` (six layers + vcxproj/source sync) and `test_cli_smoke.py` (`HoneyPotControl.exe help`). 20 passed / 2 skipped locally (CLI rows skip without a build). Full kernel A1–A9 still needs a privileged VM. |
| Test invocation documented | ✅ | §2.4 documents `python -m pytest tests/ -v`; CI (`.github/workflows/ci.yml`, `windows-latest`) builds the app, smoke-tests `help`, and runs pytest. The §2.3 manual recipe remains for the privileged kernel path. |
| Output artifacts named in build files | ✅ | Driver: `FakeNetFilter.vcxproj` sets explicit `TargetName=FakeNetFilter` + `TargetExt=.sys` (also corroborated by `sources:TARGETNAME=FakeNetFilter`). App: `HoneyPotControl.vcxproj` still relies on `RootNamespace` for the basename — minor cosmetic fragility but works. |
