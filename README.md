# Kernel-Mode Deception Framework (KDF)

A six-layer kernel-mode honeypot for Windows that observes attacker
interaction with the kernel, redirects probing into a fake "universe" of
synthetic kernel objects, and produces structured behavioural reports
suitable for downstream forensic review.

Designed as a research artefact and analyst tool, not a runtime
mitigation. The driver does not block, terminate, or otherwise interfere
with attacker code paths beyond observing and redirecting them.

---

## Architecture

```
[Trigger] -> [Detection] -> [Deception] -> [Logging] -> [Extraction] -> [Control]
```

| Layer | Responsibility |
|---|---|
| Trigger | Fake device driver, fake registry keys. Also implements passive inline hooks for a curated syscall set (`NtOpenProcess`, `ZwQuerySystemInformation`), but **these are experimental and not wired up**: `InitializeTriggerLayer()` never calls `InstallInlineHook()`, so the driver as shipped does not hook anything and observes no syscalls. See "Status" below. |
| Detection | Kernel-mode syscall logger; per-call stack fingerprinting; memory-access pattern tracking; RWX-allocation heuristics. Only reachable once the Trigger-layer hooks above are wired up. |
| Deception | Synthetic `EPROCESS` / `ETHREAD` objects with non-canonical `PEB` addresses. `UpdateFakeStructures()` (anti-fingerprint mutation) exists but is not currently called by any timer, so fake structures do not change over time yet. |
| Logging | Non-paged-pool ring buffer; AES-XTS encryption (currently a documented placeholder, see `LoggingLayer.c`). Export is on-demand via IOCTL today; automatic periodic export is not yet wired to a timer. |
| Extraction | Payload pattern matching (heap-spray, ROP-chain signatures) and classification helpers exist but currently have no call sites -- nothing feeds them data until the Trigger-layer hooks are wired up. |
| Control | Config parser; per-layer enable/disable; IOCTL surface for user-mode tooling. |

Detailed flow: `ARCHITECTURE.md`.

## Building

See `BUILD.md` for the full instructions, including WDK / VS prerequisites
and three build paths (Visual Studio, MSBuild, legacy WDK `sources`).

Short form:

```cmd
cd KernelDriver
build -cZ                    # WDK build environment, uses the sources file

cd ..\UserModeApp
msbuild HoneyPotControl.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Installation

```cmd
bcdedit /set testsigning on            # one-time, requires reboot
mkdir C:\Release
copy KernelDriver\x64\Release\FakeNetFilter.sys C:\Release\
copy config\honey.conf C:\Release\
sc create FakeNetFilter binPath= "C:\Release\FakeNetFilter.sys" type= kernel
sc start FakeNetFilter
HoneyPotControl.exe
```

## Configuration

Edit `C:\Release\honey.conf` (copied from `config/honey.conf` at install
time) to configure layer enablement, buffer sizes, and intervals. The
sample config documents every key.

## Threat model and scope

This is **observability and deception infrastructure**, not a mitigation:

- The driver does not block, terminate, or unhook attacker code.
- It does not make security decisions on behalf of the system.
- The encryption used by the logging layer is a documented placeholder
  (`LoggingLayer.c`); production deployment requires replacing it with
  Windows CNG–backed AES-XTS.
- Several detection heuristics (CNN-based behaviour classification, SPI
  hardware integration) are explicitly placeholders.

It is intended for use on dedicated research VMs / lab hosts that the
operator owns, with test-signing enabled.

## Limitations

- **Inline hooking is experimental and not wired up.** `InstallInlineHook()`
  and the `Hooked*` stubs in `TriggerLayer.c` exist but have no active call
  path in the shipped driver, and the stubs do not call through to the real
  syscall -- installing them as-is would break real process-handle opens on
  the system. Hooking is inline on a curated syscall set by design; full
  SSDT coverage is out of scope regardless.
- Stack fingerprint / heuristic-based detection produces false positives
  on legitimate JIT engines and other RWX-using workloads, and is only
  reachable once the hooks above are wired up.
- Crypto and disassembly are simplified (see source comments).
- `tests/` (pytest) covers repo structure and the user-mode CLI; there is
  no automated harness for the kernel driver itself, which requires a
  privileged test environment to exercise.

## Status

Research / non-production. The Trigger/Detection/Extraction pipeline
described above (inline hooking, exploit fingerprinting) is present in
source but not wired to run by default -- see "Limitations". Intended for
lab and academic study of kernel-mode deception techniques.

## References

- L. Spitzner, *Honeypots: Tracking Hackers*. Addison-Wesley, 2002.
- N. Provos, *A Virtual Honeypot Framework* (Honeyd). USENIX Security, 2004.
- NIST SP 800-160 vol. 2, *Developing Cyber-Resilient Systems: A Systems
  Security Engineering Approach* — covers deception as a design
  pattern.
- Microsoft Driver Development Kit — KMDF reference for the driver
  primitives used here.

## License

MIT — see `LICENSE`.
