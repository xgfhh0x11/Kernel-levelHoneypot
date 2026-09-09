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
| Trigger | Fake device driver, fake registry keys, passive inline hooks on a curated set of syscalls (`NtOpenProcess`, `ZwQuerySystemInformation`). |
| Detection | Kernel-mode syscall logger; per-call stack fingerprinting; memory-access pattern tracking; RWX-allocation heuristics. |
| Deception | Synthetic `EPROCESS` / `ETHREAD` objects with non-canonical `PEB` addresses; periodic anti-fingerprint mutation. |
| Logging | Non-paged-pool ring buffer; AES-XTS encryption (currently a documented placeholder, see `LoggingLayer.c`); periodic export. |
| Extraction | Payload pattern matching (heap-spray, ROP-chain signatures); per-event classification labels for downstream review. |
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

- Hooks are inline on a curated syscall set; full SSDT coverage is out
  of scope.
- Stack fingerprint / heuristic-based detection produces false positives
  on legitimate JIT engines and other RWX-using workloads.
- Crypto and disassembly are simplified (see source comments).
- No automated tests; the driver requires a privileged test environment
  to exercise.

## Status

Research / non-production. Intended for lab and academic study of
kernel-mode deception techniques.

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
