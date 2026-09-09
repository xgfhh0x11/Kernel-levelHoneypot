# Kernel-Level Honeypot Architecture

## Overview

This kernel-level honeypot system implements a multi-layered architecture designed to detect, deceive, and analyze attacker behavior at the Windows kernel level (Ring 0).

> **Status note:** this document describes the intended design of all six
> layers. As shipped, the Trigger-layer inline hooks are **not wired up**
> (`InitializeTriggerLayer()` never calls `InstallInlineHook()`), so the
> Detection/Extraction pipeline they would feed currently has no live data
> path, "Automatic Export" and the Deception layer's "Anti-Fingerprint
> Mechanism" are not attached to any timer, and several Extraction-layer
> analysis functions have no call sites in the driver. Each affected
> section below is flagged accordingly. See README.md "Limitations" and
> `BUILD_AND_VERIFY.md` for details.

## Pipeline Flow

```
[Trigger] -> [Detection] -> [Deception] -> [Logging] -> [Extraction] -> [Control]
```

## Layer Details

### 1. Trigger Layer (Entrypoint)

**Purpose**: Attract attacker interaction through fake resources.

**Components**:
- **Fake Device Driver** (`FakeNetFilter.sys`): Appears as a legitimate network filter driver
- **Fake Registry Keys**: Creates `HKLM\SYSTEM\FakeService` to attract registry scanners
- **Passive Inline Hooks** (⚠️ experimental, not wired up -- see status note
  above): implemented to hook critical syscalls, but never installed by
  `InitializeTriggerLayer()`:
  - `NtOpenProcess`: Intercepts process handle requests
  - `ZwQuerySystemInformation`: Intercepts system information queries

**Hook Strategy** (as designed; not currently active):
- Uses passive inline hooks (not SSDT hooks to avoid detection)
- Modifies function prologue with JMP instruction
- Preserves original functionality while logging -- **not actually true of
  the current stubs**: `HookedNtOpenProcess` never calls through to the
  real `NtOpenProcess`, so wiring this up as-is would break real
  process-handle opens system-wide (see `TriggerLayer.c`).

**Files**:
- `TriggerLayer.h` / `TriggerLayer.c`

### 2. Detection Layer (Stealth Sensor)

**Purpose**: Observe attacker behavior without detection.

**Components**:
- **Kernel-Mode Syscall Logger**: Logs all hooked syscalls with:
  - Timestamp
  - Process/Thread IDs
  - Return address
  - Parameters
  - Stack fingerprint
- **Stack Fingerprinting**: Captures stack state to detect ROP chains
- **Memory Access Pattern Tracker**: Monitors memory allocations and protections
  - Detects RWX memory (common in exploits)
  - Tracks DMA access patterns

**Detection Heuristics**:
- RWX memory allocation → Suspicious
- Making memory executable → Suspicious
- Thread creation → Suspicious
- High-privilege process access → Suspicious

**Files**:
- `DetectionLayer.h` / `DetectionLayer.c`

### 3. Deception Layer (Manipulation Module)

**Purpose**: Redirect attacker to a fake universe.

**Components**:
- **Fake EPROCESS Objects**: Creates fake process structures
  - Fake PIDs
  - Fake image names
  - Fake PEB addresses (non-canonical)
- **Fake ETHREAD Objects**: Creates fake thread structures
- **Fake Memory Layout**: Creates fake memory regions with non-canonical addresses
- **Anti-Fingerprint Mechanism**: `UpdateFakeStructures()` implements periodic
  fake-structure mutation, but ⚠️ it is not currently invoked by any
  timer/DPC/work-item -- it will not run unless something calls it.

**Deception Strategy**:
- When attacker queries fake process → Returns fake handle (requires the
  Trigger-layer hooks to be wired up first -- see status note above)
- When attacker queries system info → Returns fake process list
- Fake structures change over time (anti-fingerprint) -- ⚠️ not active yet,
  see `UpdateFakeStructures()` above

**Files**:
- `DeceptionLayer.h` / `DeceptionLayer.c`

### 4. Logging Layer (Hidden Recording)

**Purpose**: Securely record all interactions.

**Components**:
- **Ring0 Log Buffer**: Non-paged pool buffer for log entries
- **Timestamp + Syscall + Stack Hash**: Each entry includes:
  - Precise timestamp
  - Syscall type
  - Stack hash (SHA-256)
  - Process/Thread IDs
  - Entry data
- **AES-XTS Encryption**: Encrypts logs before export (currently a documented
  XOR placeholder, see `LoggingLayer.c`)
- **Automatic Export**: `LogEntry()` sets an `ExportPending` flag once the
  configured interval elapses, but ⚠️ nothing polls that flag -- there is
  no timer/DPC in this driver, so periodic export does not happen today.
  `IOCTL_HONEYPOT_EXPORT_LOGS` (on-demand export) and the unload-time flush
  in `CleanupLoggingLayer()` are the two paths that actually run.

**Log Entry Types**:
- `LogEntrySyscall`: Syscall invocations
- `LogEntryMemoryAccess`: Memory operations
- `LogEntryRegistryAccess`: Registry operations
- `LogEntryDeception`: Deception events
- `LogEntryExtraction`: Analysis results

**Files**:
- `LoggingLayer.h` / `LoggingLayer.c`

### 5. Extraction Layer (Data Extraction & Analysis)

**Purpose**: Analyze attacker's technical capabilities and tools.

⚠️ **Status**: `DisassemblePayload`, `AnalyzeHeapSpray`, `AnalyzeROPChain`,
`AnalyzeSyscallAbuse`, and `ClassifyBehavior` have no call sites in this
driver today -- there is no live path feeding them attacker data until the
Trigger-layer hooks (§1) are wired up. They are implemented and tested only
at the level of "compiles and is internally correct," not exercised.

**Components**:
- **Payload Disassembler**: Analyzes shellcode/payloads
  - Detects shellcode patterns
  - Identifies packed code
  - Counts suspicious instructions
- **Exploit Fingerprinting**: Identifies exploit types:
  - Heap Spray
  - ROP Chains
  - Syscall Abuse
  - Stack Overflow
  - Use-After-Free
  - Double Free
- **CNN-Based Behavior Classification**: Placeholder for future neural network integration

**Analysis Capabilities**:
- Heap spray detection (repeated patterns)
- ROP chain detection (RET instruction patterns)
- Syscall abuse detection (rapid syscalls)
- Shellcode identification

**Files**:
- `ExtractionLayer.h` / `ExtractionLayer.c`

### 6. Control Layer (Management & Configuration)

**Purpose**: Dynamic management of honeypot.

**Components**:
- **Configuration Parser**: Reads `C:\Release\honey.conf`
- **Layer Enable/Disable**: Can enable/disable individual layers
- **Remote Stealth Update**: Placeholder for covert channel updates
- **IOCTL Interface**: User-mode communication via device I/O

**Configuration Options**:
- Layer enable/disable flags
- Buffer sizes
- Update intervals
- Encryption settings

**IOCTL Commands**:
- `IOCTL_HONEYPOT_GET_STATS`: Get statistics
- `IOCTL_HONEYPOT_GET_LOGS`: Get log entries
- `IOCTL_HONEYPOT_RELOAD_CONFIG`: Reload configuration
- `IOCTL_HONEYPOT_EXPORT_LOGS`: Export logs to file

**Files**:
- `ControlLayer.h` / `ControlLayer.c`

## User-Mode Interface

**HoneyPotControl.exe**: Command-line application for:
- Viewing statistics
- Exporting logs
- Reloading configuration
- Monitoring honeypot state

## Data Flow Example

⚠️ This is the *intended* flow once the Trigger-layer hooks (§1) are wired
up. As shipped, step 2 does not happen, so steps 3-7 never run.

1. **Attacker** calls `NtOpenProcess` to open a process
2. **Trigger Layer** hook intercepts the call
3. **Detection Layer** logs the syscall with stack fingerprint
4. **Deception Layer** checks if target is a fake process
   - If fake → Returns fake handle
   - If real → Proceeds normally (or redirects)
5. **Logging Layer** records the event with encryption
6. **Extraction Layer** analyzes the call pattern
7. **Control Layer** manages the overall flow

## Security Considerations

⚠️ **Important Notes**:

1. **Encryption**: Current implementation uses simplified XOR (NOT secure). Replace with proper AES-XTS in production.

2. **Hook Installation**: Inline hooks modify kernel memory. Must:
   - Raise IRQL to HIGH_LEVEL
   - Disable write protection (CR0)
   - Flush instruction cache
   - Re-enable protection

3. **Memory Safety**: All kernel allocations use pool tags for debugging.

4. **Test Signing**: Driver requires test signing enabled (development only).

## Future Enhancements

1. **CNN Integration**: Real neural network for behavior classification
2. **Proper Crypto**: Replace simplified encryption with Windows CNG
3. **SPI Flash**: Hardware-based module activation (mentioned but not implemented)
4. **Covert Channel**: Remote update mechanism via hidden communication
5. **GUI Visualization**: Graphical interface for exploit chain visualization
6. **Advanced Disassembler**: Integration with Capstone or similar

## Performance Considerations

- **Log Buffer**: Circular buffer to prevent overflow
- **Spinlocks**: Used for thread-safe access to shared data
- **Non-Paged Pool**: All critical buffers in non-paged memory
- **IRQL Awareness**: All operations respect IRQL requirements

## Limitations

1. **Simplified Crypto**: Encryption is placeholder
2. **Basic Disassembler**: Limited disassembly capabilities
3. **No CNN**: Behavior classification uses heuristics only
4. **No SPI**: Hardware integration not implemented
5. **Hooks not wired up**: hook implementations exist for a small syscall
   set (expandable in principle), but `InitializeTriggerLayer()` never
   installs them -- see the status note at the top of this document

