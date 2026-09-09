#pragma once

#include <ntddk.h>

// Extraction Layer: Data extraction and analysis

#define MAX_PAYLOAD_SIZE (64 * 1024) // 64KB
#define MAX_EXPLOIT_PATTERNS 100
#define MAX_DISASSEMBLY_LINES 1000

typedef enum _EXPLOIT_TYPE {
    ExploitHeapSpray,
    ExploitROP,
    ExploitSyscallAbuse,
    ExploitStackOverflow,
    ExploitUseAfterFree,
    ExploitDoubleFree,
    ExploitUnknown
} EXPLOIT_TYPE;

typedef struct _EXPLOIT_FINGERPRINT {
    EXPLOIT_TYPE ExploitType;
    UCHAR PatternHash[32]; // SHA-256
    ULONG PatternSize;
    ULONG_PTR PatternAddress;
    LARGE_INTEGER DetectionTime;
    BOOLEAN IsConfirmed;
} EXPLOIT_FINGERPRINT, *PEXPLOIT_FINGERPRINT;

typedef struct _PAYLOAD_ANALYSIS {
    ULONG_PTR PayloadAddress;
    ULONG PayloadSize;
    UCHAR PayloadHash[32];
    ULONG InstructionCount;
    ULONG SuspiciousInstructionCount;
    BOOLEAN IsShellcode;
    BOOLEAN IsPacked;
    CHAR Disassembly[4096]; // Truncated disassembly
} PAYLOAD_ANALYSIS, *PPAYLOAD_ANALYSIS;

typedef struct _EXTRACTION_LAYER_STATE {
    BOOLEAN Initialized;
    
    // Payload disassembler
    BOOLEAN DisassemblerEnabled;
    
    // Exploit fingerprinting
    EXPLOIT_FINGERPRINT ExploitPatterns[MAX_EXPLOIT_PATTERNS];
    ULONG ExploitPatternCount;
    KSPIN_LOCK ExploitPatternLock;
    
    // Payload analysis
    PAYLOAD_ANALYSIS PayloadAnalyses[100];
    ULONG PayloadAnalysisCount;
    KSPIN_LOCK PayloadAnalysisLock;
    
    // CNN-based behavior classification (placeholder for future implementation)
    BOOLEAN CNNEnabled;
    
    // Statistics
    ULONG64 PayloadsAnalyzed;
    ULONG64 ExploitsDetected;
} EXTRACTION_LAYER_STATE, *PEXTRACTION_LAYER_STATE;

// Function declarations
NTSTATUS InitializeExtractionLayer(VOID);
VOID CleanupExtractionLayer(VOID);
// NOTE: DisassemblePayload / AnalyzeHeapSpray / AnalyzeROPChain /
// AnalyzeSyscallAbuse / ClassifyBehavior have NO CALL SITES anywhere in this
// driver -- nothing feeds them real attacker data (the syscall hooks that
// would are themselves never installed; see TriggerLayer.c). Kept as
// library-style functions for future wiring; see ExtractionLayer.c.
NTSTATUS DisassemblePayload(PVOID PayloadAddress, ULONG PayloadSize, PPAYLOAD_ANALYSIS Analysis);
NTSTATUS FingerprintExploit(PVOID PatternAddress, ULONG PatternSize, EXPLOIT_TYPE ExploitType, PEXPLOIT_FINGERPRINT Fingerprint);
NTSTATUS AnalyzeHeapSpray(PVOID MemoryRegion, SIZE_T RegionSize);
NTSTATUS AnalyzeROPChain(PVOID StackAddress, ULONG StackSize);
NTSTATUS AnalyzeSyscallAbuse(PSYSCALL_LOG_ENTRY SyscallEntry);
BOOLEAN ClassifyBehavior(PSYSCALL_LOG_ENTRY Entry); // Placeholder for CNN

