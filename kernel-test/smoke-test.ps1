<#
.SYNOPSIS
  Smoke-test the loaded FakeNetFilter driver via its IOCTL surface. SAFETY-GATED.
.DESCRIPTION
  Runs INSIDE the guest after the driver is loaded. Opens \\.\FakeNetFilter,
  sends HANDSHAKE first (several IOCTLs gate on it), then GET_STATS, GET_LOGS,
  RELOAD_CONFIG, and EXPORT_LOGS (to confirm the buffered-IOCTL fix actually
  acts). Dry-run unless -Arm.
#>
[CmdletBinding()]
param([switch]$Arm)

# CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, func, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
function Ctl([int]$func) { return (0x22 -shl 16) -bor ($func -shl 2) }
$ioctls = [ordered]@{
    IOCTL_HONEYPOT_HANDSHAKE     = Ctl 0x800
    IOCTL_HONEYPOT_GET_STATS     = Ctl 0x801
    IOCTL_HONEYPOT_GET_LOGS      = Ctl 0x802
    IOCTL_HONEYPOT_RELOAD_CONFIG = Ctl 0x803
    IOCTL_HONEYPOT_EXPORT_LOGS   = Ctl 0x804
}

if (-not $Arm) {
    Write-Host "[smoke] DRY-RUN (no -Arm). Would open \\.\FakeNetFilter and issue (HANDSHAKE first):" -ForegroundColor Yellow
    $ioctls.GetEnumerator() | ForEach-Object { Write-Host ("    {0} = 0x{1:X8}" -f $_.Key, $_.Value) }
    Write-Host "[smoke] EXPORT_LOGS must actually write/act (not silent-success) -- that is the fix under test." -ForegroundColor Yellow
    Write-Host "[smoke] Re-run with -Arm inside the DISPOSABLE guest (driver loaded, verifier on)." -ForegroundColor Yellow
    return
}

$sig = @'
using System;
using System.Runtime.InteropServices;
public static class Dev {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFile(string n, uint acc, uint share, IntPtr sa, uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inb, uint inl, byte[] outb, uint outl, out uint ret, IntPtr ov);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
}
'@
Add-Type -TypeDefinition $sig
$GENERIC_RW = 0xC0000000; $OPEN_EXISTING = 3
$h = [Dev]::CreateFile('\\.\FakeNetFilter', $GENERIC_RW, 0, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)
if ($h -eq [IntPtr](-1) -or $h -eq [IntPtr]::Zero) {
    Write-Error "CreateFile \\.\FakeNetFilter failed (Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())). Is the driver loaded?"; exit 2
}
try {
    foreach ($e in $ioctls.GetEnumerator()) {
        $inb  = New-Object byte[] 256
        $outb = New-Object byte[] 4096
        $ret = 0
        $ok = [Dev]::DeviceIoControl($h, [uint32]$e.Value, $inb, [uint32]$inb.Length, $outb, [uint32]$outb.Length, [ref]$ret, [IntPtr]::Zero)
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host ("[smoke] {0,-30} ok={1} bytes={2} win32err={3}" -f $e.Key, $ok, $ret, $err)
    }
} finally { [Dev]::CloseHandle($h) | Out-Null }
Write-Host "[smoke] done. HANDSHAKE should succeed; gated IOCTLs should then work; no bugcheck expected."
