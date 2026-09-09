<#
.SYNOPSIS
  Deploy and load FakeNetFilter.sys as a kernel service. SAFETY-GATED.
.DESCRIPTION
  Runs INSIDE the disposable guest. Without -Arm it is a DRY-RUN (prints the
  commands only). With -Arm it creates and starts the kernel service.
  Checkpoint the guest first; a kernel load can bugcheck it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$SysPath,
    [string]$Service = 'FakeNetFilter',
    [switch]$Arm
)
$ErrorActionPreference = 'Stop'
$steps = @(
    "sc.exe create $Service type= kernel start= demand binPath= `"$SysPath`"",
    "verifier /standard /driver FakeNetFilter.sys   # enable BEFORE start; needs reboot",
    "sc.exe start $Service",
    "sc.exe query $Service"
)
if (-not $Arm) {
    Write-Host "[load] DRY-RUN (no -Arm). Would run, inside the guest:" -ForegroundColor Yellow
    $steps | ForEach-Object { Write-Host "    $_" }
    Write-Host "[load] Re-run with -Arm on the DISPOSABLE guest, after a checkpoint." -ForegroundColor Yellow
    return
}
if (-not (Test-Path $SysPath)) { Write-Error "SysPath not found: $SysPath"; exit 2 }
Write-Host "[load] ARMED. Creating service $Service ..." -ForegroundColor Red
& sc.exe create $Service type= kernel start= demand binPath= "$SysPath"
Write-Host "[load] Starting $Service ..."
& sc.exe start $Service
& sc.exe query $Service
