<#
.SYNOPSIS
  Build FakeNetFilter.sys (WDM, Release, x64) with the host WDK. Runs on the HOST.
.DESCRIPTION
  Builds KernelDriver/FakeNetFilter.vcxproj and reports the .sys path. On failure
  it prints the compiler errors verbatim and exits non-zero. If this host lacks
  WDM kernel headers (ntifs.h), the build will fail here -- build in the guest or
  on a full WDK box (see README).
#>
[CmdletBinding()]
param(
    [ValidateSet('Release','Debug')] [string]$Configuration = 'Release',
    [string]$Platform = 'x64',
    [string]$TestCertificateThumbprint
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$proj = Join-Path $repo 'KernelDriver\FakeNetFilter.vcxproj'
if (-not (Test-Path $proj)) { Write-Error "Project not found: $proj"; exit 2 }

$msbuild = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' 2>$null | Select-Object -First 1
}
if (-not $msbuild) { $msbuild = (Get-Command msbuild.exe -ErrorAction SilentlyContinue).Source }
if (-not $msbuild) { Write-Error 'msbuild.exe not found (install VS + WDK build tools).'; exit 2 }

$args = @($proj, "/p:Configuration=$Configuration", "/p:Platform=$Platform", '/nologo', '/v:minimal')
if ($TestCertificateThumbprint) { $args += "/p:TestCertificate=$TestCertificateThumbprint" }
$log = Join-Path $PSScriptRoot 'build.log'
$args += @('/fl', "/flp:logfile=$log;verbosity=normal")
Write-Host "[build] msbuild: $msbuild"
Write-Host "[build] $proj ($Configuration|$Platform)"
& $msbuild @args
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host "[build] FAILED (exit $code). Errors:" -ForegroundColor Red
    if (Test-Path $log) { Select-String -Path $log -Pattern 'error|fatal' | ForEach-Object { $_.Line } }
    Write-Host "[build] If this is a missing-ntifs.h/WDK-headers failure, build in the guest or a WDK box (README)." -ForegroundColor Yellow
    exit $code
}
$sys = Get-ChildItem -Path $repo -Recurse -Filter 'FakeNetFilter.sys' -ErrorAction SilentlyContinue |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $sys) { Write-Error 'Build reported success but FakeNetFilter.sys was not found.'; exit 3 }
Write-Host "[build] OK: $($sys.FullName)" -ForegroundColor Green
Write-Output $sys.FullName
