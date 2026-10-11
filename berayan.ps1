<#
.SYNOPSIS
    Berayan - run NordVPN or Windscribe *through* your v2rayN / sing-box tunnel, from one terminal app.

.DESCRIPTION
    Interactive terminal app (menu stays on screen):
      1. choose the VPN (NordVPN or Windscribe)
      2. choose the protocol (IKEv2, Stealth, TCP, ...)
      3. choose the location
    Berayan then pins the routes, turns on its leak guard, connects the VPN through v2ray, proves the
    chain with real traffic and keeps it healthy (auto-repair) while the window stays open.

    Scripting / automation: use vpn-chain.ps1 (same engine, plain commands).

.PARAMETER ReadOnly
    Start without Administrator rights: status, test, diagnose and log only.
#>
param([switch]$ReadOnly, [switch]$NoElevate)

$ErrorActionPreference = 'Stop'
$script:RootDir = $PSScriptRoot
foreach ($m in 'Common', 'Net', 'Providers', 'Detect', 'Verify', 'Engine', 'Tui') { . (Join-Path $PSScriptRoot "src\$m.ps1") }
Initialize-Log

if ($PSVersionTable.PSVersion.Major -lt 5) { Write-Host 'Berayan needs Windows PowerShell 5.1 or newer.' -ForegroundColor Red; exit 1 }
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { Write-Host 'Berayan runs on Windows 10 / 11 only (it drives the Windows network stack).' -ForegroundColor Red; exit 1 }

if (-not $ReadOnly -and -not (Test-IsAdmin)) {
    Write-Host ''
    Write-Host '  Berayan needs Administrator rights: it adds host routes and Windows Firewall rules' -ForegroundColor Yellow
    Write-Host '  (removed again when you disconnect). Opening an elevated window ...' -ForegroundColor Yellow
    if (-not $NoElevate) {
        try {
            $exe = (Get-Process -Id $PID).Path     # same PowerShell edition the user started us with
            Start-Process -FilePath $exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath)) | Out-Null
            exit 0
        } catch {
            Write-Host '  Elevation was declined - starting in READ-ONLY mode (status, test, diagnose, log).' -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
    $ReadOnly = $true
}

Write-Log CLI "berayan $script:AppVersion started (admin=$(Test-IsAdmin), readOnly=$ReadOnly, PS $($PSVersionTable.PSVersion))" -Level DEBUG
try {
    Start-BerayanTui -ReadOnly:$ReadOnly
} catch {
    try { [Console]::Write("$([char]27)[r$([char]27)[?25h$([char]27)[0m") } catch { }
    Write-Host ''
    Write-Host "Berayan stopped with an error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log CLI "fatal: $($_.Exception.Message) $($_.ScriptStackTrace -replace "`r?`n", ' <- ')" -Level ERROR
    Write-Host "Details are in $script:LogDir. Press any key to close." -ForegroundColor DarkGray
    try { [void][Console]::ReadKey($true) } catch { }
    exit 1
}
