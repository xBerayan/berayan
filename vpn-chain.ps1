<#
.SYNOPSIS
    vpn-chain - route NordVPN's own transport through an existing v2rayN / sing-box TUN tunnel.

.DESCRIPTION
    Applications -> NordVPN tunnel -> (NordVPN transport) -> upstream TUN -> upstream server -> NordVPN server -> Internet

    Commands:
      start     detect, snapshot, pin routes, enable leak guard, wait for NordVPN, verify, monitor
      stop      remove everything vpn-chain created and verify normal connectivity
      status    concise health summary
      diagnose  detailed routing / adapter / DNS diagnostics (read-only)
      test      behavioural leak + chain tests (public IP, DNS, IPv6, traffic correlation)
      reset     crash recovery: undo any leftover vpn-chain changes
      monitor   re-attach the auto-repair monitor to an active session

.EXAMPLE
    .\vpn-chain.ps1 start                       (asks which VPN: NordVPN or Windscribe)
    .\vpn-chain.ps1 start -Vpn windscribe -Connect -Location DE -Protocol stealth
    .\vpn-chain.ps1 start -Vpn nordvpn -Connect -Location "Germany"
    .\vpn-chain.ps1 status
    .\vpn-chain.ps1 stop -DisconnectNord
#>
param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'stop', 'status', 'diagnose', 'test', 'reset', 'monitor', 'guard-on', 'guard-off', 'help')]
    [string]$Command = 'help',

    [ValidateSet('', 'nordvpn', 'windscribe')]
    [string]$Vpn,              # which VPN to chain through v2ray (asked interactively if omitted)
    [string]$ConfigPath,
    [switch]$VerboseLog,       # verbose diagnostics on the console (always written to the log file)
    [switch]$NoMonitor,        # start: return after verification instead of monitoring
    [switch]$NoElevate,        # never offer a UAC relaunch
    [switch]$Connect,          # start: let the VPN app connect via its documented CLI
    [string]$Location,         # start -Connect: NordVPN group/country ("Germany") or Windscribe location ("DE", "Frankfurt", best)
    [string]$Protocol,         # start -Connect (Windscribe): wireguard | ikev2 | udp | tcp | stealth | wstunnel
    [string]$NordGroup,        # alias of -Location for NordVPN
    [string]$NordServer,       # start -Connect: server name, e.g. "Germany #123"
    [string]$NordEndpoint,     # override: NordVPN server IP to pin
    [string[]]$UpstreamServer, # override: upstream server IP(s)/hostname(s)/CIDR(s)
    [string]$UpstreamAdapter,  # override: upstream interface alias
    [switch]$NoKillSwitch,     # start: do not block WAN-side traffic (weaker)
    [switch]$KeepOnFailure,    # start: leave changes in place when verification fails (debugging)
    [switch]$DisconnectNord    # stop/reset: disconnect NordVPN first via its documented CLI
)

$ErrorActionPreference = 'Stop'
$script:RootDir = $PSScriptRoot
. (Join-Path $PSScriptRoot 'src\Common.ps1')
. (Join-Path $PSScriptRoot 'src\Net.ps1')
. (Join-Path $PSScriptRoot 'src\Providers.ps1')
. (Join-Path $PSScriptRoot 'src\Detect.ps1')
. (Join-Path $PSScriptRoot 'src\Verify.ps1')
. (Join-Path $PSScriptRoot 'src\Engine.ps1')

$script:Verbose = [bool]$VerboseLog

if ($Command -eq 'help') { Get-Help $PSCommandPath -Detailed | Out-String | Write-Host; exit 0 }

Initialize-Log
Write-Log CLI "vpn-chain $Command (admin=$(Test-IsAdmin), PS $($PSVersionTable.PSVersion))" -Level DEBUG

$originalArgs = @($Command) + @($MyInvocation.BoundParameters.GetEnumerator() | Where-Object { $_.Key -ne 'Command' } | ForEach-Object {
    if ($_.Value -is [System.Management.Automation.SwitchParameter]) { if ($_.Value) { "-$($_.Key)" } }
    elseif ($_.Value -is [array]) { "-$($_.Key)"; ($_.Value -join ',') }
    else { "-$($_.Key)"; [string]$_.Value }
})

$exitCode = 1
try {
    $cfg = Get-Config -Path $ConfigPath
    if ($NordEndpoint)    { $cfg.nordvpn.endpoint = $NordEndpoint }
    if ($UpstreamServer)  { $cfg.upstream.serverAddresses = @($UpstreamServer | ForEach-Object { $_ -split ',' } | Where-Object { $_ }) }
    if ($UpstreamAdapter) { $cfg.upstream.adapter = $UpstreamAdapter }
    if ($NoKillSwitch)    { $cfg.killSwitch = $false }
    # Which VPN is chained on top of v2ray: -Vpn > running session > config vpn.provider > menu (start only).
    $prov = Select-VpnProvider -Requested $Vpn -Config $cfg -Session (Read-Session) -Interactive:($Command -eq 'start')
    Set-VpnProvider $prov
    Write-Log CLI "chained VPN: $script:VpnName" -Level DEBUG
    if (-not $Vpn) { $script:originalArgs = @($originalArgs) + @('-Vpn', $prov) }   # elevated relaunch must not ask again
    if (-not $Location -and $NordGroup) { $Location = $NordGroup }
    if (-not $Location -and $cfg.vpn.Contains('location')) { $Location = [string]$cfg.vpn.location }
    if (-not $Protocol -and $cfg.vpn.Contains('protocol')) { $Protocol = [string]$cfg.vpn.protocol }
    if ($Protocol -and $script:ChainVpn.Protocols -notcontains $Protocol.ToLowerInvariant()) { throw "Protocol '$Protocol' is not supported for $script:VpnName (supported: $($script:ChainVpn.Protocols -join ', '))." }
    $opt = @{ KeepGuard = $false; NoMonitor = [bool]$NoMonitor; Connect = [bool]$Connect; Location = $Location; Protocol = $Protocol; NordServer = $NordServer; KeepOnFailure = [bool]$KeepOnFailure; DisconnectNord = [bool]$DisconnectNord }

    switch ($Command) {
        'start'    { if (-not (Assert-Admin -Command $Command -OriginalArgs $originalArgs -NoElevate:$NoElevate)) { $exitCode = 2; break }; $exitCode = @(Invoke-Start $cfg $opt )[-1] }
        'stop'     { if (-not (Assert-Admin -Command $Command -OriginalArgs $originalArgs -NoElevate:$NoElevate)) { $exitCode = 2; break }; $exitCode = @(Invoke-Stop $cfg $opt )[-1] }
        'reset'    { if (-not (Assert-Admin -Command $Command -OriginalArgs $originalArgs -NoElevate:$NoElevate)) { $exitCode = 2; break }; $exitCode = @(Invoke-Stop $cfg $opt -Reset )[-1] }
        'monitor'  { if (-not (Assert-Admin -Command $Command -OriginalArgs $originalArgs -NoElevate:$NoElevate)) { $exitCode = 2; break }; $exitCode = @(Invoke-Monitor $cfg )[-1] }
        'guard-on' { if (-not (Assert-Admin -Command $Command -OriginalArgs $originalArgs -NoElevate:$NoElevate)) { $exitCode = 2; break }; $exitCode = @(Invoke-GuardOn $cfg)[-1] }
        'guard-off'{ if (-not (Assert-Admin -Command $Command -OriginalArgs $originalArgs -NoElevate:$NoElevate)) { $exitCode = 2; break }; $exitCode = @(Invoke-Stop $cfg $opt)[-1] }
        'status'   { $st = Write-StatusSummary -Config $cfg; $exitCode = if ($st -eq 'CHAIN_OK') { 0 } else { 4 } }
        'diagnose' { $exitCode = @(Invoke-Diagnose $cfg )[-1] }
        'test'     { $exitCode = @(Invoke-Test $cfg )[-1] }
    }
} catch {
    Write-Log CLI "fatal: $($_.Exception.Message)" -Level ERROR
    Write-Log CLI ($_.ScriptStackTrace -replace "`r?`n", ' <- ') -Level DEBUG
    $exitCode = 1
}
exit $exitCode
