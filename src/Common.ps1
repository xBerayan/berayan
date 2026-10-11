# Common.ps1 - logging, configuration, elevation, session state, journal.
# Dot-sourced by vpn-chain.ps1. Windows PowerShell 5.1 compatible.

Set-StrictMode -Version 1.0   # v2 would reject the intrinsic .Count on unrolled single results

$script:ToolName      = 'vpn-chain'
$script:FirewallGroup = 'vpn-chain'           # every firewall rule we create carries this group
$script:RulePrefix    = 'vpn-chain-'
$script:StateDir      = Join-Path $env:ProgramData 'vpn-chain'
$script:SessionFile   = Join-Path $script:StateDir 'session.json'
$script:LogDir        = Join-Path $script:RootDir 'logs'
$script:Verbose       = $false
$script:LogFile       = $null
$script:MutexName     = 'Global\vpn-chain-mutation-lock'
$script:LogQuiet      = $false    # true in the interactive app: log lines never reach the terminal
$script:ConsoleMute   = $false    # true while the interactive app shows its own progress view
$script:LogHook       = $null     # interactive app: scriptblock(tag, message, level) fed by every log line
$script:Interactive   = $false    # true inside the interactive terminal app (enables Esc-to-cancel)
$script:AppVersion    = '2.0.0'

# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

function Initialize-Log {
    if (-not (Test-Path $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
    $script:LogFile = Join-Path $script:LogDir ("vpn-chain-{0}.log" -f (Get-Date -Format 'yyyyMMdd'))
    # Bounded logs: keep the 14 newest files, cap the current file at 5 MB.
    Get-ChildItem $script:LogDir -Filter 'vpn-chain-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -Skip 14 |
        Remove-Item -Force -ErrorAction SilentlyContinue
    if ((Test-Path $script:LogFile) -and ((Get-Item $script:LogFile).Length -gt 5MB)) {
        Move-Item $script:LogFile ($script:LogFile + '.old') -Force -ErrorAction SilentlyContinue
    }
}

# The engine's messages are written in terms of "NordVPN"; when another provider is chained,
# user-visible text is re-labelled here (provider internals never depend on these strings).
function ConvertTo-VpnText {
    param([AllowNull()][string]$Text)
    if ($null -eq $Text) { return $Text }
    $name = Get-Variable -Name VpnName -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if (-not $name -or $name -eq 'NordVPN') { return $Text }
    return ($Text -replace 'NordVPN', $name)
}

function Get-VpnTag {
    $name = Get-Variable -Name VpnName -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($name) { return $name.ToUpperInvariant() } else { return 'VPN' }
}

function Write-Host {
    # Thin wrapper: provider re-labelling for every console line, then the real Write-Host.
    [CmdletBinding()]
    param([Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]$Object,
          $ForegroundColor, $BackgroundColor, [switch]$NoNewline)
    process {
        if ($script:ConsoleMute) { return }     # interactive app is drawing its own progress view
        $p = @{}
        if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $p.ForegroundColor = $ForegroundColor }
        if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $p.BackgroundColor = $BackgroundColor }
        if ($NoNewline) { $p.NoNewline = $true }
        $text = if ($null -eq $Object) { '' } else { (@($Object) | ForEach-Object { "$_" }) -join ' ' }
        Microsoft.PowerShell.Utility\Write-Host (ConvertTo-VpnText $text) @p
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Tag,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG','OK')][string]$Level = 'INFO'
    )
    if ($Tag -in @('NORDVPN', 'VPN')) { $Tag = Get-VpnTag }
    $Message = ConvertTo-VpnText $Message
    $line = '{0} [{1}] [{2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Tag, $Message
    if ($script:LogFile) {
        try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch { }
    }
    if ($script:LogHook -and $Level -ne 'DEBUG') { try { & $script:LogHook $Tag $Message $Level } catch { } }
    if ($Level -eq 'DEBUG' -and -not $script:Verbose) { return }
    if ($script:LogQuiet) { return }   # interactive app: logs go to the log file only (clean screen)
    $color = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'DEBUG' { 'DarkGray' } 'OK' { 'Green' } default { 'Gray' } }
    Write-Host ('[{0}] {1}' -f $Tag, $Message) -ForegroundColor $color
}

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

function Get-DefaultConfig {
    [ordered]@{
        upstream = [ordered]@{
            type            = 'auto'      # auto | tun | proxy
            adapter         = 'auto'      # interface alias, or auto
            serverAddresses = @()         # upstream VPN/proxy server IPs, CIDRs or hostnames (merged with auto-detection)
            bootstrapDns    = @('auto')   # DNS the core uses to resolve its server name; auto = read from v2rayN's generated config
            processNames    = @()         # extra core process names to inspect
            clashApi        = [ordered]@{ url = ''; secret = '' }   # optional sing-box/mihomo Clash API for endpoint discovery
        }
        vpn = [ordered]@{
            provider = 'ask'              # ask | nordvpn | windscribe  (VPN chained on top of v2ray)
        }
        guard = [ordered]@{
            autoStart = $true             # leak guard turns on when Berayan opens (and when v2ray comes back up)
        }
        nordvpn = [ordered]@{             # settings for the chained VPN (any provider)
            adapter           = 'auto'    # interface alias, or auto
            protocol          = 'auto'    # informational; detected from adapter/process
            endpoint          = 'auto'    # NordVPN server IP override, or auto
            installPath       = 'auto'
            connectTimeoutSec = 180
        }
        ipv6Policy           = 'block-if-unsafe'   # block-if-unsafe | block-all | allow
        dnsLeakProtection    = $true
        killSwitch           = $true
        allowLan             = $true
        allowRemoteAddresses = @()       # extra destinations allowed on WAN-side interfaces (e.g. a Tailscale DERP IP)
        dnsBootstrapAllow    = @()       # DNS servers the upstream core may query directly over WAN
        ipCheckServices      = @(
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com',
            'https://checkip.amazonaws.com'
        )
        ipv6CheckServices    = @('https://api6.ipify.org', 'https://ipv6.icanhazip.com')
        nordInsightsUrl      = 'https://api.nordvpn.com/v1/helpers/ips/insights'
        monitor              = [ordered]@{ safetyIntervalSec = 20 }
    }
}

function Merge-Config {
    param($Base, $Override)
    if ($null -eq $Override) { return $Base }
    foreach ($p in $Override.PSObject.Properties) {
        $name = $p.Name
        $val  = $p.Value
        if ($Base.Contains($name) -and ($Base[$name] -is [System.Collections.IDictionary]) -and ($val -is [pscustomobject])) {
            $Base[$name] = Merge-Config -Base $Base[$name] -Override $val
        } else {
            $Base[$name] = $val
        }
    }
    return $Base
}

function Get-Config {
    param([string]$Path)
    $cfg = Get-DefaultConfig
    if (-not $Path) { $Path = Join-Path $script:RootDir 'config.json' }
    if (Test-Path $Path) {
        try {
            $json = Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "Config file '$Path' is not valid JSON: $($_.Exception.Message)"
        }
        $cfg = Merge-Config -Base $cfg -Override $json
        Write-Log CONFIG "Loaded $Path" -Level DEBUG
    } else {
        Write-Log CONFIG "No config.json found - using defaults (see config.example.json)" -Level DEBUG
    }
    if ($cfg.ipv6Policy -notin @('block-if-unsafe','block-all','allow')) {
        throw "Invalid ipv6Policy '$($cfg.ipv6Policy)'. Use block-if-unsafe, block-all or allow."
    }
    return $cfg
}

# ----------------------------------------------------------------------------
# Elevation
# ----------------------------------------------------------------------------

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    param([string]$Command, [string[]]$OriginalArgs, [switch]$NoElevate)
    if (Test-IsAdmin) { return $true }
    Write-Host ''
    Write-Host "'$Command' needs Administrator rights because it adds/removes host routes" -ForegroundColor Yellow
    Write-Host 'and Windows Firewall rules (both are machine-wide network settings).' -ForegroundColor Yellow
    Write-Host "Read-only commands (status, diagnose, test) work without elevation." -ForegroundColor Yellow
    if ($NoElevate) { return $false }
    $answer = Read-Host 'Relaunch this command elevated (UAC prompt)? [Y/n]'
    if ($answer -and $answer -notmatch '^(y|yes)$') { return $false }
    $scriptPath = Join-Path $script:RootDir 'vpn-chain.ps1'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', ('"{0}"' -f $scriptPath)) + ($OriginalArgs | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
    })
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList | Out-Null
    Write-Host 'Elevated window launched.' -ForegroundColor Green
    return $false
}

# ----------------------------------------------------------------------------
# Mutation lock (prevents a monitor and a stop/reset from mutating concurrently)
# ----------------------------------------------------------------------------

function Invoke-WithLock {
    param([Parameter(Mandatory)][scriptblock]$Script, [int]$TimeoutSec = 60)
    $mutex = New-Object System.Threading.Mutex($false, $script:MutexName)
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds($TimeoutSec)) }
        catch [System.Threading.AbandonedMutexException] { $acquired = $true }   # previous holder crashed
        if (-not $acquired) { throw 'Timed out waiting for another vpn-chain operation to finish.' }
        & $Script
    } finally {
        if ($acquired) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

# ----------------------------------------------------------------------------
# Session state + journal
#
# The journal is the authoritative list of every mutation this tool made.
# An entry is written with status 'pending' BEFORE the mutation and switched to
# 'applied' after verification, so a crash at any point leaves enough
# information for 'reset' to undo it idempotently.
# ----------------------------------------------------------------------------

function New-Session {
    [ordered]@{
        version   = 1
        id        = [guid]::NewGuid().ToString()
        status    = 'starting'       # starting | waiting-nordvpn | active | stopping | failed
        createdAt = (Get-Date).ToString('o')
        updatedAt = (Get-Date).ToString('o')
        monitorPid = $null
        snapshot  = $null
        context   = [ordered]@{}
        journal   = @()
    }
}

function ConvertTo-Hashtable {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject }
    # Note: '-is [pscustomobject]' is true for ANY PSObject-wrapped value (e.g. pipeline strings),
    # so compare the real type name.
    if ($InputObject.GetType().FullName -eq 'System.Management.Automation.PSCustomObject') {
        $h = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-Hashtable $p.Value }
        return $h
    }
    if (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string])) {
        return ,@($InputObject | ForEach-Object { ConvertTo-Hashtable $_ })   # ',' keeps 0/1-element arrays as arrays
    }
    return $InputObject
}

function Read-Session {
    if (-not (Test-Path $script:SessionFile)) { return $null }
    try {
        $obj = Get-Content $script:SessionFile -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $s = ConvertTo-Hashtable $obj
        $s.journal = @($s.journal | Where-Object { $_ })
        return $s
    } catch {
        Write-Log STATE "Session file is unreadable ($($_.Exception.Message)); 'reset' will fall back to group-based cleanup." -Level WARN
        return [ordered]@{ status = 'corrupt'; journal = @(); snapshot = $null; context = [ordered]@{} }
    }
}

function Save-Session {
    param([Parameter(Mandatory)]$Session)
    if (-not (Test-Path $script:StateDir)) { New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null }
    $Session.updatedAt = (Get-Date).ToString('o')
    $json = $Session | ConvertTo-Json -Depth 12
    $tmp = $script:SessionFile + '.tmp'
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -Path $tmp -Destination $script:SessionFile -Force   # atomic replace on NTFS
}

function Remove-SessionFile {
    if (Test-Path $script:SessionFile) {
        $archive = Join-Path $script:StateDir ("session-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Move-Item $script:SessionFile $archive -Force -ErrorAction SilentlyContinue
        Get-ChildItem $script:StateDir -Filter 'session-*.json' | Sort-Object LastWriteTime -Descending |
            Select-Object -Skip 5 | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

function Add-JournalEntry {
    param([Parameter(Mandatory)]$Session, [Parameter(Mandatory)][System.Collections.IDictionary]$Entry)
    $Entry['status'] = 'pending'
    $Entry['at'] = (Get-Date).ToString('o')
    $Session.journal = @($Session.journal) + @($Entry)
    Save-Session $Session
    return $Entry
}

function Set-JournalEntryStatus {
    param($Session, $Entry, [string]$Status)
    $Entry['status'] = $Status
    Save-Session $Session
}
