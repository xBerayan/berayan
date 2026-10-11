# Providers.ps1 - the VPN chained on top of the v2ray upstream (NordVPN or Windscribe).
# Everything provider-specific lives here; the engine only uses the generic functions below.
# Only documented, user-facing interfaces are used: each app's own CLI, its adapters, and
# read-only log lines. Nothing is patched, injected or extracted.

$script:Providers = [ordered]@{
    nordvpn = [pscustomobject]@{
        Key            = 'nordvpn'
        Display        = 'NordVPN'
        AdapterPattern = 'NordLynx|TAP-NordVPN|OpenVPN Data Channel Offload for NordVPN|NordVPN'
        ServiceName    = 'nordvpn-service'
        Root           = (Join-Path $env:ProgramFiles 'NordVPN')
        CliName        = 'NordVPN.exe'
        Transport      = @('openvpn-nordvpn')          # user-mode transport processes (OpenVPN)
        Protocols      = @('auto', 'app', 'openvpn-tcp', 'openvpn-udp', 'nordlynx')   # chosen in the NordVPN app (CLI cannot switch)
    }
    windscribe = [pscustomobject]@{
        Key            = 'windscribe'
        Display        = 'Windscribe'
        AdapterPattern = 'Windscribe'
        ServiceName    = 'WindscribeService'
        Root           = (Join-Path $env:ProgramFiles 'Windscribe')
        CliName        = 'windscribe-cli.exe'
        Transport      = @('windscribeopenvpn', 'windscribewstunnel', 'WireguardService')
        Protocols      = @('wireguard', 'ikev2', 'udp', 'tcp', 'stealth', 'wstunnel')
    }
}

# Active provider (set by Set-VpnProvider). Defaults keep read-only commands working.
$script:ChainVpn = $script:Providers['nordvpn']
$script:VpnName = 'NordVPN'
$script:NordAdapterPattern = $script:ChainVpn.AdapterPattern
$script:VpnInterfaceMetric = 100   # chained-VPN adapter metric while chained (above any WAN default route)

function Set-VpnProvider {
    param([Parameter(Mandatory)][string]$Key)
    $k = $Key.ToLowerInvariant()
    if (-not $script:Providers.Contains($k)) { throw "Unknown VPN '$Key'. Supported: $($script:Providers.Keys -join ', ')" }
    $script:ChainVpn = $script:Providers[$k]
    $script:VpnName = $script:ChainVpn.Display
    $script:NordAdapterPattern = $script:ChainVpn.AdapterPattern    # used by Get-InterfaceInventory
}

function Select-VpnProvider {
    # Order: -Vpn parameter > active session > config "vpn.provider" > interactive menu > NordVPN.
    param([string]$Requested, $Config, $Session, [switch]$Interactive)
    if ($Requested) { return $Requested }
    if ($Session -and $Session.context -and $Session.context.provider) { return [string]$Session.context.provider }
    $cfgProv = if ($Config.Contains('vpn') -and $Config.vpn) { [string]$Config.vpn.provider } else { '' }
    if ($cfgProv -and $cfgProv -ne 'ask') { return $cfgProv }
    if ($Interactive -and [Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) {
        Write-Host ''
        Write-Host 'Which VPN do you want to connect through v2ray?' -ForegroundColor Cyan
        $keys = @($script:Providers.Keys)
        for ($i = 0; $i -lt $keys.Count; $i++) {
            $p = $script:Providers[$keys[$i]]
            $inst = if (Test-Path (Join-Path $p.Root $p.CliName)) { 'installed' } else { 'not installed' }
            Write-Host ('  [{0}] {1}  ({2})' -f ($i + 1), $p.Display, $inst)
        }
        while ($true) {
            $a = Read-Host "Choose 1-$($keys.Count)"
            if ($a -match '^\d+$' -and [int]$a -ge 1 -and [int]$a -le $keys.Count) { return $keys[[int]$a - 1] }
            $hit = $keys | Where-Object { $_ -eq $a.ToLowerInvariant() -or $script:Providers[$_].Display -eq $a }
            if ($hit) { return @($hit)[0] }
        }
    }
    return 'nordvpn'
}

function Get-VpnProtocolChoices {
    # Protocol menu for the interactive app. Order = recommendation for running *through v2ray*.
    param([string]$Key)
    switch ($Key) {
        'windscribe' {
            @(
                [pscustomobject]@{ Id = 'ikev2';     Label = 'IKEv2';                    Note = 'Verified working through v2ray. Fast, built into Windows.'; Level = 'good' }
                [pscustomobject]@{ Id = 'stealth';   Label = 'Stealth (OpenVPN in TLS)'; Note = 'Looks like HTTPS. Good fallback when IKEv2 is blocked.'; Level = 'good' }
                [pscustomobject]@{ Id = 'tcp';       Label = 'OpenVPN TCP';              Note = 'Most compatible. Slower (TCP inside TCP).'; Level = 'good' }
                [pscustomobject]@{ Id = 'wstunnel';  Label = 'WStunnel (WebSocket)';     Note = 'OpenVPN over WebSocket. Similar to Stealth.'; Level = 'good' }
                [pscustomobject]@{ Id = 'udp';       Label = 'OpenVPN UDP';              Note = 'Fast. Port is chosen automatically to avoid ports v2ray blocks.'; Level = 'ok' }
                [pscustomobject]@{ Id = 'wireguard'; Label = 'WireGuard';                Note = 'Windscribe''s WireGuard client blocks all non-tunnel traffic, which cuts v2ray off. Usually fails.'; Level = 'bad' }
            )
        }
        'nordvpn' {
            # The NordVPN Windows CLI cannot select a protocol: it is set in the app, we verify it after connect.
            @(
                [pscustomobject]@{ Id = 'app';      Label = 'Use the protocol set in the NordVPN app'; Note = 'No change - whatever NordVPN > Settings > Connection > VPN protocol says.'; Level = 'good' }
                [pscustomobject]@{ Id = 'openvpn-tcp'; Label = 'OpenVPN TCP';  Note = 'Set it in NordVPN > Settings > Connection > VPN protocol first. Most robust through v2ray.'; Level = 'good' }
                [pscustomobject]@{ Id = 'openvpn-udp'; Label = 'OpenVPN UDP';  Note = 'Set it in the NordVPN app first. Faster.'; Level = 'ok' }
                [pscustomobject]@{ Id = 'nordlynx'; Label = 'NordLynx (WireGuard)';    Note = 'Set it in the NordVPN app first. Needs Split tunneling for xray/sing-box (LeakBlock).'; Level = 'ok' }
            )
        }
    }
}

function Get-VpnLocationHint {
    param([string]$Key)
    switch ($Key) {
        'windscribe' { 'Enter = best location   e.g.  DE   Frankfurt   "US East"   Toronto' }
        'nordvpn'    { 'Enter = recommended server   e.g.  Germany   Netherlands   "United States"' }
    }
}

function Get-VpnInstall {
    param($Config)
    $p = $script:ChainVpn
    $root = $p.Root
    if ($p.Key -eq 'nordvpn' -and $Config.nordvpn.installPath -and $Config.nordvpn.installPath -ne 'auto') { $root = $Config.nordvpn.installPath }
    $cli = Join-Path $root $p.CliName
    $svc = Get-Service -Name $p.ServiceName -ErrorAction SilentlyContinue
    $ver = $null
    if ($p.Key -eq 'nordvpn' -and (Test-Path $root)) {
        $ver = Get-ChildItem $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\d+(\.\d+)+$' } |
            Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1 -ExpandProperty Name
    } elseif (Test-Path $cli) { $ver = (Get-Item $cli).VersionInfo.ProductVersion }
    [pscustomobject]@{
        Installed    = (Test-Path $cli)
        Root         = $root
        CliPath      = if (Test-Path $cli) { $cli } else { $null }
        Version      = $ver
        ServiceState = if ($svc) { [string]$svc.Status } else { 'NotInstalled' }
    }
}

function Invoke-VpnCli {
    param($Install, [string[]]$Arguments, [switch]$Wait, [int]$TimeoutSec = 20)
    if (-not $Install.CliPath) { throw "$script:VpnName CLI not found; connect it manually." }
    Write-Log VPN "running documented CLI: $(Split-Path $Install.CliPath -Leaf) $($Arguments -join ' ')"
    $quoted = @($Arguments | ForEach-Object { if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ } })
    $p = Start-Process -FilePath $Install.CliPath -ArgumentList $quoted -WindowStyle Hidden -PassThru
    if ($Wait) { [void]$p.WaitForExit($TimeoutSec * 1000) }
}

function Invoke-VpnConnect {
    param($Install, [string]$Location, [string]$Protocol)
    switch ($script:ChainVpn.Key) {
        'nordvpn' {
            $a = @('-c'); if ($Location) { $a += @('-g', $Location) }
            Invoke-VpnCli $Install $a
        }
        'windscribe' {
            # -n: return immediately; we watch the adapters ourselves.
            $a = @('connect', '-n')
            $a += $(if ($Location) { $Location } else { 'best' })
            if ($Protocol) { $a += (Resolve-WindscribeProtocolPort $Install $Protocol) }
            Invoke-VpnCli $Install $a
        }
    }
}

function Resolve-WindscribeProtocolPort {
    # UDP protocols: pick a port the upstream actually carries (v2rayN rejects UDP 443 = QUIC and
    # hijacks 53 for DNS, which silently kills WireGuard's default port 443).
    param($Install, [string]$Protocol)
    $proto = $Protocol.ToLowerInvariant()
    if ($proto -match ':' -or $proto -notin @('wireguard', 'udp')) { return $proto }
    $blocked = @(Get-UpstreamBlockedUdpPorts)
    $offered = @()
    try { $offered = @((& $Install.CliPath ports $proto 2>&1 | Out-String) -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }) } catch { }
    $ok = @($offered | Where-Object { $blocked -notcontains $_ })
    # Prefer ports that look like ordinary VPN/other traffic over 80/123 which middleboxes like to touch.
    $pick = @($ok | Sort-Object { switch ($_) { 1194 { 0 } 65142 { 1 } 54783 { 1 } 80 { 2 } 123 { 3 } default { 4 } } }) | Select-Object -First 1
    if ($pick) {
        Write-Log VPN "upstream blocks UDP ports [$($blocked -join ', ')]; using $proto port $pick (offered: $($offered -join ', '))" -Level OK
        return "${proto}:$pick"
    }
    Write-Log VPN "could not choose a safe $proto port (offered: $($offered -join ', '); blocked: $($blocked -join ', ')) - using the app default" -Level WARN
    return $proto
}

function Invoke-VpnDisconnect {
    param($Install)
    switch ($script:ChainVpn.Key) {
        'nordvpn'    { Invoke-VpnCli $Install @('-d') }
        'windscribe' { Invoke-VpnCli $Install @('disconnect') -Wait }
    }
}

function Get-WindscribeStatus {
    $cli = Join-Path $script:Providers['windscribe'].Root 'windscribe-cli.exe'
    if (-not (Test-Path $cli)) { return $null }
    try { $out = & $cli status 2>&1 | Out-String } catch { return $null }
    $get = { param($k) if ($out -match "(?m)^$k\s*:\s*(.+)$") { $Matches[1].Trim() } else { $null } }
    # Note: the 'Public IP' line is deliberately not parsed (it can be the real WAN address).
    [pscustomobject]@{ Login = (& $get 'Login state'); Firewall = (& $get 'Firewall state'); Connect = (& $get 'Connect state') }
}

function Get-WindscribeEngineSetting {
    # Read-only: Windscribe logs its full engine settings as JSON on start/changes; return one value.
    param([string]$Name)
    $f = Join-Path $env:LOCALAPPDATA 'Windscribe\Windscribe2\client.log'
    if (-not (Test-Path $f)) { return $null }
    $hit = Select-String -Path $f -Pattern 'Engine settings' -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($hit -and $hit.Line -match ('\\?"' + [regex]::Escape($Name) + '\\?"\s*:\s*([a-z0-9]+)')) { return $Matches[1] }
    return $null
}

function Get-VpnConnectState {
    # 'connected' | 'connecting' | 'disconnected' | 'unknown' as reported by the app itself.
    switch ($script:ChainVpn.Key) {
        'windscribe' {
            $s = Get-WindscribeStatus
            if (-not $s -or -not $s.Connect) { return 'unknown' }
            if ($s.Connect -match '^Connected') { return 'connected' }
            if ($s.Connect -match '^Connecting') { return 'connecting' }
            return 'disconnected'
        }
        default { return 'unknown' }
    }
}

function Get-VpnAnnouncedEndpoints {
    # Server IPs the VPN app announces in its own log *before* its handshake starts
    # (read-only). Pinning them to the upstream at that moment means the very first
    # handshake already travels through v2ray - no race with route changes later.
    #   Windscribe: "Location nodes: node1 = {ip1 = a, ip2 = b ...}" and "Connecting to IP: "x""
    #   NordVPN:    Telio event {"State":"connecting",...,"Endpoint":"x:51820"}
    param([datetime]$Since = (Get-Date).AddMinutes(-10))
    $ips = @()
    switch ($script:ChainVpn.Key) {
        'windscribe' {
            $f = Join-Path $env:LOCALAPPDATA 'Windscribe\Windscribe2\client.log'
            if (-not (Test-Path $f)) { return @() }
            $since = $Since.ToString('yyyy-MM-dd HH:mm:ss')
            foreach ($l in @(Get-Content $f -Tail 600 -ErrorAction SilentlyContinue)) {
                if ($l -notmatch '"tm": "([^"]+)"' -or $Matches[1].Substring(0, 19) -lt $since) { continue }
                if ($l -match 'Connecting to IP: \\"([0-9.]+)\\"') { $ips += $Matches[1] }
                elseif ($l -match 'Location nodes:') { $ips += @([regex]::Matches($l, 'ip\d+ = ([0-9.]+)') | ForEach-Object { $_.Groups[1].Value }) }
            }
        }
        'nordvpn' {
            $f = Get-ChildItem (Join-Path $env:ProgramData 'NordVPN\logs') -Filter 'service-connection-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if (-not $f) { return @() }
            $since = $Since.ToString('HH:mm:ss')
            foreach ($l in @(Get-Content $f.FullName -Tail 400 -ErrorAction SilentlyContinue)) {
                if ($l -match '^\[(\d\d:\d\d:\d\d)' -and $Matches[1] -lt $since) { continue }
                if ($l -match 'Telio event raised: .*"State":"(connecting|connected)".*"Endpoint":"([0-9.]+):\d+"') { $ips += $Matches[2] }
            }
        }
    }
    return @($ips | Where-Object { Test-IsPublicIp $_ } | Select-Object -Unique)
}

function Get-VpnProtocol {
    # Protocol of the active connection, from the adapter type / transport processes.
    param($Active)
    if (-not $Active) { return 'none' }
    $d = "$($Active.Alias) $($Active.Description)"
    $tp = @(Get-Process -Name $script:ChainVpn.Transport -ErrorAction SilentlyContinue)
    switch ($script:ChainVpn.Key) {
        'nordvpn' {
            if ($d -match 'NordLynx') { return 'NordLynx' }
            if ($tp.Count) {
                $tcp = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $tp.Id -contains $_.OwningProcess -and (Test-IsPublicIp $_.RemoteAddress) })
                return $(if ($tcp.Count) { 'OpenVPN-TCP' } else { 'OpenVPN-UDP' })
            }
            return 'OpenVPN'
        }
        'windscribe' {
            if ($Active.NetType -eq 'Ppp' -or $d -match 'IKEv2') { return 'IKEv2' }
            if ($d -match 'Wireguard|WireGuard') { return 'WireGuard' }
            if (@($tp | Where-Object Name -eq 'windscribewstunnel').Count) { return 'WStunnel' }
            $ov = @($tp | Where-Object Name -eq 'windscribeopenvpn')
            if ($ov.Count) {
                $tcp = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $ov.Id -contains $_.OwningProcess -and (Test-IsPublicIp $_.RemoteAddress) })
                return $(if ($tcp.Count) { 'OpenVPN-TCP/Stealth' } else { 'OpenVPN-UDP' })
            }
            if (@($tp | Where-Object Name -eq 'WireguardService').Count) { return 'WireGuard' }
            return 'unknown'
        }
    }
}

function Get-VpnConflicts {
    # Provider features that block the upstream core while the VPN is connected.
    # Returns a list of @{ Issue; Fix } (empty = nothing known to conflict).
    param([string[]]$CorePaths = @(), $Since)
    $out = @()
    $apps = if ($CorePaths.Count) { ($CorePaths -join '  and  ') } else { 'xray.exe and sing-box.exe from your v2rayN folder' }
    switch ($script:ChainVpn.Key) {
        'nordvpn' {
            # NordVPN 8.x applies "LeakBlock" (WinDivert) on every connection: only the NordLynx/OpenVPN
            # adapter may carry traffic. It cuts the v2ray core's own server connection - and with it the
            # path NordVPN itself runs through - unless the core is excluded via Split tunneling.
            $f = Get-ChildItem (Join-Path $env:ProgramData 'NordVPN\logs') -Filter 'service-2*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($f) {
                $st = Select-String -Path $f.FullName -Pattern 'SplitTunneling was not turned on, because SplitTunnelingMode is Off|SplitTunneling (was )?turned on|Applying LeakBlock' -ErrorAction SilentlyContinue | Select-Object -Last 2
                $off = @($st | Where-Object { $_.Line -match 'SplitTunnelingMode is Off' }).Count -gt 0
                $leak = @($st | Where-Object { $_.Line -match 'Applying LeakBlock' }).Count -gt 0
                if ($off -or $leak) {
                    $out += [pscustomobject]@{
                        Issue = 'NordVPN applies LeakBlock on every connection (only its own adapter may send traffic). That blocks the v2ray core''s connection to its server, so the path NordVPN runs through collapses and NordVPN reconnects in a loop.' + $(if ($off) { ' Split tunneling is currently OFF.' } else { '' })
                        Fix   = "NordVPN > Settings > Split tunneling: turn ON, choose 'Bypass VPN for selected apps', add $apps. Then run start again."
                    }
                }
            }
        }
        'windscribe' {
            # "Terminate sockets": on every connect Windscribe closes ALL TCP connections on the PC -
            # including the v2ray core's link to its server, which carries Windscribe's own tunnel.
            # Result: connect -> transport killed -> reconnect loop (seen as closeAllTcpConnections).
            # Definitive evidence: the service log records each socket purge. The logged settings dump
            # (only refreshed on app start) is used as a non-blocking hint before connecting.
            $purged = $false
            if ($Since) {
                $svc = Join-Path $script:Providers['windscribe'].Root 'windscribe_service.log'
                $since = $Since.ToString('yyyy-MM-dd HH:mm:ss')
                $purged = [bool](@(Get-Content $svc -Tail 3000 -ErrorAction SilentlyContinue | Where-Object {
                    $_ -match 'closeAllTcpConnections' -and $_ -match '"tm": "([^"]+)"' -and $Matches[1].Substring(0, 19) -ge $since }).Count)
            }
            $eng = Get-WindscribeEngineSetting 'isTerminateSockets'
            if ($purged -or (-not $Since -and $eng -eq 'true')) {
                $out += [pscustomobject]@{
                    Issue = $(if ($purged) { 'Windscribe closed all TCP connections on connect ("Terminate sockets" is ON) - this kills the v2ray core''s connection that Windscribe itself runs through, so it disconnects itself in a loop.' }
                              else { 'Windscribe "Terminate sockets" appears ON (from its last logged settings; may be stale): on connect it closes all TCP connections, including the v2ray core''s, which breaks the chain.' })
                    Fix   = 'Windscribe > Preferences > Connection > "Terminate Sockets": turn OFF. Then run start again.'
                    Blocking = $purged
                }
            }
            $s = Get-WindscribeStatus
            if ($s -and $s.Firewall -match '^on') {
                $out += [pscustomobject]@{
                    Issue = 'Windscribe firewall is ON: it blocks everything except the Windscribe tunnel, including the v2ray core''s connection to its own server (the path Windscribe would run through).'
                    Fix   = "Windscribe > Preferences > Connection > Firewall Mode: Manual and turn the firewall off (or exclude $apps via Split Tunneling > Exclusive). vpn-chain's own kill switch stays active."
                }
            }
            if ($s -and $s.Login -and $s.Login -notmatch 'Logged in') {
                $out += [pscustomobject]@{ Issue = "Windscribe is not logged in ($($s.Login))."; Fix = 'Log in to the Windscribe app (or windscribe-cli login).' }
            }
        }
    }
    return $out
}

function Get-CoreExecutablePaths {
    # Full paths of the v2ray core executables (for split-tunnel instructions).
    $paths = @()
    foreach ($n in 'xray', 'sing-box', 'v2ray', 'mihomo') {
        foreach ($p in @(Get-Process -Name $n -ErrorAction SilentlyContinue)) {
            $exe = $p.Path
            if (-not $exe) { $exe = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue).ExecutablePath }
            if ($exe -and $exe -notmatch 'sing-box-daemon') { $paths += $exe }
        }
    }
    return @($paths | Select-Object -Unique)
}
