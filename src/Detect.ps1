# Detect.ps1 - upstream (v2rayN / sing-box / other tunnel) and NordVPN detection.
# Read-only: nothing in this file mutates system state.

$script:ClashApiCache = $null
$script:CoreProcessPattern = '^(sing-box.*|xray.*|v2ray.*|v2rayN|mihomo.*|clash.*|verge.*|hysteria.*|tuic.*|naive|juicity.*|Hiddify.*|nekoray|nekobox.*|throne|V2RayEz.*|tun2socks.*|brook.*|trojan.*|shadowsocks.*|sslocal|ss-local)$'

function Get-CoreProcesses {
    param($Config)
    $extra = @($Config.upstream.processNames | Where-Object { $_ })
    @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $script:CoreProcessPattern -or $extra -contains $_.Name
    })
}

function Get-SystemProxyInfo {
    $p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $enabled = [bool]($p -and $p.ProxyEnable -eq 1)
    $server = if ($p -and ($p.PSObject.Properties.Name -contains 'ProxyServer')) { [string]$p.ProxyServer } else { '' }
    $pac = if ($p -and ($p.PSObject.Properties.Name -contains 'AutoConfigURL')) { [string]$p.AutoConfigURL } else { '' }
    [pscustomobject]@{ Enabled = $enabled; Server = $server; Pac = $pac; Local = ($server -match '127\.0\.0\.1|localhost|\[::1\]') }
}

function Get-ProcessConnections {
    param([int[]]$ProcessId)
    if (-not $ProcessId) { return @() }
    @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $ProcessId -contains $_.OwningProcess })
}

function Test-IsHostName {
    param([string]$Value)
    return ($Value -and -not (Test-IpAddressString $Value) -and $Value -notmatch '/' -and $Value -match '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
}

function Resolve-AddressList {
    # IPs and CIDRs pass through. Hostnames are resolved through the upstream's own bootstrap DNS
    # when known (the system resolver may be censored/poisoned, e.g. answering 10.10.34.x), and
    # non-public answers are discarded.
    param([string[]]$Items, [string[]]$Resolver = @())
    $out = @()
    foreach ($i in @($Items | Where-Object { $_ })) {
        if (Test-IpAddressString $i) { $out += $i; continue }
        if ($i -match '/') { try { [void](Get-CidrRange $i); $out += $i } catch { Write-Log UPSTREAM "Ignoring invalid CIDR '$i'" -Level WARN }; continue }
        $ips = @()
        try {
            if (@($Resolver).Count) {
                $ips = @(Resolve-DnsName -Name $i -Server $Resolver[0] -DnsOnly -QuickTimeout -ErrorAction Stop |
                    Where-Object { $_.Type -in @('A','AAAA') } | ForEach-Object IPAddress)
            } else {
                $ips = @([System.Net.Dns]::GetHostAddresses($i) | ForEach-Object { $_.IPAddressToString })
            }
        } catch { Write-Log UPSTREAM "Could not resolve server '$i' ($($_.Exception.Message))" -Level WARN }
        $bogus = @($ips | Where-Object { -not (Test-IsPublicIp $_) })
        if ($bogus.Count) {
            # A forged answer poisons the whole response (e.g. the AAAA twin 2001:4188:2:600:10:10:34:35 of 10.10.34.35).
            Write-Log UPSTREAM "Discarding all answers for '$i' ($($ips -join ', ')): contains non-public address(es) - DNS censorship/poisoning" -Level WARN
            continue
        }
        $out += $ips
    }
    return @($out | Select-Object -Unique)
}

function Get-V2rayNConfigDirs {
    # v2rayN writes the generated core configs to <v2rayN>\binConfigs (read-only use).
    $dirs = @()
    foreach ($p in @(Get-Process -Name 'v2rayN' -ErrorAction SilentlyContinue)) {
        $exe = $p.Path
        if (-not $exe) { $exe = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue).ExecutablePath }
        if ($exe) { $dirs += Join-Path (Split-Path $exe) 'binConfigs' }
    }
    # Remember where v2rayN lives, so its profile is still readable while it restarts.
    $memo = Join-Path $script:StateDir 'v2rayn-configdir.txt'
    if ($dirs.Count) {
        try { if (-not (Test-Path $script:StateDir)) { New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null }; Set-Content -Path $memo -Value $dirs[0] -Encoding UTF8 -ErrorAction Stop } catch { }
    } elseif (Test-Path $memo) {
        $d = (Get-Content $memo -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($d -and (Test-Path $d)) { $dirs += $d }
    }
    return @($dirs | Select-Object -Unique)
}

function Get-V2rayNClashApi {
    # sing-box's Clash API (experimental.clash_api) lists live TUN connections - including NordLynx's
    # kernel UDP flow, which is invisible in the Windows socket table.
    foreach ($d in (Get-V2rayNConfigDirs)) {
        $f = Join-Path $d 'configPre.json'
        if (-not (Test-Path $f)) { continue }
        try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        $c = $j.experimental.clash_api
        if ($c -and $c.external_controller) {
            $secret = if ($c.PSObject.Properties.Name -contains 'secret') { [string]$c.secret } else { '' }
            return [pscustomobject]@{ url = 'http://' + $c.external_controller; secret = $secret }
        }
    }
    return $null
}

function Get-NordTelioEndpoint {
    # Best-effort, read-only: the NordVPN service logs each NordLynx peer state change, e.g.
    #   Telio event raised: {"State":"connected",...,"Endpoint":"194.35.233.72:51820",...,"LinkState":"Up"}
    # Used only as a fallback when the upstream exposes no connection list.
    $dir = Join-Path $env:ProgramData 'NordVPN\logs'
    $f = Get-ChildItem $dir -Filter 'service-connection-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $f) { return $null }
    $hit = Select-String -Path $f.FullName -Pattern 'Telio event raised: (\{.*\})' -ErrorAction SilentlyContinue | Select-Object -Last 1
    if (-not $hit) { return $null }
    try { $ev = $hit.Matches[0].Groups[1].Value | ConvertFrom-Json } catch { return $null }
    if ($ev.State -notin @('connecting','connected')) { return $null }
    $ip = ([string]$ev.Endpoint) -replace ':\d+$', '' -replace '^\[|\]$', ''
    if (Test-IsPublicIp $ip) { return [pscustomobject]@{ Ip = $ip; LinkState = [string]$ev.LinkState; State = [string]$ev.State } }
    return $null
}

function Get-V2rayNBootstrapDns {
    # Best-effort, read-only: the "direct" DNS servers in v2rayN's generated configs are what the
    # core uses to resolve its own server name.
    $ips = @()
    foreach ($d in (Get-V2rayNConfigDirs)) {
        foreach ($name in 'configPre.json', 'config.json') {
            $f = Join-Path $d $name
            if (-not (Test-Path $f)) { continue }
            try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
            if (-not ($j.PSObject.Properties.Name -contains 'dns') -or -not $j.dns) { continue }
            foreach ($s in @($j.dns.servers)) {
                if ($s -is [string]) { continue }   # bare string = remote/default server
                $tag = [string]$s.tag
                $addr = if ($s.PSObject.Properties.Name -contains 'server') { [string]$s.server } elseif ($s.PSObject.Properties.Name -contains 'address') { [string]$s.address } else { '' }
                $addr = $addr -replace '^(udp|tcp)://', '' -replace ':53$', ''
                $isRemote = ($s.PSObject.Properties.Name -contains 'detour' -and $s.detour -eq 'proxy')
                if ($tag -match '^(direct|local)' -and -not $isRemote -and (Test-IsPublicIp $addr)) { $ips += $addr }
            }
        }
    }
    return @($ips | Select-Object -Unique)
}

function Get-V2rayNServerAddresses {
    # Proxy server address(es) of the profile v2rayN is running right now (read-only), from the
    # generated xray (config.json) and sing-box (configPre.json) outbounds. This keeps the leak guard
    # correct when the user switches servers - no need to wait for a socket to show up.
    param([string[]]$Dirs)
    if (-not $Dirs) { $Dirs = @(Get-V2rayNConfigDirs) }
    $out = @()
    foreach ($d in $Dirs) {
        foreach ($name in 'config.json', 'configPre.json') {
            $f = Join-Path $d $name
            if (-not (Test-Path $f)) { continue }
            try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
            foreach ($o in @($j.outbounds)) {
                if (-not $o) { continue }
                $names = $o.PSObject.Properties.Name
                $kind = if ($names -contains 'protocol') { [string]$o.protocol } elseif ($names -contains 'type') { [string]$o.type } else { '' }
                if ($kind -in @('freedom', 'blackhole', 'dns', 'direct', 'block', 'selector', 'urltest', 'loopback', '')) { continue }
                $cand = @()
                if ($names -contains 'server') { $cand += [string]$o.server }                       # sing-box
                if ($names -contains 'settings' -and $o.settings) {                                    # xray
                    $s = $o.settings; $sn = $s.PSObject.Properties.Name
                    if ($sn -contains 'address') { $cand += [string]$s.address }
                    if ($sn -contains 'vnext')   { $cand += @($s.vnext | ForEach-Object { [string]$_.address }) }
                    if ($sn -contains 'servers') { $cand += @($s.servers | ForEach-Object { [string]$_.address }) }
                    if ($sn -contains 'peers')   { $cand += @($s.peers | ForEach-Object { ([string]$_.endpoint) -replace ':\d+$', '' -replace '^\[|\]$', '' }) }
                }
                $out += @($cand | Where-Object { $_ -and $_ -notmatch '^(127\.|localhost$|::1$)' })
            }
        }
    }
    return @($out | Select-Object -Unique)
}

function Get-UpstreamBlockedUdpPorts {
    # UDP destination ports the upstream core will NOT carry, read from v2rayN's generated sing-box
    # config (read-only): "reject" rules (v2rayN blocks QUIC = UDP 443 by default) and DNS hijack (53).
    # A VPN whose transport uses one of these ports can never handshake through the upstream.
    $ports = @(53)
    foreach ($d in (Get-V2rayNConfigDirs)) {
        $f = Join-Path $d 'configPre.json'
        if (-not (Test-Path $f)) { continue }
        try { $j = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        foreach ($r in @($j.route.rules)) {
            $names = $r.PSObject.Properties.Name
            if (-not ($names -contains 'port') -or -not ($names -contains 'action')) { continue }
            if ($names -contains 'process_path' -or $names -contains 'process_name' -or $names -contains 'ip_cidr' -or $names -contains 'domain') { continue }  # scoped rules
            $udp = (-not ($names -contains 'network')) -or (@($r.network) -contains 'udp')
            if ($udp -and $r.action -in @('reject', 'hijack-dns')) { $ports += @($r.port | ForEach-Object { [int]$_ }) }
        }
    }
    return @($ports | Sort-Object -Unique)
}

function Get-UpstreamServerNames {
    # Hostnames the core used to reach its servers: configured names plus Windows DNS cache entries
    # whose answer is one of the detected server IPs (proves the core resolves via the system resolver).
    param([string[]]$Configured, [string[]]$ServerIps)
    $names = @($Configured | Where-Object { Test-IsHostName $_ })
    if (@($ServerIps).Count) {
        $names += @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $ServerIps -contains $_.Data -and $_.Entry } | ForEach-Object { $_.Entry })
    }
    return @($names | ForEach-Object { $_.ToLowerInvariant().TrimEnd('.') } | Select-Object -Unique)
}

function Get-UpstreamInfo {
    # Classifies the upstream into: tun | proxy | none, and finds its adapter and server endpoints.
    param([Parameter(Mandatory)]$Inventory, [Parameter(Mandatory)]$Config, $NordInfo, [string[]]$KnownNordEndpoints = @(),
          # Only valid before NordVPN connects: afterwards NordVPN's own endpoint host route would be
          # mistaken for an upstream server (and wrongly exempted from the kill switch).
          [switch]$IncludeHostRoutes)
    $procs = Get-CoreProcesses $Config
    $proxy = Get-SystemProxyInfo
    $nordIdx = @($Inventory | Where-Object Kind -eq 'nordvpn' | ForEach-Object ifIndex)

    # --- adapter -------------------------------------------------------------
    $adapter = $null
    $ambiguous = @()
    if ($Config.upstream.adapter -and $Config.upstream.adapter -ne 'auto') {
        $adapter = $Inventory | Where-Object { $_.Alias -eq $Config.upstream.adapter } | Select-Object -First 1
        if (-not $adapter) { Write-Log UPSTREAM "Configured upstream adapter '$($Config.upstream.adapter)' not found" -Level WARN }
    } else {
        $cands = @($Inventory | Where-Object {
            $_.IsUp -and $_.Kind -in @('virtual-tunnel','virtual') -and $_.HasDefault4 -and ($nordIdx -notcontains $_.ifIndex)
        })
        # A real TUN/PPP default route is on-link; a tethering NIC has a gateway. Prefer tunnel-like ones.
        $scored = $cands | ForEach-Object {
            $score = 0
            if ($_.Kind -eq 'virtual-tunnel') { $score += 2 }
            if (-not $_.Gateway4) { $score += 1 }
            if ($_.Description -match 'sing|wintun|v2ray|xray|clash|mihomo|meta|hiddify') { $score += 2 }
            [pscustomobject]@{ If = $_; Score = $score; Metric = if ($null -ne $_.DefaultMetric4) { $_.DefaultMetric4 } else { 9999 } }
        } | Where-Object { $_.Score -ge 2 } | Sort-Object @{e='Score';Descending=$true}, Metric
        $scored = @($scored)
        if ($scored.Count) { $adapter = $scored[0].If }
        if ($scored.Count -gt 1) { $ambiguous = @($scored | Select-Object -Skip 1 | ForEach-Object { $_.If.Alias }) }
    }

    $mode = 'none'
    if ($Config.upstream.type -eq 'proxy') { $mode = 'proxy' }
    elseif ($adapter -and $adapter.IsUp) { $mode = 'tun' }
    elseif ($Config.upstream.type -eq 'tun') { $mode = 'tun-missing' }
    elseif ($procs.Count -or ($proxy.Enabled -and $proxy.Local)) { $mode = 'proxy' }

    # --- local proxy ports (informational / proxy-only detection) ------------
    $listen = @()
    if ($procs.Count) {
        $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { ($procs.Id -contains $_.OwningProcess) -and $_.LocalAddress -in @('127.0.0.1','::1','0.0.0.0','::') } |
            ForEach-Object { '{0}:{1}' -f $_.LocalAddress, $_.LocalPort } | Select-Object -Unique)
    }

    # --- server endpoints ----------------------------------------------------
    $tunnelLocal = @()
    if ($adapter) { $tunnelLocal += $adapter.IPv4 + $adapter.IPv6 }
    $nordLocal = @($Inventory | Where-Object Kind -eq 'nordvpn' | ForEach-Object { $_.IPv4 + $_.IPv6 })

    # Bootstrap DNS = the resolver the core uses for its own server name (kept outside NordVPN).
    $cfgBoot = @($Config.upstream.bootstrapDns | Where-Object { $_ -and $_ -ne 'auto' })
    $bootstrap = if ($cfgBoot.Count) { $cfgBoot } else { @(Get-V2rayNBootstrapDns) }
    $bootstrap = @(@($bootstrap) + @($Config.dnsBootstrapAllow) | Where-Object { $_ -and (Test-IpAddressString $_) } | Select-Object -Unique)

    $servers = @()
    $sources = @{}
    foreach ($ip in (Resolve-AddressList $Config.upstream.serverAddresses -Resolver $bootstrap)) { $servers += $ip; $sources[$ip] = 'config' }
    # The server(s) of the profile v2rayN runs right now (follows server switches).
    $v2nAddrs = @(Get-V2rayNServerAddresses)
    foreach ($ip in (Resolve-AddressList $v2nAddrs -Resolver $bootstrap)) { if ($servers -notcontains $ip) { $servers += $ip; $sources[$ip] = 'v2rayN-profile' } }
    $v2nNames = @($v2nAddrs | Where-Object { Test-IsHostName $_ })

    $conns = Get-ProcessConnections -ProcessId @($procs | ForEach-Object Id)
    $loopConns = @($conns | Where-Object { $nordLocal -contains $_.LocalAddress -and (Test-IsPublicIp $_.RemoteAddress) })
    $directToNord = @($conns | Where-Object { $KnownNordEndpoints -contains $_.RemoteAddress -and $tunnelLocal -notcontains $_.LocalAddress })
    $wanConns = @($conns | Where-Object {
        $_.State -in @('Established','SynSent') -and (Test-IsPublicIp $_.RemoteAddress) -and
        $tunnelLocal -notcontains $_.LocalAddress -and $nordLocal -notcontains $_.LocalAddress -and
        $KnownNordEndpoints -notcontains $_.RemoteAddress
    })
    $byRemote = @($wanConns | Group-Object RemoteAddress | Sort-Object Count -Descending)
    # Always merged with the configured list, so the server v2rayN is using right now is never missed.
    foreach ($g in ($byRemote | Select-Object -First 4)) {
        if ($servers -notcontains $g.Name) { $servers += $g.Name; $sources[$g.Name] = "core-connection x$($g.Count)" }
    }
    # Kernel tunnels (IKEv2, OpenVPN, WireGuard) pin their own server as a /32 host route on the WAN side.
    if ($mode -eq 'tun' -and $IncludeHostRoutes -and -not @($Config.upstream.serverAddresses).Count) {
        $wanIdx = @($Inventory | Where-Object { $_.Kind -in @('physical','virtual','other') -and $_.Gateway4 } | ForEach-Object ifIndex)
        Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {
            $_.DestinationPrefix -like '*/32' -and $wanIdx -contains $_.ifIndex -and $_.NextHop -ne '0.0.0.0'
        } | ForEach-Object {
            $ip = ($_.DestinationPrefix -split '/')[0]
            if ((Test-IsPublicIp $ip) -and $servers -notcontains $ip -and $KnownNordEndpoints -notcontains $ip) { $servers += $ip; $sources[$ip] = 'existing-host-route' }
        }
    }

    [pscustomobject]@{
        Mode            = $mode
        Adapter         = $adapter
        AmbiguousWith   = $ambiguous
        Processes       = @($procs | ForEach-Object { '{0}({1})' -f $_.Name, $_.Id })
        ProcessIds      = @($procs | ForEach-Object Id)
        ListenPorts     = $listen
        SystemProxy     = $proxy
        Servers         = @($servers | Select-Object -Unique)
        ServerSources   = $sources
        # Remote IPs the core reaches from a WAN address = proof that traffic leaves on the WAN,
        # whatever the route table says (e.g. v2rayN: xray -> TUN -> sing-box "direct" by process rule).
        WanRemotes      = @($wanConns | ForEach-Object RemoteAddress | Select-Object -Unique)
        ServerNames     = @(@(Get-UpstreamServerNames -Configured $Config.upstream.serverAddresses -ServerIps $servers) + $v2nNames | Select-Object -Unique)
        BootstrapDns    = $bootstrap
        ServersAmbiguous = ($byRemote.Count -gt 2 -and -not @($Config.upstream.serverAddresses).Count)
        LoopConnections = $loopConns
        DirectToNord    = $directToNord
    }
}

# ----------------------------------------------------------------------------
# NordVPN
# ----------------------------------------------------------------------------

function Get-NordVpnInstall {
    # Kept for compatibility: the chained VPN is provider-driven (see Providers.ps1).
    param($Config)
    return Get-VpnInstall $Config
}

function Get-NordKillSwitchHint {
    # Best-effort, read-only kill-switch/firewall state of the chained VPN.
    #  NordVPN: its service logs the Internet Kill Switch state (no documented API).
    #  Windscribe: 'windscribe-cli status' reports the firewall state.
    if ($script:ChainVpn.Key -eq 'windscribe') {
        $s = Get-WindscribeStatus
        if ($s -and $s.Firewall) { return "firewall $($s.Firewall.ToLowerInvariant())" }
        return 'unknown'
    }
    $dir = Join-Path $env:ProgramData 'NordVPN\logs'
    $files = @(Get-ChildItem $dir -Filter 'service-2*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3)
    foreach ($f in $files) {
        $hit = Select-String -Path $f.FullName -Pattern 'KillSwitch is (enabled|disabled)|Internet KillSwitch is already (enabled|disabled)|(Enabling|Disabling) Internet KillSwitch' -ErrorAction SilentlyContinue | Select-Object -Last 1
        if ($hit) {
            if ($hit.Line -match 'is enabled|already enabled|Enabling Internet KillSwitch') { return 'enabled' }
            return 'disabled'
        }
    }
    return 'unknown'
}

function Get-ClashApiTarget {
    param($Config)
    if ($Config.upstream.clashApi -and [string]$Config.upstream.clashApi.url) {
        return [pscustomobject]@{ url = [string]$Config.upstream.clashApi.url; secret = [string]$Config.upstream.clashApi.secret }
    }
    if (-not $script:ClashApiCache) { $script:ClashApiCache = @{ v = (Get-V2rayNClashApi) } }
    return $script:ClashApiCache.v
}

function Get-ClashApiEndpoints {
    # Optional: sing-box / mihomo Clash API lists live connections through the TUN, which reveals
    # NordLynx/OpenVPN-UDP server endpoints that are otherwise invisible (kernel UDP sockets).
    param($Config, [switch]$Raw)
    $api = Get-ClashApiTarget $Config
    if (-not $api) { return @() }
    try {
        $req = [System.Net.HttpWebRequest]::Create(($api.url.TrimEnd('/') + '/connections'))
        $req.Proxy = $null; $req.Timeout = 3000
        if ($api.secret) { $req.Headers.Add('Authorization', 'Bearer ' + $api.secret) }
        $resp = $req.GetResponse()
        try { $body = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } finally { $resp.Close() }
        $data = $body | ConvertFrom-Json
        # VPN transport flows: kernel senders (WireGuard / IKEv2 have no process path) or the
        # provider's user-mode transport processes. DNS (53) is hijacked by the core, not transport.
        $tp = ($script:ChainVpn.Transport | ForEach-Object { [regex]::Escape($_) }) -join '|'
        $vpn = @($data.connections | Where-Object {
            $port = "$($_.metadata.destinationPort)"
            $proc = [string]$_.metadata.processPath
            $port -ne '53' -and (Test-IsPublicIp ([string]$_.metadata.destinationIP)) -and (
                ($script:ChainVpn.Key -eq 'nordvpn' -and $port -in @('51820','1194')) -or
                ($tp -and $proc -match $tp) -or
                (-not $proc -and $script:ChainVpn.Key -eq 'windscribe' -and $_.metadata.network -eq 'udp'))
        })
        if ($Raw) { return $vpn }
        return @($vpn | ForEach-Object { $_.metadata.destinationIP } | Where-Object { Test-IsPublicIp $_ } | Select-Object -Unique)
    } catch {
        Write-Log NORDVPN "Clash API query failed: $($_.Exception.Message)" -Level DEBUG
        return @()
    }
}

function Get-NordVpnInfo {
    param([Parameter(Mandatory)]$Inventory, [Parameter(Mandatory)]$Config, $Snapshot, [int[]]$OwnRouteIfIndex = @(), [string[]]$OwnRoutePrefixes = @(), [string[]]$UpstreamServers = @(),
          $Since)   # session start: enables endpoint discovery from the VPN app's own log
    $nordIfs = @($Inventory | Where-Object Kind -eq 'nordvpn')
    if ($Config.nordvpn.adapter -and $Config.nordvpn.adapter -ne 'auto') {
        $nordIfs = @($Inventory | Where-Object Alias -eq $Config.nordvpn.adapter)
    }
    $active = $nordIfs | Where-Object { $_.IsUp -and $_.IPv4.Count } | Sort-Object Metric4 | Select-Object -First 1

    # User-mode transport processes of the chained VPN (OpenVPN / Stealth / WStunnel).
    $ovpn = @(Get-Process -Name $script:ChainVpn.Transport -ErrorAction SilentlyContinue)
    $protocol = Get-VpnProtocol $active

    # --- endpoint discovery, most to least authoritative ---------------------
    $endpoints = @()
    $source = 'unknown'
    if ($Config.nordvpn.endpoint -and $Config.nordvpn.endpoint -ne 'auto') {
        $endpoints = Resolve-AddressList @($Config.nordvpn.endpoint); $source = 'config'
    }
    if (-not $endpoints.Count -and $Since) {
        # What the VPN app itself announced since this session began (works before the handshake).
        $ann = @(Get-VpnAnnouncedEndpoints -Since $Since | Where-Object { $UpstreamServers -notcontains $_ })
        if ($ann.Count) { $endpoints = $ann; $source = 'vpn-app-log' }
    }
    if (-not $endpoints.Count -and $ovpn.Count) {
        $tcp = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $ovpn.Id -contains $_.OwningProcess -and (Test-IsPublicIp $_.RemoteAddress) })
        if ($tcp.Count) { $endpoints = @($tcp.RemoteAddress | Select-Object -Unique); $source = 'openvpn-tcp-connection' }
        else {
            foreach ($p in $ovpn) {
                $cl = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cl -match '--remote\s+(\S+)') { if (Test-IsPublicIp $Matches[1]) { $endpoints += $Matches[1]; $source = 'openvpn-cmdline' } }
            }
        }
    }
    $nordActivity = [bool](@($nordIfs | Where-Object IsUp).Count -or $ovpn.Count)
    if (-not $endpoints.Count -and $Snapshot -and $nordActivity) {
        # Host routes that appeared after the snapshot, not created by us, not on NordVPN's own adapter,
        # not one of this machine's own addresses - only while NordVPN is actually (dis)connecting.
        $localIps = @($Inventory | ForEach-Object { $_.IPv4 + $_.IPv6 })
        $before = @{}
        foreach ($r in @($Snapshot.routes)) { $before['{0}|{1}' -f $r.prefix, $r.ifIndex] = $true }
        $nordIdx = @($nordIfs | ForEach-Object ifIndex)
        $new = Get-NetRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object {
            ($_.DestinationPrefix -like '*/32' -or $_.DestinationPrefix -like '*/128') -and
            -not $before.ContainsKey(('{0}|{1}' -f $_.DestinationPrefix, $_.ifIndex)) -and
            $nordIdx -notcontains $_.ifIndex -and
            $OwnRoutePrefixes -notcontains $_.DestinationPrefix
        } | ForEach-Object { ($_.DestinationPrefix -split '/')[0] } | Where-Object { (Test-IsPublicIp $_) -and $UpstreamServers -notcontains $_ -and $localIps -notcontains $_ } | Select-Object -Unique
        if (@($new).Count) { $endpoints = @($new); $source = 'new-host-route' }
    }
    if (-not $endpoints.Count -and $nordActivity) {
        $clash = @(Get-ClashApiEndpoints $Config)
        if ($clash.Count) { $endpoints = $clash; $source = 'clash-api' }
    }
    if (-not $endpoints.Count -and $nordActivity -and $script:ChainVpn.Key -eq 'nordvpn' -and $protocol -eq 'NordLynx') {
        $t = Get-NordTelioEndpoint
        if ($t) { $endpoints = @($t.Ip); $source = "nordvpn-log ($($t.State), link $($t.LinkState))" }
    }

    [pscustomobject]@{
        Adapters      = $nordIfs
        Active        = $active
        Connected     = [bool]$active
        Protocol      = $protocol
        DefaultStyle  = if ($active) { $active.DefaultStyle4 } else { '' }
        HasIPv6       = [bool]($active -and $active.GlobalIPv6.Count -and $active.HasDefault6)
        Endpoints     = @($endpoints)
        EndpointSource = $source
        DnsServers    = if ($active) { $active.DnsServers } else { @() }
    }
}

function Get-WanSideInterfaces {
    # Every interface that is neither NordVPN, the upstream tunnel, nor loopback.
    # The leak guard blocks these (except the upstream server / LAN exemptions).
    param($Inventory, $UpstreamAdapter)
    @($Inventory | Where-Object {
        $_.Kind -notin @('loopback','nordvpn') -and (-not $UpstreamAdapter -or $_.ifIndex -ne $UpstreamAdapter.ifIndex) -and $_.Alias
    })
}

function Get-PrimaryWan {
    # The WAN interface the upstream server should be pinned to: best default route with a real gateway.
    param($Inventory, $UpstreamAdapter, [int]$Family = 4)
    $wan = Get-WanSideInterfaces $Inventory $UpstreamAdapter
    if ($Family -eq 4) {
        $wan | Where-Object { $_.IsUp -and $_.Gateway4 } | Sort-Object DefaultMetric4 | Select-Object -First 1
    } else {
        $wan | Where-Object { $_.IsUp -and $_.Gateway6 } | Sort-Object Metric6 | Select-Object -First 1
    }
}

function Get-NetworkSnapshot {
    [ordered]@{
        takenAt = (Get-Date).ToString('o')
        routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -notmatch '^(ff|224\.|255\.)' } | ForEach-Object {
            [ordered]@{ prefix = $_.DestinationPrefix; ifIndex = [int]$_.ifIndex; alias = $_.InterfaceAlias; nextHop = $_.NextHop; metric = [int]$_.RouteMetric }
        })
        interfaceMetrics = @(Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object {
            [ordered]@{ ifIndex = [int]$_.ifIndex; alias = $_.InterfaceAlias; family = [string]$_.AddressFamily; metric = [int]$_.InterfaceMetric; automatic = [string]$_.AutomaticMetric }
        })
        dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object {
            [ordered]@{ ifIndex = [int]$_.InterfaceIndex; alias = $_.InterfaceAlias; family = [int]$_.AddressFamily; servers = @($_.ServerAddresses) }
        })
        ipv6Bindings = @(Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | ForEach-Object {
            [ordered]@{ alias = $_.Name; enabled = [bool]$_.Enabled }
        })
        nrpt = @(Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue | ForEach-Object { [ordered]@{ namespace = @($_.Namespace); servers = @($_.NameServers) } })
        ourFirewallRules = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue | ForEach-Object Name)
        systemProxy = (Get-SystemProxyInfo)
    }
}
