# Verify.ps1 - chain classification (pure) and behavioural verification (probes).

# ----------------------------------------------------------------------------
# Pure classifier. Input: facts hashtable. Output: state + reasons.
# Facts (all optional unless noted):
#   upstreamMode        tun | proxy | none | tun-missing        (required)
#   upstreamUp          bool
#   nordUp              bool                                    (required)
#   nordEndpointIf      upstream | nord | wan | unknown
#   upstreamServerIfs   array of wan | nord | upstream
#   coreLoop            bool  (upstream core sockets sourced from a NordVPN address)
#   coreDirectToNord    bool  (upstream core itself connects to the NordVPN endpoint over WAN)
#   appDefaultIf        nord | upstream | wan | none
#   publicIp, upstreamExitIp, directIp   strings
#   ipv6Leak            bool|$null
#   dnsLeak             bool|$null
#   correlation         chained | not-chained | unknown
# ----------------------------------------------------------------------------

function Get-ChainState {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$F)
    $reasons = New-Object System.Collections.Generic.List[string]
    function v($k) { if ($F.Contains($k)) { $F[$k] } else { $null } }

    $mode = v 'upstreamMode'
    $nordUp = [bool](v 'nordUp')
    $upUp = [bool](v 'upstreamUp')

    if ($mode -eq 'proxy') {
        $reasons.Add('Upstream is proxy-only (system/SOCKS/HTTP proxy). A proxy cannot carry NordVPN''s NordLynx/OpenVPN transport, so NordVPN would bypass it.')
        return [pscustomobject]@{ State = 'UPSTREAM_NOT_SUPPORTED'; Reasons = $reasons.ToArray() }
    }

    $srvIfs = @(v 'upstreamServerIfs')
    if ((v 'nordEndpointIf') -eq 'nord') { $reasons.Add('NordVPN endpoint route points into the NordVPN tunnel itself (recursion).') }
    if ($srvIfs -contains 'nord') { $reasons.Add('Upstream server traffic is routed into the NordVPN tunnel (upstream -> NordVPN -> upstream loop).') }
    # Note: upstream server -> upstream TUN is NOT treated as a loop. TUN cores routinely receive their
    # own transport and re-emit it on the WAN (process rules / interface binding); real recursion would
    # make the upstream fail outright, which other checks catch.
    if (v 'coreLoop') { $reasons.Add('Upstream core sockets are sourced from the NordVPN adapter: the core bound itself to NordVPN (loop). Set sing-box route.default_interface to the physical adapter, or disable auto_detect_interface.') }
    if ($reasons.Count) { return [pscustomobject]@{ State = 'ROUTING_LOOP'; Reasons = $reasons.ToArray() } }

    $pub = v 'publicIp'; $upExit = v 'upstreamExitIp'; $direct = v 'directIp'

    if (-not $nordUp -and -not $upUp) {
        if ($pub) { $reasons.Add("Neither tunnel is up but the Internet is reachable directly (public IP $pub).") ; return [pscustomobject]@{ State = 'DIRECT_LEAK'; Reasons = $reasons.ToArray() } }
        $reasons.Add('Neither NordVPN nor the upstream tunnel is up.')
        return [pscustomobject]@{ State = 'UNKNOWN'; Reasons = $reasons.ToArray() }
    }
    if (-not $nordUp) {
        $reasons.Add('NordVPN is not connected; traffic exits through the upstream only.')
        return [pscustomobject]@{ State = 'UPSTREAM_ONLY'; Reasons = $reasons.ToArray() }
    }

    if ($direct -and $pub -and $pub -eq $direct) {
        $reasons.Add("Public IP $pub equals the direct WAN IP.")
        return [pscustomobject]@{ State = 'DIRECT_LEAK'; Reasons = $reasons.ToArray() }
    }
    if ((v 'appDefaultIf') -eq 'wan') {
        $reasons.Add('Application default route points at a WAN interface, not NordVPN.')
        return [pscustomobject]@{ State = 'DIRECT_LEAK'; Reasons = $reasons.ToArray() }
    }
    if ((v 'ipv6Leak') -eq $true) {
        $reasons.Add('IPv6 traffic reaches the Internet outside the NordVPN tunnel.')
        return [pscustomobject]@{ State = 'DIRECT_LEAK'; Reasons = $reasons.ToArray() }
    }

    if (-not $upUp) { $reasons.Add('Upstream tunnel is down: NordVPN transport cannot traverse it.') }
    if ((v 'nordEndpointIf') -eq 'wan') { $reasons.Add('NordVPN server transport is routed directly to the WAN, bypassing the upstream.') }
    if (v 'coreDirectToNord') { $reasons.Add('The upstream core sends NordVPN transport out via its own "direct" outbound (routing rule match), so it never reaches the upstream server.') }
    if ((v 'correlation') -eq 'not-chained') { $reasons.Add('Traffic test: bytes through NordVPN did not appear on the upstream adapter.') }
    if ($reasons.Count) { return [pscustomobject]@{ State = 'NORDVPN_ONLY'; Reasons = $reasons.ToArray() } }

    if ((v 'appDefaultIf') -eq 'upstream' -or ($upExit -and $pub -and $pub -eq $upExit)) {
        $reasons.Add('Applications exit through the upstream, not NordVPN (NordVPN route not preferred or split tunnelling).')
        return [pscustomobject]@{ State = 'UPSTREAM_ONLY'; Reasons = $reasons.ToArray() }
    }
    if (v 'systemProxyBypass') {
        $reasons.Add('Windows system proxy points at the local upstream core: browsers/proxy-aware apps bypass NordVPN. In v2rayN choose "Clear system proxy".')
        return [pscustomobject]@{ State = 'UPSTREAM_ONLY'; Reasons = $reasons.ToArray() }
    }
    if ((v 'dnsLeak') -eq $true) {
        $reasons.Add('A DNS server outside the NordVPN tunnel is reachable / was used.')
        return [pscustomobject]@{ State = 'DNS_LEAK'; Reasons = $reasons.ToArray() }
    }

    $proven = ((v 'nordEndpointIf') -eq 'upstream') -or ((v 'correlation') -eq 'chained')
    if (-not $proven) {
        $reasons.Add('NordVPN endpoint unknown and no traffic test result: chain order cannot be proven. Run "vpn-chain test".')
        return [pscustomobject]@{ State = 'UNKNOWN'; Reasons = $reasons.ToArray() }
    }
    return [pscustomobject]@{ State = 'CHAIN_OK'; Reasons = @() }
}

# ----------------------------------------------------------------------------
# Fact gathering
# ----------------------------------------------------------------------------

function Get-IfRole {
    param([int]$IfIndex, $UpstreamAdapter, $NordInfo)
    if ($null -eq $IfIndex) { return 'unknown' }
    if ($NordInfo -and @($NordInfo.Adapters | ForEach-Object ifIndex) -contains $IfIndex) { return 'nord' }
    if ($UpstreamAdapter -and $UpstreamAdapter.ifIndex -eq $IfIndex) { return 'upstream' }
    return 'wan'
}

function Get-CorrelationKey {
    param($Env)
    if (-not ($Env.Nord.Active -and $Env.Upstream.Adapter)) { return $null }
    '{0}|{1}|{2}' -f $Env.Nord.Active.ifIndex, $Env.Upstream.Adapter.ifIndex, $Env.Nord.Protocol
}

function Get-LocalFacts {
    # Facts that need no Internet traffic: adapters, routes, sockets.
    # A traffic-correlation result from an earlier 'start'/'test' is reused (labelled as cached)
    # only while the same NordVPN adapter, upstream adapter and protocol are in place.
    param($Env, $Session)
    $f = [ordered]@{
        upstreamMode = $Env.Upstream.Mode
        upstreamUp   = [bool]($Env.Upstream.Adapter -and $Env.Upstream.Adapter.IsUp)
        nordUp       = $Env.Nord.Connected
    }
    if ($Env.Nord.Endpoints.Count) {
        $roles = @($Env.Nord.Endpoints | ForEach-Object { $r = Get-EffectiveRoute $_; if ($r) { Get-IfRole $r.ifIndex $Env.Upstream.Adapter $Env.Nord } else { 'unknown' } })
        $f.nordEndpointIf = if ($roles -contains 'nord') { 'nord' } elseif ($roles -contains 'wan') { 'wan' } elseif ($roles -contains 'upstream') { 'upstream' } else { 'unknown' }
    } else { $f.nordEndpointIf = 'unknown' }
    # Socket evidence beats the route table: if the core is connected to the server from a WAN
    # address, the transport leaves on the WAN (the route lookup alone can't see process rules/binding).
    $wanRemotes = @($Env.Upstream.WanRemotes)
    $f.upstreamServerIfs = @($Env.Upstream.Servers | Where-Object { $_ -notmatch '/' } | ForEach-Object {
        if ($wanRemotes -contains $_) { 'wan' }
        else { $r = Get-EffectiveRoute $_; if ($r) { Get-IfRole $r.ifIndex $Env.Upstream.Adapter $Env.Nord } }
    })
    $f.systemProxyBypass = [bool]($Env.Upstream.Mode -eq 'tun' -and $Env.Upstream.SystemProxy.Enabled -and $Env.Upstream.SystemProxy.Local)
    $f.coreLoop = [bool]($Env.Upstream.LoopConnections.Count)
    $f.coreDirectToNord = [bool]($Env.Upstream.DirectToNord.Count)
    $probe = Get-EffectiveRoute '1.1.1.1'
    $f.appDefaultIf = if ($probe) { Get-IfRole $probe.ifIndex $Env.Upstream.Adapter $Env.Nord } else { 'none' }
    if ($Session -and $Session.context -and $Session.context.correlation -and $Session.context.correlationKey -eq (Get-CorrelationKey $Env)) {
        $f.correlation = $Session.context.correlation
        $f.correlationCached = $true
    }
    return $f
}

function Test-TrafficCorrelation {
    # Empirical proof of encapsulation order: download a known amount through the default
    # route (NordVPN) and check that roughly the same volume crossed the upstream adapter.
    param($Env, [int]$Bytes = 4000000)
    if (-not ($Env.Nord.Active -and $Env.Upstream.Adapter)) { return [pscustomobject]@{ Result = 'unknown'; Detail = 'NordVPN or upstream adapter missing' } }
    $nIdx = $Env.Nord.Active.ifIndex; $uIdx = $Env.Upstream.Adapter.ifIndex
    $urls = @("https://speed.cloudflare.com/__down?bytes=$Bytes", 'https://proof.ovh.net/files/10Mb.dat', 'http://speedtest.tele2.net/10MB.zip')
    $s0 = Get-InterfaceStats @($nIdx, $uIdx)
    $got = 0
    foreach ($u in $urls) {
        try { $got = (Invoke-HttpGet -Url $u -TimeoutMs 30000 -MaxBytes 0).Bytes; if ($got -gt 1000000) { break } } catch { Write-Log VERIFY "download probe $u failed: $($_.Exception.Message)" -Level DEBUG }
    }
    Start-Sleep -Milliseconds 500
    $s1 = Get-InterfaceStats @($nIdx, $uIdx)
    if ($got -lt 1000000 -or -not $s0.ContainsKey($nIdx) -or -not $s0.ContainsKey($uIdx) -or -not $s1.ContainsKey($nIdx) -or -not $s1.ContainsKey($uIdx)) {
        return [pscustomobject]@{ Result = 'unknown'; Detail = "download probe unavailable or adapter counters not exposed (downloaded $got bytes)" }
    }
    $dn = $s1[$nIdx].Rx - $s0[$nIdx].Rx
    $du = $s1[$uIdx].Rx - $s0[$uIdx].Rx
    $detail = 'downloaded {0:N0} B; NordVPN rx +{1:N0} B; upstream rx +{2:N0} B' -f $got, $dn, $du
    if ($dn -lt ($got * 0.5)) { return [pscustomobject]@{ Result = 'unknown'; Detail = "$detail (download did not traverse NordVPN adapter)" } }
    if ($du -ge ($dn * 0.8)) { return [pscustomobject]@{ Result = 'chained'; Detail = $detail } }
    return [pscustomobject]@{ Result = 'not-chained'; Detail = $detail }
}

function Test-DnsPath {
    # 1) Every DNS server configured on a non-NordVPN interface must be unreachable (blocked).
    # 2) Resolver egress check (informational) via whoami.akamai.net.
    param($Env)
    $nordIdx = @($Env.Nord.Adapters | ForEach-Object ifIndex)
    $others = @($Env.Inventory | Where-Object { $_.IsUp -and $nordIdx -notcontains $_.ifIndex -and $_.Kind -ne 'loopback' } |
        ForEach-Object { $_.DnsServers } | Where-Object { $_ -and (Test-IpAddressString $_) } | Select-Object -Unique)
    $results = @()
    foreach ($s in $others) {
        $res = Test-RawDnsReachable -Server $s
        $results += [pscustomobject]@{ Server = $s; Result = $res }
        Write-Log DNS "non-NordVPN resolver $s -> $res" -Level DEBUG
    }
    $resolverEgress = $null
    try {
        $a = Resolve-DnsName -Name 'whoami.akamai.net' -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
        if ($a) { $resolverEgress = $a.IPAddress }
    } catch { }
    $resolves = $false
    try { $resolves = [bool](Resolve-DnsName -Name 'www.example.com' -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop) } catch { }
    [pscustomobject]@{
        OtherResolvers = $results
        Leak           = [bool](@($results | Where-Object Result -eq 'reachable').Count)
        ResolverEgress = $resolverEgress
        Resolves       = $resolves
        NordDns        = $Env.Nord.DnsServers
    }
}

function Test-IPv6Egress {
    param($Config)
    $r = Get-PublicIp -Services $Config.ipv6CheckServices -TimeoutMs 5000 -FirstOnly
    return $r.Ip
}

function Get-NordInsights {
    param($Config)
    if (-not $Config.nordInsightsUrl) { return $null }
    try { return ((Invoke-HttpGet -Url $Config.nordInsightsUrl -TimeoutMs 8000).Body | ConvertFrom-Json) } catch { return $null }
}
