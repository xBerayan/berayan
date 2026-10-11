# Engine.ps1 - desired-state model, transactional reconcile, commands.

# ----------------------------------------------------------------------------
# Environment
# ----------------------------------------------------------------------------

function Get-ChainEnvironment {
    param([Parameter(Mandatory)]$Config, $Session)
    $inv = @(Get-InterfaceInventory)
    $ctx = if ($Session) { $Session.context } else { $null }

    # Sticky upstream adapter: once a session picked an adapter, keep it while it exists.
    $cfgForUp = $Config
    if ($ctx -and $ctx.upstreamAlias -and $Config.upstream.adapter -eq 'auto' -and ($inv | Where-Object { $_.Alias -eq $ctx.upstreamAlias -and $_.IsUp })) {
        $cfgForUp = ConvertTo-Hashtable ($Config | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
        $cfgForUp.upstream.adapter = $ctx.upstreamAlias
    }
    $knownNord = if ($ctx -and $ctx.nordEndpoints) { @($ctx.nordEndpoints) } else { @() }
    $nordUpNow = [bool](@($inv | Where-Object { $_.Kind -eq 'nordvpn' -and $_.IsUp }).Count)
    $hostRoutes = (-not $Session) -and (-not $nordUpNow)
    $up = Get-UpstreamInfo -Inventory $inv -Config $cfgForUp -KnownNordEndpoints $knownNord -IncludeHostRoutes:$hostRoutes
    if ($ctx -and $ctx.upstreamServers) {
        # Servers learned at start stay valid even when their sockets are momentarily not visible.
        $up.Servers = @(@($ctx.upstreamServers) + @($up.Servers) | Where-Object { $_ } | Select-Object -Unique)
    }
    if ($ctx) {
        # Same for server names / bootstrap DNS (the DNS cache entry may expire mid-session).
        $up.ServerNames  = @(@($ctx.upstreamServerNames) + @($up.ServerNames) | Where-Object { $_ } | Select-Object -Unique)
        $up.BootstrapDns = @(@($ctx.bootstrapDns) + @($up.BootstrapDns) | Where-Object { $_ } | Select-Object -Unique)
    }

    $ownPrefixes = @()
    if ($Session) { $ownPrefixes = @($Session.journal | Where-Object { $_.kind -eq 'route' } | ForEach-Object { $_.prefix }) }
    $snap = if ($Session) { $Session.snapshot } else { $null }
    # No fallback to previously seen endpoints: after a server switch that would pin a stale IP
    # and present it as evidence. Unknown stays unknown.
    $since = if ($Session -and $Session.createdAt) { [datetime]$Session.createdAt } else { $null }
    $nord = Get-NordVpnInfo -Inventory $inv -Config $Config -Snapshot $snap -OwnRoutePrefixes $ownPrefixes -UpstreamServers $up.Servers -Since $since
    if ($nord.Endpoints.Count -and $up.ProcessIds.Count) {
        # Re-check "core sends NordVPN transport direct" now that endpoints are known.
        $up = Get-UpstreamInfo -Inventory $inv -Config $cfgForUp -KnownNordEndpoints $nord.Endpoints -IncludeHostRoutes:$hostRoutes
        if ($ctx -and $ctx.upstreamServers) { $up.Servers = @(@($ctx.upstreamServers) + @($up.Servers) | Where-Object { $_ } | Select-Object -Unique) }
        if ($ctx) {
            $up.ServerNames  = @(@($ctx.upstreamServerNames) + @($up.ServerNames) | Where-Object { $_ } | Select-Object -Unique)
            $up.BootstrapDns = @(@($ctx.bootstrapDns) + @($up.BootstrapDns) | Where-Object { $_ } | Select-Object -Unique)
        }
    }
    [pscustomobject]@{ Config = $Config; Inventory = $inv; Upstream = $up; Nord = $nord }
}

# ----------------------------------------------------------------------------
# Desired state
# ----------------------------------------------------------------------------

function New-RuleSpec {
    param([string]$Purpose, [string]$Protocol, [string[]]$Remote, [string[]]$Ports, $Interfaces)
    $ifs = @($Interfaces | Where-Object { $_ })
    if (-not $ifs.Count -or -not @($Remote).Count) { return $null }
    $spec = [ordered]@{
        kind = 'fwrule'; purpose = $Purpose; protocol = $Protocol
        remoteAddress = @($Remote); remotePort = @($Ports | Where-Object { $_ })
        interfaceAlias = @($ifs | ForEach-Object Alias | Select-Object -Unique)
        ifKeys = @($ifs | ForEach-Object { '{0}#{1}' -f $_.Alias, $_.ifIndex } | Sort-Object -Unique)
    }
    $spec.signature = Get-RuleSignature $spec
    $spec.name = '{0}{1}-{2}' -f $script:RulePrefix, $Purpose, $spec.signature
    return $spec
}

function New-RouteSpec {
    param([string]$Purpose, [string]$Ip, $Interface, [string]$NextHop)
    [ordered]@{
        kind = 'route'; purpose = $Purpose; family = (Get-IpFamily $Ip)
        prefix = (Get-HostPrefix $Ip); ifIndex = [int]$Interface.ifIndex; alias = $Interface.Alias
        nextHop = $NextHop; metric = 0
    }
}

function Get-DesiredState {
    param([Parameter(Mandatory)]$Env, [switch]$NordPhase)
    $cfg = $Env.Config
    $upIf = $Env.Upstream.Adapter
    $items = New-Object System.Collections.Generic.List[object]
    $notes = New-Object System.Collections.Generic.List[string]
    $wan = Get-WanSideInterfaces $Env.Inventory $upIf
    $srv = @($Env.Upstream.Servers)
    $srvHosts = @($srv | Where-Object { $_ -notmatch '/' })
    $nordEps = @($Env.Nord.Endpoints)

    # 1. Upstream server(s) -> physical WAN (prevents upstream -> NordVPN -> upstream recursion).
    foreach ($ip in $srvHosts) {
        $fam = Get-IpFamily $ip
        $p = Get-PrimaryWan $Env.Inventory $upIf $fam
        if (-not $p) { $notes.Add("No IPv$fam WAN gateway for upstream server $ip; not pinned."); continue }
        $gw = if ($fam -eq 4) { $p.Gateway4 } else { $p.Gateway6 }
        $items.Add((New-RouteSpec 'upstream-server' $ip $p $gw))
    }

    # 1b. The core's bootstrap DNS -> physical WAN, and the core's server names -> that DNS (NRPT).
    #     Without this, once NordVPN owns system DNS the core would resolve its own server *through
    #     NordVPN*, whose transport depends on that very core: a reconnect deadlock.
    $boot = @($Env.Upstream.BootstrapDns | Where-Object { $_ })
    foreach ($ip in $boot) {
        $fam = Get-IpFamily $ip
        $p = Get-PrimaryWan $Env.Inventory $upIf $fam
        if (-not $p) { $notes.Add("No IPv$fam WAN gateway for bootstrap DNS $ip; not pinned."); continue }
        $gw = if ($fam -eq 4) { $p.Gateway4 } else { $p.Gateway6 }
        $items.Add((New-RouteSpec 'upstream-dns' $ip $p $gw))
    }
    if ($boot.Count) {
        foreach ($n in @($Env.Upstream.ServerNames)) {
            $items.Add([ordered]@{ kind = 'nrpt'; purpose = 'upstream-name'; namespace = $n; nameServers = @($boot) })
        }
    } elseif (@($Env.Upstream.ServerNames).Count) {
        $notes.Add("Upstream server name(s) $(@($Env.Upstream.ServerNames) -join ', ') are resolved by Windows, but no bootstrap DNS is known. After NordVPN connects those lookups would go through NordVPN (reconnect deadlock). Set upstream.bootstrapDns.")
    }

    # 1c. Applications -> NordVPN. A TUN upstream often has interface metric 0 and wins against
    #     NordVPN's own 0.0.0.0/0 (NordLynx metric 5): NordVPN "connects" but nothing - not even its
    #     DNS - flows through it, and NordVPN tears the connection down. Two /1 routes are more
    #     specific than any /0, so they win regardless of metrics. NordLynx's own encrypted packets
    #     are unaffected: wireguard-nt excludes its own adapter when routing the endpoint.
    # 1d. Keep the chained VPN's adapters *less* preferred than the WAN as "default interface".
    #     sing-box (auto_detect_interface) follows the best 0.0.0.0/0 route; a VPN installing a
    #     low-metric /0 (IKEv2, NordLynx) makes it switch interface and reset every connection -
    #     including the flow the VPN itself runs on. Apps are unaffected: they use the /1 routes.
    foreach ($a in @($Env.Nord.Adapters)) {
        if ($null -ne $a.Metric4) {
            $items.Add([ordered]@{ kind = 'ifmetric'; purpose = 'vpn-metric'; ifIndex = [int]$a.ifIndex; alias = $a.Alias; metric = $script:VpnInterfaceMetric })
        }
    }

    $nordAct = $Env.Nord.Active
    if ($nordAct -and $Env.Nord.Connected) {
        $nh = if ($nordAct.Gateway4) { $nordAct.Gateway4 } else { '0.0.0.0' }
        foreach ($half in '0.0.0.0/1', '128.0.0.0/1') {
            $items.Add([ordered]@{ kind = 'route'; purpose = 'nord-default'; family = 4; prefix = $half; ifIndex = [int]$nordAct.ifIndex; alias = $nordAct.Alias; nextHop = $nh; metric = 0 })
        }
    }

    # 2. NordVPN server endpoint(s) -> upstream tunnel (forces NordVPN transport through the upstream).
    if ($upIf -and $upIf.IsUp) {
        foreach ($ip in $nordEps) {
            $fam = Get-IpFamily $ip
            if ($fam -eq 6 -and -not $upIf.IPv6.Count) { $notes.Add("NordVPN endpoint $ip is IPv6 but the upstream tunnel has no IPv6; not pinned."); continue }
            $nh = if ($fam -eq 4) { if ($upIf.Gateway4) { $upIf.Gateway4 } else { '0.0.0.0' } } else { if ($upIf.Gateway6) { $upIf.Gateway6 } else { '::' } }
            $items.Add((New-RouteSpec 'nord-endpoint' $ip $upIf $nh))
        }
    }

    # 3. Leak guard on WAN-side interfaces (fail-closed kill switch).
    $exempt = @($srv) + $boot + @($cfg.allowRemoteAddresses | Where-Object { $_ })
    $allow4 = @($exempt | Where-Object { (Get-IpFamily $_) -eq 4 })
    $allow6 = @($exempt | Where-Object { (Get-IpFamily $_) -eq 6 })
    $allow4 += $(if ($cfg.allowLan) { $script:LanAllow4 } else { $script:LinkAllow4 })
    $allow6 += $(if ($cfg.allowLan) { $script:LanAllow6 } else { $script:LinkAllow6 })
    # NordVPN endpoints must never be allowed on WAN, even if a user allow-list overlaps them.
    if ($cfg.killSwitch) {
        $items.Add((New-RuleSpec 'killswitch-v4' 'Any' (Get-RangeComplement -Exclude $allow4 -Family 4) @() $wan))
        $items.Add((New-RuleSpec 'killswitch-v6' 'Any' (Get-RangeComplement -Exclude $allow6 -Family 6) @() $wan))
    }
    if ($nordEps.Count) {
        $items.Add((New-RuleSpec 'nord-endpoint-direct' 'Any' $nordEps @() $wan))
    }

    # 4. DNS leak protection: no DNS/DoT over WAN; no DNS via the upstream once NordVPN is involved.
    if ($cfg.dnsLeakProtection) {
        # $boot already includes dnsBootstrapAllow (merged in Get-UpstreamInfo).
        $dnsRemote = @()
        foreach ($fam in 4, 6) { $dnsRemote += Get-RangeComplement -Exclude @($boot | Where-Object { (Get-IpFamily $_) -eq $fam }) -Family $fam }
        foreach ($proto in 'UDP', 'TCP') {
            $items.Add((New-RuleSpec "dns-wan-$($proto.ToLower())" $proto $dnsRemote @('53','853') $wan))
            if ($NordPhase -and $upIf) {
                $items.Add((New-RuleSpec "dns-upstream-$($proto.ToLower())" $proto @('Any') @('53','853') @($upIf)))
            }
        }
    }

    # 5. IPv6: only NordVPN may carry IPv6 (block-if-unsafe), or nothing may (block-all).
    if ($cfg.ipv6Policy -ne 'allow') {
        if (-not $cfg.killSwitch) {
            $items.Add((New-RuleSpec 'ipv6-wan' 'Any' (Get-RangeComplement -Exclude $allow6 -Family 6) @() $wan))
        }
        if ($upIf) {
            $ex = $script:LinkAllow6 + @($nordEps | Where-Object { (Get-IpFamily $_) -eq 6 })
            $items.Add((New-RuleSpec 'ipv6-upstream' 'Any' (Get-RangeComplement -Exclude $ex -Family 6) @() @($upIf)))
        }
        if ($cfg.ipv6Policy -eq 'block-all' -and $Env.Nord.Adapters.Count) {
            $items.Add((New-RuleSpec 'ipv6-nordvpn' 'Any' (Get-RangeComplement -Exclude $script:LinkAllow6 -Family 6) @() @($Env.Nord.Adapters)))
        }
    }

    [pscustomobject]@{ Items = @($items | Where-Object { $_ }); Notes = $notes.ToArray() }
}

# ----------------------------------------------------------------------------
# Transactional reconcile
# ----------------------------------------------------------------------------

function Get-ItemKey {
    param($Item)
    if ($Item.kind -eq 'route') { return 'route|{0}|{1}|{2}' -f $Item.prefix, $Item.ifIndex, $Item.nextHop }
    if ($Item.kind -eq 'nrpt') { return 'nrpt|{0}|{1}' -f $Item.namespace, (@($Item.nameServers) -join ',') }
    if ($Item.kind -eq 'ifmetric') { return 'ifmetric|{0}' -f $Item.ifIndex }
    return 'fw|' + $Item.name
}

function Invoke-ApplyItem {
    param($Session, $Item)
    $entry = [ordered]@{}
    foreach ($k in $Item.Keys) { $entry[$k] = $Item[$k] }
    if ($Item.kind -eq 'route') {
        if ((Test-RouteExists $Item.prefix $Item.ifIndex $Item.nextHop) -or
            ($Item.purpose -eq 'nord-default' -and (Test-RoutePrefixOnInterface $Item.prefix $Item.ifIndex))) {
            # Already there (e.g. the VPN installs 0/1 + 128/1 itself): not ours, never journaled or removed.
            Write-Log ROUTE "$($Item.prefix) via $($Item.alias) already present (not created by vpn-chain) - leaving as is" -Level DEBUG
            return $true
        }
        $entry = Add-JournalEntry $Session $entry
        try {
            Add-HostRoute $Item.prefix $Item.ifIndex $Item.nextHop $Item.metric
            if (-not (Test-RouteExists $Item.prefix $Item.ifIndex $Item.nextHop)) { throw 'route not present after creation' }
        } catch {
            try { Remove-HostRoute $Item.prefix $Item.ifIndex $Item.nextHop } catch { }
            Set-JournalEntryStatus $Session $entry 'removed'
            throw "Failed to add route $($Item.prefix) via $($Item.alias): $($_.Exception.Message)"
        }
        Set-JournalEntryStatus $Session $entry 'applied'
        $what = switch ($Item.purpose) { 'nord-endpoint' { 'NordVPN endpoint pinned to upstream' } 'upstream-dns' { 'upstream bootstrap DNS pinned to WAN' } 'nord-default' { 'application default route forced into NordVPN' } default { 'upstream server pinned to WAN' } }
        Write-Log ROUTE "$what`: $($Item.prefix) -> $($Item.alias) (nexthop $($Item.nextHop))" -Level OK
        return $true
    }
    if ($Item.kind -eq 'ifmetric') {
        $cur = Get-ChainIfMetric $Item.ifIndex
        if (-not $cur -or $cur.Metric -ge $Item.metric) { return $true }      # absent, or already high enough: not ours
        $entry['prevMetric'] = $cur.Metric; $entry['prevAutomatic'] = $cur.Automatic
        $entry = Add-JournalEntry $Session $entry
        try { Set-ChainIfMetric $Item.ifIndex $Item.metric }
        catch { Set-JournalEntryStatus $Session $entry 'removed'; throw "Failed to set interface metric on $($Item.alias): $($_.Exception.Message)" }
        Set-JournalEntryStatus $Session $entry 'applied'
        Write-Log ROUTE "NordVPN adapter '$($Item.alias)' interface metric $($cur.Metric) -> $($Item.metric) (keeps the upstream core on the WAN)" -Level OK
        return $true
    }
    if ($Item.kind -eq 'nrpt') {
        $entry = Add-JournalEntry $Session $entry
        try {
            $entry['ruleName'] = Add-ChainNrptRule -Namespace $Item.namespace -NameServers @($Item.nameServers)
            Save-Session $Session
            if (-not (Test-ChainNrptRule $entry['ruleName'])) { throw 'NRPT rule not present after creation' }
        } catch {
            if ($entry['ruleName']) { try { Remove-ChainNrptRule $entry['ruleName'] } catch { } }
            Set-JournalEntryStatus $Session $entry 'removed'
            throw "Failed to add NRPT rule for $($Item.namespace): $($_.Exception.Message)"
        }
        Set-JournalEntryStatus $Session $entry 'applied'
        Write-Log DNS "upstream server name '$($Item.namespace)' resolves via bootstrap DNS $(@($Item.nameServers) -join ', ') (kept outside NordVPN)" -Level OK
        return $true
    }
    $entry = Add-JournalEntry $Session $entry
    try {
        Add-ChainFirewallRule $Item
        if (-not (Get-NetFirewallRule -Name $Item.name -ErrorAction SilentlyContinue)) { throw 'rule not present after creation' }
    } catch {
        try { Remove-ChainFirewallRule $Item.name } catch { }
        Set-JournalEntryStatus $Session $entry 'removed'
        throw "Failed to add firewall rule $($Item.name): $($_.Exception.Message)"
    }
    Set-JournalEntryStatus $Session $entry 'applied'
    $tag = if ($Item.purpose -like 'dns-*') { 'DNS' } elseif ($Item.purpose -like 'ipv6-*') { 'IPV6' } else { 'FIREWALL' }
    Write-Log $tag "guard active: $($Item.purpose) on $(@($Item.interfaceAlias) -join ', ')" -Level OK
    return $true
}

function Undo-JournalItem {
    param($Item)
    if ($Item.kind -eq 'route') {
        Remove-HostRoute $Item.prefix ([int]$Item.ifIndex) $Item.nextHop
        Write-Log ROLLBACK "route removed: $($Item.prefix) via $($Item.alias)"
    } elseif ($Item.kind -eq 'fwrule') {
        Remove-ChainFirewallRule $Item.name
        Write-Log ROLLBACK "firewall rule removed: $($Item.purpose)"
    } elseif ($Item.kind -eq 'ifmetric') {
        if ($Item.Contains('prevMetric')) { Restore-ChainIfMetric ([int]$Item.ifIndex) ([int]$Item.prevMetric) ([bool]$Item.prevAutomatic) }
        Write-Log ROLLBACK "interface metric restored: $($Item.alias)"
    } elseif ($Item.kind -eq 'nrpt') {
        # A 'pending' entry may lack ruleName (crash mid-create); the comment-tag sweep in Undo-All covers it.
        if ($Item.ruleName) { Remove-ChainNrptRule $Item.ruleName }
        Write-Log ROLLBACK "NRPT rule removed: $($Item.namespace)"
    }
}

function Invoke-Reconcile {
    # Adds missing items first, then removes obsolete ones (never a window without protection).
    param([Parameter(Mandatory)]$Session, [Parameter(Mandatory)]$Desired)
    $applied = @{}
    foreach ($j in @($Session.journal)) { if ($j.status -in @('applied','pending')) { $applied[(Get-ItemKey $j)] = $j } }
    $want = @{}
    $changes = 0
    foreach ($d in $Desired.Items) {
        $k = Get-ItemKey $d
        $want[$k] = $true
        if ($applied.ContainsKey($k)) {
            # VPN apps may reset their adapter metric on reconnect: re-assert it (original value stays journaled).
            if ($d.kind -eq 'ifmetric') {
                $cur = Get-ChainIfMetric $d.ifIndex
                if ($cur -and $cur.Metric -lt $d.metric) { try { Set-ChainIfMetric $d.ifIndex $d.metric; $changes++ } catch { } }
            }
            continue
        }
        [void](Invoke-ApplyItem $Session $d)
        $changes++
    }
    foreach ($j in @($Session.journal)) {
        if ($j.status -notin @('applied','pending')) { continue }
        if ($want.ContainsKey((Get-ItemKey $j))) { continue }
        try { Undo-JournalItem $j; $j.status = 'removed'; $changes++ }
        catch { Write-Log ROLLBACK "could not remove obsolete $($j.kind) $($j.prefix)$($j.name): $($_.Exception.Message)" -Level WARN; $j.status = 'failed-removal' }
    }
    $Session.journal = @($Session.journal | Where-Object { $_.status -ne 'removed' })
    Save-Session $Session
    foreach ($n in $Desired.Notes) { Write-Log ROUTE $n -Level WARN }
    return $changes
}

function Undo-All {
    # Reverse-order removal of everything in the journal, then a sweep of our firewall group.
    param($Session)
    $failures = 0
    $journal = @($Session.journal)
    [Array]::Reverse($journal)
    foreach ($j in $journal) {
        try { Undo-JournalItem $j; $j.status = 'removed' }
        catch { $failures++; $j.status = 'failed-removal'; Write-Log ROLLBACK "failed to remove $($j.kind) $($j.prefix)$($j.name): $($_.Exception.Message)" -Level ERROR }
    }
    foreach ($r in @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue)) {
        try { $r | Remove-NetFirewallRule -ErrorAction Stop; Write-Log ROLLBACK "firewall rule removed (group sweep): $($r.Name)" }
        catch { $failures++; Write-Log ROLLBACK "failed to remove $($r.Name): $($_.Exception.Message)" -Level ERROR }
    }
    foreach ($n in @(Get-OrphanChainNrptRules)) {
        try { Remove-ChainNrptRule $n; Write-Log ROLLBACK "NRPT rule removed (tag sweep): $n" }
        catch { $failures++; Write-Log ROLLBACK "failed to remove NRPT rule $n`: $($_.Exception.Message)" -Level ERROR }
    }
    $Session.journal = @($Session.journal | Where-Object { $_.status -ne 'removed' })
    if ($Session.Contains('id')) { Save-Session $Session }
    return $failures
}

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

function Test-TcpConnect {
    param([string]$Ip = '1.1.1.1', [int]$Port = 443, [int]$TimeoutMs = 4000)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($Ip, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $c.EndConnect($ar); return $true
    } catch { return $false } finally { $c.Close() }
}

function Write-Banner { param([string]$Text, [string]$Color = 'Cyan') Write-Host ''; Write-Host "== $Text ==" -ForegroundColor $Color }

function Write-Unavailable {
    param([string]$Code, [string[]]$Why, [string[]]$Fix)
    Write-Host ''
    Write-Host "CHAIN_UNAVAILABLE ($Code)" -ForegroundColor Red
    foreach ($w in $Why) { Write-Host "  reason : $w" -ForegroundColor Red }
    foreach ($f in $Fix) { Write-Host "  fix    : $f" -ForegroundColor Yellow }
    Write-Log START "CHAIN_UNAVAILABLE ($Code): $($Why -join ' | ')" -Level ERROR
}

function Invoke-NordCli {
    param($Install, [string[]]$Arguments)
    if (-not $Install.CliPath) { throw 'NordVPN.exe not found; connect NordVPN manually.' }
    Write-Log NORDVPN "running documented CLI: NordVPN.exe $($Arguments -join ' ')"
    Start-Process -FilePath $Install.CliPath -ArgumentList $Arguments -WindowStyle Hidden | Out-Null
}

function Wait-NetworkChange {
    param([int]$TimeoutSec)
    $id = 'vpnchain.wait.' + [guid]::NewGuid().ToString('N')
    Register-ObjectEvent -InputObject ([System.Net.NetworkInformation.NetworkChange]) -EventName NetworkAddressChanged -SourceIdentifier $id | Out-Null
    try { $e = Wait-Event -SourceIdentifier $id -Timeout $TimeoutSec; if ($e) { $e | Remove-Event } }
    finally { Unregister-Event -SourceIdentifier $id -ErrorAction SilentlyContinue; Get-Event -SourceIdentifier $id -ErrorAction SilentlyContinue | Remove-Event }
}

# ----------------------------------------------------------------------------
# Full verification
# ----------------------------------------------------------------------------

function Invoke-ChainVerification {
    param([Parameter(Mandatory)]$Env, $Session, [switch]$Traffic, [switch]$Quick)
    $cfg = $Env.Config
    $facts = Get-LocalFacts $Env $Session
    if ($Session -and $Session.context.upstreamExitIp) { $facts.upstreamExitIp = $Session.context.upstreamExitIp }
    if ($cfg.Contains('directPublicIp') -and $cfg.directPublicIp) { $facts.directIp = $cfg.directPublicIp }
    $report = [ordered]@{}

    $ip = Get-PublicIp -Services $cfg.ipCheckServices -FirstOnly:$Quick
    $facts.publicIp = $ip.Ip
    $report.publicIp = $ip
    if (-not $Quick) {
        $ins = Get-NordInsights $cfg
        $report.nordInsights = $ins
        $v6 = Test-IPv6Egress $cfg
        $report.ipv6Egress = $v6
        $facts.ipv6Leak = if ($cfg.ipv6Policy -eq 'allow') { $null } elseif ($v6 -and -not ($Env.Nord.HasIPv6 -and $cfg.ipv6Policy -eq 'block-if-unsafe')) { $true } else { $false }
        if ($Env.Nord.Connected) {
            $dns = Test-DnsPath $Env
            $report.dns = $dns
            $facts.dnsLeak = $dns.Leak
        }
        if ($Traffic -and $Env.Nord.Connected) {
            $corr = Test-TrafficCorrelation $Env
            $report.correlation = $corr
            $facts.correlation = $corr.Result
            $facts.correlationCached = $false
            if ($Session -and $Session.Contains('id') -and $corr.Result -in @('chained','not-chained')) {
                $Session.context.correlation = $corr.Result
                $Session.context.correlationKey = Get-CorrelationKey $Env
                try { Save-Session $Session } catch { Write-Log STATE 'could not cache traffic-test result (not elevated?)' -Level DEBUG }
            }
        }
    }
    $state = Get-ChainState $facts
    if ($report.Contains('dns') -and $report.dns -and -not $report.dns.Resolves -and $state.State -eq 'CHAIN_OK') {
        $state = [pscustomobject]@{ State = 'UNKNOWN'; Reasons = @('DNS resolution through NordVPN fails. If the upstream TUN uses strict_route (v2rayN "Strict Route"), it blocks DNS on every other adapter including NordVPN - disable it.') }
    }
    [pscustomobject]@{ Facts = $facts; State = $state; Report = $report }
}

function Write-VerificationReport {
    param($Env, $V, $Session)
    $f = $V.Facts
    $r = $V.Report
    Write-Banner 'Verification report'
    $rows = @(
        @('Upstream mode', $Env.Upstream.Mode),
        @('Upstream adapter', $(if ($Env.Upstream.Adapter) { '{0} (if {1})' -f $Env.Upstream.Adapter.Alias, $Env.Upstream.Adapter.ifIndex } else { '-' })),
        @('Upstream servers', ($Env.Upstream.Servers -join ', ')),
        @('Upstream server path', (@($f.upstreamServerIfs) -join ', ')),
        @('NordVPN', $(if ($Env.Nord.Connected) { '{0} on {1}' -f $Env.Nord.Protocol, $Env.Nord.Active.Alias } else { 'disconnected' })),
        @('NordVPN endpoint', $(if ($Env.Nord.Endpoints.Count) { '{0} [{1}]' -f ($Env.Nord.Endpoints -join ', '), $Env.Nord.EndpointSource } else { 'unknown' })),
        @('NordVPN endpoint path', $f.nordEndpointIf),
        @('App default path', $f.appDefaultIf),
        @('Public IPv4', $(if ($r.publicIp.Ip) { '{0} ({1}/{2} services agree)' -f $r.publicIp.Ip, $r.publicIp.Agree, $r.publicIp.Total } else { 'unreachable' })),
        @('Upstream exit IPv4', $(if ($f.Contains('upstreamExitIp') -and $f.upstreamExitIp) { $f.upstreamExitIp } else { 'not recorded' }))
    )
    if ($r.Contains('nordInsights') -and $r.nordInsights) { $rows += ,@('NordVPN says protected', ('{0} ({1}, {2})' -f $r.nordInsights.protected, $r.nordInsights.isp, $r.nordInsights.country)) }
    if ($r.Contains('ipv6Egress')) { $rows += ,@('Public IPv6', $(if ($r.ipv6Egress) { $r.ipv6Egress } else { 'none (blocked/unavailable)' })) }
    if ($r.Contains('dns') -and $r.dns) {
        $rows += ,@('DNS (NordVPN)', ($r.dns.NordDns -join ', '))
        $rows += ,@('Other resolvers', $(if ($r.dns.OtherResolvers.Count) { ($r.dns.OtherResolvers | ForEach-Object { '{0}={1}' -f $_.Server, $_.Result }) -join ', ' } else { 'none' }))
        $rows += ,@('Resolver egress', $(if ($r.dns.ResolverEgress) { $r.dns.ResolverEgress } else { '-' }))
    }
    if ($r.Contains('correlation') -and $r.correlation) { $rows += ,@('Traffic test', ('{0}: {1}' -f $r.correlation.Result, $r.correlation.Detail)) }
    # What the upstream core itself sees of the VPN transport (sing-box/mihomo Clash API).
    $flows = @(Get-ClashApiEndpoints $Env.Config -Raw)
    if ($flows.Count) {
        $rows += ,@('VPN flows in upstream', (($flows | Select-Object -First 4 | ForEach-Object {
            '{0}:{1}/{2} up {3:N0}B down {4:N0}B via {5}' -f $_.metadata.destinationIP, $_.metadata.destinationPort, $_.metadata.network, [int64]$_.upload, [int64]$_.download, (@($_.chains) -join '>')
        }) -join ' | '))
        if (@($flows | Where-Object { [int64]$_.upload -gt 0 -and [int64]$_.download -eq 0 }).Count) {
            $rows += ,@('', 'VPN server never answered through the upstream (sent > 0, received 0): blocked beyond the upstream exit, or the upstream does not relay this protocol')
        }
    }
    foreach ($row in $rows) { Write-Host ('  {0,-24} {1}' -f $row[0], $row[1]) }
    $color = if ($V.State.State -eq 'CHAIN_OK') { 'Green' } else { 'Red' }
    Write-Host ''
    Write-Host ('  STATE: {0}' -f $V.State.State) -ForegroundColor $color
    foreach ($why in $V.State.Reasons) { Write-Host "   - $why" -ForegroundColor Yellow }
    if ($r.publicIp.Ip) { Write-Log VERIFY "final public IP $($r.publicIp.Ip)" }
    Write-Log VERIFY "state $($V.State.State) $($V.State.Reasons -join ' | ')" -Level $(if ($V.State.State -eq 'CHAIN_OK') { 'OK' } else { 'WARN' })
}

# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------

function Invoke-Start {
    param($Config, [hashtable]$Opt)
    $existing = Read-Session
    if ($existing -and $existing.status -in @('starting','waiting-nordvpn','active','stopping','corrupt')) {
        Write-Host "A vpn-chain session already exists (status: $($existing.status)). Use 'status', 'stop' or 'reset'." -ForegroundColor Yellow
        return 1
    }
    $stale = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue).Count + @(Get-OrphanChainNrptRules).Count
    if ($stale) { Write-Host "Found $stale leftover vpn-chain rule(s) from an interrupted session. Run '.\vpn-chain.cmd reset' first." -ForegroundColor Yellow; return 1 }

    Write-Banner 'Detecting environment'
    $install = Get-NordVpnInstall $Config
    if (-not $install.Installed) { Write-Unavailable 'NORDVPN_NOT_FOUND' @("NordVPN not found at $($install.Root)") @('Install the official NordVPN Windows app or set nordvpn.installPath.'); return 3 }
    Write-Log NORDVPN "installed: $($install.Version) service=$($install.ServiceState)"
    if ($install.ServiceState -ne 'Running') { Write-Unavailable 'NORDVPN_SERVICE' @("nordvpn-service is $($install.ServiceState)") @('Start the NordVPN app (it starts its service).'); return 3 }

    $env0 = Get-ChainEnvironment $Config $null
    # v2rayN recreates its TUN whenever it restarts the core (server switch, settings change):
    # give a briefly missing upstream adapter up to 30 s to come back.
    $until = (Get-Date).AddSeconds(30)
    while ($env0.Upstream.Mode -in @('none','tun-missing') -and (Get-Date) -lt $until) {
        Write-Log UPSTREAM 'upstream tunnel adapter not present yet - waiting (core restarting?)' -Level WARN
        Wait-NetworkChange -TimeoutSec 3
        $env0 = Get-ChainEnvironment $Config $null
    }
    $up = $env0.Upstream
    switch ($up.Mode) {
        'proxy' {
            Write-Unavailable 'UPSTREAM_NOT_SUPPORTED' @(
                "Upstream is proxy-only (processes: $($up.Processes -join ', '); system proxy: $($up.SystemProxy.Server); listening: $($up.ListenPorts -join ', ')).",
                'A system/SOCKS/HTTP proxy only carries applications that use it. NordVPN''s NordLynx (UDP) / OpenVPN transport is sent by a driver/service that ignores the proxy, so it would go DIRECTLY to the Internet.'
            ) @('Enable TUN mode in v2rayN (TUN switch on the main window) or add a "tun" inbound with auto_route to sing-box, then re-run start.',
                'Alternative without TUN: use the official OpenVPN client with a NordVPN .ovpn (TCP) file and "socks-proxy 127.0.0.1 <port>".')
            return 3
        }
        'none' { Write-Unavailable 'NO_UPSTREAM' @('No upstream tunnel adapter with a default route was found.') @('Connect v2rayN/sing-box in TUN mode first and confirm it works, or set upstream.adapter in config.json.'); return 3 }
        'tun-missing' { Write-Unavailable 'NO_UPSTREAM' @("Configured upstream adapter '$($Config.upstream.adapter)' is not up.") @('Connect the upstream first.'); return 3 }
    }
    Write-Log UPSTREAM "adapter detected: $($up.Adapter.Alias) (if $($up.Adapter.ifIndex), '$($up.Adapter.Description)', default $($up.Adapter.DefaultStyle4))" -Level OK
    if ($up.AmbiguousWith.Count) { Write-Log UPSTREAM "other candidate tunnel adapters: $($up.AmbiguousWith -join ', ') - set upstream.adapter to choose explicitly" -Level WARN }
    if ($up.Processes.Count) { Write-Log UPSTREAM "core processes: $($up.Processes -join ', ')" }
    foreach ($s in $up.Servers) { Write-Log UPSTREAM "tunnel endpoint detected: $s ($($up.ServerSources[$s]))" -Level OK }
    if (-not $up.Servers.Count) { Write-Log UPSTREAM 'upstream server endpoint not identified (UDP-based protocols are invisible to the socket table)' -Level WARN }
    if ($up.ServersAmbiguous) { Write-Log UPSTREAM 'several remote addresses seen for the core; if the kill switch blocks your upstream, set upstream.serverAddresses' -Level WARN }
    foreach ($n in $up.ServerNames) { Write-Log UPSTREAM "server name resolved by Windows: $n" }
    if ($up.BootstrapDns.Count) { Write-Log UPSTREAM "bootstrap DNS (core's direct resolver): $($up.BootstrapDns -join ', ')" -Level OK }

    # A system proxy pointing at the local core lets proxy-aware apps (browsers) go
    # app -> core -> upstream server directly, completely bypassing NordVPN.
    if ($up.Mode -eq 'tun' -and $up.SystemProxy.Enabled -and $up.SystemProxy.Local) {
        Write-Unavailable 'SYSTEM_PROXY_BYPASS' @("Windows system proxy is set to the local core ($($up.SystemProxy.Server)). Browsers and other proxy-aware apps would send traffic straight to the upstream, skipping NordVPN.") @('In v2rayN (bottom bar) set System proxy to "Clear system proxy" - TUN mode alone carries all traffic. Then re-run start.')
        return 3
    }
    if ($up.ServerNames.Count -and -not $up.BootstrapDns.Count -and $Config.dnsLeakProtection) {
        Write-Unavailable 'UPSTREAM_DNS_UNKNOWN' @("The upstream core resolves its server name(s) ($($up.ServerNames -join ', ')) through Windows DNS, but its direct resolver could not be determined. Once NordVPN owns system DNS, those lookups would need NordVPN, which itself needs the core - a reconnect deadlock.") @('Set upstream.bootstrapDns in config.json to the "direct DNS" your v2rayN/sing-box uses (e.g. ["119.29.29.29"]), or use an IP address as the server address in v2rayN.')
        return 3
    }

    if ($Config.killSwitch -and -not $up.Servers.Count) {
        Write-Unavailable 'UPSTREAM_ENDPOINT_UNKNOWN' @('The kill switch must allow the upstream core to reach its own server, but that server could not be identified.') @('Set upstream.serverAddresses in config.json (IP, hostname or CIDR), or run with -NoKillSwitch (weaker leak protection).')
        return 3
    }
    if ($Config.killSwitch -or $Config.dnsLeakProtection -or $Config.ipv6Policy -ne 'allow') {
        $fw = Test-FirewallActive
        if (-not $fw.Ok) {
            Write-Unavailable 'FIREWALL_DISABLED' @("Windows Firewall service running=$($fw.ServiceRunning), disabled profiles: $($fw.DisabledProfiles -join ', '). Leak-guard rules would have no effect.") @('Enable Windows Firewall for all profiles (vpn-chain will not change security settings for you), or disable killSwitch/dnsLeakProtection/ipv6Policy knowingly.')
            return 3
        }
    }

    $nordAtStart = $env0.Nord.Connected
    $ks = Get-NordKillSwitchHint
    Write-Log NORDVPN "Kill Switch / firewall (best-effort): $ks"
    if ($ks -eq 'enabled') { Write-Log NORDVPN 'NordVPN Kill Switch appears ENABLED. It may block the upstream core''s own server connection; if the chain fails, turn it off in NordVPN > Settings > Kill Switch (vpn-chain provides its own leak guard).' -Level WARN }

    # Provider features that cut the v2ray core off while the VPN is connected.
    $corePaths = @(Get-CoreExecutablePaths)
    $conflicts = @(Get-VpnConflicts -CorePaths $corePaths)
    foreach ($c in $conflicts) { Write-Log VPN "CONFLICT: $($c.Issue)" -Level WARN; Write-Log VPN "  fix: $($c.Fix)" -Level WARN }
    if ($script:ChainVpn.Key -eq 'windscribe' -and @($conflicts | Where-Object { $_.Issue -match 'firewall is ON|not logged in' }).Count) {
        Write-Unavailable 'VPN_CONFLICT' @($conflicts | ForEach-Object Issue) @($conflicts | ForEach-Object Fix)
        return 3
    }

    # Validate upstream really carries default traffic.
    $upstreamExit = $null
    if (-not $nordAtStart) {
        $facts0 = Get-LocalFacts $env0
        if ($facts0.appDefaultIf -ne 'upstream') {
            Write-Unavailable 'UPSTREAM_NOT_DEFAULT' @("Default traffic currently uses '$($facts0.appDefaultIf)', not the upstream tunnel.") @('Make sure v2rayN/sing-box TUN has auto_route enabled and is connected.')
            return 3
        }
        $ip0 = Get-PublicIp -Services $Config.ipCheckServices
        if (-not $ip0.Ip) { Write-Unavailable 'UPSTREAM_OFFLINE' @('No IP-check service is reachable through the upstream tunnel.') @('Verify the upstream works (open a website), then retry.'); return 3 }
        $upstreamExit = $ip0.Ip
        Write-Log UPSTREAM "upstream working, exit IP $upstreamExit ($($ip0.Agree)/$($ip0.Total) services agree)" -Level OK
    } else {
        Write-Log NORDVPN 'NordVPN is already connected. Its first handshake may not have used the upstream; after start completes, reconnect NordVPN once.' -Level WARN
    }

    # Snapshot + session.
    $session = New-Session
    $session.snapshot = Get-NetworkSnapshot
    $session.context = [ordered]@{
        upstreamAlias = $up.Adapter.Alias; upstreamIfIndex = $up.Adapter.ifIndex
        upstreamServers = @($up.Servers); upstreamExitIp = $upstreamExit
        upstreamServerNames = @($up.ServerNames); bootstrapDns = @($up.BootstrapDns)
        nordEndpoints = @(); nordConnectedAtStart = $nordAtStart; provider = $script:ChainVpn.Key
        config = [ordered]@{ killSwitch = $Config.killSwitch; dnsLeakProtection = $Config.dnsLeakProtection; ipv6Policy = $Config.ipv6Policy }
    }
    Save-Session $session
    Write-Log STATE "snapshot saved ($(@($session.snapshot.routes).Count) routes, $(@($session.snapshot.dns).Count) DNS entries) -> $script:SessionFile"

    $committed = $false
    try {
        Write-Banner 'Applying pre-NordVPN protections'
        Invoke-WithLock { [void](Invoke-Reconcile $session (Get-DesiredState $env0)) }

        if (-not $nordAtStart) {
            $ip1 = Get-PublicIp -Services $Config.ipCheckServices -FirstOnly
            if ($ip1.Ip -ne $upstreamExit) {
                # xray re-resolves its server name every ~TTL seconds; give the new NRPT path a moment.
                Start-Sleep -Seconds 5
                $ip1 = Get-PublicIp -Services $Config.ipCheckServices -FirstOnly
            }
            if ($ip1.Ip -ne $upstreamExit) {
                Write-Unavailable 'UPSTREAM_BLOCKED_BY_GUARD' @(
                    "After enabling the leak guard the upstream no longer works (public IP: '$($ip1.Ip)', expected $upstreamExit).",
                    "Allowed on WAN: servers [$($up.Servers -join ', ')], bootstrap DNS [$($up.BootstrapDns -join ', ')]. Something else the core needs directly is being blocked (another server IP, or its DNS)."
                ) @('Add the missing server IPs/CIDRs to upstream.serverAddresses and the core''s direct DNS to upstream.bootstrapDns, then retry. "vpn-chain diagnose" shows what the core is connected to.')
                return 3
            }
            Write-Log VERIFY 'upstream still healthy with leak guard active' -Level OK
        }

        # Wait for NordVPN.
        $session.status = 'waiting-nordvpn'; Save-Session $session
        if ($Opt.Connect) {
            # Never interrupt a connection the user (or the app's auto-connect) already started.
            $cs = Get-VpnConnectState
            if ($cs -in @('connecting', 'connected') -or $env0.Nord.Connected) { Write-Log VPN "NordVPN is already $cs - not sending a connect command" -Level WARN }
            else { Invoke-VpnConnect $install $Opt.Location $Opt.Protocol }
        }
        $envN = $null
        $deadline = (Get-Date).AddSeconds([int]$Config.nordvpn.connectTimeoutSec)
        if (-not $nordAtStart) { Write-Host ''; Write-Host ('>>> Now connect NordVPN (any protocol). Waiting up to {0}s...' -f $Config.nordvpn.connectTimeoutSec) -ForegroundColor Cyan }
        while ($true) {
            $envN = Get-ChainEnvironment $Config $session
            if ($envN.Nord.Endpoints.Count -and -not (@($session.context.nordEndpoints) | Where-Object { $envN.Nord.Endpoints -contains $_ })) {
                foreach ($e in $envN.Nord.Endpoints) { Write-Log NORDVPN "endpoint detected: $e ($($envN.Nord.EndpointSource))" -Level OK }
                $session.context.nordEndpoints = @($envN.Nord.Endpoints)
                Invoke-WithLock { [void](Invoke-Reconcile $session (Get-DesiredState $envN)) }
            }
            if ($envN.Nord.Connected) { break }
            if (Test-UserCancel) { Write-Log START 'cancelled by user while waiting for NordVPN' -Level WARN; return 3 }
            if ((Get-Date) -gt $deadline) {
                Write-Unavailable 'NORDVPN_NOT_CONNECTED' @("NordVPN did not connect within $($Config.nordvpn.connectTimeoutSec)s.") @('If NordVPN kept failing while vpn-chain was waiting, NordVPN may be binding its transport to the physical adapter (blocked by the leak guard). Run "vpn-chain diagnose" and see docs/architecture.md.')
                return 3
            }
            Wait-NetworkChange -TimeoutSec 1
        }
        Write-Log NORDVPN "adapter detected: $($envN.Nord.Active.Alias) protocol=$($envN.Nord.Protocol) default-route=$($envN.Nord.DefaultStyle)" -Level OK

        # Settle: let routes/endpoint appear, then apply NordVPN-phase protections.
        $settleUntil = (Get-Date).AddSeconds(45)
        $online = $false
        while ((Get-Date) -lt $settleUntil) {
            $envN = Get-ChainEnvironment $Config $session
            if ($envN.Nord.Endpoints.Count) { $session.context.nordEndpoints = @($envN.Nord.Endpoints) }
            Invoke-WithLock { [void](Invoke-Reconcile $session (Get-DesiredState $envN -NordPhase)) }
            if (Test-TcpConnect) { $online = $true; break }
            if (Test-UserCancel) { Write-Log START 'cancelled by user while NordVPN was settling' -Level WARN; return 3 }
            Start-Sleep -Seconds 3
        }
        if ($envN.Nord.Endpoints.Count) { Write-Log NORDVPN "endpoint: $($envN.Nord.Endpoints -join ', ') ($($envN.Nord.EndpointSource))" -Level OK }
        else { Write-Log NORDVPN 'endpoint not identifiable (kernel UDP socket); relying on the upstream default route + leak guard. Configure upstream.clashApi or nordvpn.endpoint to enable pinning.' -Level WARN }
        if (-not $online) { Write-Log VERIFY 'no TCP connectivity through NordVPN after 45s' -Level WARN }

        Write-Banner 'Verifying chain'
        $session = Read-Session
        $v = Invoke-ChainVerification -Env $envN -Session $session -Traffic
        Write-VerificationReport $envN $v $session
        if ($v.State.State -ne 'CHAIN_OK') {
            # Explain *why* using what the VPN app itself reports (e.g. NordVPN LeakBlock).
            $post = @(Get-VpnConflicts -CorePaths $corePaths -Since ([datetime]$session.createdAt))
            if ($post.Count) {
                Write-Banner 'Most likely cause' 'Yellow'
                foreach ($c in $post) { Write-Host "  - $($c.Issue)" -ForegroundColor Yellow; Write-Host "    fix: $($c.Fix)" -ForegroundColor Cyan }
            }
            if ($Opt.KeepOnFailure) { Write-Host 'Verification failed; -KeepOnFailure set, leaving changes in place for inspection. Run stop/reset when done.' -ForegroundColor Yellow; $committed = $true; $session.status = 'active'; Save-Session $session; return 4 }
            Write-Unavailable $v.State.State $v.State.Reasons @('See "vpn-chain diagnose" and the Troubleshooting section of README.md.')
            return 4
        }
        $session.status = 'active'; Save-Session $session
        $committed = $true
        Write-Log VERIFY 'chain healthy' -Level OK
    } finally {
        if (-not $committed) {
            Write-Banner 'Rolling back' 'Yellow'
            $s = Read-Session
            if ($s) { $s.status = 'stopping'; Save-Session $s; $fail = Invoke-WithLock { Undo-All $s }; if (-not $fail) { Remove-SessionFile; Write-Log ROLLBACK 'configuration restored' -Level OK } else { Write-Log ROLLBACK "$fail item(s) could not be removed; run 'vpn-chain reset'" -Level ERROR } }
        }
    }
    [void](Write-StatusSummary -Config $Config)
    if (-not $Opt.NoMonitor) { return (Invoke-Monitor $Config) }
    Write-Host "Chain active. Run 'vpn-chain monitor' to auto-repair after reconnects, 'vpn-chain stop' to restore." -ForegroundColor Cyan
    return 0
}

function Invoke-MonitorTick {
    # One auto-repair pass: re-detect, reconcile routes/guards, classify. Used by the CLI monitor
    # and by the interactive terminal app (which runs it in the background between key presses).
    param($Config)
    Invoke-WithLock {
        $s = Read-Session
        if (-not $s -or $s.status -ne 'active') { return @{ Exit = $true } }
        $env = Get-ChainEnvironment $Config $s
        if ($env.Nord.Connected -and $env.Nord.Endpoints.Count) { $s.context.nordEndpoints = @($env.Nord.Endpoints) }
        if ($env.Upstream.Adapter) { $s.context.upstreamIfIndex = $env.Upstream.Adapter.ifIndex; $s.context.upstreamAlias = $env.Upstream.Adapter.Alias }
        $changes = Invoke-Reconcile $s (Get-DesiredState $env -NordPhase)
        @{
            Exit = $false; Changes = $changes; Env = $env
            Ep = (@($env.Nord.Endpoints) -join ',')
            UpIf = $(if ($env.Upstream.Adapter) { $env.Upstream.Adapter.ifIndex } else { $null })
            UpAlias = $(if ($env.Upstream.Adapter) { $env.Upstream.Adapter.Alias } else { $null })
            State = (Get-ChainState (Get-LocalFacts $env $s))
        }
    }
}

function Test-UserCancel {
    # Interactive app only: Esc / Q aborts a long wait (start rolls back cleanly).
    if (-not $script:Interactive) { return $false }
    try {
        while ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq 'Escape' -or $k.KeyChar -in @('q', 'Q')) { return $true }
        }
    } catch { }
    return $false
}

function Invoke-Monitor {
    param($Config)
    $session = Read-Session
    if (-not $session -or $session.status -ne 'active') { Write-Host 'No active vpn-chain session.' -ForegroundColor Yellow; return 1 }
    if ($session.monitorPid -and $session.monitorPid -ne $PID -and (Get-Process -Id $session.monitorPid -ErrorAction SilentlyContinue)) {
        Write-Host "A monitor is already running (PID $($session.monitorPid))." -ForegroundColor Yellow; return 1
    }
    $session.monitorPid = $PID; Save-Session $session
    $interval = [int]$Config.monitor.safetyIntervalSec
    $src = 'vpnchain.monitor'
    Register-ObjectEvent -InputObject ([System.Net.NetworkInformation.NetworkChange]) -EventName NetworkAddressChanged -SourceIdentifier $src | Out-Null
    Write-Banner 'Monitoring (Ctrl+C to stop monitoring; protections stay active until "vpn-chain stop")'
    $lastState = $null; $lastEp = (@($session.context.nordEndpoints) -join ','); $lastUp = $session.context.upstreamIfIndex
    try {
        while ($true) {
            $ev = Wait-Event -SourceIdentifier $src -Timeout $interval
            if ($ev) { Start-Sleep -Seconds 2; Get-Event -SourceIdentifier $src -ErrorAction SilentlyContinue | Remove-Event }
            $tick = Invoke-MonitorTick $Config
            if ($tick.Exit) { Write-Log MONITOR 'session no longer active - monitor exiting'; break }
            if ($tick.Ep -and $tick.Ep -ne $lastEp) { Write-Log NORDVPN "endpoint changed: '$lastEp' -> '$($tick.Ep)' (re-pinned)" -Level WARN; $lastEp = $tick.Ep }
            if ($tick.UpIf -and $tick.UpIf -ne $lastUp) { Write-Log UPSTREAM "upstream adapter changed -> $($tick.UpAlias) (if $($tick.UpIf))" -Level WARN; $lastUp = $tick.UpIf }
            if ($tick.State.State -ne $lastState) {
                Write-Log MONITOR "state: $($tick.State.State) $($tick.State.Reasons -join ' | ')" -Level $(if ($tick.State.State -eq 'CHAIN_OK') { 'OK' } else { 'WARN' })
                $lastState = $tick.State.State
            }
            if ($tick.Changes) { Write-Log MONITOR "$($tick.Changes) routing/guard change(s) applied" }
        }
    } finally {
        Unregister-Event -SourceIdentifier $src -ErrorAction SilentlyContinue
        $s = Read-Session
        if ($s -and $s.Contains('monitorPid') -and $s.monitorPid -eq $PID) { $s.monitorPid = $null; Save-Session $s }
        Write-Host "Monitor stopped. Protections remain active - run 'vpn-chain stop' to restore." -ForegroundColor Yellow
    }
    return 0
}

function Stop-MonitorProcess {
    param($Session)
    if (-not $Session -or -not $Session.monitorPid -or $Session.monitorPid -eq $PID) { return }
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$($Session.monitorPid)" -ErrorAction SilentlyContinue
    if ($p -and $p.CommandLine -match 'vpn-chain\.ps1') {
        Stop-Process -Id $Session.monitorPid -Force -ErrorAction SilentlyContinue
        Write-Log MONITOR "stopped monitor process $($Session.monitorPid)"
    }
}

function Invoke-Stop {
    param($Config, [hashtable]$Opt, [switch]$Reset)
    $session = Read-Session
    $orphans = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue) + @(Get-OrphanChainNrptRules)
    if (-not $session -and -not @($orphans | Where-Object { $_ }).Count) {
        Write-Host 'No vpn-chain session or leftover changes found. Nothing to do.' -ForegroundColor Green
        return 0
    }
    if (-not $session) { $session = [ordered]@{ status = 'orphaned'; journal = @(); snapshot = $null; context = [ordered]@{} } }
    if (-not $Reset -and $session.status -eq 'corrupt') { Write-Host "Session file is corrupt; use 'vpn-chain reset'." -ForegroundColor Yellow; return 1 }

    if ($Opt.DisconnectNord) {
        $install = Get-NordVpnInstall $Config
        try {
            Invoke-VpnDisconnect $install
            $until = (Get-Date).AddSeconds(30)
            while ((Get-Date) -lt $until -and (Get-NordVpnInfo -Inventory @(Get-InterfaceInventory) -Config $Config).Connected) { Start-Sleep -Seconds 2 }
        } catch { Write-Log NORDVPN $_.Exception.Message -Level WARN }
    }

    Write-Banner $(if ($Reset) { 'Resetting (crash recovery)' } else { 'Stopping chain' })
    if ($session.Contains('id')) { $session.status = 'stopping'; Save-Session $session }
    Stop-MonitorProcess $session
    $fail = Invoke-WithLock { Undo-All $session }
    if ($fail) {
        Write-Log ROLLBACK "$fail item(s) could not be removed. The session file is kept: re-run 'vpn-chain reset'." -Level ERROR
        return 1
    }
    Remove-SessionFile
    Write-Log ROLLBACK 'configuration restored' -Level OK

    # Verify restoration.
    $routesLeft = @()
    foreach ($j in @($session.journal)) { if ($j.kind -eq 'route' -and (Test-RouteExists $j.prefix ([int]$j.ifIndex) $j.nextHop)) { $routesLeft += $j.prefix } }
    $rulesLeft = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue)
    if ($session.snapshot) {
        $now = @{}
        foreach ($d in @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object ServerAddresses)) { $now['{0}|{1}' -f $d.InterfaceIndex, $d.AddressFamily] = (@($d.ServerAddresses) -join ',') }
        foreach ($d in @($session.snapshot.dns)) {
            $k = '{0}|{1}' -f $d.ifIndex, $d.family
            if ($now.ContainsKey($k) -and $now[$k] -ne (@($d.servers) -join ',')) { Write-Log DNS "DNS servers on '$($d.alias)' differ from the pre-chain snapshot (changed by another program, e.g. NordVPN/upstream): was $(@($d.servers) -join ',') now $($now[$k])" -Level WARN }
        }
    }
    if ($routesLeft.Count -or $rulesLeft.Count) { Write-Log ROLLBACK "leftovers: routes=$($routesLeft -join ',') rules=$(@($rulesLeft.Name) -join ',')" -Level ERROR; return 1 }
    $nordStill = (Get-NordVpnInfo -Inventory @(Get-InterfaceInventory) -Config $Config).Connected
    if ($nordStill) { Write-Log NORDVPN 'NordVPN is still connected: its transport now follows normal routing (no longer pinned through the upstream). Disconnect it if that matters (or use stop -DisconnectNord).' -Level WARN }
    $ok = Test-TcpConnect
    $ip = Get-PublicIp -Services $Config.ipCheckServices -FirstOnly
    if ($ok) { Write-Log VERIFY "normal connectivity OK, public IP now $($ip.Ip)" -Level OK } else { Write-Log VERIFY 'no Internet connectivity after restore - check your upstream/NordVPN apps' -Level WARN }
    return 0
}

function Write-StatusSummary {
    param($Config)
    $session = Read-Session
    $env = Get-ChainEnvironment $Config $session
    $facts = Get-LocalFacts $env $session
    if ($session -and $session.context.upstreamExitIp) { $facts.upstreamExitIp = $session.context.upstreamExitIp }
    $ip = Get-PublicIp -Services $Config.ipCheckServices -FirstOnly -TimeoutMs 5000
    $facts.publicIp = $ip.Ip
    $st = Get-ChainState $facts
    $journal = if ($session) { @($session.journal | Where-Object { $_.status -eq 'applied' }) } else { @() }
    $dnsGuard = @($journal | Where-Object { $_.purpose -like 'dns-*' }).Count -gt 0
    $v6Guard = (@($journal | Where-Object { $_.purpose -like 'ipv6-*' -or $_.purpose -eq 'killswitch-v6' }).Count -gt 0)
    $ks = @($journal | Where-Object { $_.purpose -like 'killswitch-*' }).Count -gt 0
    $upTxt = switch ($env.Upstream.Mode) {
        'tun'   { 'Connected ({0}{1})' -f $env.Upstream.Adapter.Alias, $(if ($env.Upstream.Processes.Count) { ', ' + ($env.Upstream.Processes -join ' ') } else { '' }) }
        'proxy' { 'Proxy-only (not chainable)' }
        default { 'Not connected' }
    }
    $nordTxt = if ($env.Nord.Connected) { 'Connected ({0}{1})' -f $env.Nord.Protocol, $(if ($env.Nord.Endpoints.Count) { ', endpoint ' + ($env.Nord.Endpoints -join ',') + ' via ' + $facts.nordEndpointIf } else { '' }) } else { 'Disconnected' }
    $chainTxt = if ($st.State -eq 'CHAIN_OK') { 'Healthy' } else { $st.State }
    $dnsTxt = if ($dnsGuard -and $env.Nord.Connected) { 'Protected (NordVPN DNS only)' } elseif ($dnsGuard) { 'Guarded (WAN DNS blocked)' } else { 'Unprotected' }
    $v6Txt = if ($env.Nord.HasIPv6 -and $Config.ipv6Policy -eq 'block-if-unsafe') { 'Via NordVPN' } elseif ($v6Guard) { 'Protected (blocked outside NordVPN)' } else { 'Not guarded' }
    Write-Host ''
    Write-Host ('Session:  {0}' -f $(if ($session) { "$($session.status) since $($session.createdAt)$(if ($session.monitorPid) { ", monitor PID $($session.monitorPid)" })" } else { 'none' }))
    Write-Host ('Upstream: {0}' -f $upTxt)
    Write-Host ('NordVPN:  {0}' -f $nordTxt)
    Write-Host ('Chain:    {0}' -f $chainTxt) -ForegroundColor $(if ($st.State -eq 'CHAIN_OK') { 'Green' } else { 'Yellow' })
    Write-Host ('DNS:      {0}' -f $dnsTxt)
    Write-Host ('IPv6:     {0}' -f $v6Txt)
    Write-Host ('KillSw:   {0}' -f $(if ($ks) { 'Active (WAN limited to upstream server + LAN)' } else { 'Off' }))
    Write-Host ('Final IP: {0}' -f $(if ($ip.Ip) { $ip.Ip } else { 'unreachable' }))
    foreach ($r in $st.Reasons) { Write-Host "  - $r" -ForegroundColor Yellow }
    return $st.State
}

function Invoke-Diagnose {
    param($Config)
    $session = Read-Session
    $env = Get-ChainEnvironment $Config $session
    Write-Banner 'Interfaces'
    $env.Inventory | Sort-Object Kind, ifIndex | Format-Table -AutoSize @{l='If';e={$_.ifIndex}}, Alias, Kind, @{l='Up';e={$_.IsUp}}, @{l='Type';e={$_.NetType}}, @{l='M4';e={$_.Metric4}},
        @{l='Default4';e={$_.DefaultStyle4}}, @{l='GW4';e={$_.Gateway4}}, @{l='IPv4';e={$_.IPv4 -join ','}}, @{l='GlobalIPv6';e={$_.GlobalIPv6 -join ','}}, @{l='DNS';e={$_.DnsServers -join ','}} | Out-String -Width 260 | Write-Host

    Write-Banner 'Default routes'
    Get-NetRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','::/0','::/1','8000::/1') } |
        Sort-Object AddressFamily, RouteMetric | Format-Table -AutoSize ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric | Out-String -Width 200 | Write-Host

    Write-Banner 'Upstream'
    $u = $env.Upstream
    Write-Host "  mode            : $($u.Mode)"
    Write-Host "  adapter         : $(if ($u.Adapter) { '{0} (if {1}) {2}' -f $u.Adapter.Alias, $u.Adapter.ifIndex, $u.Adapter.Description } else { '-' })"
    if ($u.AmbiguousWith.Count) { Write-Host "  other candidates: $($u.AmbiguousWith -join ', ')" -ForegroundColor Yellow }
    Write-Host "  core processes  : $($u.Processes -join ', ')"
    Write-Host "  local listeners : $($u.ListenPorts -join ', ')"
    Write-Host "  system proxy    : enabled=$($u.SystemProxy.Enabled) server=$($u.SystemProxy.Server) pac=$($u.SystemProxy.Pac)"
    if ($u.SystemProxy.Enabled -and $u.SystemProxy.Local) { Write-Host '                    ^ proxy-aware apps would bypass NordVPN - choose "Clear system proxy" in v2rayN' -ForegroundColor Red }
    Write-Host "  server names    : $(if ($u.ServerNames.Count) { $u.ServerNames -join ', ' } else { '-' })"
    Write-Host "  bootstrap DNS   : $(if ($u.BootstrapDns.Count) { $u.BootstrapDns -join ', ' } else { '-' })"
    Write-Host "  blocked UDP     : $((Get-UpstreamBlockedUdpPorts) -join ', ')  (the chained VPN must not use these ports)"
    foreach ($n in @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq $script:NrptComment })) { Write-Host "  NRPT (ours)     : $(@($n.Namespace) -join ',') -> $(@($n.NameServers) -join ',')" }
    foreach ($s in $u.Servers) {
        $r = Get-EffectiveRoute $s
        Write-Host ("  server          : {0} [{1}] -> {2}" -f $s, $u.ServerSources[$s], $(if ($r) { '{0} via {1} ({2})' -f $r.Prefix, $r.Alias, (Get-IfRole $r.ifIndex $u.Adapter $env.Nord) } else { 'no route' }))
    }
    foreach ($c in $u.LoopConnections) { Write-Host "  LOOP            : core socket $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) is sourced from NordVPN" -ForegroundColor Red }
    foreach ($c in $u.DirectToNord) { Write-Host "  DIRECT          : core connects to NordVPN endpoint $($c.RemoteAddress) itself (routing rule 'direct')" -ForegroundColor Red }

    Write-Banner 'NordVPN'
    $inst = Get-NordVpnInstall $Config
    $n = $env.Nord
    Write-Host "  installed       : $($inst.Installed) $($inst.Version) ($($inst.Root)) service=$($inst.ServiceState)"
    Write-Host "  adapters        : $(($n.Adapters | ForEach-Object { '{0}[{1}]={2}' -f $_.Alias, $_.ifIndex, $(if ($_.IsUp) { 'up' } else { 'down' }) }) -join ', ')"
    Write-Host "  connected       : $($n.Connected) protocol=$($n.Protocol) default-route=$($n.DefaultStyle) ipv6=$($n.HasIPv6)"
    Write-Host "  DNS             : $($n.DnsServers -join ', ')"
    Write-Host "  kill switch     : $(Get-NordKillSwitchHint) (best-effort from service log)"
    foreach ($e in $n.Endpoints) {
        $r = Get-EffectiveRoute $e
        Write-Host ("  endpoint        : {0} [{1}] -> {2}" -f $e, $n.EndpointSource, $(if ($r) { '{0} via {1} ({2})' -f $r.Prefix, $r.Alias, (Get-IfRole $r.ifIndex $u.Adapter $n) } else { 'no route' }))
    }
    if (-not $n.Endpoints.Count) { Write-Host '  endpoint        : unknown' }

    Write-Banner 'DNS client'
    $nrpt = @(Get-DnsClientNrptPolicy -ErrorAction SilentlyContinue)
    Write-Host "  NRPT rules      : $(if ($nrpt.Count) { ($nrpt | ForEach-Object { '{0}->{1}' -f ($_.Namespace -join ','), ($_.NameServers -join ',') }) -join '; ' } else { 'none' })"
    $smart = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue)
    Write-Host "  smart multi-homed resolution policy: $(if ($smart -and ($smart.PSObject.Properties.Name -contains 'DisableSmartNameResolution')) { $smart.DisableSmartNameResolution } else { 'default (queries may go to all adapters -> vpn-chain blocks non-NordVPN DNS)' })"

    Write-Banner 'vpn-chain state'
    $fw = Test-FirewallActive
    Write-Host "  firewall        : service=$($fw.ServiceRunning) disabledProfiles=$($fw.DisabledProfiles -join ',')"
    if ($session) {
        Write-Host "  session         : $($session.status) since $($session.createdAt) monitor=$($session.monitorPid)"
        Write-Host "  upstream exit   : $($session.context.upstreamExitIp)"
        foreach ($j in $session.journal) {
            if ($j.kind -eq 'route') { Write-Host ("  [{0}] route {1} via {2} nh {3} ({4})" -f $j.status, $j.prefix, $j.alias, $j.nextHop, $j.purpose) }
            else { Write-Host ("  [{0}] fw {1} on {2}; remote={3}{4}" -f $j.status, $j.purpose, (@($j.interfaceAlias) -join ','), ((@($j.remoteAddress) | Select-Object -First 3) -join ','), $(if (@($j.remoteAddress).Count -gt 3) { ",... (+$(@($j.remoteAddress).Count - 3))" })) }
        }
    } else { Write-Host '  session         : none' }
    $orph = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue)
    Write-Host "  our fw rules    : $($orph.Count)"

    Write-Banner 'Classification (local facts only - run "test" for behavioural checks)'
    $facts = Get-LocalFacts $env $session
    $facts.GetEnumerator() | ForEach-Object { Write-Host ('  {0,-18} {1}' -f $_.Key, (@($_.Value) -join ',')) }
    $st = Get-ChainState $facts
    Write-Host "  => $($st.State)" -ForegroundColor $(if ($st.State -eq 'CHAIN_OK') { 'Green' } else { 'Yellow' })
    foreach ($r in $st.Reasons) { Write-Host "     - $r" -ForegroundColor Yellow }
    return 0
}

function Invoke-Test {
    param($Config)
    $session = Read-Session
    $env = Get-ChainEnvironment $Config $session
    Write-Log VERIFY 'running behavioural tests (public IPv4/IPv6, DNS path, traffic correlation)...'
    $v = Invoke-ChainVerification -Env $env -Session $session -Traffic
    Write-VerificationReport $env $v $session
    Write-Banner 'Checks'
    $f = $v.Facts; $r = $v.Report
    $checks = @(
        @('Upstream VPN detected', ($env.Upstream.Mode -eq 'tun')),
        @('NordVPN detected/connected', $env.Nord.Connected),
        @('Normal traffic exits through NordVPN', ($f.appDefaultIf -eq 'nord')),
        @('NordVPN transport traverses upstream', (($f.nordEndpointIf -eq 'upstream') -or ($f.Contains('correlation') -and $f.correlation -eq 'chained'))),
        @('Upstream transport does not recurse', (-not $f.coreLoop -and @($f.upstreamServerIfs | Where-Object { $_ -ne 'wan' }).Count -eq 0)),
        @('Final IPv4 differs from upstream exit', $(if (-not ($f.Contains('upstreamExitIp') -and $f.upstreamExitIp)) { $null } else { [bool]($env.Nord.Connected -and $r.publicIp.Ip -and $r.publicIp.Ip -ne $f.upstreamExitIp) })),
        @('DNS does not leak', $(if ($f.Contains('dnsLeak')) { $f.dnsLeak -eq $false } else { $null })),
        @('IPv6 does not bypass the chain', $(if ($f.Contains('ipv6Leak') -and $null -ne $f.ipv6Leak) { $f.ipv6Leak -ne $true } else { $null }))
    )
    foreach ($c in $checks) {
        # $null = no evidence available (e.g. NordVPN not connected, no recorded upstream exit) -> SKIP, never PASS.
        $label = if ($null -eq $c[1]) { 'SKIP' } elseif ($c[1]) { 'PASS' } else { 'FAIL' }
        Write-Host ('  [{0}] {1}' -f $label, $c[0]) -ForegroundColor $(switch ($label) { 'PASS' { 'Green' } 'SKIP' { 'DarkYellow' } default { 'Red' } })
    }
    if ($v.State.State -eq 'CHAIN_OK') { return 0 } else { return 4 }
}
