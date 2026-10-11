# Self-contained test runner (no Pester dependency; Windows ships only Pester 3.4).
# Runs pure-logic tests and transactional engine tests against an in-memory fake
# route/firewall store - it never touches the real network configuration.
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1

$ErrorActionPreference = 'Stop'
$script:RootDir = Split-Path $PSScriptRoot -Parent
. (Join-Path $script:RootDir 'src\Common.ps1')
. (Join-Path $script:RootDir 'src\Net.ps1')
. (Join-Path $script:RootDir 'src\Providers.ps1')
. (Join-Path $script:RootDir 'src\Detect.ps1')
. (Join-Path $script:RootDir 'src\Verify.ps1')
. (Join-Path $script:RootDir 'src\Engine.ps1')
. (Join-Path $script:RootDir 'src\Tui.ps1')

# Isolate state + logs.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('vpn-chain-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory $tmp | Out-Null
$script:StateDir = $tmp
$script:SessionFile = Join-Path $tmp 'session.json'
$script:LogDir = Join-Path $tmp 'logs'
$script:MutexName = 'Local\vpn-chain-test-' + [guid]::NewGuid().ToString('N')
Initialize-Log
function Write-Host { }   # keep output readable; results are printed via [Console]

$script:pass = 0; $script:fail = 0
function It([string]$Name, [scriptblock]$Body) {
    try { & $Body; $script:pass++; [Console]::WriteLine("  PASS  $Name") }
    catch { $script:fail++; [Console]::ForegroundColor = 'Red'; [Console]::WriteLine("  FAIL  $Name`n        $($_.Exception.Message)"); [Console]::ResetColor() }
}
function Assert-Equal($Expected, $Actual, [string]$Msg = '') {
    if ((@($Expected) -join '|') -ne (@($Actual) -join '|')) { throw "expected [$(@($Expected) -join ', ')] got [$(@($Actual) -join ', ')] $Msg" }
}
function Assert-True($Cond, [string]$Msg = 'condition false') { if (-not $Cond) { throw $Msg } }
function Section([string]$Name) { [Console]::WriteLine(''); [Console]::WriteLine("[$Name]") }

# ---------------------------------------------------------------------------
Section 'IP math'
It 'IPv4 round-trip' { Assert-Equal '203.0.113.7' (ConvertFrom-IpBigInt (ConvertTo-IpBigInt '203.0.113.7') 4) }
It 'IPv6 round-trip' { Assert-Equal '2001:db8::1' (ConvertFrom-IpBigInt (ConvertTo-IpBigInt '2001:db8::1') 6) }
It 'CIDR range' { $r = Get-CidrRange '10.1.2.3/8'; Assert-Equal '10.0.0.0' (ConvertFrom-IpBigInt $r.Start 4); Assert-Equal '10.255.255.255' (ConvertFrom-IpBigInt $r.End 4) }
It 'complement of single IPv4' { Assert-Equal @('0.0.0.0-1.2.3.3', '1.2.3.5-255.255.255.255') (Get-RangeComplement -Exclude @('1.2.3.4') -Family 4) }
It 'complement merges overlaps and edges' {
    Assert-Equal @('10.0.0.1-10.255.255.255') (Get-RangeComplement -Exclude @('0.0.0.0/5', '8.0.0.0/7', '11.0.0.0/8', '12.0.0.0/6', '16.0.0.0/4', '32.0.0.0/3', '64.0.0.0/2', '128.0.0.0/1', '10.0.0.0/32') -Family 4 | Select-Object -Skip 0) 'expected only 10.0.0.1+ hole'
}
It 'complement of nothing is everything' { Assert-Equal @('0.0.0.0-255.255.255.255') (Get-RangeComplement -Exclude @() -Family 4) }
It 'complement of everything is empty' { Assert-Equal 0 (@(Get-RangeComplement -Exclude @('0.0.0.0/0') -Family 4)).Count }
It 'IPv6 complement ignores IPv4 entries' { Assert-Equal @('::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'fec0::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') (Get-RangeComplement -Exclude @('fe80::/10', '1.2.3.4') -Family 6) }
It 'LAN allow-list keeps public space blocked' {
    $c = Get-RangeComplement -Exclude ($script:LanAllow4 + @('149.102.227.91')) -Family 4
    Assert-True ($c -contains '149.102.227.92-169.253.255.255') 'upstream server hole missing'
    Assert-True (-not ($c | Where-Object { $_ -like '192.168.*' })) 'LAN not exempted'
}
It 'public / private classification' {
    Assert-True (Test-IsPublicIp '8.8.8.8'); Assert-True (-not (Test-IsPublicIp '192.168.1.1')); Assert-True (-not (Test-IsPublicIp '100.64.0.1'))
    Assert-True (Test-IsPublicIp '2606:4700::1111'); Assert-True (-not (Test-IsPublicIp 'fe80::1')); Assert-True (-not (Test-IsPublicIp 'not-an-ip'))
}
It 'host prefix' { Assert-Equal '1.2.3.4/32' (Get-HostPrefix '1.2.3.4'); Assert-Equal '2001:db8::1/128' (Get-HostPrefix '2001:db8::1') }
It 'DNS query packet shape' { $q = New-DnsQueryBytes -Name 'a.bc' -Id 0x1234; Assert-Equal @(0x12, 0x34, 1, 0, 0, 1) $q[0..5]; Assert-Equal (12 + 2 + 3 + 1 + 4) $q.Length }

# ---------------------------------------------------------------------------
Section 'Config'
It 'defaults' { $c = Get-Config -Path (Join-Path $tmp 'missing.json'); Assert-Equal 'block-if-unsafe' $c.ipv6Policy; Assert-True $c.killSwitch }
It 'merge override keeps nested defaults' {
    $p = Join-Path $tmp 'c.json'; '{"upstream":{"adapter":"singbox_tun"},"killSwitch":false}' | Set-Content $p
    $c = Get-Config -Path $p
    Assert-Equal 'singbox_tun' $c.upstream.adapter; Assert-Equal 'auto' $c.upstream.type; Assert-Equal $false $c.killSwitch
}
It 'invalid ipv6Policy rejected' {
    $p = Join-Path $tmp 'bad.json'; '{"ipv6Policy":"maybe"}' | Set-Content $p
    $threw = $false; try { Get-Config -Path $p | Out-Null } catch { $threw = $true }; Assert-True $threw
}
It 'session JSON round-trip keeps 1-element arrays' {
    $s = New-Session; $s.context.upstreamServers = @('1.2.3.4'); Save-Session $s
    $r = Read-Session; Assert-True ($r.context.upstreamServers -is [array]) 'array lost'; Assert-Equal '1.2.3.4' $r.context.upstreamServers[0]
    Remove-Item $script:SessionFile
}

# ---------------------------------------------------------------------------
Section 'VPN providers'
It 'provider selection precedence: parameter > session > config > default' {
    $c = Get-DefaultConfig
    Assert-Equal 'windscribe' (Select-VpnProvider -Requested 'windscribe' -Config $c)
    $s = [ordered]@{ context = [ordered]@{ provider = 'windscribe' } }
    Assert-Equal 'windscribe' (Select-VpnProvider -Config $c -Session $s)
    $c.vpn.provider = 'windscribe'; Assert-Equal 'windscribe' (Select-VpnProvider -Config $c)
    $c.vpn.provider = 'ask'; Assert-Equal 'nordvpn' (Select-VpnProvider -Config $c)   # non-interactive fallback
}
It 'Set-VpnProvider switches adapter pattern and user-facing name' {
    Set-VpnProvider windscribe
    Assert-Equal 'Windscribe' $script:VpnName
    Assert-True ('Windscribe IKEv2' -match $script:NordAdapterPattern) 'IKEv2 adapter must be the chained VPN'
    Assert-Equal 'Windscribe endpoint pinned' (ConvertTo-VpnText 'NordVPN endpoint pinned')
    Assert-Equal 'WINDSCRIBE' (Get-VpnTag)
    Set-VpnProvider nordvpn
    Assert-Equal 'NordVPN endpoint pinned' (ConvertTo-VpnText 'NordVPN endpoint pinned')
    Assert-True ('NordLynx Tunnel' -match $script:NordAdapterPattern)
}
It 'unknown provider is rejected' { $threw = $false; try { Set-VpnProvider 'expressvpn' } catch { $threw = $true }; Assert-True $threw }

# ---------------------------------------------------------------------------
Section 'Terminal app (pure parts)'
It 'BERAYAN banner: 5 equal-width ASCII rows that fit an 80-column console' {
    $b = @(Get-Banner)
    Assert-Equal 5 $b.Count
    Assert-Equal 1 @($b | ForEach-Object Length | Select-Object -Unique).Count
    Assert-True ($b[0].Length -le 78) "banner too wide: $($b[0].Length)"
    Assert-True (-not ($b -join '' | Select-String -Pattern '[^\x20-\x7e]')) 'banner must be pure ASCII'
}
It 'dashboard lines are always lists of [text, color] segments' {
    $script:Dash.Scanned = $false
    foreach ($l in @(Get-DashboardLines)) { foreach ($s in $l) { Assert-Equal 2 @($s).Count 'segment shape' } }
    $script:Dash.Scanned = $true; $script:Dash.UpMode = 'tun'; $script:Dash.State = 'CHAIN_OK'; $script:Dash.LastTick = Get-Date; $script:Dash.Session = $true
    $lines = @(Get-DashboardLines)
    Assert-Equal 6 $lines.Count
    foreach ($l in $lines) { foreach ($s in $l) { Assert-Equal 2 @($s).Count 'segment shape' } }
}
It 'protocol catalogs: Windscribe IKEv2 first and WireGuard flagged; NordVPN app-protocol default' {
    $w = @(Get-VpnProtocolChoices windscribe)
    Assert-Equal 'ikev2' $w[0].Id
    Assert-Equal 'bad' ($w | Where-Object Id -eq 'wireguard').Level
    foreach ($c in $w) { Assert-True ($script:Providers['windscribe'].Protocols -contains $c.Id) "CLI must accept $($c.Id)" }
    $n = @(Get-VpnProtocolChoices nordvpn)
    Assert-Equal 'app' $n[0].Id
    foreach ($c in $n) { Assert-True ($script:Providers['nordvpn'].Protocols -contains $c.Id) "CLI must accept $($c.Id)" }
}
It 'user choices persist to config.json and merge with defaults' {
    $saved = $script:RootDir; $script:RootDir = $tmp
    try {
        Set-UserConfigValue 'vpn.provider' 'windscribe'
        Set-UserConfigValue 'vpn.protocol' 'ikev2'
        Set-UserConfigValue 'killSwitch' $false
        $c = Get-Config -Path (Join-Path $tmp 'config.json')
        Assert-Equal 'windscribe' $c.vpn.provider; Assert-Equal 'ikev2' $c.vpn.protocol; Assert-Equal $false $c.killSwitch
        Assert-Equal 'block-if-unsafe' $c.ipv6Policy
    } finally { $script:RootDir = $saved }
}

# ---------------------------------------------------------------------------
Section 'Classifier (state matrix)'
$base = @{ upstreamMode = 'tun'; upstreamUp = $true; nordUp = $true; nordEndpointIf = 'upstream'; upstreamServerIfs = @('wan'); appDefaultIf = 'nord'; publicIp = '5.5.5.5'; upstreamExitIp = '6.6.6.6'; dnsLeak = $false; ipv6Leak = $false }
function F([hashtable]$Over) { $h = [ordered]@{}; foreach ($k in $base.Keys) { $h[$k] = $base[$k] }; foreach ($k in $Over.Keys) { $h[$k] = $Over[$k] }; $h }
$matrix = @(
    @('healthy chain', @{}, 'CHAIN_OK'),
    @('healthy via traffic proof only', @{ nordEndpointIf = 'unknown'; correlation = 'chained' }, 'CHAIN_OK'),
    @('endpoint unknown, no proof', @{ nordEndpointIf = 'unknown' }, 'UNKNOWN'),
    @('proxy-only upstream', @{ upstreamMode = 'proxy' }, 'UPSTREAM_NOT_SUPPORTED'),
    @('nord endpoint loops into nord', @{ nordEndpointIf = 'nord' }, 'ROUTING_LOOP'),
    @('upstream server via nord', @{ upstreamServerIfs = @('nord') }, 'ROUTING_LOOP'),
    @('upstream server via own TUN (v2rayN process bypass) is not a loop', @{ upstreamServerIfs = @('upstream', 'wan') }, 'CHAIN_OK'),
    @('core bound to nord', @{ coreLoop = $true }, 'ROUTING_LOOP'),
    @('nord transport direct', @{ nordEndpointIf = 'wan' }, 'NORDVPN_ONLY'),
    @('upstream down', @{ upstreamUp = $false }, 'NORDVPN_ONLY'),
    @('core direct-routes nord', @{ coreDirectToNord = $true }, 'NORDVPN_ONLY'),
    @('traffic not chained', @{ correlation = 'not-chained' }, 'NORDVPN_ONLY'),
    @('nord down', @{ nordUp = $false }, 'UPSTREAM_ONLY'),
    @('exit equals upstream', @{ publicIp = '6.6.6.6' }, 'UPSTREAM_ONLY'),
    @('both down but online', @{ nordUp = $false; upstreamUp = $false }, 'DIRECT_LEAK'),
    @('both down offline', @{ nordUp = $false; upstreamUp = $false; publicIp = $null }, 'UNKNOWN'),
    @('apps default to WAN', @{ appDefaultIf = 'wan' }, 'DIRECT_LEAK'),
    @('ipv6 leak', @{ ipv6Leak = $true }, 'DIRECT_LEAK'),
    @('direct IP seen', @{ directIp = '5.5.5.5' }, 'DIRECT_LEAK'),
    @('dns leak', @{ dnsLeak = $true }, 'DNS_LEAK'),
    @('system proxy bypasses NordVPN', @{ systemProxyBypass = $true }, 'UPSTREAM_ONLY')
)
foreach ($m in $matrix) { $n = $m[0]; $o = $m[1]; $e = $m[2]; It "classify: $n -> $e" { Assert-Equal $e (Get-ChainState (F $o)).State }.GetNewClosure() }

# ---------------------------------------------------------------------------
Section 'Desired state'
function New-FakeIf($idx, $alias, $kind, [string]$gw4 = $null, [bool]$up = $true) {
    [pscustomobject]@{ ifIndex = $idx; Alias = $alias; Kind = $kind; IsUp = $up; IPv4 = @("10.0.0.$idx"); IPv6 = @(); GlobalIPv6 = @(); Gateway4 = $gw4; Gateway6 = $null
        DefaultMetric4 = 25; Metric6 = 25; HasDefault4 = [bool]$gw4; HasDefault6 = $false; Description = $alias; DnsServers = @() }
}
$eth = New-FakeIf 22 'Ethernet' 'physical' '192.168.1.1'
$wifi = New-FakeIf 27 'Wi-Fi' 'physical' $null $false
$tun = New-FakeIf 50 'singbox_tun' 'virtual-tunnel'
$nlx = New-FakeIf 91 'NordLynx' 'nordvpn'
function New-FakeEnv([string[]]$NordEps = @(), [hashtable]$CfgOver = @{}) {
    $cfg = Get-DefaultConfig; foreach ($k in $CfgOver.Keys) { $cfg[$k] = $CfgOver[$k] }
    [pscustomobject]@{
        Config = $cfg; Inventory = @($eth, $wifi, $tun, $nlx)
        Upstream = [pscustomobject]@{ Mode = 'tun'; Adapter = $tun; Servers = @('149.102.227.91'); ProcessIds = @(); LoopConnections = @(); DirectToNord = @() }
        Nord = [pscustomobject]@{ Adapters = @($nlx); Active = $nlx; Connected = $true; Endpoints = @($NordEps); HasIPv6 = $false; DnsServers = @('103.86.96.100') }
    }
}
It 'pins upstream server to WAN gateway and NordVPN endpoint to the upstream TUN' {
    $d = Get-DesiredState (New-FakeEnv @('185.1.1.1')) -NordPhase
    $routes = @($d.Items | Where-Object kind -eq 'route')
    $u = $routes | Where-Object purpose -eq 'upstream-server'; $n = $routes | Where-Object purpose -eq 'nord-endpoint'
    Assert-Equal '149.102.227.91/32' $u.prefix; Assert-Equal 22 $u.ifIndex; Assert-Equal '192.168.1.1' $u.nextHop
    Assert-Equal '185.1.1.1/32' $n.prefix; Assert-Equal 50 $n.ifIndex; Assert-Equal '0.0.0.0' $n.nextHop
}
It 'kill switch covers every WAN-side interface but never the tunnels' {
    $d = Get-DesiredState (New-FakeEnv @('185.1.1.1')) -NordPhase
    $ks = $d.Items | Where-Object purpose -eq 'killswitch-v4'
    Assert-Equal @('Ethernet', 'Wi-Fi') ($ks.interfaceAlias | Sort-Object)
    Assert-True ($ks.remoteAddress -notcontains '149.102.227.91') 'upstream server must be exempt'
    Assert-True (@($ks.remoteAddress | Where-Object { $_ -like '149.102.227.92-*' }).Count -eq 1) 'hole expected right after the upstream server'
}
It 'connected NordVPN gets 0/1 + 128/1 so it beats a metric-0 upstream TUN default route' {
    $d = Get-DesiredState (New-FakeEnv) -NordPhase
    $r = @($d.Items | Where-Object purpose -eq 'nord-default')
    Assert-Equal @('0.0.0.0/1', '128.0.0.0/1') @($r.prefix); Assert-Equal @(91, 91) @($r.ifIndex)
    $e = New-FakeEnv; $e.Nord.Connected = $false
    Assert-Equal 0 @((Get-DesiredState $e -NordPhase).Items | Where-Object purpose -eq 'nord-default').Count
}
It 'NordVPN endpoint is explicitly blocked on WAN' {
    $d = Get-DesiredState (New-FakeEnv @('185.1.1.1')) -NordPhase
    Assert-Equal '185.1.1.1' ($d.Items | Where-Object purpose -eq 'nord-endpoint-direct').remoteAddress
}
It 'DNS over the upstream is only blocked in the NordVPN phase' {
    $pre = Get-DesiredState (New-FakeEnv) ; $post = Get-DesiredState (New-FakeEnv) -NordPhase
    Assert-Equal 0 @($pre.Items | Where-Object purpose -like 'dns-upstream-*').Count
    Assert-Equal 2 @($post.Items | Where-Object purpose -like 'dns-upstream-*').Count
    Assert-Equal 2 @($pre.Items | Where-Object purpose -like 'dns-wan-*').Count
}
It 'IPv6 blocked on upstream tunnel, allowed only via NordVPN' {
    $d = Get-DesiredState (New-FakeEnv) -NordPhase
    Assert-Equal 1 @($d.Items | Where-Object purpose -eq 'ipv6-upstream').Count
    Assert-Equal 0 @($d.Items | Where-Object purpose -eq 'ipv6-nordvpn').Count
    $all = Get-DesiredState (New-FakeEnv -CfgOver @{ ipv6Policy = 'block-all' }) -NordPhase
    Assert-Equal 1 @($all.Items | Where-Object purpose -eq 'ipv6-nordvpn').Count
}
It 'no kill switch -> dedicated IPv6 WAN rule instead' {
    $d = Get-DesiredState (New-FakeEnv -CfgOver @{ killSwitch = $false }) -NordPhase
    Assert-Equal 0 @($d.Items | Where-Object purpose -like 'killswitch-*').Count
    Assert-Equal 1 @($d.Items | Where-Object purpose -eq 'ipv6-wan').Count
}
It 'bootstrap DNS: pinned to WAN, exempt from kill switch + DNS guard, server names mapped via NRPT' {
    $e = New-FakeEnv @('185.1.1.1')
    $e.Upstream | Add-Member ServerNames @('ru08.example.net') -Force
    $e.Upstream | Add-Member BootstrapDns @('119.29.29.29') -Force
    $d = Get-DesiredState $e -NordPhase
    $r = $d.Items | Where-Object purpose -eq 'upstream-dns'
    Assert-Equal '119.29.29.29/32' $r.prefix; Assert-Equal 22 $r.ifIndex
    $n = $d.Items | Where-Object kind -eq 'nrpt'
    Assert-Equal 'ru08.example.net' $n.namespace; Assert-Equal '119.29.29.29' $n.nameServers
    $ks = $d.Items | Where-Object purpose -eq 'killswitch-v4'
    Assert-True (@($ks.remoteAddress | Where-Object { $_ -like '*-119.29.29.28' }).Count -eq 1) 'kill switch must exempt bootstrap DNS'
    $dns = $d.Items | Where-Object purpose -eq 'dns-wan-udp'
    Assert-True (@($dns.remoteAddress | Where-Object { $_ -like '119.29.29.30-*' }).Count -eq 1) 'DNS guard must exempt bootstrap DNS'
}
It 'server names without bootstrap DNS produce a deadlock warning, no NRPT' {
    $e = New-FakeEnv
    $e.Upstream | Add-Member ServerNames @('ru08.example.net') -Force
    $d = Get-DesiredState $e
    Assert-Equal 0 @($d.Items | Where-Object kind -eq 'nrpt').Count
    Assert-True (@($d.Notes | Where-Object { $_ -like '*deadlock*' }).Count -eq 1)
}
It 'rule names change when the upstream adapter is re-created (new ifIndex)' {
    $a = (Get-DesiredState (New-FakeEnv) -NordPhase).Items | Where-Object purpose -eq 'dns-upstream-udp'
    $tun.ifIndex = 51
    $b = (Get-DesiredState (New-FakeEnv) -NordPhase).Items | Where-Object purpose -eq 'dns-upstream-udp'
    $tun.ifIndex = 50
    Assert-True ($a.name -ne $b.name) 'signature should include ifIndex'
}

# ---------------------------------------------------------------------------
Section 'Transactional engine (fake route/firewall store)'
$script:FakeRoutes = @{}; $script:FakeRules = @{}; $script:FailNextRoute = $false
function Test-RouteExists([string]$Prefix, [int]$IfIndex, [string]$NextHop) { $script:FakeRoutes.ContainsKey("$Prefix|$IfIndex|$NextHop") }
function Add-HostRoute([string]$Prefix, [int]$IfIndex, [string]$NextHop, [int]$Metric) {
    if ($script:FailNextRoute) { $script:FailNextRoute = $false; throw 'simulated New-NetRoute failure' }
    $script:FakeRoutes["$Prefix|$IfIndex|$NextHop"] = 'ours'
}
function Remove-HostRoute([string]$Prefix, [int]$IfIndex, [string]$NextHop) { $script:FakeRoutes.Remove("$Prefix|$IfIndex|$NextHop") }
function Test-RoutePrefixOnInterface([string]$Prefix, [int]$IfIndex) { [bool]@($script:FakeRoutes.Keys | Where-Object { $_ -like "$Prefix|$IfIndex|*" }).Count }
It 'VPN that already installs 0/1 + 128/1 (any nexthop) is left alone' {
    $script:FakeRoutes = @{ '0.0.0.0/1|91|10.9.0.1' = 'vpn'; '128.0.0.0/1|91|10.9.0.1' = 'vpn' }; $script:FakeRules = @{}
    $s = New-Session; Save-Session $s
    [void](Invoke-Reconcile $s (Get-DesiredState (New-FakeEnv) -NordPhase))
    Assert-Equal 0 @($s.journal | Where-Object purpose -eq 'nord-default').Count
    [void](Undo-All $s)
    Assert-True ($script:FakeRoutes.ContainsKey('0.0.0.0/1|91|10.9.0.1')) 'VPN route must survive'
}
function Add-ChainFirewallRule($Spec) { $script:FakeRules[$Spec.name] = $script:FirewallGroup }
function Remove-ChainFirewallRule([string]$Name) { $script:FakeRules.Remove($Name) }
function Get-NetFirewallRule([string]$Name, [string]$Group, $ErrorAction) {
    if ($Name) { if ($script:FakeRules.ContainsKey($Name)) { [pscustomobject]@{ Name = $Name; Group = $script:FakeRules[$Name] } } }
    elseif ($Group) { $script:FakeRules.Keys | Where-Object { $script:FakeRules[$_] -eq $Group } | ForEach-Object { [pscustomobject]@{ Name = $_; Group = $Group } } }
}
function Remove-NetFirewallRule { process { $script:FakeRules.Remove($_.Name) } }
$script:FakeMetric = @{}
function Get-ChainIfMetric([int]$IfIndex) { if ($script:FakeMetric.ContainsKey($IfIndex)) { [pscustomobject]@{ Metric = $script:FakeMetric[$IfIndex]; Automatic = $true } } }
function Set-ChainIfMetric([int]$IfIndex, [int]$Metric) { $script:FakeMetric[$IfIndex] = $Metric }
function Restore-ChainIfMetric([int]$IfIndex, [int]$Metric, [bool]$Automatic) { $script:FakeMetric[$IfIndex] = $Metric }
It 'VPN adapter metric raised above WAN, re-asserted after the app resets it, restored on undo' {
    $script:FakeRoutes = @{}; $script:FakeRules = @{}; $script:FakeMetric = @{ 91 = 5 }
    $nlx | Add-Member Metric4 5 -Force
    $s = New-Session; Save-Session $s
    $d = Get-DesiredState (New-FakeEnv) -NordPhase
    [void](Invoke-Reconcile $s $d)
    Assert-Equal 100 $script:FakeMetric[91]
    $script:FakeMetric[91] = 5                       # NordVPN reconnect resets it
    [void](Invoke-Reconcile $s $d)
    Assert-Equal 100 $script:FakeMetric[91]
    [void](Undo-All $s)
    Assert-Equal 5 $script:FakeMetric[91]
    $nlx.PSObject.Properties.Remove('Metric4')
}
$script:FakeNrpt = @{}
function Add-ChainNrptRule([string]$Namespace, [string[]]$NameServers) { $id = '{' + [guid]::NewGuid() + '}'; $script:FakeNrpt[$id] = 'ours'; $id }
function Test-ChainNrptRule([string]$RuleName) { $script:FakeNrpt.ContainsKey($RuleName) }
function Remove-ChainNrptRule([string]$RuleName) { if ($script:FakeNrpt[$RuleName] -eq 'foreign') { throw 'refusing foreign' }; $script:FakeNrpt.Remove($RuleName) }
function Get-OrphanChainNrptRules { @($script:FakeNrpt.Keys | Where-Object { $script:FakeNrpt[$_] -eq 'ours' }) }
function New-NrptEnv { $e = New-FakeEnv @('185.1.1.1'); $e.Upstream | Add-Member ServerNames @('ru08.example.net') -Force; $e.Upstream | Add-Member BootstrapDns @('119.29.29.29') -Force; $e }

It 'NRPT rule journaled, idempotent, removed on undo; foreign NRPT untouched' {
    $script:FakeRoutes = @{}; $script:FakeRules = @{}; $script:FakeNrpt = @{ '{foreign}' = 'foreign' }
    $s = New-Session; Save-Session $s
    $d = Get-DesiredState (New-NrptEnv) -NordPhase
    [void](Invoke-Reconcile $s $d)
    Assert-Equal 2 $script:FakeNrpt.Count
    Assert-True ([bool](@($s.journal | Where-Object { $_.kind -eq 'nrpt' -and $_.ruleName }).Count)) 'ruleName not journaled'
    Assert-Equal 0 (Invoke-Reconcile $s $d)
    Assert-Equal 0 (Undo-All $s)
    Assert-Equal @('{foreign}') @($script:FakeNrpt.Keys)
}
It 'reset sweeps an NRPT rule whose creation was never journaled (crash mid-create)' {
    $script:FakeNrpt = @{ '{lost}' = 'ours'; '{foreign}' = 'foreign' }; $script:FakeRules = @{}
    $orphan = [ordered]@{ status = 'orphaned'; journal = @(); snapshot = $null; context = [ordered]@{} }
    Assert-Equal 0 (Undo-All $orphan)
    Assert-Equal @('{foreign}') @($script:FakeNrpt.Keys)
}

It 'apply -> idempotent re-apply -> full undo restores the original state' {
    $script:FakeRoutes = @{ 'keep/32|7|1.1.1.1' = 'foreign' }; $script:FakeRules = @{ 'SomeoneElse' = 'Other' }
    $s = New-Session; Save-Session $s
    $d = Get-DesiredState (New-FakeEnv @('185.1.1.1')) -NordPhase
    $n1 = Invoke-Reconcile $s $d
    Assert-True ($n1 -gt 5) "expected several changes, got $n1"
    Assert-True ($script:FakeRoutes.ContainsKey('185.1.1.1/32|50|0.0.0.0')) 'nord pin missing'
    Assert-Equal 0 (Invoke-Reconcile $s $d) 're-apply should be a no-op'
    Assert-Equal 0 (Undo-All $s)
    Assert-Equal @('keep/32|7|1.1.1.1') @($script:FakeRoutes.Keys) 'foreign route must survive'
    Assert-Equal @('SomeoneElse') @($script:FakeRules.Keys) 'foreign rule must survive'
}
It 'NordVPN server change re-pins only the endpoint route' {
    $script:FakeRoutes = @{}; $script:FakeRules = @{}
    $s = New-Session; Save-Session $s
    [void](Invoke-Reconcile $s (Get-DesiredState (New-FakeEnv @('185.1.1.1')) -NordPhase))
    $before = @($script:FakeRules.Keys | Where-Object { $_ -notlike '*nord-endpoint-direct*' } | Sort-Object)
    [void](Invoke-Reconcile $s (Get-DesiredState (New-FakeEnv @('185.2.2.2')) -NordPhase))
    Assert-True ($script:FakeRoutes.ContainsKey('185.2.2.2/32|50|0.0.0.0')) 'new pin missing'
    Assert-True (-not $script:FakeRoutes.ContainsKey('185.1.1.1/32|50|0.0.0.0')) 'old pin not removed'
    Assert-Equal $before @($script:FakeRules.Keys | Where-Object { $_ -notlike '*nord-endpoint-direct*' } | Sort-Object) 'unrelated rules must not churn'
    [void](Undo-All $s)
}
It 'pre-existing identical route is never journaled nor removed' {
    $script:FakeRoutes = @{ '149.102.227.91/32|22|192.168.1.1' = 'windscribe' }; $script:FakeRules = @{}
    $s = New-Session; Save-Session $s
    [void](Invoke-Reconcile $s (Get-DesiredState (New-FakeEnv) -NordPhase))
    Assert-Equal 0 @($s.journal | Where-Object { $_.purpose -eq 'upstream-server' }).Count
    [void](Undo-All $s)
    Assert-True ($script:FakeRoutes.ContainsKey('149.102.227.91/32|22|192.168.1.1')) 'foreign pin removed!'
}
It 'failure mid-apply throws and leaves nothing pending' {
    $script:FakeRoutes = @{}; $script:FakeRules = @{}
    $s = New-Session; Save-Session $s
    $script:FailNextRoute = $true
    $threw = $false; try { [void](Invoke-Reconcile $s (Get-DesiredState (New-FakeEnv @('185.1.1.1')) -NordPhase)) } catch { $threw = $true }
    Assert-True $threw 'expected failure'
    Assert-Equal 0 @((Read-Session).journal | Where-Object { $_.status -eq 'pending' }).Count
    [void](Undo-All (Read-Session))
    Assert-Equal 0 $script:FakeRoutes.Count; Assert-Equal 0 $script:FakeRules.Count
}
It 'crash recovery: reset undoes a journal left behind by a killed process' {
    $script:FakeRoutes = @{}; $script:FakeRules = @{}
    $s = New-Session; Save-Session $s
    [void](Invoke-Reconcile $s (Get-DesiredState (New-FakeEnv @('185.1.1.1')) -NordPhase))
    # simulate crash: a pending entry whose mutation did happen
    $script:FakeRoutes['9.9.9.9/32|50|0.0.0.0'] = 'ours'
    $s.journal = @($s.journal) + @([ordered]@{ kind = 'route'; purpose = 'nord-endpoint'; prefix = '9.9.9.9/32'; ifIndex = 50; alias = 'singbox_tun'; nextHop = '0.0.0.0'; status = 'pending' })
    Save-Session $s
    $loaded = Read-Session   # what 'reset' sees after the crash
    Assert-Equal 0 (Undo-All $loaded)
    Assert-Equal 0 $script:FakeRoutes.Count; Assert-Equal 0 $script:FakeRules.Count
}
It 'reset without any session file sweeps only our firewall group' {
    $script:FakeRules = @{ 'vpn-chain-killswitch-v4-abc' = 'vpn-chain'; 'Foreign' = 'Other' }
    $orphan = [ordered]@{ status = 'orphaned'; journal = @(); snapshot = $null; context = [ordered]@{} }
    Assert-Equal 0 (Undo-All $orphan)
    Assert-Equal @('Foreign') @($script:FakeRules.Keys)
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
[Console]::WriteLine('')
[Console]::WriteLine("Passed: $script:pass  Failed: $script:fail")
exit $script:fail
