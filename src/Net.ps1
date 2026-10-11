# Net.ps1 - IP math, interface inventory, route and firewall primitives.
# Pure helpers (IP math, range complement) are side-effect free and unit-tested.

Add-Type -AssemblyName System.Numerics

# ----------------------------------------------------------------------------
# IP math (IPv4 + IPv6 via BigInteger)
# ----------------------------------------------------------------------------

function ConvertTo-IpBigInt {
    param([Parameter(Mandatory)][string]$Ip)
    $addr = [System.Net.IPAddress]::Parse($Ip)
    $bytes = $addr.GetAddressBytes()          # network (big-endian) order
    [Array]::Reverse($bytes)                  # BigInteger wants little-endian
    $bytes = $bytes + [byte]0                 # force positive
    return New-Object System.Numerics.BigInteger(,[byte[]]$bytes)
}

function ConvertFrom-IpBigInt {
    param([Parameter(Mandatory)][System.Numerics.BigInteger]$Value, [ValidateSet(4,6)][int]$Family)
    $len = if ($Family -eq 4) { 4 } else { 16 }
    $le = $Value.ToByteArray()
    $out = New-Object byte[] $len
    for ($i = 0; $i -lt [Math]::Min($len, $le.Length); $i++) { $out[$len - 1 - $i] = $le[$i] }
    return ([System.Net.IPAddress]::new($out)).ToString()
}

function Get-IpFamily {
    param([Parameter(Mandatory)][string]$Ip)
    $addr = [System.Net.IPAddress]::Parse(($Ip -split '/')[0])
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { 6 } else { 4 }
}

function Test-IpAddressString {
    param([string]$Value)
    $tmp = $null
    return [System.Net.IPAddress]::TryParse([string]$Value, [ref]$tmp)
}

function Get-CidrRange {
    # Returns @{ Family; Start; End } (BigInteger bounds) for 'a.b.c.d/nn', '2001:db8::/32' or a bare IP.
    param([Parameter(Mandatory)][string]$Cidr)
    $parts = $Cidr -split '/'
    $family = Get-IpFamily $parts[0]
    $bits = if ($family -eq 4) { 32 } else { 128 }
    $prefix = if ($parts.Count -gt 1) { [int]$parts[1] } else { $bits }
    $ip = ConvertTo-IpBigInt $parts[0]
    $hostBits = $bits - $prefix
    $size = [System.Numerics.BigInteger]::Pow(2, $hostBits)
    $start = [System.Numerics.BigInteger]::Divide($ip, $size) * $size
    $end = $start + $size - 1
    return [pscustomobject]@{ Family = $family; Start = $start; End = $end }
}

function Get-RangeComplement {
    # Complement of the given CIDRs/IPs within the whole address space of one family.
    # Output: list of strings usable as Windows Firewall RemoteAddress ('a-b' or single IP).
    param([string[]]$Exclude = @(), [Parameter(Mandatory)][ValidateSet(4,6)][int]$Family)
    $max = if ($Family -eq 4) { [System.Numerics.BigInteger]::Pow(2,32) - 1 } else { [System.Numerics.BigInteger]::Pow(2,128) - 1 }
    $ranges = @($Exclude | Where-Object { $_ } | ForEach-Object { Get-CidrRange $_ } | Where-Object { $_.Family -eq $Family } | Sort-Object { $_.Start })
    $result = New-Object System.Collections.Generic.List[string]
    $cursor = [System.Numerics.BigInteger]::Zero
    foreach ($r in $ranges) {
        if ($r.Start -gt $cursor) { $result.Add((Format-IpRange $cursor ($r.Start - 1) $Family)) }
        if ($r.End + 1 -gt $cursor) { $cursor = $r.End + 1 }
        if ($cursor -gt $max) { break }
    }
    if ($cursor -le $max) { $result.Add((Format-IpRange $cursor $max $Family)) }
    return $result.ToArray()
}

function Format-IpRange {
    param([System.Numerics.BigInteger]$Start, [System.Numerics.BigInteger]$End, [int]$Family)
    $a = ConvertFrom-IpBigInt $Start $Family
    if ($Start -eq $End) { return $a }
    return '{0}-{1}' -f $a, (ConvertFrom-IpBigInt $End $Family)
}

function Test-IpInCidr {
    param([string]$Ip, [string]$Cidr)
    if ((Get-IpFamily $Ip) -ne (Get-IpFamily $Cidr)) { return $false }
    $r = Get-CidrRange $Cidr
    $v = ConvertTo-IpBigInt $Ip
    return ($v -ge $r.Start -and $v -le $r.End)
}

$script:NonPublic4 = @('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12',
                       '192.0.0.0/24','192.0.2.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24',
                       '203.0.113.0/24','224.0.0.0/4','240.0.0.0/4')
$script:NonPublic6 = @('::/128','::1/128','fe80::/10','fc00::/7','ff00::/8','2001:db8::/32','64:ff9b::/96')

# Ranges allowed on WAN-side interfaces when allowLan is true (LAN, DHCP, multicast, CGNAT gateway).
$script:LanAllow4 = @('10.0.0.0/8','100.64.0.0/10','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','255.255.255.255/32')
$script:LanAllow6 = @('fe80::/10','fc00::/7','ff00::/8')
# Always allowed even without allowLan: link-local + multicast (DHCP/ND/router discovery keep the NIC alive).
$script:LinkAllow4 = @('169.254.0.0/16','224.0.0.0/4','255.255.255.255/32')
$script:LinkAllow6 = @('fe80::/10','ff00::/8')

function Test-IsPublicIp {
    param([string]$Ip)
    if (-not (Test-IpAddressString $Ip)) { return $false }
    $list = if ((Get-IpFamily $Ip) -eq 4) { $script:NonPublic4 } else { $script:NonPublic6 }
    foreach ($c in $list) { if (Test-IpInCidr $Ip $c) { return $false } }
    return $true
}

function Get-HostPrefix {
    param([string]$Ip)
    if ((Get-IpFamily $Ip) -eq 4) { "$Ip/32" } else { "$Ip/128" }
}

# ----------------------------------------------------------------------------
# Interface inventory
# ----------------------------------------------------------------------------

$script:NordAdapterPattern  = 'NordLynx|TAP-NordVPN|OpenVPN Data Channel Offload for NordVPN|NordVPN'
$script:TunnelDescPattern   = 'sing|wintun|v2ray|xray|clash|mihomo|meta|hiddify|nekoray|nekobox|tun2socks|tun|wireguard|ikev2|vpn|ppp|windscribe'

function Get-InterfaceInventory {
    # One object per IP interface (covers NDIS adapters and RAS/PPP interfaces such as IKEv2).
    $adapters = @{}
    foreach ($a in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) { $adapters[[int]$a.ifIndex] = $a }

    $dotnet = @{}
    foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        $idx = $null
        try { $idx = $ni.GetIPProperties().GetIPv4Properties().Index } catch { }
        if ($null -eq $idx) { try { $idx = $ni.GetIPProperties().GetIPv6Properties().Index } catch { } }
        if ($null -ne $idx) { $dotnet[[int]$idx] = $ni }
    }

    $ipIfs = @(Get-NetIPInterface -ErrorAction SilentlyContinue)
    $addrs = @(Get-NetIPAddress -ErrorAction SilentlyContinue)
    $routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    $dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue)

    $result = @()
    foreach ($idx in ($ipIfs | Select-Object -ExpandProperty ifIndex -Unique)) {
        $idx = [int]$idx
        $v4 = $ipIfs | Where-Object { $_.ifIndex -eq $idx -and $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1
        $v6 = $ipIfs | Where-Object { $_.ifIndex -eq $idx -and $_.AddressFamily -eq 'IPv6' } | Select-Object -First 1
        $any = if ($v4) { $v4 } else { $v6 }
        $ad = $adapters[$idx]
        $ni = $dotnet[$idx]
        $desc = if ($ad) { [string]$ad.InterfaceDescription } elseif ($ni) { [string]$ni.Description } else { '' }
        $alias = [string]$any.InterfaceAlias
        $isUp = ($any.ConnectionState -eq 'Connected')
        if ($ni) { $isUp = $isUp -or ($ni.OperationalStatus -eq 'Up') }
        $niType = if ($ni) { [string]$ni.NetworkInterfaceType } else { '' }
        $hardware = [bool]($ad -and $ad.HardwareInterface)
        $ifRoutes = @($routes | Where-Object { $_.ifIndex -eq $idx })
        $def4 = @($ifRoutes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' })
        $split4 = (@($ifRoutes | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') }).Count -eq 2)
        $def6 = @($ifRoutes | Where-Object { $_.DestinationPrefix -eq '::/0' })
        $split6 = (@($ifRoutes | Where-Object { $_.DestinationPrefix -in @('::/1','8000::/1') }).Count -eq 2)
        $gw4 = ($def4 | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric | Select-Object -First 1)
        $gw6 = ($def6 | Where-Object { $_.NextHop -and $_.NextHop -ne '::' } | Sort-Object RouteMetric | Select-Object -First 1)

        $kind = 'other'
        if ($alias -like 'Loopback*' -or $niType -eq 'Loopback') { $kind = 'loopback' }
        elseif ("$alias $desc" -match $script:NordAdapterPattern) { $kind = 'nordvpn' }
        elseif ($hardware) { $kind = 'physical' }
        elseif ($niType -in @('Ppp','Tunnel','53') -or $desc -match $script:TunnelDescPattern) { $kind = 'virtual-tunnel' }
        else { $kind = 'virtual' }

        $result += [pscustomobject]@{
            ifIndex      = $idx
            Alias        = $alias
            Description  = $desc
            Kind         = $kind
            IsUp         = [bool]$isUp
            Hardware     = $hardware
            NetType      = $niType
            Metric4      = if ($v4) { [int]$v4.InterfaceMetric } else { $null }
            Metric6      = if ($v6) { [int]$v6.InterfaceMetric } else { $null }
            IPv4         = @($addrs | Where-Object { $_.ifIndex -eq $idx -and $_.AddressFamily -eq 'IPv4' } | ForEach-Object { $_.IPAddress })
            IPv6         = @($addrs | Where-Object { $_.ifIndex -eq $idx -and $_.AddressFamily -eq 'IPv6' } | ForEach-Object { $_.IPAddress })
            GlobalIPv6   = @($addrs | Where-Object { $_.ifIndex -eq $idx -and $_.AddressFamily -eq 'IPv6' -and (Test-IsPublicIp $_.IPAddress) } | ForEach-Object { $_.IPAddress })
            HasDefault4  = ($def4.Count -gt 0 -or $split4)
            DefaultStyle4 = if ($split4) { 'split(0/1+128/1)' } elseif ($def4.Count) { '0.0.0.0/0' } else { '' }
            HasDefault6  = ($def6.Count -gt 0 -or $split6)
            DefaultMetric4 = if ($def4.Count) { [int](($def4 | Measure-Object RouteMetric -Minimum).Minimum) + [int]$v4.InterfaceMetric } elseif ($split4) { 0 } else { $null }
            Gateway4     = if ($gw4) { [string]$gw4.NextHop } else { $null }
            Gateway6     = if ($gw6) { [string]$gw6.NextHop } else { $null }
            DnsServers   = @($dns | Where-Object { $_.InterfaceIndex -eq $idx } | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -and $_ -notlike 'fec0:0:0:ffff::*' })
            DotNet       = $ni
        }
    }
    return $result
}

function Get-InterfaceStats {
    param([int[]]$IfIndex)
    $out = @{}
    foreach ($ni in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        $idx = $null
        try { $idx = $ni.GetIPProperties().GetIPv4Properties().Index } catch { }
        if ($null -eq $idx) { try { $idx = $ni.GetIPProperties().GetIPv6Properties().Index } catch { } }
        if ($null -ne $idx -and $IfIndex -contains [int]$idx) {
            try {
                $s = $ni.GetIPStatistics()
                $out[[int]$idx] = [pscustomobject]@{ Rx = [int64]$s.BytesReceived; Tx = [int64]$s.BytesSent }
            } catch { }
        }
    }
    return $out
}

# ----------------------------------------------------------------------------
# Route lookup + mutation
# ----------------------------------------------------------------------------

function Get-EffectiveRoute {
    # What the Windows stack would actually use for this destination right now.
    param([Parameter(Mandatory)][string]$Ip)
    try {
        $r = Find-NetRoute -RemoteIPAddress $Ip -ErrorAction Stop | Where-Object { $_ -is [Microsoft.Management.Infrastructure.CimInstance] -and $_.CimClass.CimClassName -eq 'MSFT_NetRoute' } | Select-Object -First 1
        if ($r) { return [pscustomobject]@{ ifIndex = [int]$r.ifIndex; Alias = $r.InterfaceAlias; Prefix = $r.DestinationPrefix; NextHop = $r.NextHop } }
    } catch { }
    return $null
}

function Get-RouteKey { param($R) '{0}|{1}|{2}' -f $R.prefix, $R.ifIndex, $R.nextHop }

function Test-RouteExists {
    param([string]$Prefix, [int]$IfIndex, [string]$NextHop)
    $r = Get-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $IfIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $NextHop }
    return [bool]$r
}

function Test-RoutePrefixOnInterface {
    param([string]$Prefix, [int]$IfIndex)
    return [bool](Get-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $IfIndex -ErrorAction SilentlyContinue)
}

function Add-HostRoute {
    param([string]$Prefix, [int]$IfIndex, [string]$NextHop, [int]$Metric = 0)
    # ActiveStore only: never persisted, a reboot always clears it.
    New-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $IfIndex -NextHop $NextHop -RouteMetric $Metric `
        -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
}

function Remove-HostRoute {
    param([string]$Prefix, [int]$IfIndex, [string]$NextHop)
    $r = Get-NetRoute -DestinationPrefix $Prefix -InterfaceIndex $IfIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $NextHop }
    if ($r) { $r | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
}

# ----------------------------------------------------------------------------
# Interface metric (IPv4) - only for the chained VPN's own adapters
# ----------------------------------------------------------------------------

function Get-ChainIfMetric {
    param([int]$IfIndex)
    $i = Get-NetIPInterface -InterfaceIndex $IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $i) { return $null }
    [pscustomobject]@{ Metric = [int]$i.InterfaceMetric; Automatic = ([string]$i.AutomaticMetric -eq 'Enabled') }
}

function Set-ChainIfMetric {
    param([int]$IfIndex, [int]$Metric)
    Set-NetIPInterface -InterfaceIndex $IfIndex -AddressFamily IPv4 -InterfaceMetric $Metric -ErrorAction Stop
}

function Restore-ChainIfMetric {
    param([int]$IfIndex, [int]$Metric, [bool]$Automatic)
    if (-not (Get-ChainIfMetric $IfIndex)) { return }     # adapter gone (e.g. RAS) - nothing to restore
    if ($Automatic) { Set-NetIPInterface -InterfaceIndex $IfIndex -AddressFamily IPv4 -AutomaticMetric Enabled -ErrorAction Stop }
    else { Set-NetIPInterface -InterfaceIndex $IfIndex -AddressFamily IPv4 -InterfaceMetric $Metric -ErrorAction Stop }
}

# ----------------------------------------------------------------------------
# Firewall rules (always in our own group; we never touch any other rule)
# ----------------------------------------------------------------------------

function Get-RuleSignature {
    param([System.Collections.IDictionary]$Spec)
    # ifKeys = alias#ifIndex: a re-created adapter (new index) yields a new signature, so the
    # rule is re-created and re-bound to the new interface instance.
    $ifs = if ($Spec.Contains('ifKeys')) { $Spec.ifKeys } else { $Spec.interfaceAlias }
    $text = '{0}|{1}|{2}|{3}|{4}' -f $Spec.protocol, (@($Spec.remoteAddress) -join ','), (@($Spec.remotePort) -join ','), (@($ifs | Sort-Object) -join ','), $Spec.purpose
    $sha = [System.Security.Cryptography.SHA1]::Create()
    $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
    return (-join ($hash[0..4] | ForEach-Object { $_.ToString('x2') }))
}

function Add-ChainFirewallRule {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Spec)
    # VPN apps delete/re-create adapters while connecting; only bind to interfaces that exist now
    # (the monitor re-binds once they come back - their alias#ifIndex is part of the signature).
    $present = @(Get-NetIPInterface -ErrorAction SilentlyContinue | ForEach-Object InterfaceAlias | Select-Object -Unique)
    $aliases = @($Spec.interfaceAlias | Where-Object { $present -contains $_ })
    if (-not $aliases.Count) { throw "none of the rule's interfaces exist right now ($(@($Spec.interfaceAlias) -join ', '))" }
    $Spec.interfaceAlias = $aliases
    $p = @{
        Name         = $Spec.name
        DisplayName  = "vpn-chain: $($Spec.purpose)"
        Group        = $script:FirewallGroup
        Description  = "Created by vpn-chain (temporary leak guard). Removed by 'vpn-chain stop' or 'vpn-chain reset'. sig=$($Spec.signature)"
        Direction    = 'Outbound'
        Action       = 'Block'
        Profile      = 'Any'
        Protocol     = $Spec.protocol
        RemoteAddress = @($Spec.remoteAddress)
        InterfaceAlias = @($Spec.interfaceAlias | ForEach-Object { [System.Management.Automation.WildcardPattern]::Escape($_) })
        ErrorAction  = 'Stop'
    }
    if ($Spec.remotePort -and @($Spec.remotePort).Count) { $p.RemotePort = @($Spec.remotePort) }
    New-NetFirewallRule @p | Out-Null
}

function Remove-ChainFirewallRule {
    param([Parameter(Mandatory)][string]$Name)
    $r = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($r) {
        if ($r.Group -ne $script:FirewallGroup) { throw "Refusing to remove firewall rule '$Name': it does not belong to group '$($script:FirewallGroup)'." }
        $r | Remove-NetFirewallRule -ErrorAction Stop
    }
}

# ----------------------------------------------------------------------------
# NRPT (Name Resolution Policy Table) - used only to keep the upstream core's own
# server-name lookups on its bootstrap DNS, outside NordVPN. Tagged by comment.
# ----------------------------------------------------------------------------

$script:NrptComment = 'vpn-chain: upstream server name resolution (temporary)'

function Add-ChainNrptRule {
    param([Parameter(Mandatory)][string]$Namespace, [Parameter(Mandatory)][string[]]$NameServers)
    $r = Add-DnsClientNrptRule -Namespace $Namespace -NameServers $NameServers -Comment $script:NrptComment -PassThru -ErrorAction Stop
    return [string]$r.Name
}

function Test-ChainNrptRule {
    param([string]$RuleName)
    if (-not $RuleName) { return $false }
    return [bool](Get-DnsClientNrptRule -Name $RuleName -ErrorAction SilentlyContinue)
}

function Remove-ChainNrptRule {
    param([Parameter(Mandatory)][string]$RuleName)
    $r = Get-DnsClientNrptRule -Name $RuleName -ErrorAction SilentlyContinue
    if ($r) {
        if ($r.Comment -ne $script:NrptComment) { throw "Refusing to remove NRPT rule $RuleName`: not created by vpn-chain." }
        Remove-DnsClientNrptRule -Name $RuleName -Force -ErrorAction Stop
    }
}

function Get-OrphanChainNrptRules {
    @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { $_.Comment -eq $script:NrptComment } | ForEach-Object { [string]$_.Name })
}

function Test-FirewallActive {
    # Rules only take effect when the profile(s) of the affected interfaces have the firewall enabled.
    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $disabled = @($profiles | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
    $svc = Get-Service -Name mpssvc -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ServiceRunning   = [bool]($svc -and $svc.Status -eq 'Running')
        DisabledProfiles = $disabled
        Ok               = [bool]($svc -and $svc.Status -eq 'Running' -and $disabled.Count -eq 0)
    }
}

# ----------------------------------------------------------------------------
# Probes (bypass the WinINET system proxy on purpose: we measure the routing path)
# ----------------------------------------------------------------------------

function Invoke-HttpGet {
    param([Parameter(Mandatory)][string]$Url, [int]$TimeoutMs = 8000, [int]$MaxBytes = 65536)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $req = [System.Net.HttpWebRequest]::Create($Url)
    $req.Proxy = $null
    $req.Timeout = $TimeoutMs
    $req.ReadWriteTimeout = $TimeoutMs
    $req.UserAgent = 'vpn-chain/1.0'
    $resp = $req.GetResponse()
    try {
        $stream = $resp.GetResponseStream()
        $buf = New-Object byte[] 8192
        $ms = New-Object System.IO.MemoryStream
        $total = 0
        while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
            $total += $n
            if ($total -le $MaxBytes) { $ms.Write($buf, 0, $n) }
        }
        return [pscustomobject]@{ Body = [System.Text.Encoding]::UTF8.GetString($ms.ToArray()); Bytes = $total }
    } finally { $resp.Close() }
}

function Get-PublicIp {
    # Majority vote over independent services; degrades gracefully if some are down.
    param([string[]]$Services, [int]$TimeoutMs = 6000, [switch]$FirstOnly)
    $results = @()
    foreach ($s in $Services) {
        try {
            $body = (Invoke-HttpGet -Url $s -TimeoutMs $TimeoutMs).Body.Trim()
            if (Test-IpAddressString $body) {
                $results += [pscustomobject]@{ Service = $s; Ip = $body }
                Write-Log VERIFY "$s -> $body" -Level DEBUG
                if ($FirstOnly) { break }
            }
        } catch { Write-Log VERIFY "$s unavailable: $($_.Exception.Message)" -Level DEBUG }
    }
    if (-not $results) { return [pscustomobject]@{ Ip = $null; Agree = 0; Total = 0; Results = @() } }
    $top = $results | Group-Object Ip | Sort-Object Count -Descending | Select-Object -First 1
    return [pscustomobject]@{ Ip = $top.Name; Agree = $top.Count; Total = $results.Count; Results = $results }
}

function New-DnsQueryBytes {
    param([string]$Name = 'example.com', [int]$Id = 0x5a5a)
    $bytes = New-Object System.Collections.Generic.List[byte]
    $bytes.AddRange([byte[]]@([byte](($Id -shr 8) -band 0xff), [byte]($Id -band 0xff), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
    foreach ($label in $Name.Split('.')) {
        $b = [System.Text.Encoding]::ASCII.GetBytes($label)
        $bytes.Add([byte]$b.Length); $bytes.AddRange($b)
    }
    $bytes.AddRange([byte[]]@(0x00, 0x00, 0x01, 0x00, 0x01))
    return $bytes.ToArray()
}

function Test-RawDnsReachable {
    # Sends one A query straight to a DNS server (not via the Windows DNS client).
    # Result: 'reachable' (leak path open) | 'blocked' (local firewall refused) | 'no-response'
    param([Parameter(Mandatory)][string]$Server, [int]$TimeoutMs = 1500)
    $family = if ((Get-IpFamily $Server) -eq 4) { [System.Net.Sockets.AddressFamily]::InterNetwork } else { [System.Net.Sockets.AddressFamily]::InterNetworkV6 }
    $udp = New-Object System.Net.Sockets.UdpClient($family)
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $id = Get-Random -Minimum 1 -Maximum 65535
        [byte[]]$q = New-DnsQueryBytes -Id $id
        try { [void]$udp.Send($q, $q.Length, [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Server), 53)) }
        catch { return 'blocked' }
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        try {
            $resp = $udp.Receive([ref]$ep)
            # [int] cast: '-shl' on a [byte] overflows instead of widening.
            if ($resp.Length -ge 2 -and ((([int]$resp[0]) -shl 8) -bor [int]$resp[1]) -eq $id) { return 'reachable' }
            return 'no-response'
        } catch {
            # PowerShell wraps socket errors in MethodInvocationException.
            $se = $_.Exception.InnerException
            if ($se -is [System.Net.Sockets.SocketException] -and $se.SocketErrorCode -eq 'AccessDenied') { return 'blocked' }
            return 'no-response'
        }
    } finally { $udp.Close() }
}
