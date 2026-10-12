# Tui.ps1 - TunnelStack interactive terminal app.
#
#  * A bold red BERAYAN banner is drawn at the top and locked there with a VT scroll region
#    (DECSTBM): everything else - menus, operation output - scrolls underneath it.
#  * The menu stays on screen; while a chain is active the app runs the auto-repair pass in the
#    background between key presses and refreshes the dashboard in place.
#  * Source is pure ASCII; box/status glyphs are built from char codes so the file renders the same
#    in Windows PowerShell 5.1 regardless of file encoding or console code page.

$script:E = [char]27
$script:Vt = $false
$script:HeaderRows = 8
$script:ScreenSize = ''
$script:Dot = [string][char]0x25A0     # filled square (present in every console font)
$script:HLine = [string][char]0x2500   # box-drawing horizontal line
$script:TuiReadOnly = $false
$script:GuardUserOff = $false      # user turned the guard off this session: don't auto-enable it again
$script:GuardAutoFailed = $false   # a background auto-enable failed: don't retry every tick
$script:Dash = @{
    Scanned = $false; UpMode = '-'; UpAdapter = ''; UpProcs = ''; UpExit = ''
    VpnName = ''; VpnUp = $false; VpnProto = ''; VpnWhere = ''
    State = ''; Reasons = @(); Session = $false; LastTick = $null
    PublicIp = ''; PublicAt = $null; Guards = ''
}

# ----------------------------------------------------------------------------
# Console plumbing
# ----------------------------------------------------------------------------

function Enable-VtMode {
    try {
        if (-not ('TunnelStackNative.Con' -as [type])) {
            Add-Type -Namespace TunnelStackNative -Name Con -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern System.IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetConsoleMode(System.IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleMode(System.IntPtr hConsoleHandle, uint dwMode);
'@
        }
        $h = [TunnelStackNative.Con]::GetStdHandle(-11)
        $mode = [uint32]0
        if (-not [TunnelStackNative.Con]::GetConsoleMode($h, [ref]$mode)) { return $false }
        if (($mode -band 4) -ne 0) { return $true }
        return [TunnelStackNative.Con]::SetConsoleMode($h, ($mode -bor 4))   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    } catch { return $false }
}

$script:AnsiMap = @{
    Red = '31'; BoldRed = '1;31'; Green = '32'; BoldGreen = '1;32'; Yellow = '33'; BoldYellow = '1;33'
    Cyan = '36'; BoldCyan = '1;36'; White = '97'; BoldWhite = '1;97'; Gray = '37'; DarkGray = '90'; Magenta = '35'
}
$script:HostColorMap = @{
    Red = 'Red'; BoldRed = 'Red'; Green = 'Green'; BoldGreen = 'Green'; Yellow = 'Yellow'; BoldYellow = 'Yellow'
    Cyan = 'Cyan'; BoldCyan = 'Cyan'; White = 'White'; BoldWhite = 'White'; Gray = 'Gray'; DarkGray = 'DarkGray'; Magenta = 'Magenta'
}

function Write-Tui {
    # Direct console output (bypasses the provider re-labelling Write-Host wrapper on purpose).
    param([string]$Text = '', [string]$Color = '', [switch]$NoNewline)
    if ($script:Vt) {
        $s = if ($Color -and $script:AnsiMap.ContainsKey($Color)) { "$script:E[$($script:AnsiMap[$Color])m$Text$script:E[0m" } else { $Text }
        if (-not $NoNewline) { $s += "`r`n" }
        [Console]::Write($s)
    } else {
        $p = @{ NoNewline = [bool]$NoNewline }
        if ($Color -and $script:HostColorMap.ContainsKey($Color)) { $p.ForegroundColor = $script:HostColorMap[$Color] }
        Microsoft.PowerShell.Utility\Write-Host $Text @p
    }
}

function Write-Segments {
    # One line made of colored segments: @( @('text','Color'), ... )
    param([object[]]$Segments)
    foreach ($s in $Segments) { Write-Tui $s[0] $s[1] -NoNewline }
    Write-Tui ''
}

function Get-Banner {
    $L = @{
        B = @(' ____  ', '| __ ) ', '|  _ \ ', '| |_) |', '|____/ ')
        E = @(' _____ ', '| ____|', '|  _|  ', '| |___ ', '|_____|')
        R = @(' ____  ', '|  _ \ ', '| |_) |', '|  _ < ', '|_| \_\')
        A = @('    _    ', '   / \   ', '  / _ \  ', ' / ___ \ ', '/_/   \_\')
        Y = @('__   __', '\ \ / /', ' \ V / ', '  | |  ', '  |_|  ')
        N = @(' _   _ ', '| \ | |', '|  \| |', '| |\  |', '|_| \_|')
    }
    $rows = @()
    for ($i = 0; $i -lt 5; $i++) { $rows += ((@('B', 'E', 'R', 'A', 'Y', 'A', 'N') | ForEach-Object { $L[$_][$i] }) -join ' ') }
    return $rows
}

function Get-Centered { param([string]$Text, [int]$Width) $pad = [Math]::Max(0, [int](($Width - $Text.Length) / 2)); (' ' * $pad) + $Text }

function Write-Header {
    # Draws the locked header (rows 1..HeaderRows) and confines all other output below it.
    $w = [Math]::Max(40, [Console]::WindowWidth)
    $h = [Console]::WindowHeight
    $tag = "v2ray  ->  VPN chain   |   NordVPN  /  Windscribe   |   v$script:AppVersion$(if ($script:TuiReadOnly) { '   |   READ-ONLY' })"
    if ($script:Vt) {
        [Console]::Write("$script:E[r$script:E[H")                       # full screen, home
        [Console]::Write("$script:E[2K`r`n")
        foreach ($row in (Get-Banner)) { [Console]::Write("$script:E[2K$script:E[1;31m" + (Get-Centered $row $w) + "$script:E[0m`r`n") }
        [Console]::Write("$script:E[2K$script:E[90m" + (Get-Centered $tag $w) + "$script:E[0m`r`n")
        [Console]::Write("$script:E[2K$script:E[31m" + ($script:HLine * ($w - 1)) + "$script:E[0m")
        if ($h -gt $script:HeaderRows + 6) { [Console]::Write("$script:E[$($script:HeaderRows + 1);$($h)r") }   # lock header
        [Console]::Write("$script:E[$($script:HeaderRows + 1);1H")
    } else {
        Clear-Host
        Write-Tui ''
        foreach ($row in (Get-Banner)) { Write-Tui (Get-Centered $row $w) 'BoldRed' }
        Write-Tui (Get-Centered $tag $w) 'DarkGray'
        Write-Tui ('-' * ($w - 1)) 'Red'
    }
    $script:ScreenSize = "$([Console]::WindowWidth)x$([Console]::WindowHeight)"
}

function Clear-Content {
    if ($script:Vt) {
        if ($script:ScreenSize -ne "$([Console]::WindowWidth)x$([Console]::WindowHeight)") { [Console]::Write("$script:E[2J"); Write-Header }
        [Console]::Write("$script:E[$($script:HeaderRows + 1);1H$script:E[0J")
    } else { Write-Header }
}

function Set-CursorVisible { param([bool]$On) if ($script:Vt) { [Console]::Write($(if ($On) { "$script:E[?25h" } else { "$script:E[?25l" })) } }

function Clear-KeyBuffer { try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch { } }

function Wait-AnyKey {
    param([string]$Prompt = 'Press any key to return to the menu')
    Write-Tui ''
    Write-Tui "  $Prompt" 'DarkGray'
    Clear-KeyBuffer
    [void][Console]::ReadKey($true)
}

function Read-Key {
    # Single key; returns upper-case char, or ENTER / ESC / RESIZE / IDLE (after $IdleSec of no input).
    param([int]$IdleSec = 0)
    $start = Get-Date
    while ($true) {
        if ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq 'Enter') { return 'ENTER' }
            if ($k.Key -eq 'Escape') { return 'ESC' }
            if ($k.Key -eq 'C' -and ($k.Modifiers -band [ConsoleModifiers]::Control)) { return 'Q' }
            return ([string]$k.KeyChar).ToUpperInvariant()
        }
        if ($script:ScreenSize -and $script:ScreenSize -ne "$([Console]::WindowWidth)x$([Console]::WindowHeight)") { return 'RESIZE' }
        if ($IdleSec -gt 0 -and ((Get-Date) - $start).TotalSeconds -ge $IdleSec) { return 'IDLE' }
        Start-Sleep -Milliseconds 120
    }
}

function Read-Text {
    # Key-based line editor. NOT [Console]::ReadLine(): with TreatControlCAsInput on, Enter arrives
    # as a bare CR and .NET's ReadLine blocks forever waiting for the LF (the app looked frozen).
    # Returns $Default on empty Enter, $null on Esc.
    param([string]$Prompt, [string]$Default = '', [int]$MaxLength = 120)
    Set-CursorVisible $true
    $suffix = if ($Default) { " [$Default]" } else { '' }
    Write-Tui "  $Prompt$suffix`: " 'BoldWhite' -NoNewline
    Clear-KeyBuffer
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
        $k = [Console]::ReadKey($true)
        switch ($k.Key) {
            'Enter'     { Write-Tui ''; $v = $sb.ToString().Trim(); if ($v) { return $v } else { return $Default } }
            'Escape'    { Write-Tui ''; return $null }
            'Backspace' { if ($sb.Length -gt 0) { [void]$sb.Remove($sb.Length - 1, 1); Write-Tui "`b `b" -NoNewline } }
            default {
                $c = $k.KeyChar
                if ([int]$c -ge 32 -and $sb.Length -lt $MaxLength) { [void]$sb.Append($c); Write-Tui ([string]$c) 'White' -NoNewline }
            }
        }
    }
}

function Select-FromScrollList {
    # Scrollable, searchable picker. Items: objects with Label, Detail (optional), Group (optional).
    # Keys: Up/Down, PgUp/PgDn, Home/End, type to filter, Backspace, Enter = select, Esc = back.
    # Returns the selected item, or $null on Esc.
    param([string]$Title, [string]$Subtitle = '', [object[]]$Items, [int]$Default = 0)
    $filter = ''
    $sel = [Math]::Max(0, [Math]::Min($Default, $Items.Count - 1))
    $top = 0
    Set-CursorVisible $false
    Clear-KeyBuffer
    while ($true) {
        # @(...) around the whole if: a single match would otherwise unroll to a bare PSCustomObject,
        # which has no .Count in Windows PowerShell 5.1 (looked like "no match").
        $view = @(if ($filter) { $Items | Where-Object { "$($_.Label) $($_.Detail) $($_.Group)" -like "*$filter*" } } else { $Items })
        $page = [Math]::Max(5, [Console]::WindowHeight - $script:HeaderRows - 11)
        if ($sel -ge $view.Count) { $sel = [Math]::Max(0, $view.Count - 1) }
        if ($sel -lt $top) { $top = $sel }
        if ($sel -ge $top + $page) { $top = $sel - $page + 1 }
        $w = [Console]::WindowWidth

        Clear-Content
        Write-Tui ''
        Write-Tui "  $Title" 'BoldRed'
        if ($Subtitle) { Write-Tui "  $Subtitle" 'BoldCyan' }
        Write-Segments @(@('  Search: ', 'DarkGray'), @($(if ($filter) { $filter } else { '(type to filter)' }), $(if ($filter) { 'BoldWhite' } else { 'DarkGray' })), @("     $($view.Count) of $($Items.Count)", 'DarkGray'))
        Write-Tui ''
        if (-not $view.Count) { Write-Tui '     no match - Backspace to edit the search' 'Yellow' }
        $end = [Math]::Min($view.Count, $top + $page)
        for ($i = $top; $i -lt $end; $i++) {
            $it = $view[$i]
            $label = [string]$it.Label
            $detail = if ($it.Detail) { "   $($it.Detail)" } else { '' }
            $line = "$label$detail"
            if ($line.Length -gt $w - 10) { $line = $line.Substring(0, $w - 10) }
            if ($i -eq $sel) {
                if ($script:Vt) { [Console]::Write("  $script:E[1;31m>$script:E[0m $script:E[7m $line $script:E[0m`r`n") }
                else { Write-Tui "  >  $line" 'BoldRed' }
            } else {
                Write-Segments @(@('     ', 'DarkGray'), @($label, $(switch ($it.Group) { 'special' { 'Cyan' } 'static' { 'Magenta' } default { 'White' } })), @($detail, 'DarkGray'))
            }
        }
        for ($i = $end - $top; $i -lt $page; $i++) { Write-Tui '' }
        $more = if ($view.Count -gt $page) { "  rows $($top + 1)-$end of $($view.Count)" } else { '' }
        Write-Segments @(@('  Up/Down PgUp/PgDn Home/End  move   ', 'DarkGray'), @('Enter', 'BoldRed'), @(' select   ', 'DarkGray'), @('Esc', 'BoldRed'), @(' back   type to search', 'DarkGray'), @($more, 'DarkGray'))

        $k = [Console]::ReadKey($true)
        switch ($k.Key) {
            'UpArrow'   { if ($sel -gt 0) { $sel-- } }
            'DownArrow' { if ($sel -lt $view.Count - 1) { $sel++ } }
            'PageUp'    { $sel = [Math]::Max(0, $sel - $page) }
            'PageDown'  { $sel = [Math]::Min([Math]::Max(0, $view.Count - 1), $sel + $page) }
            'Home'      { $sel = 0 }
            'End'       { $sel = [Math]::Max(0, $view.Count - 1) }
            'Enter'     { if ($view.Count) { return $view[$sel] } }
            'Escape'    { if ($filter) { $filter = ''; $sel = 0; $top = 0 } else { return $null } }
            'Backspace' { if ($filter.Length) { $filter = $filter.Substring(0, $filter.Length - 1); $sel = 0; $top = 0 } }
            default {
                $c = $k.KeyChar
                if ([int]$c -ge 32 -and $filter.Length -lt 40) { $filter += $c; $sel = 0; $top = 0 }
            }
        }
    }
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $true)
    Write-Tui "  $Prompt $(if ($Default) { '[Y/n]' } else { '[y/N]' }) " 'BoldWhite' -NoNewline
    Clear-KeyBuffer
    while ($true) {
        $k = Read-Key
        if ($k -eq 'ENTER') { Write-Tui ''; return $Default }
        if ($k -eq 'Y') { Write-Tui 'y'; return $true }
        if ($k -in @('N', 'ESC')) { Write-Tui 'n'; return $false }
    }
}

# ----------------------------------------------------------------------------
# User config persistence (config.json next to the tool; only keys the user chose)
# ----------------------------------------------------------------------------

function Get-UserConfigPath { Join-Path $script:RootDir 'config.json' }

function Set-UserConfigValue {
    param([Parameter(Mandatory)][string]$Path, $Value)
    if ($script:TuiReadOnly) { return }    # read-only mode never writes anything
    $file = Get-UserConfigPath
    $obj = [ordered]@{}
    if (Test-Path $file) { try { $obj = ConvertTo-Hashtable (Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { $obj = [ordered]@{} } }
    if ($null -eq $obj) { $obj = [ordered]@{} }
    $parts = $Path.Split('.')
    $node = $obj
    for ($i = 0; $i -lt $parts.Count - 1; $i++) {
        if (-not $node.Contains($parts[$i]) -or -not ($node[$parts[$i]] -is [System.Collections.IDictionary])) { $node[$parts[$i]] = [ordered]@{} }
        $node = $node[$parts[$i]]
    }
    $node[$parts[-1]] = $Value
    [System.IO.File]::WriteAllText($file, ($obj | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
}

# ----------------------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------------------

function Update-Dashboard {
    # $Tick: optional result of Invoke-MonitorTick (avoids scanning twice).
    param($Config, $Tick, [switch]$PublicIp)
    $s = Read-Session
    $env = if ($Tick -and $Tick.Env) { $Tick.Env } else { Get-ChainEnvironment $Config $s }
    $u = $env.Upstream
    $d = $script:Dash
    $d.Scanned = $true
    $d.UpMode = $u.Mode
    $d.UpAdapter = if ($u.Adapter) { $u.Adapter.Alias } else { '' }
    $d.UpProcs = (@($u.Processes | ForEach-Object { ($_ -split '\(')[0] } | Where-Object { $_ -ne 'sing-box-daemon' } | Select-Object -Unique) -join '/')
    if ($s -and $s.context.upstreamExitIp) { $d.UpExit = $s.context.upstreamExitIp }
    $d.VpnName = $script:ChainVpn.Display
    $d.VpnUp = [bool]$env.Nord.Connected
    $d.VpnProto = if ($env.Nord.Connected) { $env.Nord.Protocol } else { '' }
    $d.VpnWhere = ''
    if ($script:ChainVpn.Key -eq 'windscribe') {
        $ws = Get-WindscribeStatus
        if ($ws -and $ws.Connect) { $d.VpnWhere = ($ws.Connect -replace '^(Connected|Connecting):\s*', '') }
    }
    $d.Session = [bool]($s -and $s.status -eq 'active')
    $d.Guard = [bool]($s -and $s.status -in @('active', 'guard'))
    $st = if ($Tick -and $Tick.State) { $Tick.State } else { Get-ChainState (Get-LocalFacts $env $s) }
    $d.State = $st.State; $d.Reasons = @($st.Reasons)
    $journal = if ($s) { @($s.journal | Where-Object { $_.status -eq 'applied' }) } else { @() }
    $g = @()
    $g += $(if (@($journal | Where-Object { $_.purpose -like 'killswitch-*' }).Count) { 'kill switch ON' } else { 'kill switch off' })
    $g += $(if (@($journal | Where-Object { $_.purpose -like 'dns-*' }).Count) { 'DNS locked to VPN' } else { 'DNS not guarded' })
    $g += $(if (@($journal | Where-Object { $_.purpose -like 'ipv6-*' -or $_.purpose -eq 'killswitch-v6' }).Count) { 'IPv6 blocked' } else { 'IPv6 not guarded' })
    $d.Guards = $g -join '  |  '
    $d.LastTick = Get-Date
    if ($PublicIp) {
        $ip = Get-PublicIp -Services $Config.ipCheckServices -FirstOnly -TimeoutMs 5000
        $d.PublicIp = if ($ip.Ip) { $ip.Ip } else { 'unreachable' }
        $d.PublicAt = Get-Date
        if (-not $d.Session -and -not $d.VpnUp -and $ip.Ip -and $u.Mode -eq 'tun') { $d.UpExit = $ip.Ip }
    }
}

function Get-DashboardLines {
    $d = $script:Dash
    $lines = @()
    if (-not $d.Scanned) { return @(, @(@('  Scanning network...', 'DarkGray'), @('', 'DarkGray'))) }   # 2 segments: avoids @() flattening
    $upOk = ($d.UpMode -eq 'tun')
    $upTxt = switch ($d.UpMode) { 'tun' { 'Connected' } 'proxy' { 'Proxy-only (enable TUN in v2rayN)' } default { 'Not running (start v2rayN with TUN on)' } }
    $upDetail = @($d.UpAdapter, $d.UpProcs, $(if ($d.UpExit) { "exit $($d.UpExit)" })) | Where-Object { $_ }
    $lines += , @(@('  UPSTREAM   ', 'DarkGray'), @($script:Dot, $(if ($upOk) { 'Green' } else { 'Red' })), @(" $upTxt", 'White'), @("   $($upDetail -join '  |  ')", 'Gray'))

    $vpnDetail = @($d.VpnProto, $d.VpnWhere) | Where-Object { $_ }
    $vpnTxt = if ($d.VpnUp) { "$($d.VpnName) connected" } else { "$($d.VpnName) disconnected" }
    $lines += , @(@('  VPN        ', 'DarkGray'), @($script:Dot, $(if ($d.VpnUp) { 'Green' } else { 'DarkGray' })), @(" $vpnTxt", 'White'), @("   $($vpnDetail -join '  |  ')", 'Gray'))

    if ($d.Session) {
        $chainColor = switch ($d.State) { 'CHAIN_OK' { 'Green' } 'UPSTREAM_ONLY' { 'Yellow' } 'UNKNOWN' { 'Yellow' } default { 'Red' } }
        $chainTxt = if ($d.State -eq 'CHAIN_OK') { 'HEALTHY' } else { $d.State }
        $lines += , @(@('  CHAIN      ', 'DarkGray'), @($script:Dot, $chainColor), @(" $chainTxt", $(if ($d.State -eq 'CHAIN_OK') { 'BoldGreen' } else { 'White' })), @("   apps -> $($d.VpnName) -> v2ray -> internet", 'Gray'))
    } else {
        $lines += , @(@('  CHAIN      ', 'DarkGray'), @($script:Dot, 'DarkGray'), @(' not connected', 'White'), @('   press 1 to connect a VPN through v2ray', 'DarkGray'))
    }

    if ($d.Guard -and $upOk) {
        $lines += , @(@('  LEAK GUARD ', 'DarkGray'), @($script:Dot, 'Green'), @(' ON', 'BoldGreen'), @("   only v2ray can reach the internet  |  auto-repair $($d.LastTick.ToString('HH:mm:ss'))", 'Gray'))
    } elseif ($d.Guard) {
        $lines += , @(@('  LEAK GUARD ', 'DarkGray'), @($script:Dot, 'Yellow'), @(' ON - BLOCKING', 'BoldYellow'), @('   v2ray is down: internet blocked so your real IP cannot leak', 'Yellow'))
    } else {
        $lines += , @(@('  LEAK GUARD ', 'DarkGray'), @($script:Dot, 'Red'), @(' OFF', 'BoldRed'), @('   if v2ray drops, your real IP is exposed  -  press G', 'Gray'))
    }

    $ipTxt = if ($d.PublicIp) { $d.PublicIp } else { '-' }
    $ipWhen = if ($d.PublicAt) { "   (checked $($d.PublicAt.ToString('HH:mm:ss')))" } else { '   (press R to check)' }
    $lines += , @(@('  PUBLIC IP  ', 'DarkGray'), @("  $ipTxt", 'BoldCyan'), @($ipWhen, 'DarkGray'))
    $why = @($d.Reasons | Select-Object -First 1)
    $lines += , @(@('             ', 'DarkGray'), @($(if ($d.Session -and $why.Count -and $d.State -ne 'CHAIN_OK') { "  $($why[0])" } else { '' }), 'Yellow'))
    return $lines
}

function Write-Dashboard {
    param([switch]$InPlace)
    $w = [Console]::WindowWidth
    $lines = Get-DashboardLines
    $row = $script:HeaderRows + 2
    foreach ($l in $lines) {
        if ($InPlace -and $script:Vt) { [Console]::Write("$script:E[$row;1H$script:E[2K") }
        # Trim the last segment so a line never wraps (wrapping would shift the layout).
        $used = 0; $segs = @()
        foreach ($s in $l) {
            $t = [string]$s[0]
            if ($used + $t.Length -ge $w - 1) { $t = $t.Substring(0, [Math]::Max(0, $w - 2 - $used)) }
            $used += $t.Length; $segs += , @($t, $s[1])
        }
        Write-Segments $segs
        $row++
    }
}

# ----------------------------------------------------------------------------
# Screens
# ----------------------------------------------------------------------------

function Write-MenuItem {
    param([string]$Key, [string]$Label, [string]$Hint = '', [switch]$Disabled)
    if ($Disabled) { Write-Segments @(@("   [$Key] ", 'DarkGray'), @($Label, 'DarkGray'), @("  $Hint", 'DarkGray')); return }
    Write-Segments @(@('   [', 'DarkGray'), @($Key, 'BoldRed'), @('] ', 'DarkGray'), @($Label, 'BoldWhite'), @("  $Hint", 'DarkGray'))
}

function Write-MainScreen {
    Clear-Content
    Write-Tui ''
    Write-Dashboard
    Write-Tui ("  " + ($script:HLine * [Math]::Max(10, [Console]::WindowWidth - 4))) 'DarkGray'
    $ro = $script:TuiReadOnly
    $active = $script:Dash.Session
    Write-MenuItem '1' $(if ($active) { 'Reconnect / change VPN' } else { 'Connect' }) $(if ($ro) { 'choose VPN  ->  protocol  ->  location  (connecting needs Administrator)' } else { 'choose VPN  ->  protocol  ->  location' })
    Write-MenuItem '2' 'Disconnect' 'VPN off (leak guard stays on), or everything off' -Disabled:($ro -or -not $active)
    Write-MenuItem 'G' $(if ($script:Dash.Guard) { 'Leak guard: ON' } else { 'Leak guard: OFF' }) $(if ($script:Dash.Guard) { 'press to turn off' } else { 'press to turn on - blocks your real IP if v2ray drops' }) -Disabled:$ro
    Write-MenuItem '3' 'Full test' 'public IP, DNS, IPv6, traffic proof'
    Write-MenuItem '4' 'Diagnose' 'adapters, routes, upstream, VPN details'
    Write-MenuItem '5' 'Settings' 'kill switch, DNS, IPv6, upstream servers'
    Write-MenuItem '6' 'Reset' 'recover after a crash / reboot' -Disabled:$ro
    Write-MenuItem '7' 'View log' ''
    Write-Segments @(@('   [', 'DarkGray'), @('R', 'BoldRed'), @('] Refresh   [', 'DarkGray'), @('Q', 'BoldRed'), @('] Quit', 'DarkGray'))
    Write-Tui ''
    Write-Tui '  Select an option: ' 'BoldWhite' -NoNewline
}

function Invoke-TuiAction {
    # Runs an engine operation with its normal (scrolling) output below the locked banner.
    param([string]$Title, [scriptblock]$Body, [switch]$NoPause)
    Clear-Content
    Set-CursorVisible $true
    Write-Tui ''
    Write-Tui "  $Title" 'BoldRed'
    Write-Tui ("  " + ($script:HLine * [Math]::Max(10, $Title.Length))) 'Red'
    $script:LogQuiet = $true        # reports only - log lines never reach the screen
    $script:Interactive = $true
    $result = $null
    try { $result = & $Body }
    catch { Write-Tui ''; Write-Tui "  Error: $($_.Exception.Message)" 'BoldRed'; Write-Log TUI "action '$Title' failed: $($_.Exception.Message)" -Level ERROR }
    if (-not $NoPause) { Wait-AnyKey }
    return $result
}

# ----------------------------------------------------------------------------
# Clean progress view for operations (connect, leak guard, disconnect, reset)
# ----------------------------------------------------------------------------

$script:Op = $null

function New-OpPhases {
    param([string]$Kind)
    $defs = switch ($Kind) {
        'connect'    { @(@('v2ray', 'Check v2ray tunnel'), @('guard', 'Leak guard'), @('vpn', "Connect $($script:ChainVpn.Display)"), @('routes', 'Route VPN through v2ray'), @('verify', 'Verify (IP, DNS, IPv6, traffic)')) }
        'guard-on'   { @(@('v2ray', 'Check v2ray tunnel'), @('guard', 'Turn on leak guard'), @('verify', 'Check internet through v2ray')) }
        'disconnect' { @(@('vpn', "Disconnect $($script:ChainVpn.Display)"), @('restore', 'Remove VPN routes'), @('verify', 'Check internet')) }
        default      { @(@('restore', 'Remove TunnelStack changes'), @('verify', 'Check internet')) }
    }
    @($defs | ForEach-Object { [pscustomobject]@{ Key = $_[0]; Label = $_[1]; State = 'wait'; Detail = '' } })
}

function Set-OpPhase {
    param([string]$Key, [string]$State, [string]$Detail)
    $p = @($script:Op.Phases | Where-Object Key -eq $Key) | Select-Object -First 1
    if (-not $p) { return }
    if ($p.State -eq 'fail' -and $State -ne 'fail') { return }
    # Starting a later phase completes the earlier running ones.
    if ($State -eq 'run') { foreach ($q in $script:Op.Phases) { if ($q -eq $p) { break }; if ($q.State -eq 'run') { $q.State = 'done' } } }
    $p.State = $State
    if ($Detail) { $p.Detail = $Detail }
}

function Get-OpCurrentKey {
    $r = @($script:Op.Phases | Where-Object State -eq 'run') | Select-Object -First 1
    if (-not $r) { $r = @($script:Op.Phases | Where-Object State -eq 'wait') | Select-Object -First 1 }
    if ($r) { $r.Key } else { $null }
}

function Update-OpFromLog {
    # Turns engine log events into progress-step updates (the log file keeps the full detail).
    param([string]$Tag, [string]$Msg, [string]$Level)
    if (-not $script:Op) { return }
    $vpnTag = Get-VpnTag
    switch -Regex ($Tag) {
        '^FIX$' { $script:Op.Fixes += $Msg; return }
    }
    if ($Tag -eq 'START' -and $Msg -match 'CHAIN_UNAVAILABLE \(([A-Z_]+)\): (.*)') { $script:Op.Error = $Matches[2]; $k = Get-OpCurrentKey; if ($k) { Set-OpPhase $k 'fail' '' } }
    elseif ($Tag -eq 'UPSTREAM') {
        if ($Msg -match 'adapter detected: (\S+)') { Set-OpPhase 'v2ray' 'run' "tunnel $($Matches[1])" }
        elseif ($Msg -match 'upstream working, exit IP (\S+)') { Set-OpPhase 'v2ray' 'done' "v2ray exit $($Matches[1])" }
        elseif ($Msg -match 'not present yet') { Set-OpPhase 'v2ray' 'run' 'waiting for the v2ray TUN adapter ...' }
    }
    elseif ($Tag -eq 'GUARD') {
        if ($Msg -match 'building the chain on top') { Set-OpPhase 'v2ray' 'done' ''; Set-OpPhase 'guard' 'done' 'already on' }
        elseif ($Msg -match 'leak guard ON.*exit (\S+)\)') { Set-OpPhase 'guard' 'done' 'only v2ray can reach the internet'; Set-OpPhase 'verify' 'done' "internet OK via v2ray ($($Matches[1]))" }
        elseif ($Msg -match 'leak guard ON') { Set-OpPhase 'guard' 'done' 'only v2ray can reach the internet'; Set-OpPhase 'restore' 'done' 'back to v2ray-only protection' }
    }
    elseif ($Tag -in @('FIREWALL', 'DNS', 'IPV6') -and $Msg -match 'guard active') { Set-OpPhase 'guard' 'run' 'blocking the physical network ...' }
    elseif ($Tag -eq 'ROUTE') {
        if ($Msg -match 'upstream server pinned|bootstrap DNS pinned') { Set-OpPhase 'guard' 'run' 'pinning the v2ray server ...' }
        elseif ($Msg -match 'endpoint pinned') { Set-OpPhase 'routes' 'run' 'VPN server pinned into v2ray' }
        elseif ($Msg -match 'default route forced') { Set-OpPhase 'routes' 'run' 'apps routed into the VPN' }
        elseif ($Msg -match 'interface metric') { Set-OpPhase 'routes' 'run' 'v2ray kept on the physical network' }
    }
    elseif ($Tag -eq 'VERIFY') {
        if ($Msg -match 'upstream still healthy with leak guard') { Set-OpPhase 'guard' 'done' 'on - v2ray still works' }
        elseif ($Msg -match 'verifying the chain') { Set-OpPhase 'verify' 'run' 'testing ...' }
        elseif ($Msg -match 'final public IP (\S+)') { $script:Op.Ip = $Matches[1] }
        elseif ($Msg -match '^state CHAIN_OK') { Set-OpPhase 'verify' 'done' 'chain healthy' }
        elseif ($Msg -match '^state (\S+)\s*(.*)') { $script:Op.Error = $(if ($Matches[2]) { $Matches[2] } else { $Matches[1] }); Set-OpPhase 'verify' 'fail' $Matches[1] }
        elseif ($Msg -match 'no TCP connectivity') { Set-OpPhase 'routes' 'run' 'no traffic through the VPN yet ...' }
        elseif ($Msg -match 'normal connectivity OK, public IP now (\S+)') { $script:Op.Ip = $Matches[1]; Set-OpPhase 'verify' 'done' "internet OK ($($Matches[1]))" }
        elseif ($Msg -match 'no Internet connectivity after restore') { Set-OpPhase 'verify' 'fail' 'no internet - check v2rayN' }
    }
    elseif ($Tag -eq 'ROLLBACK') {
        if ($Msg -match 'configuration restored') { Set-OpPhase 'restore' 'done' 'network restored' }
        elseif ($Msg -match 'removed|restored') { Set-OpPhase 'restore' 'run' 'removing changes ...' }
        if ($script:Op.Kind -eq 'disconnect') { Set-OpPhase 'vpn' 'done' '' }
    }
    elseif ($Tag -eq $vpnTag -or $Tag -eq 'VPN') {
        if ($Msg -match 'running documented CLI: .*disconnect') { Set-OpPhase 'vpn' 'run' 'disconnecting ...' }
        elseif ($Msg -match 'running documented CLI') { Set-OpPhase 'vpn' 'run' 'connecting ...' }
        elseif ($Msg -match 'not sending a connect') { Set-OpPhase 'vpn' 'run' 'already connecting - waiting ...' }
        elseif ($Msg -match 'adapter detected: .*protocol=(\S+)') { Set-OpPhase 'vpn' 'done' "connected ($($Matches[1]))" }
        elseif ($Msg -match 'CONFLICT: (.*)') { $script:Op.Warnings += $Matches[1] }
        elseif ($Msg -match 'using \S+ port (\d+)') { Set-OpPhase 'vpn' 'run' "connecting (port $($Matches[1]), v2ray-safe) ..." }
    }
    if ($Level -eq 'ERROR' -and -not $script:Op.Error -and $Tag -notin @('TUI')) {
        $script:Op.Error = $Msg; $k = Get-OpCurrentKey; if ($k) { Set-OpPhase $k 'fail' '' }
    }
    Write-OpPhases
}

function Write-OpPhases {
    param([switch]$Force)
    if (-not $script:Op) { return }
    if (-not $script:Vt -and -not $Force) { return }     # no in-place redraw without VT: print once at the end
    $w = [Console]::WindowWidth
    $row = $script:Op.Row
    foreach ($p in $script:Op.Phases) {
        if ($script:Vt) { [Console]::Write("$script:E[$row;1H$script:E[2K") }
        $tag = switch ($p.State) { 'done' { @(' OK ', 'BoldGreen') } 'run' { @(' .. ', 'BoldYellow') } 'fail' { @('FAIL', 'BoldRed') } 'skip' { @(' -- ', 'DarkGray') } default { @('    ', 'DarkGray') } }
        $label = $p.Label.PadRight(34)
        $detail = [string]$p.Detail
        $max = [Math]::Max(0, $w - 48)
        if ($detail.Length -gt $max) { $detail = $detail.Substring(0, $max) }
        Write-Segments @(@('   [', 'DarkGray'), $tag, @('] ', 'DarkGray'), @($label, $(if ($p.State -eq 'wait') { 'DarkGray' } else { 'White' })), @($detail, $(if ($p.State -eq 'fail') { 'Red' } else { 'Gray' })))
        $row++
    }
    if ($script:Vt) { [Console]::Write("$script:E[$row;1H") }
}

function Invoke-TuiOperation {
    # Runs an engine operation behind a clean step list; returns the engine's exit code.
    param([string]$Title, [string]$Kind, [scriptblock]$Body)
    Clear-Content
    Set-CursorVisible $false
    Write-Tui ''
    Write-Tui "  $Title" 'BoldRed'
    Write-Tui ("  " + ($script:HLine * [Math]::Max(10, $Title.Length))) 'Red'
    Write-Tui ''
    $script:Op = [pscustomobject]@{ Kind = $Kind; Phases = @(New-OpPhases $Kind); Row = $script:HeaderRows + 5; Error = ''; Fixes = @(); Warnings = @(); Ip = '' }
    if (-not $script:Vt) { $script:Op.Row = 0 }
    Write-OpPhases -Force
    if ($Kind -eq 'connect') { Write-Tui ''; Write-Tui '  Esc cancels (everything is rolled back; the leak guard stays on).' 'DarkGray' }
    $script:LogQuiet = $true; $script:ConsoleMute = $true; $script:Interactive = $true
    $script:LogHook = { param($t, $m, $l) Update-OpFromLog $t $m $l }
    $rc = 1
    try { $rc = @(& $Body)[-1] }
    catch { $script:Op.Error = $_.Exception.Message; $k = Get-OpCurrentKey; if ($k) { Set-OpPhase $k 'fail' '' }; Write-Log TUI "operation '$Title' failed: $($_.Exception.Message)" -Level ERROR }
    finally { $script:LogHook = $null; $script:ConsoleMute = $false }
    $ok = ($rc -eq 0 -and -not $script:Op.Error)
    foreach ($p in $script:Op.Phases) {
        if ($p.State -eq 'run') { $p.State = $(if ($ok) { 'done' } else { 'fail' }) }
        elseif ($p.State -eq 'wait') { $p.State = 'skip' }
    }
    Write-OpPhases -Force
    if (-not $script:Vt) { Write-Tui '' }
    return [pscustomobject]@{ Ok = $ok; Code = $rc; Error = $script:Op.Error; Fixes = @($script:Op.Fixes | Select-Object -Unique); Warnings = @($script:Op.Warnings | Select-Object -Unique); Ip = $script:Op.Ip }
}

function Write-ResultCard {
    param($Result, [string]$OkTitle, [string[]]$OkLines = @(), [string]$FailTitle)
    $row = $script:HeaderRows + 6 + @($script:Op.Phases).Count
    if ($script:Vt) { [Console]::Write("$script:E[$row;1H$script:E[0J") }
    Write-Tui ''
    if ($Result.Ok) {
        Write-Tui "  $OkTitle" 'BoldGreen'
        foreach ($l in $OkLines) { Write-Tui "  $l" 'White' }
    } else {
        Write-Tui "  $FailTitle" 'BoldRed'
        if ($Result.Error) { Write-Tui "  Why: $($Result.Error)" 'Yellow' }
        foreach ($f in $Result.Fixes) { Write-Tui "  Fix: $f" 'Cyan' }
        foreach ($wn in ($Result.Warnings | Select-Object -First 2)) { Write-Tui "  Note: $wn" 'DarkGray' }
    }
    $s = Read-Session
    if ($s -and $s.status -in @('guard', 'active')) { Write-Tui '  Leak guard is ON - your real IP cannot leak.' 'Green' }
    Write-Tui "  Details: View log (7)" 'DarkGray'
    Wait-AnyKey
}

function Select-FromList {
    # Numbered list; returns index (0-based) or -1 on Esc. Items: objects with Label/Note/Level.
    param([string]$Title, [object[]]$Items, [int]$Default = 0)
    Write-Tui ''
    Write-Tui "  $Title" 'BoldCyan'
    Write-Tui ''
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        $c = switch ($it.Level) { 'good' { 'Green' } 'ok' { 'Yellow' } 'bad' { 'Red' } 'off' { 'DarkGray' } default { 'White' } }
        $mark = if ($i -eq $Default) { ' (default)' } else { '' }
        Write-Segments @(@('   [', 'DarkGray'), @("$($i + 1)", 'BoldRed'), @('] ', 'DarkGray'), @($it.Label, 'BoldWhite'), @($mark, 'DarkGray'))
        if ($it.Note) { Write-Tui "       $($it.Note)" $c }
    }
    Write-Tui ''
    Write-Tui "  Choose 1-$($Items.Count), Enter = default, Esc = back: " 'BoldWhite' -NoNewline
    while ($true) {
        $k = Read-Key
        if ($k -eq 'ESC') { Write-Tui ''; return -1 }
        if ($k -eq 'ENTER') { Write-Tui "$($Default + 1)"; return $Default }
        if ($k -match '^\d$' -and [int]$k -ge 1 -and [int]$k -le $Items.Count) { Write-Tui $k; return ([int]$k - 1) }
    }
}

function Write-Check {
    param([string]$Status, [string]$Text)   # Status: ok | warn | fail
    $tag = switch ($Status) { 'ok' { @(' OK ', 'BoldGreen') } 'warn' { @('WARN', 'BoldYellow') } default { @('FAIL', 'BoldRed') } }
    Write-Segments @(@('   [', 'DarkGray'), $tag, @('] ', 'DarkGray'), @($Text, $(if ($Status -eq 'fail') { 'White' } else { 'Gray' })))
}

function Invoke-ConnectWizard {
    param($Config)
    $existing = Read-Session
    Clear-Content
    Set-CursorVisible $true
    Write-Tui ''
    Write-Tui '  CONNECT  -  run a VPN through your v2ray tunnel' 'BoldRed'

    # Step 1 - VPN
    $keys = @($script:Providers.Keys)
    $items = foreach ($k in $keys) {
        $p = $script:Providers[$k]
        $installed = Test-Path (Join-Path $p.Root $p.CliName)
        [pscustomobject]@{ Label = $p.Display; Note = $(if ($installed) { 'installed' } else { 'not installed - get it from the official website first' }); Level = $(if ($installed) { 'good' } else { 'off' }) }
    }
    $cfgProv = [string]$Config.vpn.provider
    $defIdx = [Math]::Max(0, [array]::IndexOf($keys, $(if ($cfgProv -and $cfgProv -ne 'ask') { $cfgProv } else { $script:ChainVpn.Key })))
    $i = Select-FromList 'Step 1/3  -  Which VPN do you want to connect?' $items $defIdx
    if ($i -lt 0) { return }
    $prov = $keys[$i]
    if ($items[$i].Level -eq 'off') {
        Write-Tui ''; Write-Tui "  $($script:Providers[$prov].Display) is not installed on this PC." 'BoldYellow'
        Wait-AnyKey; return
    }
    Set-VpnProvider $prov

    # Step 2 - protocol
    $choices = @(Get-VpnProtocolChoices $prov)
    $lastProto = if ($cfgProv -eq $prov) { [string]$Config.vpn.protocol } else { '' }
    $pIdx = 0
    for ($j = 0; $j -lt $choices.Count; $j++) { if ($choices[$j].Id -eq $lastProto) { $pIdx = $j } }
    Clear-Content
    Write-Tui ''
    Write-Tui "  CONNECT  -  $($script:ChainVpn.Display)" 'BoldRed'
    $j = Select-FromList 'Step 2/3  -  Which protocol do you want to connect with first?' $choices $pIdx
    if ($j -lt 0) { return }
    $proto = $choices[$j]
    if ($proto.Level -eq 'bad' -and -not (Read-YesNo "  $($proto.Label) usually fails through v2ray. Use it anyway?" $false)) { return }
    if ($prov -eq 'nordvpn' -and $proto.Id -ne 'app') {
        Write-Tui ''
        Write-Tui "  NordVPN's command line cannot switch protocols. Open the NordVPN app:" 'Yellow'
        Write-Tui "     Settings  >  Connection  >  VPN protocol  >  $($proto.Label)" 'BoldWhite'
        Write-Tui '  (vpn-chain checks the protocol after connecting.)' 'DarkGray'
        Write-Tui ''
        Write-Tui '  Press Enter when done, Esc to go back.' 'BoldWhite'
        while ($true) { $k = Read-Key; if ($k -eq 'ENTER') { break }; if ($k -eq 'ESC') { return } }
    }

    # Step 3 - location (scrollable, searchable list)
    Clear-Content
    Write-Tui ''
    Write-Tui '  Loading locations ...' 'DarkGray'
    $locItems = @(Get-VpnLocationChoices $prov)
    $lastLoc = if ($cfgProv -eq $prov -and $Config.vpn.Contains('location') -and $Config.vpn.location -and $Config.vpn.location -ne 'best') { [string]$Config.vpn.location } else { '' }
    $lIdx = 0
    if ($lastLoc) { for ($j = 0; $j -lt $locItems.Count; $j++) { if ($locItems[$j].Value -eq $lastLoc) { $lIdx = $j; break } } }
    $pick = Select-FromScrollList "CONNECT  -  $($script:ChainVpn.Display)  |  $($proto.Label)" 'Step 3/3  -  Choose a location' $locItems $lIdx
    if (-not $pick) { return }
    $loc = [string]$pick.Value
    if ($loc -eq '__static__') {
        Clear-Content
        Write-Tui ''
        Write-Tui "  CONNECT  -  $($script:ChainVpn.Display)  |  $($proto.Label)  |  static IP" 'BoldRed'
        Write-Tui ''
        Write-Tui '  Your Windscribe static IPs are listed at windscribe.com > My Account > Static IPs.' 'DarkGray'
        Write-Tui '  Type its city (e.g. Washington DC) or its IP address.' 'DarkGray'
        Write-Tui ''
        $v = Read-Text 'Static IP (city or IP)' ''
        if (-not $v) { return }
        $loc = "static:$v"
    }
    elseif ($loc -eq '__custom__') {
        Clear-Content
        Write-Tui ''
        Write-Tui "  CONNECT  -  $($script:ChainVpn.Display)  |  $($proto.Label)" 'BoldRed'
        Write-Tui ''
        Write-Tui "  $(Get-VpnLocationHint $prov)" 'DarkGray'
        Write-Tui ''
        $loc = Read-Text 'Location' $lastLoc
        if ($null -eq $loc) { return }
        if ($loc -eq 'best') { $loc = '' }
    }
    Set-CursorVisible $true

    Set-UserConfigValue 'vpn.provider' $prov
    Set-UserConfigValue 'vpn.protocol' $proto.Id
    Set-UserConfigValue 'vpn.location' $(if ($loc) { $loc } else { 'best' })
    $Config = Get-Config

    # Pre-flight
    Clear-Content
    Write-Tui ''
    Write-Tui "  CONNECT  -  $($script:ChainVpn.Display)  |  $($proto.Label)  |  $(if ($loc) { $loc } else { 'best location' })" 'BoldRed'
    Write-Tui ''
    Write-Tui '  Pre-flight checks' 'BoldCyan'
    $blocking = $false
    if ($script:TuiReadOnly) { $blocking = $true; Write-Check 'fail' 'Read-only mode: TunnelStack will not change anything. Start it normally (no -ReadOnly) to connect.' }
    elseif (Test-IsAdmin) { Write-Check 'ok' 'Running as Administrator' }
    else { $blocking = $true; Write-Check 'fail' 'Not running as Administrator - close TunnelStack and start it again, then accept the UAC prompt.' }
    $script:LogQuiet = $true      # detection warnings go to the log; the checks below explain them
    try { $env = Get-ChainEnvironment $Config $null } finally { $script:LogQuiet = $false }
    $u = $env.Upstream
    if ($u.Mode -eq 'tun') { Write-Check 'ok' "v2ray TUN up: $($u.Adapter.Alias)  ($((@($u.Processes) | ForEach-Object { ($_ -split '\(')[0] } | Where-Object { $_ -ne 'sing-box-daemon' } | Select-Object -Unique) -join ', '))" }
    else { $blocking = $true; Write-Check 'fail' 'No v2ray TUN tunnel found - start v2rayN / sing-box with TUN mode ON and check a website loads.' }
    if ($u.SystemProxy.Enabled -and $u.SystemProxy.Local) { $blocking = $true; Write-Check 'fail' 'System proxy is ON - in v2rayN choose "Clear system proxy" (TUN alone carries everything).' }
    else { Write-Check 'ok' 'System proxy off' }
    $inst = Get-VpnInstall $Config
    if ($inst.Installed -and $inst.ServiceState -eq 'Running') { Write-Check 'ok' "$($script:ChainVpn.Display) $($inst.Version) installed, service running" }
    else { $blocking = $true; Write-Check 'fail' "$($script:ChainVpn.Display) service is $($inst.ServiceState) - open the app once." }
    foreach ($c in @(Get-VpnConflicts -CorePaths (Get-CoreExecutablePaths))) {
        $hard = ($c.Issue -match 'firewall is ON|not logged in')
        if ($hard) { $blocking = $true }
        Write-Check $(if ($hard) { 'fail' } else { 'warn' }) $c.Issue
        Write-Tui "          fix: $($c.Fix)" 'Cyan'
    }
    if ($existing -and $existing.status -eq 'active') { Write-Check 'warn' 'A chain is already active - it will be stopped first.' }
    Write-Tui ''
    if ($blocking) { Write-Tui '  Fix the FAIL items above, then try again.' 'BoldYellow'; Wait-AnyKey; return }
    if (-not (Read-YesNo 'Connect now?' $true)) { return }

    $wsProto = if ($prov -eq 'windscribe') { $proto.Id } else { $null }
    $where = if ($loc -like 'static:*') { "static IP $($loc.Substring(7))" } elseif ($loc) { $loc } else { 'best location' }
    $res = Invoke-TuiOperation "CONNECTING  $($script:ChainVpn.Display)  |  $($proto.Label)  |  $where" 'connect' {
        if ($existing -and $existing.status -eq 'active') {
            # switching VPN/location: drop the old chain but keep the leak guard underneath
            [void](Invoke-Stop $Config @{ DisconnectNord = $true; KeepGuard = $true })
        } elseif ($existing -and $existing.status -in @('starting', 'waiting-nordvpn', 'stopping', 'corrupt')) {
            [void](Invoke-Stop $Config @{ DisconnectNord = $false } -Reset)
        }
        $opt = @{ NoMonitor = $true; Connect = $true; Location = $loc; Protocol = $wsProto; NordServer = $null; KeepOnFailure = $false; DisconnectNord = $false }
        @(Invoke-Start $Config $opt)[-1]
    }
    $script:LogQuiet = $true
    Update-Dashboard $Config -PublicIp
    $exit = if ($script:Dash.UpExit) { $script:Dash.UpExit } else { 'v2ray' }
    Write-ResultCard $res 'CONNECTED' @(
        "Your IP:   $($script:Dash.PublicIp)   ($($script:ChainVpn.Display) $(if ($script:Dash.VpnWhere) { '- ' + $script:Dash.VpnWhere }))",
        "Path:      apps  ->  $($script:ChainVpn.Display)  ->  v2ray ($exit)  ->  internet",
        'DNS only via the VPN, IPv6 blocked, auto-repair on while TunnelStack is open.'
    ) 'NOT CONNECTED'
}

function Invoke-DisconnectScreen {
    param($Config)
    Clear-Content
    Write-Tui ''
    Write-Tui '  DISCONNECT' 'BoldRed'
    Write-Tui ''
    Write-MenuItem '1' "Disconnect $($script:ChainVpn.Display), keep the leak guard" 'recommended - internet only through v2ray, your IP stays hidden'
    Write-MenuItem '2' 'Turn everything off' 'VPN off, leak guard off, normal network restored'
    Write-Segments @(@('   [', 'DarkGray'), @('Esc', 'BoldRed'), @('] Back', 'DarkGray'))
    Write-Tui ''
    Write-Tui '  Select: ' 'BoldWhite' -NoNewline
    $k = $null
    while ($k -notin @('1', '2', 'ENTER', 'ESC')) { $k = Read-Key }
    if ($k -eq 'ESC') { return }
    $keep = ($k -ne '2')
    if ($keep) {
        $res = Invoke-TuiOperation "DISCONNECTING  $($script:ChainVpn.Display)  (leak guard stays on)" 'disconnect' { Invoke-Stop $Config @{ DisconnectNord = $true; KeepGuard = $true } }
    } else {
        $res = Invoke-TuiOperation 'TURNING EVERYTHING OFF' 'disconnect' { Invoke-Stop $Config @{ DisconnectNord = $true } }
        $script:GuardUserOff = $true
    }
    Update-Dashboard $Config -PublicIp
    Write-ResultCard $res $(if ($keep) { 'VPN DISCONNECTED - LEAK GUARD ON' } else { 'EVERYTHING OFF' }) @(
        "Your IP:   $($script:Dash.PublicIp)",
        $(if ($keep) { 'Internet only through v2ray. If v2ray drops, traffic is blocked instead of leaking.' } else { 'Normal networking restored. Press G to turn the leak guard back on.' })
    ) 'DISCONNECT INCOMPLETE'
}

function Invoke-GuardScreen {
    param($Config)
    $s = Read-Session
    if ($s -and $s.status -eq 'active') {
        Clear-Content; Write-Tui ''; Write-Tui '  LEAK GUARD' 'BoldRed'; Write-Tui ''
        Write-Tui "  The leak guard is part of the active $($script:ChainVpn.Display) connection." 'White'
        Write-Tui '  Use 2 (Disconnect) to turn the VPN or everything off.' 'DarkGray'
        Wait-AnyKey; return
    }
    if ($s -and $s.status -eq 'guard') {
        Clear-Content; Write-Tui ''; Write-Tui '  LEAK GUARD' 'BoldRed'; Write-Tui ''
        Write-Tui '  Turning the leak guard OFF means: if v2ray drops, apps use your real connection' 'Yellow'
        Write-Tui '  and your real IP becomes visible.' 'Yellow'
        Write-Tui ''
        if (-not (Read-YesNo 'Turn the leak guard OFF?' $false)) { return }
        $res = Invoke-TuiOperation 'TURNING THE LEAK GUARD OFF' 'reset' { Invoke-Stop $Config @{ DisconnectNord = $false } }
        $script:GuardUserOff = $true
        Update-Dashboard $Config -PublicIp
        Write-ResultCard $res 'LEAK GUARD OFF' @("Your IP:   $($script:Dash.PublicIp)", 'Normal networking. Press G to turn it back on.') 'COULD NOT TURN THE LEAK GUARD OFF'
        return
    }
    $res = Invoke-TuiOperation 'TURNING THE LEAK GUARD ON' 'guard-on' { Invoke-GuardOn $Config }
    $script:GuardAutoFailed = $false; if ($res.Ok) { $script:GuardUserOff = $false }
    Update-Dashboard $Config -PublicIp
    Write-ResultCard $res 'LEAK GUARD ON' @(
        "Your IP:   $($script:Dash.PublicIp)   (v2ray exit)",
        'Only v2ray can reach the internet. If v2ray drops, traffic is blocked - your real IP never leaks.'
    ) 'LEAK GUARD NOT ENABLED'
}

function Invoke-SettingsScreen {
    param($Config)
    while ($true) {
        $Config = Get-Config
        Clear-Content
        Write-Tui ''
        Write-Tui '  SETTINGS   (saved to config.json, applied on the next connect)' 'BoldRed'
        Write-Tui ''
        $onoff = { param($v) if ($v) { 'ON' } else { 'OFF' } }
        Write-MenuItem '1' ("Kill switch            " + (& $onoff $Config.killSwitch)) 'block everything on the WAN except the v2ray server + LAN'
        Write-MenuItem '2' ("DNS leak protection    " + (& $onoff $Config.dnsLeakProtection)) 'only the VPN''s DNS can answer'
        Write-MenuItem '3' ("IPv6 policy            " + $Config.ipv6Policy) 'block-if-unsafe | block-all | allow'
        Write-MenuItem '4' ("Allow LAN              " + (& $onoff $Config.allowLan)) 'printers, NAS, router page'
        Write-MenuItem '5' ("Extra v2ray servers    " + $(if (@($Config.upstream.serverAddresses).Count) { @($Config.upstream.serverAddresses) -join ', ' } else { '(auto-detect)' })) 'IPs/CIDRs the kill switch must allow'
        Write-MenuItem '6' ("VPN connect timeout    " + $Config.nordvpn.connectTimeoutSec + ' s') ''
        Write-MenuItem '7' ("Leak guard on start    " + (& $onoff $Config.guard.autoStart)) 'turn the leak guard on automatically when TunnelStack opens'
        Write-Segments @(@('   [', 'DarkGray'), @('B', 'BoldRed'), @('] Back', 'DarkGray'))
        Write-Tui ''
        Write-Tui '  Select: ' 'BoldWhite' -NoNewline
        $k = Read-Key
        switch ($k) {
            '1' { Set-UserConfigValue 'killSwitch' (-not $Config.killSwitch) }
            '2' { Set-UserConfigValue 'dnsLeakProtection' (-not $Config.dnsLeakProtection) }
            '3' { $order = @('block-if-unsafe', 'block-all', 'allow'); $n = $order[([array]::IndexOf($order, [string]$Config.ipv6Policy) + 1) % 3]; Set-UserConfigValue 'ipv6Policy' $n }
            '4' { Set-UserConfigValue 'allowLan' (-not $Config.allowLan) }
            '5' { Write-Tui ''; $v = Read-Text 'Comma-separated IPs/CIDRs (empty = auto-detect, Esc = keep)' ''; if ($null -ne $v) { Set-UserConfigValue 'upstream.serverAddresses' @($v -split '[,\s]+' | Where-Object { $_ }) } }
            '6' { Write-Tui ''; $v = Read-Text 'Seconds' ([string]$Config.nordvpn.connectTimeoutSec); if ($v -match '^\d+$') { Set-UserConfigValue 'nordvpn.connectTimeoutSec' ([int]$v) } }
            '7' { Set-UserConfigValue 'guard.autoStart' (-not $Config.guard.autoStart) }
            { $_ -in @('B', 'ESC', 'Q') } { return }
        }
    }
}

function Show-LogScreen {
    Invoke-TuiAction 'LOG  (most recent lines)' {
        $f = Get-ChildItem $script:LogDir -Filter 'vpn-chain-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $f) { Write-Tui '  (no log yet)' 'DarkGray'; return }
        $n = [Math]::Max(10, [Console]::WindowHeight - $script:HeaderRows - 8)
        foreach ($l in @(Get-Content $f.FullName -Tail $n)) {
            $c = if ($l -match '\[ERROR\]') { 'Red' } elseif ($l -match '\[WARN\]') { 'Yellow' } elseif ($l -match '\[OK\]') { 'Green' } elseif ($l -match '\[DEBUG\]') { 'DarkGray' } else { 'Gray' }
            Write-Tui ('  ' + $l.Substring(0, [Math]::Min($l.Length, [Console]::WindowWidth - 3))) $c
        }
        Write-Tui ''
        Write-Tui "  Full log: $($f.FullName)" 'DarkGray'
    }
}

function Invoke-QuitScreen {
    param($Config)
    if (-not $script:Dash.Guard -or $script:TuiReadOnly) { return $true }   # nothing running / read-only
    Clear-Content
    Write-Tui ''
    Write-Tui '  QUIT' 'BoldRed'
    Write-Tui ''
    Write-Tui "  $(if ($script:Dash.Session) { "$($script:ChainVpn.Display) through v2ray and the leak guard are on." } else { 'The leak guard is on.' })" 'White'
    Write-Tui ''
    Write-MenuItem 'S' 'Turn everything off and quit' 'default - VPN off, leak guard off, normal network restored'
    Write-MenuItem 'K' 'Keep protection on and quit' 'stays fail-closed; auto-repair stops until TunnelStack is opened again'
    Write-MenuItem 'C' 'Cancel' ''
    Write-Tui ''
    Write-Tui '  Select: ' 'BoldWhite' -NoNewline
    while ($true) {
        switch (Read-Key) {
            { $_ -in @('S', 'ENTER') } {
                $res = Invoke-TuiOperation 'TURNING EVERYTHING OFF' 'disconnect' { Invoke-Stop $Config @{ DisconnectNord = [bool]$script:Dash.Session } }
                if (-not $res.Ok) { Write-ResultCard $res '' @() 'COULD NOT TURN EVERYTHING OFF - use Reset (6) next time' }
                return $true
            }
            'K' { return $true }
            { $_ -in @('C', 'ESC') } { return $false }
        }
    }
}

# ----------------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------------

function Start-TunnelStackTui {
    param([switch]$ReadOnly)
    $script:TuiReadOnly = [bool]$ReadOnly
    $script:Vt = Enable-VtMode
    try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
    try { $Host.UI.RawUI.WindowTitle = "TunnelStack $script:AppVersion$(if ($ReadOnly) { ' (read-only)' })" } catch { }
    try { [Console]::TreatControlCAsInput = $true } catch { }
    if ($script:Vt) { [Console]::Write("$script:E[2J$script:E[3J") }
    Write-Header

    $config = Get-Config
    $s = Read-Session
    $prov = Select-VpnProvider -Config $config -Session $s
    Set-VpnProvider $prov

    $script:LogQuiet = $true          # clean UI: log lines go to the log file only, never to the screen
    Set-CursorVisible $false
    Write-Tui ''
    Write-Tui '  Scanning network ...' 'DarkGray'
    Update-Dashboard $config -PublicIp

    # Leak guard on start: protection is on whenever TunnelStack is on.
    if (-not $script:TuiReadOnly -and $config.guard.autoStart -and -not $script:Dash.Guard -and $script:Dash.UpMode -eq 'tun') {
        $res = Invoke-TuiOperation 'TURNING THE LEAK GUARD ON' 'guard-on' { Invoke-GuardOn $config }
        Update-Dashboard $config -PublicIp
        if (-not $res.Ok) { Write-ResultCard $res '' @() 'LEAK GUARD NOT ENABLED' }
    }

    $netEvt = 'tunnelstack.net'
    Register-ObjectEvent -InputObject ([System.Net.NetworkInformation.NetworkChange]) -EventName NetworkAddressChanged -SourceIdentifier $netEvt | Out-Null
    $interval = [Math]::Max(5, [int]$config.monitor.safetyIntervalSec)
    $lastIpCheck = Get-Date
    try {
        while ($true) {
            Write-MainScreen
            Set-CursorVisible $false
            $fits = ([Console]::WindowHeight -ge $script:HeaderRows + 24)
            $k = 'IDLE'
            while ($k -in @('IDLE')) {
                $k = Read-Key -IdleSec $interval
                if ($k -ne 'IDLE') { break }
                # Background auto-repair (or just a status refresh when no chain is active).
                $evt = Get-Event -SourceIdentifier $netEvt -ErrorAction SilentlyContinue
                if ($evt) { $evt | Remove-Event }
                $script:LogQuiet = $true; $script:ConsoleMute = $true
                try {
                    $tick = $null
                    if ($script:Dash.Guard -and -not $script:TuiReadOnly) { $tick = Invoke-MonitorTick $config }
                    elseif (-not $script:TuiReadOnly -and $config.guard.autoStart -and -not $script:GuardUserOff -and $script:Dash.UpMode -eq 'tun') {
                        # v2ray came (back) up while the guard was off: switch it on quietly (once - no retry loop).
                        if (-not $script:GuardAutoFailed) { if (@(Invoke-GuardOn $config)[-1] -ne 0) { $script:GuardAutoFailed = $true } }
                    }
                    $wantIp = ((Get-Date) - $lastIpCheck).TotalSeconds -ge 120
                    Update-Dashboard $config -Tick $(if ($tick -and -not $tick.Exit) { $tick } else { $null }) -PublicIp:$wantIp
                    if ($wantIp) { $lastIpCheck = Get-Date }
                } catch { Write-Log TUI "background tick failed: $($_.Exception.Message)" -Level WARN }
                finally { $script:ConsoleMute = $false }
                if ($fits -and $script:Vt) {
                    Write-Dashboard -InPlace
                    [Console]::Write("$script:E[$([Console]::WindowHeight);1H")
                } else { break }
            }
            switch ($k) {
                '1' { Invoke-ConnectWizard $config; $config = Get-Config }   # read-only: pre-flight explains admin is needed
                '2' { if (-not $script:TuiReadOnly -and $script:Dash.Session) { Invoke-DisconnectScreen $config } }
                '3' { Invoke-TuiAction 'FULL TEST' { [void](Invoke-Test $config) }; Update-Dashboard $config -PublicIp; $lastIpCheck = Get-Date }
                '4' { Invoke-TuiAction 'DIAGNOSE' { [void](Invoke-Diagnose $config) } }
                '5' { Invoke-SettingsScreen $config; $config = Get-Config }
                'G' { if (-not $script:TuiReadOnly) { Invoke-GuardScreen $config } }
                '6' {
                    if (-not $script:TuiReadOnly) {
                        $res = Invoke-TuiOperation 'RESET  (remove every TunnelStack change)' 'reset' { Invoke-Stop $config @{ DisconnectNord = $false } -Reset }
                        $script:GuardUserOff = $true
                        Update-Dashboard $config -PublicIp
                        Write-ResultCard $res 'RESET DONE' @("Your IP:   $($script:Dash.PublicIp)", 'All TunnelStack changes removed. Press G to turn the leak guard on again.') 'RESET INCOMPLETE'
                    }
                }
                '7' { Show-LogScreen }
                'R' { Clear-Content; Write-Tui ''; Write-Tui '  Refreshing ...' 'DarkGray'; Update-Dashboard $config -PublicIp; $lastIpCheck = Get-Date }
                'RESIZE' { if ($script:Vt) { [Console]::Write("$script:E[2J") }; Write-Header }
                { $_ -in @('Q', 'ESC') } { if (Invoke-QuitScreen $config) { return } }
            }
        }
    } finally {
        Unregister-Event -SourceIdentifier $netEvt -ErrorAction SilentlyContinue
        try { [Console]::TreatControlCAsInput = $false } catch { }
        if ($script:Vt) { [Console]::Write("$script:E[r$script:E[?25h$script:E[0m$script:E[$([Console]::WindowHeight);1H") }
        Write-Tui ''
        Write-Tui '  Bye. Run tunnelstack.cmd again any time.' 'DarkGray'
    }
}
