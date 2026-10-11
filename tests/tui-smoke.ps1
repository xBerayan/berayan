# End-to-end smoke test of the interactive terminal app in a REAL console window.
# Launches berayan.ps1 -ReadOnly (no admin, no network changes), attaches to its console,
# reads the screen buffer (text + colours) and sends key presses.
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\tui-smoke.ps1
param([int]$StartupWaitSec = 20)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

if (-not ('TuiProbe.ConsoleProbe' -as [type])) {
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
namespace TuiProbe {
public static class ConsoleProbe {
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool FreeConsole();
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool AttachConsole(uint pid);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sec, uint d, uint f, IntPtr t);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] public struct COORD { public short X; public short Y; }
  [StructLayout(LayoutKind.Sequential)] public struct SMALL_RECT { public short Left, Top, Right, Bottom; }
  [StructLayout(LayoutKind.Sequential)] public struct CSBI { public COORD Size; public COORD Cursor; public short Attr; public SMALL_RECT Window; public COORD MaxSize; }
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetConsoleScreenBufferInfo(IntPtr h, out CSBI i);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool ReadConsoleOutputCharacter(IntPtr h, StringBuilder sb, uint len, COORD c, out uint read);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadConsoleOutputAttribute(IntPtr h, [Out] ushort[] a, uint len, COORD c, out uint read);
  [StructLayout(LayoutKind.Explicit, CharSet=CharSet.Unicode)] public struct KEY { [FieldOffset(0)] public int Down; [FieldOffset(4)] public short Repeat; [FieldOffset(6)] public short Vk; [FieldOffset(8)] public short Scan; [FieldOffset(10)] public char Ch; [FieldOffset(12)] public int Ctrl; }
  [StructLayout(LayoutKind.Explicit)] public struct INPUT { [FieldOffset(0)] public short Type; [FieldOffset(4)] public KEY Key; }
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool WriteConsoleInput(IntPtr h, INPUT[] b, uint n, out uint w);

  static IntPtr Open(uint pid, string name) {
    FreeConsole();
    if (!AttachConsole(pid)) throw new Exception("AttachConsole failed: " + Marshal.GetLastWin32Error());
    IntPtr h = CreateFile(name, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
    if (h == new IntPtr(-1)) throw new Exception("CreateFile " + name + " failed");
    return h;
  }
  // Visible window rows; attrs[i] = foreground attribute of the first non-space char on row i.
  public static string[] Snapshot(uint pid, out int[] attrs) {
    IntPtr h = Open(pid, "CONOUT$");
    try {
      CSBI i; GetConsoleScreenBufferInfo(h, out i);
      int w = i.Size.X, top = i.Window.Top, rows = i.Window.Bottom - i.Window.Top + 1;
      string[] lines = new string[rows]; attrs = new int[rows];
      for (int r = 0; r < rows; r++) {
        var sb = new StringBuilder(w); uint n; COORD c = new COORD { X = 0, Y = (short)(top + r) };
        ReadConsoleOutputCharacter(h, sb, (uint)w, c, out n);
        string s = sb.ToString(); lines[r] = s.TrimEnd();
        int x = 0; while (x < s.Length && s[x] == ' ') x++;
        if (x < s.Length) { ushort[] a = new ushort[1]; COORD c2 = new COORD { X = (short)x, Y = (short)(top + r) }; ReadConsoleOutputAttribute(h, a, 1, c2, out n); attrs[r] = a[0] & 0x0F; } else attrs[r] = -1;
      }
      return lines;
    } finally { CloseHandle(h); FreeConsole(); }
  }
  public static void SendKey(uint pid, char ch, short vk) {
    IntPtr h = Open(pid, "CONIN$");
    try {
      var recs = new INPUT[2];
      for (int k = 0; k < 2; k++) { recs[k].Type = 1; recs[k].Key = new KEY { Down = k == 0 ? 1 : 0, Repeat = 1, Vk = vk, Ch = ch }; }
      uint w; WriteConsoleInput(h, recs, 2, out w);
    } finally { CloseHandle(h); FreeConsole(); }
  }
}}
'@
}

$pass = 0; $fail = 0
function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { $script:pass++; Write-Output "  PASS  $Name" } else { $script:fail++; Write-Output "  FAIL  $Name  $Detail" }
}
function Snap { $a = $null; $l = [TuiProbe.ConsoleProbe]::Snapshot([uint32]$script:proc.Id, [ref]$a); $script:attrs = $a; return $l }
function Key([string]$k) {
    $map = @{ 'ENTER' = @([char]13, 0x0D); 'ESC' = @([char]27, 0x1B); 'DOWN' = @([char]0, 0x28); 'UP' = @([char]0, 0x26); 'PGDN' = @([char]0, 0x22); 'BACK' = @([char]8, 0x08) }
    if ($map.ContainsKey($k)) { [TuiProbe.ConsoleProbe]::SendKey([uint32]$script:proc.Id, $map[$k][0], [int16]$map[$k][1]) }
    else { $c = [char]$k; [TuiProbe.ConsoleProbe]::SendKey([uint32]$script:proc.Id, $c, [int16][int][char]([string]$c).ToUpperInvariant()) }
}
function Find([string[]]$Lines, [string]$Pattern) { for ($i = 0; $i -lt $Lines.Count; $i++) { if ($Lines[$i] -match $Pattern) { return $i } }; return -1 }

$script:proc = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f (Join-Path $root 'berayan.ps1')), '-ReadOnly') -PassThru
try {
    $deadline = (Get-Date).AddSeconds($StartupWaitSec + 40)
    do { Start-Sleep -Seconds 2; $s = Snap } until ((Find $s 'Select an option') -ge 0 -or (Get-Date) -gt $deadline)
    Write-Output '--- main screen ---'; $s | Select-Object -First 32 | ForEach-Object { "  |$_" }

    $b = Find $s '__   __'
    Check 'BERAYAN banner drawn at the top' ($b -ge 0 -and $b -le 2) "row $b"
    Check 'banner is red (bold/bright)' ($b -ge 0 -and ($script:attrs[$b] -band 4) -eq 4) "attr $($script:attrs[$b])"
    Check 'tagline + READ-ONLY marker' ((Find $s 'v2ray  ->  VPN chain.*READ-ONLY') -ge 0)
    Check 'dashboard: UPSTREAM / VPN / CHAIN / PUBLIC IP' (((Find $s '^\s+UPSTREAM') -ge 0) -and ((Find $s '^\s+VPN ') -ge 0) -and ((Find $s '^\s+CHAIN') -ge 0) -and ((Find $s 'PUBLIC IP') -ge 0))
    Check 'menu items present' (((Find $s '\[1\] (Connect|Reconnect)') -ge 0) -and ((Find $s '\[3\] Full test') -ge 0) -and ((Find $s '\[Q\] Quit') -ge 0))

    Key '4'                                   # Diagnose: long output must scroll UNDER the locked banner
    $deadline = (Get-Date).AddSeconds(60)
    do { Start-Sleep -Seconds 2; $s = Snap } until ((Find $s 'Press any key') -ge 0 -or (Get-Date) -gt $deadline)
    Write-Output '--- after Diagnose (scrolled) ---'; $s | Select-Object -First 12 | ForEach-Object { "  |$_" }
    $b2 = Find $s '__   __'
    Check 'banner still locked at the top after long output' ($b2 -eq $b) "row $b2"
    Check 'diagnose output rendered below the banner' (((Find $s 'Press any key') -gt $b2))

    Key 'ENTER'; Start-Sleep -Seconds 2
    Key '5'; Start-Sleep -Seconds 2; $s = Snap
    Check 'settings screen' ((Find $s 'SETTINGS') -ge 0 -and (Find $s 'Kill switch') -ge 0)
    Key 'B'; Start-Sleep -Seconds 2; $s = Snap
    Check 'back to main menu' ((Find $s 'Select an option') -ge 0)
    # Connect wizard: VPN -> protocol -> location -> pre-flight (read-only must stop at pre-flight)
    Key '1'; Start-Sleep -Seconds 2; $s = Snap
    Check 'wizard step 1 lists NordVPN and Windscribe' (((Find $s 'Step 1/3') -ge 0) -and ((Find $s '\] NordVPN') -ge 0) -and ((Find $s '\] Windscribe') -ge 0))
    Key '2'; Start-Sleep -Seconds 2; $s = Snap
    Write-Output '--- wizard step 2 ---'; $s | Select-Object -Skip 8 -First 20 | ForEach-Object { "  |$_" }
    Check 'wizard step 2 offers Windscribe protocols (IKEv2, Stealth, TCP ...)' (((Find $s 'Step 2/3') -ge 0) -and ((Find $s '\] IKEv2') -ge 0) -and ((Find $s 'Stealth') -ge 0) -and ((Find $s 'OpenVPN TCP') -ge 0))
    Key 'ENTER'
    $deadline = (Get-Date).AddSeconds(30)
    do { Start-Sleep -Seconds 1; $s = Snap } until ((Find $s 'Step 3/3') -ge 0 -or (Get-Date) -gt $deadline)
    Write-Output '--- location picker ---'; $s | Select-Object -Skip 8 -First 16 | ForEach-Object { "  |$_" }
    Check 'location picker: scrollable list with search + key help' (((Find $s 'Step 3/3') -ge 0) -and ((Find $s 'Search:') -ge 0) -and ((Find $s 'Best location') -ge 0) -and ((Find $s 'PgUp/PgDn') -ge 0))
    Key 'PGDN'; Start-Sleep -Milliseconds 800; $s = Snap
    Check 'location picker scrolls (PgDn)' ((Find $s 'rows \d+-\d+ of') -ge 0 -and (Find $s 'rows 1-') -lt 0)
    foreach ($c in 'g', 'e', 'r', 'm') { Key $c }
    Start-Sleep -Seconds 1; $s = Snap
    Check 'type-to-search filters to Germany' (((Find $s 'Search: germ') -ge 0) -and ((Find $s '>\s+Germany') -ge 0))
    Key 'ENTER'      # select Germany -> pre-flight
    $deadline = (Get-Date).AddSeconds(40)
    do { Start-Sleep -Seconds 2; $s = Snap } until ((Find $s 'Pre-flight') -ge 0 -and (Find $s 'Press any key|Connect now') -ge 0 -or (Get-Date) -gt $deadline)
    Write-Output '--- pre-flight ---'; $s | Select-Object -Skip 8 -First 16 | ForEach-Object { "  |$_" }
    $asked = (Find $s 'Connect now') -ge 0
    if ($asked) { Key 'N' }   # safety net: never confirm a connect from the smoke test
    Check 'pre-flight blocks in read-only mode (never offers to connect)' (((Find $s 'FAIL.*(Read-only|Administrator)') -ge 0) -and -not $asked)
    Check 'chosen location (Germany = DE) carried into pre-flight' ((Find $s 'CONNECT .*\|\s+DE') -ge 0)
    Key 'ENTER'; Start-Sleep -Seconds 2

    # Regression: typing a custom location + Enter used to freeze ([Console]::ReadLine with Ctrl+C-as-input).
    Key '1'; Start-Sleep -Seconds 2; Key '2'; Start-Sleep -Seconds 2; Key 'ENTER'
    $deadline = (Get-Date).AddSeconds(30)
    do { Start-Sleep -Seconds 1; $s = Snap } until ((Find $s 'Step 3/3') -ge 0 -or (Get-Date) -gt $deadline)
    foreach ($c in 't', 'y', 'p', 'e') { Key $c }; Start-Sleep -Milliseconds 800
    Key 'ENTER'; Start-Sleep -Seconds 1
    Key 'F'; Key 'r'; Key 'a'; Key 'n'; Key 'k'; Key 'x'; Key 'BACK'; Start-Sleep -Milliseconds 500; Key 'ENTER'
    $deadline = (Get-Date).AddSeconds(40)
    do { Start-Sleep -Seconds 2; $s = Snap } until (((Find $s 'Pre-flight') -ge 0 -and (Find $s 'Press any key|Connect now') -ge 0) -or (Get-Date) -gt $deadline)
    $okCustom = ((Find $s 'Pre-flight') -ge 0) -and ((Find $s 'CONNECT .*\|\s+Frank\b') -ge 0) -and ((Find $s 'Frankx') -lt 0)
    if (-not $okCustom) { Write-Output '--- custom-location screen ---'; $s | Select-Object -Skip 8 -First 14 | ForEach-Object { "  |$_" } }
    Check 'typed custom location + Enter does not freeze (Backspace works)' $okCustom
    if ((Find $s 'Connect now') -ge 0) { Key 'N' }
    Key 'ENTER'; Start-Sleep -Seconds 2
    Key 'Q'
    $null = $script:proc.WaitForExit(10000)
    Check 'Q quits cleanly' ($script:proc.HasExited)
} finally {
    if (-not $script:proc.HasExited) { Stop-Process -Id $script:proc.Id -Force -ErrorAction SilentlyContinue }
}
Write-Output ''
Write-Output "TUI smoke: passed $pass, failed $fail"
exit $fail
