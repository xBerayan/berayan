```
 ____    _____   ____       _     __   __     _      _   _
| __ )  | ____| |  _ \     / \    \ \ / /    / \    | \ | |
|  _ \  |  _|   | |_) |   / _ \    \ V /    / _ \   |  \| |
| |_) | | |___  |  _ <   / ___ \    | |    / ___ \  | |\  |
|____/  |_____| |_| \_\ /_/   \_\   |_|   /_/   \_\ |_| \_|
```

# Berayan

![Windows 10 | 11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)
![PowerShell 5.1](https://img.shields.io/badge/PowerShell-5.1-5391FE)
![VPN: NordVPN | Windscribe](https://img.shields.io/badge/VPN-NordVPN%20%7C%20Windscribe-2EA44F)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow)

**Berayan runs NordVPN or Windscribe *through* your v2rayN / sing-box tunnel on Windows.** It works as a terminal app with a menu, leak protection, real-traffic proof and auto-repair.

```
 Your apps ──► VPN (NordVPN / Windscribe) ──► v2ray TUN (v2rayN / sing-box) ──► v2ray server ──► VPN server ──► Internet
```

- **Websites see the VPN's IP and DNS location**, not your v2ray exit.
- **The VPN server sees your v2ray exit**, never your real IP.
- If anything breaks, **traffic is blocked instead of leaking**, and disconnecting restores your network exactly as it was.

**Contents:** [Requirements](#requirements) · [Quick start](#quick-start) · [The terminal app](#the-terminal-app) · [Leak guard](#leak-guard-your-real-ip-never-leaks) · [Recommended settings](#recommended-settings-important) · [How it works](#how-it-works) · [Command line](#command-line-automation) · [Troubleshooting](#troubleshooting) · [Project layout](#project-layout)

---

## Requirements

| | |
|---|---|
| OS | **Windows 10 or 11** (x64). Uses the built-in Windows PowerShell 5.1, so there's nothing to install. |
| Upstream | **v2rayN** or **sing-box** (also Hiddify / NekoBox / Clash Verge) with **TUN mode ON** |
| VPN | the official **Windscribe** app (logged in) or **NordVPN** app |
| Rights | Administrator. Berayan asks for it through UAC, and you can start in read-only mode without it. |

> Berayan drives the Windows network stack (routes, Windows Firewall, NRPT), so it is **Windows-only**. macOS and Linux are not supported.

## Quick start

```powershell
git clone https://github.com/xBerayan/berayan.git
cd berayan
.\berayan.cmd
```

No git? Download the ZIP from GitHub, extract it, and double-click **`berayan.cmd`**.

1. Start **v2rayN** with **TUN mode ON**, and set **System proxy → Clear system proxy**.
2. Run `berayan.cmd` and accept the UAC prompt.
3. Press **1 → Connect**, then:
   - **Step 1:** choose the VPN, **NordVPN** or **Windscribe**.
   - **Step 2:** choose the protocol (**IKEv2**, **Stealth**, **TCP**, ...).
   - **Step 3:** pick the location from a scrollable list (arrow keys, PgUp/PgDn, type to search, Enter = select). Recent locations are listed first.
4. Berayan runs pre-flight checks, connects, proves the chain with real traffic, and keeps it healthy while the window stays open.

## The terminal app

```
                 BERAYAN banner (bold red, always locked at the top)
  ───────────────────────────────────────────────────────────────────
  UPSTREAM   ■ Connected   singbox_tun  |  v2rayN/xray  |  exit 203.0.113.7
  VPN        ■ Windscribe connected   IKEv2  |  Frankfurt
  CHAIN      ■ HEALTHY   apps -> Windscribe -> v2ray -> internet
  LEAK GUARD ■ ON   only v2ray can reach the internet  |  auto-repair 11:46:55
  PUBLIC IP    198.51.100.50   (checked 11:47:20)

  ───────────────────────────────────────────────────────────────────
   [1] Connect          choose VPN  ->  protocol  ->  location
   [2] Disconnect       VPN off (leak guard stays on), or everything off
   [G] Leak guard: ON   press to turn off
   [3] Full test        public IP, DNS, IPv6, traffic proof
   [4] Diagnose         adapters, routes, upstream, VPN details
   [5] Settings         kill switch, DNS, IPv6, upstream servers
   [6] Reset            recover after a crash / reboot
   [7] View log
   [R] Refresh   [Q] Quit
```

- **The menu stays on screen.** Operations show a short step list (`[ OK ]` / `[ .. ]` / `[FAIL]`) and a result card. No log lines appear on screen; the full log is under **7 View log**.
- **Auto-repair** runs in the background while the menu is open. It re-pins routes after VPN or v2ray reconnects, server switches, Wi-Fi ↔ Ethernet changes and sleep/resume.
- **Esc** cancels a connect in progress. Everything is rolled back, and the leak guard stays on.
- **Locations** are picked from a scrollable, searchable list. For Windscribe this includes your **static IPs** (e.g. "Washington DC (static IP)") and recently used cities.
- **`berayan.cmd -ReadOnly`** runs without admin and changes nothing: status, test, diagnose and log only.

## Leak guard (your real IP never leaks)

The leak guard turns **on when Berayan opens** and **off when you quit** (you can choose to keep it on). Toggle it any time with **G**.

| Situation | What happens |
|---|---|
| v2ray up, no VPN | everything goes through v2ray; the physical network may only reach your v2ray server (and LAN) |
| VPN connected through v2ray | the same, plus DNS only via the VPN and the VPN server pinned into v2ray |
| v2ray drops or restarts | traffic is **blocked**, not sent over your real connection. It resumes when v2ray is back |
| VPN drops or reconnects | traffic falls back to v2ray, never to your real IP |
| you switch servers in v2rayN | Berayan reads v2rayN's active profile and allows the new server automatically |
| Berayan or Windows crashes | the firewall rules stay (fail-closed). Open Berayan → **6 Reset**, or just turn the guard off with **G** |

It is built from Windows Firewall rules in the group `vpn-chain` plus a few routes, all journaled and removed exactly when you turn it off.

## Recommended settings (important)

A VPN app's own protections can cut v2ray off, and then the VPN loses the very path it runs through. Berayan detects these problems and tells you the fix:

| VPN | Setting | Why |
|---|---|---|
| Windscribe | Preferences → Connection → **Terminate Sockets: OFF** | Otherwise every connect closes all TCP connections, including v2ray's, and Windscribe reconnects in a loop |
| Windscribe | Protocol **IKEv2** (verified), **Stealth** or **TCP** | Windscribe's **WireGuard** client blocks all non-tunnel traffic, which also blocks v2ray |
| Windscribe | Firewall **off** / Manual | Berayan's own kill switch replaces it |
| NordVPN | Settings → **Split tunneling** → bypass `xray.exe` and `sing-box.exe` | NordVPN's always-on *LeakBlock* otherwise blocks v2ray |
| NordVPN | Protocol: **OpenVPN TCP** (set in the NordVPN app) | NordVPN's command line cannot switch protocols |
| v2rayN | **TUN ON**, **System proxy: Clear**, **Strict Route OFF** | A system proxy lets browsers skip the VPN, and Strict Route blocks the VPN's DNS |

Verified end to end on Windows 10 22H2 with v2rayN (xray VLESS-Reality) and Windscribe IKEv2. All 8 checks passed: the final IP was the VPN exit, a 4 MB traffic test was seen on both tunnels, and nothing leaked over DNS or IPv6.

## How it works

| Change | Why |
|---|---|
| `/32` route: **VPN server → v2ray TUN** | the VPN's encrypted transport must go through v2ray |
| `/32` route: **v2ray server → physical gateway** | v2ray never loops into the VPN |
| `0.0.0.0/1 + 128.0.0.0/1` → **VPN adapter** | beats v2ray's metric-0 default route, so apps really use the VPN |
| VPN adapter metric raised | sing-box keeps the physical NIC as its own interface |
| NRPT rule for the v2ray server's hostname | v2ray can always resolve its own server, without needing the VPN |
| Windows Firewall rules (group `vpn-chain`) | kill switch, DNS leak guard, IPv6 guard |
| Ports v2rayN rejects (e.g. UDP 443) avoided | the VPN transport isn't silently dropped |

Every change is written to a journal *before* it's made and removed on Disconnect. **Reset** cleans up after a crash, and routes disappear on reboot by themselves. Berayan never touches routes or rules it didn't create.

Details: [docs/architecture.md](docs/architecture.md).

## Privacy & safety

- No telemetry, no accounts, no network services, nothing installed, nothing runs at startup.
- It never reads VPN passwords, tokens or keys. It only uses each VPN's documented CLI and read-only log lines.
- The IP checks use several independent public services, so a single one being down doesn't break them.
- Logs stay in `logs\` next to the tool and contain no credentials.

## Command line (automation)

The same engine is available without the menu:

```powershell
.\vpn-chain.cmd start -Vpn windscribe -Connect -Protocol ikev2 -Location DE
.\vpn-chain.cmd status
.\vpn-chain.cmd test
.\vpn-chain.cmd stop -DisconnectNord
.\vpn-chain.cmd reset
```

Settings live in `config.json` (copy `config.example.json`). The app writes your choices there.

## Troubleshooting

| Message | Fix |
|---|---|
| `No v2ray TUN tunnel found` | start v2rayN / sing-box with TUN mode ON |
| `SYSTEM_PROXY_BYPASS` | v2rayN → System proxy → Clear system proxy |
| `VPN_CONFLICT` / "Terminate sockets" | apply the fix shown (see *Recommended settings*) |
| VPN connects then drops in a loop | Windscribe Terminate Sockets ON, NordVPN LeakBlock without split tunneling, or WireGuard |
| `UPSTREAM_BLOCKED_BY_GUARD` | Settings → Extra v2ray servers: add the server IPs your v2ray profile uses |
| `ROUTING_LOOP` | in sing-box set `route.default_interface` to your NIC, or turn off `auto_detect_interface` |
| No internet after a crash | open Berayan → **6 Reset** |

## Project layout

```
berayan/
├── berayan.cmd             ◄ start here (double-click)
├── vpn-chain.cmd           command-line version, for scripts
├── config.example.json     example settings
│
├── src/                    source code
│   ├── berayan.ps1         the terminal app
│   ├── vpn-chain.ps1       the command-line app
│   └── modules/            the shared engine: UI, routing, firewall, VPN providers, checks
│
├── docs/
│   ├── architecture.md     how the chain and the leak guard work
│   └── testing.md          live test scenarios and results
│
└── tests/
    ├── unit.ps1            66 offline tests
    └── tui-smoke.ps1       drives the real app, read-only
```

Berayan creates `config.json` (your choices) and `logs\` next to `berayan.cmd` when it runs. Both stay on your PC: they are git-ignored and never uploaded.

## Tests

```powershell
powershell -ExecutionPolicy Bypass -File tests\unit.ps1         # 66 offline unit tests
powershell -ExecutionPolicy Bypass -File tests\tui-smoke.ps1    # drives the real terminal app (read-only)
```

More in [tests/](tests) and [docs/testing.md](docs/testing.md).

## Uninstall

Disconnect (or **Reset**), then delete the folder and `%ProgramData%\vpn-chain`.

## Disclaimer

Berayan only configures your own computer. Using VPNs and proxies may be restricted where you live, and providers have their own terms. You are responsible for how you use it.

## License

[MIT](LICENSE)
