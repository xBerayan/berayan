# Berayan – architecture

## Goal

```
App packet
 → VPN adapter (NordLynx / WireGuard / OpenVPN / IKEv2)       [0/1 + 128/1 routes, VPN wins over the v2ray TUN]
 → VPN encapsulation
 → /32 route for the VPN server → v2ray TUN (Wintun)           [Berayan pin]
 → v2rayN / sing-box → xray (VLESS / VMess / Trojan / ...)
 → physical NIC                                               [/32 pin for the v2ray server + kill switch exemption]
 → v2ray server → VPN server → destination
```

The final public IP and DNS location are the VPN's, and the VPN server only ever sees the v2ray exit.

## Chosen design: native routing orchestration

It's written in Windows PowerShell 5.1 using only built-in cmdlets (`New-NetRoute`, `New-NetFirewallRule`, `Add-DnsClientNrptRule`, `Set-NetIPInterface`, …). There are no drivers, no packet copying and no services. The alternatives were rejected:

- **A WFP/WinDivert helper** isn't needed, because routes can steer the VPN's transport.
- **A VM/router** would work, but it's heavy and changes how the tool is used.

### The facts the design relies on (verified live)

1. **Windows uses the longest prefix first, then the lowest route+interface metric.** A `/32` beats `/1`, and `/1` beats `/0`, regardless of metric.
2. **The VPN's transport follows the routing table.** wireguard-nt resolves the endpoint while skipping its own adapter, and OpenVPN and IKEv2 use normal routes. So a `/32` for the VPN server on the v2ray TUN pulls the transport into v2ray.
3. **v2rayN's TUN has interface metric 0.** It beats the VPN's own `0.0.0.0/0` (metric 1–5), so without help the VPN "connects" but no app traffic (not even its DNS) uses it, and the VPN app gives up. **Fix:** `0.0.0.0/1 + 128.0.0.0/1` on the VPN adapter.
4. **sing-box (`auto_detect_interface`) follows the best `0.0.0.0/0`.** A VPN installing a low-metric `/0` can make sing-box re-bind and reset its connections. **Fix:** raise the VPN adapter's interface metric (journaled, restored).
5. **v2rayN resolves its server hostname through Windows every ~TTL.** Once the VPN owns system DNS, that would need the VPN, which needs v2ray: a deadlock. **Fix:** an NRPT rule for that hostname only, pointing at v2ray's own direct DNS. That DNS server is pinned to the WAN and exempt from the guard.
6. **v2rayN's sing-box config rejects UDP 443 (QUIC) and hijacks UDP 53.** VPN transport on those ports is silently dropped. **Fix:** Berayan reads the rejected ports and picks another VPN port (e.g. Windscribe `udp:1194`).
7. **The VPN apps' own protections cut v2ray off.** These can't be fixed from outside (no API), so Berayan detects them and tells the user the fix:
   - **Windscribe "Terminate Sockets"** closes every TCP connection on connect (`closeAllTcpConnections` in its service log), including xray's link that Windscribe runs through, so it reconnects in a loop.
   - **Windscribe WireGuard** enables wireguard-windows' "block untunneled traffic" WFP filters.
   - **NordVPN LeakBlock** (NDivert, always on while connected) whitelists only the NordVPN adapter. Split tunneling for the v2ray core executables is required.
8. **A system proxy** pointing at the local core lets browsers go app → core → v2ray server, skipping the VPN. Berayan refuses to start until it's cleared.

## What Berayan changes (all journaled)

| Item | Store | Purpose |
|---|---|---|
| `/32` VPN server(s) → v2ray TUN | ActiveStore (gone at reboot) | transport through v2ray |
| `/32` v2ray server(s) + bootstrap DNS → WAN gateway | ActiveStore | no recursion |
| `0/1 + 128/1` → VPN adapter (skipped if the VPN already has them) | ActiveStore | apps use the VPN |
| VPN adapter IPv4 interface metric → 100 | interface setting (restored) | sing-box stays on the WAN |
| NRPT: v2ray server hostname → bootstrap DNS | NRPT, comment-tagged | no DNS deadlock |
| Kill switch v4/v6 on WAN-side interfaces (except v2ray servers, bootstrap DNS, LAN) | Firewall group `vpn-chain` | fail-closed |
| VPN server(s) blocked on WAN | `vpn-chain` | no direct transport |
| DNS 53/853 blocked on WAN, and on the v2ray TUN once the VPN is up | `vpn-chain` | DNS only via the VPN |
| Global IPv6 blocked outside the VPN | `vpn-chain` | no IPv6 bypass |

**Transactions.** Every item is journaled as `pending` before it's applied and as `applied` after it's verified. Reconcile adds before it removes, so protection never has a gap. Disconnect removes the journal in reverse order and sweeps the `vpn-chain` firewall group and the tagged NRPT rules. Reset does the same after a crash, even without a session file. Routes and rules that Berayan didn't create are never touched.

## Detection

- **Upstream:** a TUN-like adapter that holds the default route, plus the core processes. Server IPs come from the core's sockets (sockets beat route lookups), from config, or from existing host routes. Hostnames come from the Windows DNS cache, and the bootstrap DNS from v2rayN's generated config. Forged DNS answers (non-public addresses) are discarded.
- **VPN:** the adapter (by provider), the protocol (adapter type plus transport processes), and the endpoint. Endpoint sources, in order: config, the server the app announces in its own log *before* the handshake, OpenVPN TCP sockets, new host routes, and the sing-box Clash API.
- **Verification is behavioral:**
  - public IPv4 from several services, plus an IPv6 probe;
  - raw DNS probes to every non-VPN resolver (all must be blocked);
  - resolver egress;
  - a **4 MB traffic-correlation test**: VPN adapter rx ≈ v2ray TUN rx proves the encapsulation order.

## States

`CHAIN_OK`, `NORDVPN_ONLY` (VPN up, transport not via v2ray), `UPSTREAM_ONLY`, `DIRECT_LEAK`, `DNS_LEAK`, `ROUTING_LOOP`, `UPSTREAM_NOT_SUPPORTED` (proxy-only upstream), `UNKNOWN`. A failed start reports `CHAIN_UNAVAILABLE (<code>)` with the exact reason and fix, and rolls back.

## Code map

| File | Role |
|---|---|
| `berayan.ps1` / `berayan.cmd` | interactive app launcher (elevation, read-only fallback) |
| `src/Tui.ps1` | terminal UI: locked banner (VT scroll region), dashboard, wizard, background auto-repair |
| `src/Engine.ps1` | desired state, transactional reconcile, start/stop/reset/monitor, verification report |
| `src/Providers.ps1` | NordVPN / Windscribe specifics (CLI, protocols, conflicts, announced endpoints) |
| `src/Detect.ps1` | upstream + VPN detection |
| `src/Verify.ps1` | classifier + behavioral probes |
| `src/Net.ps1` | IP math, routes, firewall, NRPT, metrics, probes |
| `src/Common.ps1` | config, logging, journal, elevation |
| `vpn-chain.ps1` / `.cmd` | non-interactive CLI over the same engine |
