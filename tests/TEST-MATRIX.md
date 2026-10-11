# Test matrix

There are two layers:

1. **Automated, offline:** `tests\run-tests.ps1`. It covers pure logic (IP math, range complement, config, the state classifier) and the transactional engine against an in-memory fake route/firewall store: apply, idempotent re-apply, re-pinning, failure mid-apply, crash recovery, and an orphan sweep that preserves foreign routes and rules.
2. **Live:** the scenarios below. They need real VPN sessions and an elevated shell. After each one, run `.\vpn-chain.cmd status` / `test`. After every *failure* scenario, run `.\vpn-chain.cmd stop` (or `reset`) and confirm that `diagnose` shows `our fw rules: 0` and no `vpn-chain` routes.

| # | Scenario | Procedure | Expected |
|---|---|---|---|
| 1 | No VPN connected | disconnect everything; `status` | `UNKNOWN`/`DIRECT_LEAK` (no tunnel); `start` → `CHAIN_UNAVAILABLE (NO_UPSTREAM)` and nothing changed |
| 2 | v2rayN TUN only | `status`, `diagnose` | upstream mode `tun`, adapter = v2rayN TUN, core server found; state `UPSTREAM_ONLY` |
| 3 | sing-box TUN only | as 2 | as 2 |
| 4 | NordVPN only | no upstream, NordVPN connected; `start` | `CHAIN_UNAVAILABLE (NO_UPSTREAM)`; `status` = `NORDVPN_ONLY`/`UNKNOWN` |
| 5 | v2rayN → NordVPN | upstream up, NordVPN off; `start`, connect NordVPN | `CHAIN_OK`; traffic test `chained`; endpoint path `upstream`; final IP ≠ upstream exit; NordVPN `protected=True`; raw DNS to router/upstream DNS `blocked` |
| 6 | sing-box → NordVPN | as 5 | as 5 |
| 7 | NordVPN reconnect / server change | while 5 runs with the monitor: switch NordVPN server | monitor logs `endpoint changed` and re-pins; returns to `CHAIN_OK`; no direct traffic in between (kill switch) |
| 8 | Upstream reconnect | reconnect v2rayN/sing-box | monitor logs `upstream adapter changed` if the index changed; rules re-bound; returns to `CHAIN_OK` |
| 9 | Wi-Fi disconnect/reconnect | toggle Wi-Fi / switch to Ethernet | monitor re-pins the upstream server on the new gateway; kill switch covers the new interface |
| 10 | Sleep/resume | sleep 1 min, wake | address-change event triggers a reconcile; `CHAIN_OK` after both clients reconnect |
| 11 | Application crash | kill sing-box/v2rayN core | `NORDVPN_ONLY` (upstream down); NordVPN transport **cannot** go direct (WAN blocked); restart the core → recovers |
| 12 | Forced tool termination | close the monitor window / `taskkill` mid-`start` | the next `start` refuses; `reset` restores everything; `diagnose` shows 0 rules |
| 13 | IPv6 enabled | network with native IPv6 | `test`: "Public IPv6 none" (or NordVPN IPv6 if it provides it); `IPv6 does not bypass` PASS |
| 14 | IPv6 unavailable | IPv4-only network | IPv6 probe none; no errors |
| 15 | Upstream proxy-only | v2rayN system proxy, TUN off | `start` → `CHAIN_UNAVAILABLE (UPSTREAM_NOT_SUPPORTED)`, no changes made |

## Automated suites

| Suite | What it covers |
|---|---|
| `tests\run-tests.ps1` | 65 offline tests (real network-changing cmdlets are blocked inside the suite): IP math, config, provider and location catalogs, banner/dashboard shape, classifier matrix, transactional engine against a simulated route/firewall/NRPT/metric store (apply, idempotency, re-pin, failure mid-apply, crash recovery, foreign state preserved) |
| `tests\tui-smoke.ps1` | starts the real terminal app **read-only** in a console window, reads the screen buffer and sends keys: locked red banner, dashboard, menu, diagnose scrolling under the banner, settings, connect wizard (VPN → protocol → scrollable location picker with search → pre-flight), typed custom location (regression: used to freeze), clean quit. It never changes the network. |

## Verified live (Windows 10 22H2, v2rayN + xray VLESS-Reality, Windscribe 2.24)

| Scenario | Result |
|---|---|
| Windscribe **IKEv2** through v2ray | **CHAIN_OK**, 8/8 checks: final IP = Windscribe exit, 4 MB traffic test seen on the VPN *and* the v2ray TUN, DNS only via Windscribe, no IPv6 egress |
| Windscribe WireGuard (default UDP 443) | blocked by v2rayN's QUIC reject rule → port auto-selection added |
| Windscribe WireGuard (UDP 1194) | handshake OK, then cut off by the WireGuard client's untunneled-traffic firewall → marked "usually fails" |
| Windscribe with "Terminate Sockets" ON | reconnect loop (all TCP sockets closed on every connect) → detected, fix shown |
| NordVPN NordLynx | handshake OK through v2ray, then cut off by NordVPN LeakBlock → split tunneling required, detected and explained |
| Proxy-only upstream / system proxy on | refused before any change (`UPSTREAM_NOT_SUPPORTED` / `SYSTEM_PROXY_BYPASS`) |
| Interrupted start (window killed) | `reset` restored everything (0 rules, 0 routes, 0 NRPT) |
