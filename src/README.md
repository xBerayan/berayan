# src

The source code of Berayan. You don't need to open anything here. Run **`berayan.cmd`** from the main folder.

| File | What it is |
|---|---|
| [`berayan.ps1`](berayan.ps1) | the interactive terminal app (started by `berayan.cmd`) |
| [`vpn-chain.ps1`](vpn-chain.ps1) | the command-line version (started by `vpn-chain.cmd`) |

## modules

Both apps load the same engine from [`modules/`](modules):

| Module | Role |
|---|---|
| [`Tui.ps1`](modules/Tui.ps1) | terminal UI: locked red banner, dashboard, menus, scrollable pickers, background auto-repair |
| [`Engine.ps1`](modules/Engine.ps1) | desired state, transactional apply/undo, connect / disconnect / reset, leak guard, monitor |
| [`Providers.ps1`](modules/Providers.ps1) | NordVPN and Windscribe: CLI, protocols, locations, static IPs, conflict checks |
| [`Detect.ps1`](modules/Detect.ps1) | finds the v2ray tunnel, its servers and DNS, and the VPN connection |
| [`Verify.ps1`](modules/Verify.ps1) | chain-state classifier and leak / traffic tests |
| [`Net.ps1`](modules/Net.ps1) | IP math, routes, Windows Firewall, NRPT, interface metrics |
| [`Common.ps1`](modules/Common.ps1) | logging, config, elevation, session journal |

How it all fits together: [docs/architecture.md](../docs/architecture.md).
