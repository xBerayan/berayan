# tests

Neither suite changes your network.

| Suite | What it does | Run |
|---|---|---|
| [`unit.ps1`](unit.ps1) | 66 offline tests: IP math, config, VPN catalogs, UI layout, the state classifier, and the transactional engine against a simulated route / firewall / DNS store. Real network commands are blocked inside the suite. | `powershell -ExecutionPolicy Bypass -File tests\unit.ps1` |
| [`tui-smoke.ps1`](tui-smoke.ps1) | starts the real terminal app **read-only** in a console window, reads the screen and presses keys: banner, dashboard, menus, the connect wizard and the location picker. It always answers "No" to connecting. | `powershell -ExecutionPolicy Bypass -File tests\tui-smoke.ps1` |

Live scenarios (real VPN sessions) and their results: [docs/testing.md](../docs/testing.md).
