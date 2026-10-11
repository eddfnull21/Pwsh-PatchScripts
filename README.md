# Windows Patching & Remediation Scripts

PowerShell scripts for finding and fixing vulnerable software on Windows endpoints. They update or remove outdated apps, strip end-of-life .NET and Visual C++ runtimes, apply registry-based CVE mitigations, and keep security agents healthy.

They were written for MSP use: most are pushed through an RMM (Datto RMM) and run as `SYSTEM` across many machines. Many also work in an elevated console.

> **Read a script before you run it.** These are working field tools, not a polished product. Many files end with example calls, and some of those make real changes, not just a `-WhatIf` preview. Check the bottom of every file before you run it.

## Layout

| Folder | What's in it |
|---|---|
| [`Patching/`](Patching) | Update, detect or remove scripts for each app: Adobe, Chrome, Firefox, Office, Teams, VS Code, 7-Zip, PowerToys, PuTTY, Python, ScreenConnect, 3D Viewer, Winget, plus a few one-offs in `Other/` |
| [`End-of-Life/`](End-of-Life) | Inventory and removal of end-of-life .NET and VC++ runtimes: one `-morph` script each, with read-only `Check`/`Recon` modes |
| [`Vulnerability-Mitigations/`](Vulnerability-Mitigations) | Registry mitigations (KB4073119 speculative execution, SSB, unquoted service paths, WinVerifyTrust) and the RoguePlanet Defender-engine checker and fix |
| [`Security-Agents/`](Security-Agents) | ConnectSecure (CyberCNS) agent self-heal, and Nessus agent install and removal |
| [`Diagnostics/`](Diagnostics) | Read-only health and evidence collection: Windows restart and slowness, BitLocker, RDS sessions, RAM |
| [`Admin/`](Admin) | User profile removal, a user-consent prompt, an interactive SYSTEM console helper, and a local listening-port audit |
| [`cheatsheets/`](cheatsheets) | Copy-paste quick references (markdown): [Windows patching quick reference](cheatsheets/Windows-Patching-QuickRef.md) (winget as SYSTEM, PSWindowsUpdate, KB installs, scheduled reboots, SFC/DISM/CBS, MSI watch) and [MSI uninstall by GUID](cheatsheets/MSI-Uninstall-by-GUID.md) (uninstall, leftover-entry cleanup, Package Cache bundles) |
| [`Prompts/`](Prompts) | LLM prompt templates for building HTML report dashboards (not scripts) |
| [`tests/`](tests) | Pester tests and PSScriptAnalyzer settings for the `-morph` scripts: paste-model contract, a real paste in Windows PowerShell 5.1, the `$RMM` exit and the elevation gate. Run `Invoke-Pester .	ests` in Windows PowerShell 5.1, not elevated |

`OLD/` folders hold earlier versions, kept for reference. Use the current script beside them. A `-morph` suffix marks a script merged from several older ones; the scripts it replaced are in the same folder's `OLD/` with an `-old-stable` suffix.

## Recommended scripts

| Task | Script | Notes |
|---|---|---|
| .NET end-of-life (all-in-one) | `End-of-Life/DOT_NET/morph/DotNet-EOL-morph.ps1` | `Check` (default, fast EOL scan, exits 2 if EOL found), `Recon` (who uses which runtime: Observed use / Superseded / Potential dependency / No evidence), `Remove` (EOL removal below `8.0.28`, **dry run unless `Armed`**, deny-list protects .NET Framework/VS/.NET Standard, cleans ghost ARP keys) and `Update` (latest patch via winget, then trims old patches in 8 and 10). Paste model with `$RMM` flag |
| VC++ end-of-life (all-in-one) | `End-of-Life/VC++/VCRedist-EOL-morph.ps1` | `Check` (default, read-only, exits 2 if 2005–2013 or duplicate 14.x found), `Recon` (which apps load or ship which VC++ runtime, with confidence), `Install` (latest 14.x per arch from aka.ms, signature-checked) and `Remove` (keeps the newest 14.x per arch, removes 2005–2013 and older 14.x, installs 14.x first if missing). Install/Remove are **live unless `WhatIf`** and need admin even to preview |
| Google Chrome | `Patching/Browsers/Chrome/Chrome-morph.ps1` | `Check` (default, read-only: machine and per-user versions, GoogleUpdater / Omaha / MSI deployment type; exits 2 if an install is older than the newest one, an update is staged waiting for a relaunch, the version is below `TargetVersion`, the install is MSI-only or policy blocks updates), `Recon` (every profile's Chrome folder plus uninstall entries, with an assessment for scanners reporting an old version) and `Update` (machine-wide update through the engine actually present, never closes Chrome; optional `RelaunchNotification` policy). Update needs admin even to preview. `WhatIf` supported |
| Firefox | `Patching/Browsers/Firefox/Firefox-morph.ps1` | `Check` (default, read-only: machine-wide, per-user (every profile) and Store installs with versions, uninstall registrations, which users have profile data; exits 2 if Firefox found), `Update` (machine-wide Firefox to the latest release, same architecture and language, Mozilla signature check) and `Uninstall` (manual desktop cleanup for all users, including logged-off users' registry; **keeps profiles unless `RemoveProfiles = $true`**). Update/Uninstall need admin even to preview. `WhatIf` supported |
| Adobe Acrobat | `Patching/Adobe/Adobe-Acrobat-morph.ps1` | `-Check` (default), `-Recon` (deep read-only scan, for scanners reporting stale versions), `-Update`, `-Uninstall`, `-RepairTransforms` (fixes MSI installs blocked by a missing `.mst`), `-Interactive` (menu for an elevated console). `-Force`, `-WhatIf`. Exits with RMM codes 0–10 |
| PowerToys | `Patching/PowerToys/PowerToys-morph.ps1` | `-Action Status` (default), `Update` (migrate every user to one machine-wide install) or `Uninstall` (machine and all profiles). Must run as SYSTEM. `-WhatIf`. Exits 0 / 1 / 3010 |
| Teams cleanup | `Patching/Teams/teams-omega.ps1` + `DETECTORSCRIPT_v4.PS1` | Removes Classic Teams, old New Teams builds and the Machine-Wide Installer. `-InstallLatest` optional |
| VS Code | `Patching/VSCode/VSCode-morph.ps1` | `Check` (default, read-only: latest release vs machine-wide install, lists per-user installs, exits 2 if action needed), `Update` (BITS download, SHA-256 + Microsoft signature check, asks users before closing VS Code) and `Migrate` (per-user installs to one machine-wide install, with each user's consent). `WhatIf` supported |
| Microsoft 3D Viewer | `Patching/Microsoft3DViewer/Microsoft3DViewer-morph.ps1` | `Check` (default, read-only, exits 2 if present), `Remove` (all users + provisioned package, blocks reinstall) and `RemoveWithConsent` (asks the logged-on user first; no answer = no change, exit 4). `WhatIf` supported |
| Python (python.org) | `Patching/Python/Python-morph.ps1` | `Check` (default, read-only: uninstall entries plus install folders for every profile, including the 3.14+ install manager; exits 2 if end-of-life Python, below 3.10 by default, is found) and `Remove` (bundle, MSIs, orphaned keys, PythonCore keys, folders, Package Cache and PATH, machine-wide and in every profile; other users' per-user installs are scrubbed, with `.reg` backups first). `Version` = `EOL` / `All` / `3.11` / `3.11.4`. `WhatIf` supported |
| ScreenConnect / ConnectWise Control | `Patching/ScreenConnect/ScreenConnect-morph.ps1` | Read-only. `Check` (default, fast: uninstall entries with version and uninstall command, exits 2 if installed) and `Recon` (deep trace search: MSI records, services, processes and their TCP connections, scheduled tasks, firewall rules, registry; optional files with hashes and signatures, and event logs). Exits 2 if anything is found |
| Winget bulk upgrade | `Patching/Winget/Winget-morph.ps1` | `Check` (default, read-only: lists what winget would upgrade after the exclusions, exits 2 if any) and `Upgrade` (one package at a time by exact ID, never Office/M365, waits for other installers and follows each install's logs; `ExcludedPackageIds` / `BlockingPinIds` / `AdditionalExcludePattern` in `-Options`). Upgrade needs admin even to preview. `WhatIf` supported |
| Office CVE-2026-21509 | `Patching/Office/check-cve-2026-21509.ps1`, `office-patch.ps1` | Checker, plus the registry workaround with a `.reg` backup |
| Speculative-execution mitigations | `Vulnerability-Mitigations/Registry/kb4073119mitigations.ps1` | Chooses settings by CPU vendor (Intel/AMD/ARM). Reboot required |
| Unquoted service paths | `Vulnerability-Mitigations/Registry/PROD/UnquotedServicePathEnumeration(edge).ps1` | Audits by default. `-Fix` writes a rollback CSV first; `-Rollback` restores from it |
| CVE-2013-3900 (WinVerifyTrust) | `Vulnerability-Mitigations/Registry/PROD/WinVerifyTrustv2.PS1` | Sets `EnableCertPaddingCheck` |
| RoguePlanet (Defender engine) | `Vulnerability-Mitigations/CVE-RoguePlanet/RoguePlanet-CVE-checker(sig-based).ps1`, `RMM-RoguePlanetFIX.ps1` | The checker audits local or remote machines over WinRM, with optional CSV output. The fix script audits by default (exit 2 if vulnerable) and, switched to its fix line, updates the Defender engine (elevated). Paste model with `$RMM` flag |
| Nessus agent | `Security-Agents/Nessus/Nessus-morph.ps1` | `Check` (default, read-only, exits 2 if any Nessus footprint found; never prints the agent token), `Remove` (clean msiexec uninstall plus leftover services, folders and registry), `ForceClean` (purge a broken agent install that msiexec can't remove, no msiexec) and `Link` (nessuscli cloud link; key passed in `-Options`, never stored). `WhatIf` supported |
| ConnectSecure agent health | `Security-Agents/ConnectSecure/Prod/00_CS-Agent-SelfHeal(STABLE-LEAVE-IT).ps1` | See [ConnectSecure self-heal](#connectsecure-self-heal) |
| Windows restart / slowness evidence | `Diagnostics/Windows/wincheck.ps1` | Read-only. Produces a timeline, an HTML report and a verified ZIP in `%TEMP%\WindowsDiagnostics` |
| RDS session monitor | `Diagnostics/RDS/RDSActiveSessionMonitor.ps1` | Datto RMM monitor. Alerts when active sessions drop to the threshold during business hours |
| User profile removal | `Admin/User-Removal/UserRemoval-morph.ps1` | Everything matched by SID. `Check` (default, read-only: local, domain and Entra profiles with real last-use time, accounts without a profile, broken registrations, `.bak` keys, leftover folders; exits 2 if broken state or the requested targets are found), `Remove` (by `Users` = name / `DOMAIN\name` / SID / path, or `InactiveDays`; deletes through Windows' profile API and touches nothing else if that fails; local account removed with `Users`, kept with `InactiveDays`), `Cleanup` (registrations without a folder, TEMP leftovers; `.reg` backup) and `Interactive` (console menu). Never touches built-ins (by RID), the current user or loaded profiles. Results CSV in `%ProgramData%\UserRemoval`. `WhatIf` supported |

## Running the scripts

**`-morph` scripts (Adobe, PowerToys, .NET, VC++, VS Code, 3D Viewer, Nessus, Python, Winget, ScreenConnect, Firefox, Chrome, UserRemoval)** are built to be copied whole and pasted:

1. Open the file and go to the **ENTRY POINT** block at the bottom. The safe, read-only mode is active; the other modes are commented-out lines below it. Swap the `#` to pick one.
2. **Live console or RMM remote shell:** paste the whole script. It runs that one line and leaves the session open (it prints the exit code instead of calling `exit`). The functions stay loaded, so you can type further modes straight away.
3. **RMM component:** also set `$RMM = $true` in the ENTRY POINT. The script then ends with `exit <code>` so the RMM records the result. Never set it when pasting into a shell you're still working in, or `exit` closes it.

**Older scripts** are a function plus a call at the bottom. Check that bottom call before running them, and note that some *return* an exit code rather than calling `exit`. Menu-driven tools (`UserRemoval-morph.ps1` in `Interactive` mode, `Adobe-Acrobat-morph.ps1` with `-Interactive`) and `Admin/CLI-Tool-Takeover` need an interactive elevated console.

**Always preview first.** Most remediation functions support `-WhatIf`. The .NET removal script does nothing unless you pass `-Armed`.

**Recon first, then remove.** Neither EOL `Remove` mode checks whether an app still needs the runtime it removes. Run the same script's `Recon` mode first. Removing 2005–2013 VC++ or old .NET can break line-of-business apps.

## Requirements

- Windows PowerShell 5.1, 64-bit (many scripts work on PowerShell 7 too). Remediation needs admin or SYSTEM.
- Some scripts need extra tools:
  - winget (App Installer): Winget, Adobe, .NET update, PowerToys, 7-Zip
  - the Office Deployment Tool, which some Office scripts download themselves
  - WinRM: remote RoguePlanet checks
- Scripts that download installers get them only from vendor URLs: Microsoft (`aka.ms`, `download.microsoft.com`, VS Code update API, Teams fwlink), Mozilla, Fortinet, Tenable, ConnectSecure.

## ConnectSecure self-heal

`00_CS-Agent-SelfHeal(STABLE-LEAVE-IT).ps1` checks the CyberCNS agent. It judges health from recent portal check-ins in `cybercns.log` and the agent's self-test, and compares the installed version with the one the server advertises. Depending on the result it does nothing, repairs the monitor service, updates in place, or reinstalls.

- **Configure first:** set your tenant values in `Get-CSHealTenantConfig` (CompanyID, TenantID, Secret, UninstallSecret). The shipped values are placeholders.
- **Safety rails:**
  - a global lock stops overlapping runs;
  - at most 2 reinstalls per 24 hours and 3 per 7 days;
  - it holds off while the agent is upgrading or a reboot is pending;
  - it downloads and checks the installer before uninstalling anything.
- **Exit codes:**

  | Code | Meaning |
  |---|---|
  | 0 | OK, or `-WhatIf` run |
  | 2 | Preconditions failed |
  | 3 | Action failed or error |
  | 4 | Verification failed |
  | 5 | Another run in progress |
  | 6 | Deferred |

  It also prints a `CSSH-RESULT|{json}` line for RMM parsing.
- **Environment variables:** `CS_SELFHEAL_AUTORUN` / `CS_SELFHEAL_NOAUTORUN` control auto-run.

## Known rough edges

- **Office scripts:** `Office-remover.ps1` (removes ALL Click-to-Run Office), `officething.ps1` (update request) and `office.rm.localizations.ps1` (language packs, install language always kept) follow the paste model with a safe default. The other Office scripts are older one-offs; read them before running.
- **Commented-out extras:** `wincheck.ps1`, `7zip_patch.ps1` and `check-cve-2026-21509.ps1` end with one-liners kept as comments. Run them by hand only.
- **Not yet tested:** filenames containing `(edge)`, `(edge-untested)` or `(broken)` mean what they say.

## Disclaimer

Released under the [MIT License](LICENSE). Provided as-is, with no warranty. These scripts uninstall software, delete files and registry keys, and change security settings. Test on a non-production machine first, and review every file before you deploy it to a fleet.
