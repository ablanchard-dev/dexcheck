# DexCheck

[![CI](https://github.com/ablanchard-dev/dexcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/ablanchard-dev/dexcheck/actions/workflows/ci.yml)

Forensic anti-cheat PC check for Call of Duty / Warzone, run live during a
supervised screen-share. Two native scripts — Windows (PowerShell) and macOS
(bash) — that read the machine, never modify it, and produce a timestamped
report plus a SHA-256 fingerprint of that report.

Built for the Warzup community to vet players reported for cheating: the player
runs it on a screen-share while a moderator watches the output scroll by.

## Démarrage rapide 🇫🇷 (Windows) — aucune ligne de commande à taper

1. **Télécharger** — bouton vert **Code** → **Download ZIP**.
2. **Débloquer** — clic droit sur le `.zip` → **Propriétés** → cocher **Débloquer** (en bas) → **OK**, *avant* d'extraire. Les scripts ne sont pas signés ; ça retire l'étiquette « venu d'internet » → Windows n'affiche aucun avertissement.
3. **Extraire** — clic droit sur le `.zip` → **Extraire tout**.
4. **Lancer** — ouvre le dossier extrait, double-clic sur **`LANCER-LE-CHECK.bat`**, accepte la fenêtre bleue (**UAC → Oui**). Aucune question : le check complet tourne. Un rapport `.txt` + `.html` arrive sur le **Bureau** avec une empreinte **SHA-256**.

Guide joueur détaillé (FR) : `LANCER-LE-CHECK.txt`. Vérif visuelle du setup (DMA / 2e PC) : `CHECK-CONSOLE-SETUP.txt`.

**Si le double-clic ne marche pas** — ouvre **PowerShell** (n'importe où, pas besoin d'être dans le dossier) et colle cette ligne. Elle retrouve le script où qu'il ait été extrait, le débloque et le lance :

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command '$p=(Get-ChildItem $HOME -Filter DexCheck.ps1 -Recurse -File -EA 0 | Select-Object -First 1).FullName; if (-not $p) { Write-Host ''DexCheck.ps1 introuvable : extrais d abord le ZIP.'' -Fore Red; exit 1 }; Get-ChildItem (Split-Path $p) -Recurse | Unblock-File; & $p'
```

## Quickstart 🇬🇧 (Windows) — no command line to type

1. **Download** — green **Code** button → **Download ZIP**.
2. **Unblock** — right-click the `.zip` → Properties → tick **Unblock** → OK, *before* extracting. The scripts are unsigned; this removes the Mark-of-the-Web so Windows shows no security warning.
3. **Extract** — right-click the `.zip` → Extract All.
4. **Run** — open the extracted folder, double-click **`LANCER-LE-CHECK.bat`**, accept the UAC prompt. No questions: the full check runs. A `.txt` + `.html` report lands on the Desktop with a SHA-256 fingerprint.

Player guide (French): `LANCER-LE-CHECK.txt`. Visual setup check (DMA / second PC): `CHECK-CONSOLE-SETUP.txt`.

**If the double-click fails** — open **PowerShell** (from anywhere, no need to be in the folder) and paste this line. It locates the script wherever it was extracted, unblocks it and runs it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command '$p=(Get-ChildItem $HOME -Filter DexCheck.ps1 -Recurse -File -EA 0 | Select-Object -First 1).FullName; if (-not $p) { Write-Host ''DexCheck.ps1 not found: extract the ZIP first.'' -Fore Red; exit 1 }; Get-ChildItem (Split-Path $p) -Recurse | Unblock-File; & $p'
```

## What it checks

Windows (`DexCheck.ps1` — 38 probes, +2 in `-Deep`):

- Identity and clock (clock-rollback heuristic), Windows install age
- USN journal state and a deleted-file timeline (raw USN journal reader via P/Invoke)
- Execution/existence evidence that survives deletion of the binary and reboots: Prefetch, BAM/DAM, UserAssist, Shimcache (AppCompatCache, parsed from the raw registry blob), PCA `PcaAppLaunchDic` (Win11 22H2+, also catches launches from USB / network shares)
- Live outbound TCP connections + owning process (name and path), matched against the known-cheat provider list — catches a cheat loader / licensing client talking to the internet during the session
- Processes, persistence (Run keys, scheduled tasks), injection/hijack vectors (AppInit_DLLs, AppCertDLLs, IFEO Debugger), event-log clearing (1102/104, rollover-aware)
- Anti-forensic / secure-wipe tools, browser history against known cheat domains
- DNS resolver cache (catches a cheat domain resolved by *any* process, not just the browser) and the `hosts` file (static redirects), matched against the known cheat-domain list — WARN at most (resolving a domain is not using a cheat), never an auto-verdict; the DNS cache is ephemeral (clears on reboot / TTL)
- Hardware: DMA cards, FTDI USB3 bridges, capture cards, virtual-pad drivers
- PCIe enumeration: a card announcing the **stock pcileech-fpga config space** (`VEN_10EE&DEV_0666` — a PCIe identity, not a renamable file name) is FLAG; any other Xilinx device (`VEN_10EE`, legit FPGA dev-boards) or a driverless PCIe device with an *unknown* vendor ID is WARN (dual-use), never an auto-verdict. A device from a mass-market vendor whose **driver is present but fails to start** (CM error 10/12/31/43 — exactly what happens when a DMA card clones a Realtek/Intel NIC ID and gets the real driver) is WARN; a merely driverless mass-market device (code 28, e.g. a Wi-Fi card on a fresh build) stays INFO so a new PC doesn't raise a false DMA WARN. Phantom (unplugged) devices are never classified. Read-only, so a firmware-spoofed card that clones a real device's identity *and* behaves like it evades it (see Limits)
- **Hardware identity / HWID spoof**: compares what Windows *presents* (WMI SMBIOS serials, board model/vendor, BIOS version; NIC MAC) with what it *recorded* (the `HARDWARE\DESCRIPTION\System\BIOS` hive filled by the kernel at boot; the NIC's burned-in `PermanentAddress`; a forced `NetworkAddress` in the driver key), and dates the `MachineGuid` key against the Windows install date (a key rewritten long after install is the classic spoofer footprint). Any gap is WARN, never FLAG — a Wi-Fi "random hardware address" is INFO only, and empty registry values are never compared (measured: a clean MSI board leaves them blank)
- **Code Integrity log** (`Microsoft-Windows-CodeIntegrity/Operational`, events 3001/3004/3033/3076/3077): every kernel driver Windows *refused* to load, with its path and date — written by the kernel itself, survives deletion of the `.sys`. A refused `.sys` is WARN (BYOVD / kdmapper pattern, especially from a user folder; old legit utility drivers also trip HVCI), a distinctive cheat name is FLAG and counts as an independent anti-wipe artifact for the ROUGE corroboration. Refused DLLs are ignored (measured noise: Bonjour). Paths are parsed, not the localized message text
- Kernel drivers (BYOVD): running drivers with an invalid Authenticode signature or a known-abusable name (`rtcore64`, `iqvw64e`, `gdrv`, …), plus **every registered driver service whose image lives under `\Users\`** (Temp/Downloads = the residue kdmapper leaves when its cleanup fails). `\ProgramData` is not a user zone — Battle.net's `randgrid.sys` lives there
- System security: Secure Boot, `testsigning` / `nointegritychecks`, TPM
- Known cheat providers, input-manipulation / anti-recoil devices (Cronus, XIM, Titan, ...)
- USB history: a Cronus / XIM / kmbox that was plugged in and **unplugged before the check** (registry device history, firmware descriptor — the live device probe only sees what's connected right now)
- Windows Defender detection history (`Get-MpThreat`): a cheat the antivirus already caught — a Microsoft-signed verdict that survives deletion of the binary; generic HackTool categories (Cheat Engine, solo-game trainers) stay WARN, not FLAG
- Running-process **command lines** (not just names): a cheat launched via a renamed executable but a distinctive argument
- `.gpc` Cronus scripts, detected by their **content** (GPC keywords `set_val` / `combo` / `event_press`), not just the extension
- Windows Error Reporting (WER) crash history: a cheat that crashed left its name behind (execution evidence that survives binary deletion)
- Recently opened files, Run-dialog commands and **launched executables** (RecentDocs, RunMRU, MuiCache — MuiCache keeps the full path of every exe launched through the shell and is never purged by Windows)
- **Download provenance (Mark-of-the-Web)**: the `Zone.Identifier` stream records the URL a file was downloaded from — a file pulled from a known cheat domain is flagged, and this provenance **survives wiping the browser history**
- DMA protection posture (VBS / Kernel DMA Protection availability) — INFO only, context for the PCIe probe
- **Freshness-wall timeline**: correlates the oldest artifact of each long-baseline source against the Windows install date — an innocent PC has old, desynchronized history; a wiped one has everything starting in a narrow window on an old install. Presentation only (INFO, never affects the verdict); rolling-window sources (USN, saturated Prefetch, Shimcache) are excluded from the calculation
- Volume Shadow Copies: lists restore points and flags a recent `vssadmin delete shadows` command in the history (anti-forensic tell) — listing is not deleting, so `vssadmin list` is ignored
- `-Deep`: full USN deletion dump to CSV + free-space signature carving

macOS (`DexCheck-Mac.command`): capture cards, FTDI/DMA bridges, remote-control
tools, known cheat names, persistence, SIP/Gatekeeper status, third-party kexts;
and with Full Disk Access (`--deep`) the screen-recording permission (the main
aimbot-by-vision signal), accessibility (input injection), browser history and
download quarantine.

## Design

- 100% native, zero dependencies. PowerShell 5.1+ / bash 3.2+.
- Read-only. Every probe is isolated in `try/catch`; one failing probe never aborts the run.
- Severity model `OK / INFO / WARN / FLAG`, rolled up to a verdict `CLEAN / A VERIFIER / SUSPECT / ROUGE`.
- Every `WARN`/`FLAG` states what it *shows* and — plainly — what it does **not** prove (found ≠ proven), on screen and in the report. The verdict carries a short reasoning line: what fired, whether it's explained by gaming optimization, and the standing caveat that a clean result never proves the absence of a DMA / second-PC / browser-radar cheat.
- Evasion correlation: co-occurring clean-up signals are surfaced together, and the verdict is bumped `A VERIFIER → SUSPECT` only when a *strong* signal not explained by gaming optimization (clock rollback, Defender disabled, real wipe tool, cleared logs) co-occurs with corroboration — so a debloated gaming PC (USN off + empty prefetch + recent reinstall) is never falsely escalated.
- Dual-use tooling (G HUB, DS4Windows, ...) is listed, not auto-flagged — the moderator keeps the final call.
- Word-boundary matching to kill substring false positives (`xim` is not `Maxim`, `zen` is not `Ryzen`).
- Terminal: one line per probe with a `i/N` progress counter and OK/INFO/WARN/FLAG/NA colours, verdict + action boxed at the end.
- Output: `.txt` + `.html` report and a SHA-256 hash shown on screen. The HTML puts the verdict, the action and the script fingerprint first, expands every FLAG/WARN with its "shows / does not prove" lines, and folds the OK/INFO/NA probes under a collapsible section. The hash makes the *saved report* tamper-evident (any later edit changes it); it is not proof of an honest run. Trust comes from the moderator supplying the script (or verifying its hash) and watching the live output — a player should not vet themselves with a script they brought.
- Anti-replay: pass `-Nonce "<word>"` — a word the moderator dictates at check time. It is printed on screen and written into the report, so it is folded into the SHA-256. A report carrying the moderator's fresh nonce could not have been pre-generated on a clean machine before the check — it proves the run is live for *this* session, not just un-edited afterward.

## Usage

Windows — simplest: double-click `LANCER-LE-CHECK.bat` from the extracted
folder. It asks nothing and runs the full check (`-Deep`); it elevates via UAC,
and if launched from inside the `.zip` it says to extract first. The scripts are unsigned, so a downloaded copy carries the Mark-of-the-Web
and Windows shows a one-time "Run anyway" warning — to avoid it entirely,
right-click the downloaded `.zip` → Properties → tick **Unblock** → OK *before*
extracting. The launcher also strips the Mark-of-the-Web from its own folder on
first run, so later launches are warning-free. Or from a terminal:

```
powershell -NoProfile -ExecutionPolicy Bypass -File DexCheck.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File DexCheck.ps1 -Nonce "MOT-DU-MODO"
powershell -NoProfile -ExecutionPolicy Bypass -File DexCheck.ps1 -Deep -Nonce "MOT-DU-MODO"
```

Accept the UAC prompt for full coverage (raw-volume and system-hive probes need
elevation); without it those probes degrade cleanly to N/A. Add `-Deep` for the
deeper pass, and `-Nonce "<word>"` (dictated live by the moderator) for an
anti-replay proof-of-freshness. A plain-language guide for players is in
`LANCER-LE-CHECK.txt`.

macOS:

```
bash DexCheck-Mac.command                 # light, no permissions
sudo bash DexCheck-Mac.command --deep     # needs Full Disk Access
```

## Limits (stated up front)

No client-side check is conclusive. DexCheck catches the careless cheater and
the player who wiped just before the check. It does not defeat a determined
setup: a second PC, a hardware DMA card that spoofs its IDs, a radar running in
a browser tab, or a freshly imaged OS.

On DMA specifically: "undetectable client-side" is a nuance, not an absolute. A
DMA cheat is an FPGA PCIe card on a second machine reading game memory. The
*stock* pcileech firmware still carries the Xilinx vendor ID (`VEN_10EE`) and
lazy setups leave a PCIe device with no driver — the `Cartes PCIe / DMA` probe
flags exactly those (WARN, dual-use). But a *firmware-spoofed* card clones the
config space of a legitimate device (an NVMe/SATA SSD, a NIC), so a read-only
user-mode scan sees only the benign identity the card chooses to present. Real
DMA defense today is kernel + IOMMU, done server-side by anti-cheats
(Vanguard/Ricochet 2024–2026), not by a screenshare script. So the probe catches
the careless DMA user and gives the moderator the PCIe inventory to eyeball — it
does not claim to catch a determined one. The visual setup check
(`CHECK-CONSOLE-SETUP.txt`) is the required complement, not an optional extra.

## Tests

`Test-DexCheck.ps1` runs 263 cases (BILAN line of 2026-09-14; the exact count is the BILAN line the script prints, and it grows with the suite), on every push via CI: static (UTF-8 BOM, parse), unit (detection
logic and verdict mapping), integration (real runs produce report + valid hash),
regression (no probe ends in ERROR, no false SUSPECT on a clean PC), a
true-positive simulation (admin): it plants the trace a self-erasing cheat
leaves — a deleted file with a cheat-matching name — on the live volume and
proves the raw USN reader catches it end-to-end, using a unique benign token so
the bait never trips a later real run; and a section per advanced family (HWID
spoof, DMA by PCIe identity, BYOVD via the Code Integrity log and driver
services, MuiCache) where every probe has a planted true-positive *and* a
clean-PC case built from values measured on a real clean machine. The macOS
script self-tests its pure matching logic with `--self-test`.

## Authorized use

Run with the player's consent, in a supervised screen-share. The tool reads
forensic artifacts (deletion history, installed programs, browser history); use
it only in that agreed context.

## License

MIT — see [LICENSE](LICENSE). © 2026 Alexandre Blanchard (DrDexter).
