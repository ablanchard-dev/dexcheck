# DexCheck

Forensic anti-cheat PC check for Call of Duty / Warzone, run live during a
supervised screen-share. Two native scripts — Windows (PowerShell) and macOS
(bash) — that read the machine, never modify it, and produce a timestamped
report plus a SHA-256 fingerprint of that report.

Built for the Warzup community to vet players reported for cheating: the player
runs it on a screen-share while a moderator watches the output scroll by.

## Quickstart (Windows)

1. **Download** — green **Code** button → **Download ZIP**.
2. **Unblock** — right-click the `.zip` → Properties → tick **Unblock** → OK, *before* extracting. The scripts are unsigned; this removes the Mark-of-the-Web so Windows shows no security warning.
3. **Extract** — right-click the `.zip` → Extract All.
4. **Run** — double-click **`LANCER-LE-CHECK.bat`**, type the moderator's word if given (else just Enter), accept the UAC prompt. A `.txt` + `.html` report lands on the Desktop with a SHA-256 fingerprint.

Player guide: `LANCER-LE-CHECK.txt`. Visual setup check (DMA / second PC): `CHECK-CONSOLE-SETUP.txt`.

## What it checks

Windows (`DexCheck.ps1` — 24 probes, +2 in `-Deep`):

- Identity and clock (clock-rollback heuristic), Windows install age
- USN journal state and a deleted-file timeline (raw USN journal reader via P/Invoke)
- Execution/existence evidence that survives deletion of the binary and reboots: Prefetch, BAM/DAM, UserAssist, Shimcache (AppCompatCache, parsed from the raw registry blob), PCA `PcaAppLaunchDic` (Win11 22H2+, also catches launches from USB / network shares)
- Live outbound TCP connections + owning process (name and path), matched against the known-cheat provider list — catches a cheat loader / licensing client talking to the internet during the session
- Processes, persistence (Run keys, scheduled tasks), injection/hijack vectors (AppInit_DLLs, AppCertDLLs, IFEO Debugger), event-log clearing (1102/104, rollover-aware)
- Anti-forensic / secure-wipe tools, browser history against known cheat domains
- Hardware: DMA cards, FTDI USB3 bridges, capture cards, virtual-pad drivers
- PCIe enumeration: flags a stock/lazy DMA card by its Xilinx vendor ID (`VEN_10EE`, the pcileech-fpga firmware), or a driverless PCIe device with an *unknown* vendor ID — WARN only (dual-use: legit FPGA dev-boards trigger it), never an auto-verdict. A driverless device from a mass-market vendor (Intel/AMD/NVIDIA/Realtek/… — e.g. a Wi-Fi card on a freshly built PC) is listed but downgraded to INFO, so a new build doesn't raise a false DMA WARN. Read-only, so a firmware-spoofed card that clones a real device's identity evades it (see Limits)
- System security: Secure Boot, `testsigning` / `nointegritychecks`, TPM
- Known cheat providers, input-manipulation / anti-recoil devices (Cronus, XIM, Titan, ...)
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
- Output: `.txt` + `.html` report and a SHA-256 hash shown on screen. The hash makes the *saved report* tamper-evident (any later edit changes it); it is not proof of an honest run. Trust comes from the moderator supplying the script (or verifying its hash) and watching the live output — a player should not vet themselves with a script they brought.
- Anti-replay: pass `-Nonce "<word>"` — a word the moderator dictates at check time. It is printed on screen and written into the report, so it is folded into the SHA-256. A report carrying the moderator's fresh nonce could not have been pre-generated on a clean machine before the check — it proves the run is live for *this* session, not just un-edited afterward.

## Usage

Windows — simplest: double-click `LANCER-LE-CHECK.bat`. It prompts for the
moderator's nonce (optional), then runs the check; the script self-elevates via
UAC. The scripts are unsigned, so a downloaded copy carries the Mark-of-the-Web
and Windows shows a one-time "Run anyway" warning — to avoid it entirely,
right-click the downloaded `.zip` → Properties → tick **Unblock** → OK *before*
extracting. The launcher also strips the Mark-of-the-Web from its own folder on
first run, so later launches are warning-free. Or from a terminal:

```
powershell -NoProfile -ExecutionPolicy Bypass -File DexCheck.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File DexCheck.ps1 -Nonce "MOT-DU-MODO"
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

`Test-DexCheck.ps1` runs 108 cases: static (UTF-8 BOM, parse), unit (detection
logic and verdict mapping), integration (real runs produce report + valid hash),
regression (no probe ends in ERROR, no false SUSPECT on a clean PC), and a
true-positive simulation (admin): it plants the trace a self-erasing cheat
leaves — a deleted file with a cheat-matching name — on the live volume and
proves the raw USN reader catches it end-to-end, using a unique benign token so
the bait never trips a later real run. The macOS script self-tests its pure
matching logic with `--self-test`.

## Authorized use

Run with the player's consent, in a supervised screen-share. The tool reads
forensic artifacts (deletion history, installed programs, browser history); use
it only in that agreed context.

## License

MIT — see [LICENSE](LICENSE). © 2026 Alexandre Blanchard (DrDexter).
