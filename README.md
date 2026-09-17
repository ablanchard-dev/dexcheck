# DexCheck

[![CI](https://github.com/ablanchard-dev/dexcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/ablanchard-dev/dexcheck/actions/workflows/ci.yml)

Anti-cheat PC check for Call of Duty / Warzone, run live during a supervised
screen-share. It reads the machine, never modifies it (the only thing it writes is its
own report in `%TEMP%\DexCheck`; no network access), and prints a verdict with the
detail of every finding in the window.

Built for the Warzup community to vet players reported for cheating: the player
runs it while a moderator watches the output scroll by.

## Lancer (Windows)

1. Télécharger la [dernière version](https://github.com/ablanchard-dev/dexcheck/releases/latest) : **Source code (zip)**.
2. Clic droit sur le `.zip` → **Extraire tout**.
3. Dans le dossier extrait, double-clic sur **`LANCER-LE-CHECK.bat`**, puis **Oui** sur la fenêtre bleue.

Aucune question. Le check complet tourne (environ 1 à 2 minutes), puis le verdict
et ce qui a été trouvé s'affichent dans la fenêtre. Lancé depuis l'intérieur du
`.zip`, le launcher le dit et explique comment extraire.

Guide joueur : `LANCER-LE-CHECK.txt`. Vérification visuelle du setup (DMA, 2e PC) :
`CHECK-CONSOLE-SETUP.txt`.

## What the moderator sees

End of a real run on a clean gaming PC (`-Deep`, 17/09/2026), copied as printed:

```
  ------------------------------------------------------------------
   BILAN   : 30 OK | 10 INFO | 0 WARN | 0 FLAG | 0 NA   (40 sondes)
  ==================================================================
   VERDICT : CLEAN
  ==================================================================
   ACTION  : Rien de suspect cote logiciel. Poursuivre le check visuel (DMA / 2e PC / OS reimage non couverts) : un verdict propre ne prouve pas l'absence de triche.
   Aucune sonde n'a leve de drapeau : rien de suspect dans ce qu'un check logiciel peut voir.
```

On a flagged PC, the same screen lists the FLAG findings first, then WARN, each with
what the alert means and its last pieces of evidence (file name, date, source).

## What it looks at

40 read-only probes, grouped:

- **Traces that survive deletion**: USN journal (deleted files), Prefetch, BAM/DAM,
  UserAssist, Shimcache, PCA, MuiCache, WER crashes, Defender detection history,
  download provenance (Mark-of-the-Web).
- **What runs now**: processes and command lines, outbound connections, persistence
  (Run keys, scheduled tasks with their arguments, Startup folders, services, WMI
  subscriptions), injection vectors, kernel drivers (BYOVD), refused drivers (Code Integrity log).
- **Every Windows account, not only the one running the check**: a second account used to
  cheat is read too (files of every profile, registry of every signed-in account). Accounts
  that are signed out are named in the report as not read, since reading them would mean
  loading their registry hive.
- **Hardware**: DMA cards by PCIe identity, capture cards, Cronus / XIM / kmbox
  (including unplugged before the check), HWID spoofing.
- **Clean-up signals**: cleared event logs, wipe tools, deleted shadow copies,
  clock rollback, fresh reinstall.

Full list and design notes: [PROBES.md](PROBES.md).

## How the verdict works

Each probe returns `OK / INFO / WARN / FLAG`, rolled up to
`CLEAN / A VERIFIER / SUSPECT / ROUGE`.

- **A clean PC must come out clean.** Generic words (`loader`, `cheat`) only count on
  files that can run; source files, .NET assemblies and ordinary `irm | iex`
  installers do not raise the verdict.
- **FLAG needs a distinctive product name** (a known cheat provider), never a
  category word: `aimbot-remover.exe` is not a cheat.
- **ROUGE** comes from a critical signal (a known cheat running or installed, cleared
  event logs) or from corroboration: two independent anti-wipe artifacts, or one plus
  a strong clean-up signal. Any other FLAG stays SUSPECT.
- Every WARN/FLAG says what it shows **and what it does not prove**.

## Limits

No client-side check is conclusive. DexCheck catches the careless cheater and the
player who wiped just before the check. It does not see a second PC, a DMA card
with spoofed firmware, a radar in a browser tab, or a freshly imaged OS. The visual
setup check is required, not optional.

## Tests

`Test-DexCheck.ps1`, run in CI on Windows PowerShell 5.1 (270+ cases): detection
logic, verdict mapping, real runs, and for each advanced probe a planted
true-positive plus a clean-PC case built from values measured on a real machine.
The deleted-file detection is proven end to end: the test deletes a uniquely named
bait file and checks the raw USN reader finds it, including when the file is renamed
to a neutral name before being deleted.

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-DexCheck.ps1
```

## Command line

```
powershell -NoProfile -ExecutionPolicy Bypass -File DexCheck.ps1 -Deep
bash DexCheck-Mac.command            # macOS, light
sudo bash DexCheck-Mac.command --deep
```

## Authorized use

Run with the player's consent, in a supervised screen-share.

## License

MIT, see [LICENSE](LICENSE). © 2026 Alexandre Blanchard (DrDexter).
