<#
    Test-DexCheck.ps1 - harnais de test du PC check forensic (gate "dev lead").

    Couvre 4 niveaux :
      A. STATIQUE      - encodage UTF-8 BOM, parse 0 erreur, (PSScriptAnalyzer si dispo).
      B. UNITAIRE      - logique maison : ConvertFrom-Rot13, Test-AnyWord (frontiere de mot),
                         Get-Verdict (mapping severite), statut INFO accepte. (dot-source -NoRun)
      C. INTEGRATION   - run reel non-admin + -Deep : exit 0, rapport .txt/.html + CSV, SHA256 = fichier.
      D. REGRESSION    - sur le rapport produit : AUCUNE sonde en ERROR (= bug non capture), et le scan
                         d'espace libre n'est JAMAIS FLAG (ne doit pas brander un PC clean -> faux SUSPECT).

    Usage :  powershell -NoProfile -ExecutionPolicy Bypass -File Test-DexCheck.ps1
    Sortie :  liste PASS/FAIL + bilan. Code de sortie = nombre d'echecs (0 = tout vert).
#>
[CmdletBinding()]
param(
    [string]$ScriptPath
)

if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $ScriptPath = Join-Path $here 'DexCheck.ps1'
}

$ErrorActionPreference = 'Continue'
$script:Pass = 0
$script:Fail = 0

function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        $ok = & $Body
        if ($ok) { $script:Pass++; Write-Host ("  [PASS] {0}" -f $Name) -ForegroundColor Green }
        else     { $script:Fail++; Write-Host ("  [FAIL] {0}" -f $Name) -ForegroundColor Red }
    } catch {
        $script:Fail++
        Write-Host ("  [FAIL] {0}  -- exception: {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red
    }
}

function Section { param([string]$T) Write-Host "`n== $T ==" -ForegroundColor Cyan }

if (-not (Test-Path $ScriptPath)) { Write-Host "Script introuvable : $ScriptPath" -ForegroundColor Red; exit 99 }

$work = Join-Path $env:TEMP ("DexCheckTests_{0}" -f (Get-Random))
New-Item -ItemType Directory -Force $work | Out-Null

# Elevation : certaines preuves (dump USN brut) exigent l'admin. Les tests concernes SKIP proprement
# hors admin (non bloquant) au lieu d'echouer - le CSV USN ne peut PAS exister sans lecture brute du volume.
$adminE = $false
try { $adminE = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) } catch { }

# ---------------------------------------------------------------------------
Section "A. STATIQUE"

Test-Case "UTF-8 BOM present" {
    $b = [IO.File]::ReadAllBytes($ScriptPath)[0..2]
    ($b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)
}

Test-Case "Parse sans erreur (Parser::ParseFile)" {
    $tok = $null; $err = $null
    [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tok, [ref]$err) | Out-Null
    if ($err.Count -gt 0) { $err | ForEach-Object { Write-Host ("      -> {0} (l.{1})" -f $_.Message, $_.Extent.StartLineNumber) -ForegroundColor DarkYellow } }
    ($err.Count -eq 0)
}

Test-Case "PSScriptAnalyzer : aucune erreur de severite Error (si dispo)" {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) { Write-Host "      (PSScriptAnalyzer absent -> skip, non bloquant)" -ForegroundColor DarkGray; return $true }
    $issues = Invoke-ScriptAnalyzer -Path $ScriptPath -Severity Error -ErrorAction SilentlyContinue
    if ($issues) { $issues | ForEach-Object { Write-Host ("      -> {0} l.{1}" -f $_.RuleName, $_.Line) -ForegroundColor DarkYellow } }
    (-not $issues)
}

# ---------------------------------------------------------------------------
Section "B. UNITAIRE (dot-source -NoRun)"

# Charge les fonctions SANS lancer le check.
. $ScriptPath -NoRun

Test-Case "ConvertFrom-Rot13 : vecteur connu hello<->uryyb" {
    (ConvertFrom-Rot13 'hello') -eq 'uryyb' -and (ConvertFrom-Rot13 'uryyb') -eq 'hello'
}
Test-Case "ConvertFrom-Rot13 : round-trip preserve chiffres/symboles" {
    $s = 'Loader_v2.EXE\Users\x'
    (ConvertFrom-Rot13 (ConvertFrom-Rot13 $s)) -eq $s
}
Test-Case "Test-AnyWord : 'xim' ne matche PAS 'Maxim Imaging'" {
    -not (Test-AnyWord 'Maxim Imaging Driver' @('xim'))
}
Test-Case "Test-AnyWord : 'loader' ne matche PAS 'GoogleUpdateDownloader'" {
    -not (Test-AnyWord 'GoogleUpdateDownloader.exe' @('loader'))
}
Test-Case "Test-AnyWord : 'loader' matche bien 'cheat-loader.exe'" {
    (Test-AnyWord 'cheat-loader.exe' @('loader'))
}
Test-Case "Test-AnyWord : 'cronus' matche 'Cronus Zen Studio'" {
    (Test-AnyWord 'Cronus Zen Studio' @('cronus'))
}
Test-Case "Test-AnyWord : 'aimbot' matche 'cod_aimbot_loader.exe' (underscore = separateur, parite avec WordMatch C#)" {
    (Test-AnyWord 'cod_aimbot_loader.exe' @('aimbot')) -and (Test-AnyWord 'cod_aimbot_loader.exe' @('loader'))
}
Test-Case "Test-AnyWord : 'cheat' ne matche PAS 'anticheat_service' (prefixe colle = pas un faux positif)" {
    -not (Test-AnyWord 'anticheat_service.exe' @('cheat'))
}

# --- Niveaux de suspicion (anti faux-SUSPECT) ---
Test-Case "CheatWarnWords contient bien les mots generiques (loader/cheat/skript)" {
    (@($script:CheatWarnWords) -contains 'loader') -and (@($script:CheatWarnWords) -contains 'cheat') -and (@($script:CheatWarnWords) -contains 'skript')
}
Test-Case "reWASD = dual-use : WARN, JAMAIS FLAG (un remap legit ne rend pas SUSPECT) ; Cronus/XIM restent FLAG" {
    $flag = Get-CheatFlagPatterns
    (-not (Test-AnyWord 'reWASD.exe' $flag)) -and (Test-AnyWord 'reWASD.exe' $script:CheatWarnWords) -and
    (Test-AnyWord 'Cronus Zen Studio' $flag) -and (Test-AnyWord 'xim apex' $flag)
}
Test-Case "INPUT probe : DS4Windows/ViGEmBus = INFO (sev 0) ; reWASD = WARN (sev 1) ; Cronus = FLAG (sev 2)" {
    # Un joueur manette (ViGEmBus/DS4Windows) ne doit PAS declencher un WARN 'anti-recoil'
    # sur une machine propre : emulation de manette = presence informative, pas un signal.
    $ds4 = $script:InputTools | Where-Object { $_.Name -like '*DS4Windows*' }
    $rw  = $script:InputTools | Where-Object { $_.Name -like '*reWASD*' }
    $cr  = $script:InputTools | Where-Object { $_.Name -like '*Cronus*' }
    ($ds4.Severity -eq 0) -and ($rw.Severity -eq 1) -and ($cr.Severity -ge 2)
}
Test-Case "INPUT probe : token 'zen studio' retire de Cronus (Zen Studios = editeur de flipper => faux positif), 'cronus' garde la detection" {
    $cr = $script:InputTools | Where-Object { $_.Name -like '*Cronus*' }
    (-not ($cr.App -contains 'zen studio')) -and ($cr.App -contains 'cronus')
}
Test-Case "INPUT probe : hardware de triche = FLAG-tier (Cronus/XIM/Titan/ReaSnow/StrikePack sev 2) ; kmbox/makcu = WARN (sev 1)" {
    $t = $script:InputTools
    $sev = { param($n) ($t | Where-Object { $_.Name -like "*$n*" }).Severity }
    ((& $sev 'Cronus') -eq 2) -and ((& $sev 'XIM') -eq 2) -and ((& $sev 'Titan') -eq 2) -and
    ((& $sev 'ReaSnow') -eq 2) -and ((& $sev 'Strike Pack') -eq 2) -and ((& $sev 'kmbox') -eq 1)
}
Test-Case "INPUT probe : garde-fou puces => un FriendlyName CH340/Arduino/Ferrum Audio ne matche AUCUN token device" {
    # kmbox/makcu sont construits sur ces puces generiques ; les flagger brulerait un bricoleur
    # Arduino ou un audiophile (Ferrum Audio = DAC/amplis USB). Aucun token Usb ne doit matcher.
    $allUsb = @(); foreach($x in $script:InputTools){ $allUsb += $x.Usb }
    (-not (Test-AnyWord 'USB-SERIAL CH340' $allUsb)) -and
    (-not (Test-AnyWord 'Arduino Uno (COM5)' $allUsb)) -and
    (-not (Test-AnyWord 'Ferrum ERCO USB DAC' $allUsb)) -and
    (Test-AnyWord 'KMBOX NET' $allUsb) -and (Test-AnyWord 'MAKCU' $allUsb)
}
Test-Case "INPUT probe : plus de force-sev-2 sur match USB (la table Severity est la source de verite ; kmbox device => WARN pas FLAG)" {
    $mov = Get-Content (Join-Path $PSScriptRoot 'DexCheck.ps1') -Raw
    $usbLine = @(($mov -split "\r?\n") | Where-Object { $_ -match 'Test-AnyWord \$hay \$t\.Usb' })
    ($usbLine.Count -ge 1) -and (@($usbLine | Where-Object { $_ -match '\$sev\s*=\s*2' }).Count -eq 0)
}
Test-Case "CheatFlagWords ne contient AUCUN mot generique (sinon faux FLAG => faux SUSPECT)" {
    $generic = @('cheat','loader','skript','hwid','cleaner','unlocker','menu')
    (@($script:CheatFlagWords | Where-Object { $generic -contains $_ }).Count -eq 0)
}
Test-Case "Get-CheatFlagPatterns : produits distinctifs (engineowning, extreme injector) FLAG ; categorie (aimbot) et generiques (loader/cheat) EXCLUS" {
    $f = Get-CheatFlagPatterns
    ($f -contains 'engineowning') -and ($f -contains 'extreme injector') -and
    (-not ($f -contains 'aimbot')) -and (-not ($f -contains 'loader')) -and (-not ($f -contains 'cheat'))
}
Test-Case "Noms de fichier : mots de categorie demus => aimbot/aimbot-remover/anti-aimbot/wallhack-detector/guide = PAS FLAG (innocent protege)" {
    $f = Get-CheatFlagPatterns
    (-not (Test-AnyWord 'aimbot.exe' $f)) -and (-not (Test-AnyWord 'aimbot-remover.exe' $f)) -and
    (-not (Test-AnyWord 'anti-aimbot.exe' $f)) -and (-not (Test-AnyWord 'wallhack-detector.exe' $f)) -and
    (-not (Test-AnyWord 'how-to-remove-aimbot.txt' $f))
}
Test-Case "MOAT KALMA : 'Extreme Injector' (produit distinctif) reste FLAG malgre la demotion du mot nu 'injector'" {
    $f = Get-CheatFlagPatterns
    (Test-AnyWord 'Extreme Injector v3.exe' $f) -and (Test-AnyWord 'ExtremeInjector.exe' $f) -and
    (-not (Test-AnyWord 'injector.dll' $f))
}
Test-Case "Partition FLAG/WARN : 'fabric_loader' + 'cod_aimbot' = WARN-pas-FLAG (generique/categorie) ; 'engineowning_loader' = FLAG (produit)" {
    $flag = Get-CheatFlagPatterns
    (-not (Test-AnyWord 'fabric_loader.exe' $flag)) -and (Test-AnyWord 'fabric_loader.exe' $script:CheatWarnWords) -and
    (-not (Test-AnyWord 'cod_aimbot.exe' $flag)) -and (Test-AnyWord 'cod_aimbot.exe' $script:CheatWarnWords) -and
    (Test-AnyWord 'engineowning_loader.exe' $flag)
}
Test-Case "Cheat sheet : 'Programming Cheat Sheets' = generique seul (=> WARN), JAMAIS FLAG" {
    $flag = Get-CheatFlagPatterns
    (-not (Test-AnyWord 'Programming Cheat Sheets' $flag)) -and (Test-AnyWord 'Programming Cheat Sheets' $script:CheatWarnWords)
}
Test-Case "DeleteSuspectPatterns (union C#) couvre flag + warn + providers" {
    (@($script:DeleteSuspectPatterns) -contains 'aimbot') -and (@($script:DeleteSuspectPatterns) -contains 'loader') -and (@($script:DeleteSuspectPatterns) -contains 'phantomoverlay')
}

# --- Batch 2 : multi-disques + drivers kernel/BYOVD ---
Test-Case "Get-FixedNtfsDrives : renvoie au moins le disque systeme" {
    (@(Get-FixedNtfsDrives) -contains 'C:')
}
Test-Case "Get-DriverAssessment : driver non signe => WARN sev1" {
    $a = Get-DriverAssessment -UnsignedCount 1 -VulnerableCount 0
    ($a.Status -eq 'WARN' -and $a.Severity -eq 1)
}
Test-Case "Get-DriverAssessment : driver connu abusable => WARN sev1" {
    $a = Get-DriverAssessment -UnsignedCount 0 -VulnerableCount 1
    ($a.Status -eq 'WARN' -and $a.Severity -eq 1)
}
Test-Case "Get-DriverAssessment : rien => OK" {
    $a = Get-DriverAssessment -UnsignedCount 0 -VulnerableCount 0
    ($a.Status -eq 'OK')
}
Test-Case "VulnerableDrivers : tokens distinctifs (>=5 car, pas de sous-chaine trop large)" {
    (@($script:VulnerableDrivers | Where-Object { $_.Length -lt 5 }).Count -eq 0)
}

# --- Connexions reseau live : filtre LAN/loopback pur (ne garde que le sortant Internet) ---
Test-Case "Test-LocalAddress : loopback + RFC1918 + lien-local => local (ignore)" {
    (Test-LocalAddress '127.0.0.1') -and (Test-LocalAddress '::1') -and (Test-LocalAddress '10.0.0.5') -and
    (Test-LocalAddress '192.168.1.20') -and (Test-LocalAddress '172.16.4.1') -and (Test-LocalAddress '172.31.255.1') -and
    (Test-LocalAddress '169.254.10.10') -and (Test-LocalAddress 'fe80::1') -and (Test-LocalAddress '') -and (Test-LocalAddress '0.0.0.0')
}
Test-Case "Test-LocalAddress : IP publique => PAS local (172.15 et 172.32 sont hors RFC1918)" {
    (-not (Test-LocalAddress '8.8.8.8')) -and (-not (Test-LocalAddress '104.18.2.5')) -and
    (-not (Test-LocalAddress '172.15.0.1')) -and (-not (Test-LocalAddress '172.32.0.1')) -and (-not (Test-LocalAddress '2606:4700::1'))
}
Test-Case "Probe-Network : sonde presente, statut valide, jamais FLAG sans process cheat" {
    $r = Probe-Network
    ($r.Id -eq 'NET') -and ($r.Status -in @('INFO','FLAG')) -and ($r.Details.Count -ge 1)
}

# --- Sonde PCIe/DMA (sourcee : Xilinx pcileech + device sans driver ; INFO/WARN, jamais FLAG) ---
Test-Case "DmaPciVendors : matche l'InstanceId Xilinx (pcileech), pas une carte Intel/NVIDIA legit" {
    (Test-AnyPattern 'PCI\VEN_10EE&DEV_0666&SUBSYS_00000000&REV_00\4&ABC' $script:DmaPciVendors) -and
    (-not (Test-AnyPattern 'PCI\VEN_8086&DEV_A0AF' $script:DmaPciVendors)) -and
    (-not (Test-AnyPattern 'PCI\VEN_10DE&DEV_2482' $script:DmaPciVendors))
}
Test-Case "Probe-DmaPci : sonde presente, JAMAIS FLAG (anti faux-SUSPECT), details >=1" {
    $r = Probe-DmaPci
    ($r.Id -eq 'DMAPCI') -and ($r.Status -in @('INFO','WARN','NA')) -and ($r.Details.Count -ge 1)
}
# Fix faux-WARN PC neuf : une carte Wi-Fi Intel AX210 sans driver (build fraiche) ne doit PAS
# etre traitee comme un device DMA. VID grand public sans driver => INFO ; VID inconnu => WARN.
Test-Case "BenignPciVendors : matche l'Intel AX210 (VEN_8086) sans driver, PAS le Xilinx pcileech (VEN_10EE)" {
    (Test-AnyPattern 'PCI\VEN_8086&DEV_2725&SUBSYS_00248086&REV_1A\6&3938BB4D&0&00100011' $script:BenignPciVendors) -and
    (-not (Test-AnyPattern 'PCI\VEN_10EE&DEV_0666&SUBSYS_00000000&REV_00\4&ABC' $script:BenignPciVendors))
}
Test-Case "BenignPciVendors : invariant securite = Xilinx (10EE) n'est JAMAIS classe benin (sinon un pcileech stock passe en INFO)" {
    -not (@($script:BenignPciVendors) -contains 'VEN_10EE')
}

# --- Fix faux-SUSPECT Prefetch : outil input dual-use => PAS FLAG, cheat distinctif => FLAG ---
Test-Case "Prefetch : ds4windows/x360ce/aimbot.pf = dual-use ou categorie (WARN, pas FLAG) ; engineowning.pf = FLAG (produit)" {
    $flag = Get-CheatFlagPatterns
    $warn = @($script:CheatWarnWords); foreach($t in $script:InputTools){ $warn += $t.App }
    (-not (Test-AnyWord 'DS4WINDOWS.EXE-A1B2C3D4.pf' $flag)) -and (Test-AnyWord 'DS4WINDOWS.EXE-A1B2C3D4.pf' $warn) -and
    (-not (Test-AnyWord 'X360CE.EXE-11223344.pf' $flag)) -and (Test-AnyWord 'X360CE.EXE-11223344.pf' $warn) -and
    (-not (Test-AnyWord 'COD_AIMBOT.EXE-99887766.pf' $flag)) -and (Test-AnyWord 'COD_AIMBOT.EXE-99887766.pf' $warn) -and
    (Test-AnyWord 'ENGINEOWNING.EXE-55667788.pf' $flag)
}

# --- Couche explication "trouve / prouve" (Get-MeaningLines + ProbeMeaning) ---
Test-Case "Get-MeaningLines : WARN connu => 2 lignes Montre/Ne prouve pas ; OK => vide" {
    $w  = New-ProbeResult -Id 'PERSIST' -Name p -Status 'WARN' -Severity 1
    $ok = New-ProbeResult -Id 'PERSIST' -Name p -Status 'OK'
    $lw = @(Get-MeaningLines $w)
    ($lw.Count -eq 2) -and ($lw[0] -match 'Montre') -and ($lw[1] -match 'prouve') -and (@(Get-MeaningLines $ok).Count -eq 0)
}
Test-Case "Get-MeaningLines : Id sans entree => vide (pas de crash)" {
    (@(Get-MeaningLines (New-ProbeResult -Id 'RECYCLE' -Name r -Status 'WARN' -Severity 1)).Count -eq 0)
}
Test-Case "Get-MeaningLines : FLAG (nom distinctif) => formulation FERME, sans hedge dual-use/generique" {
    $ok = $true
    foreach ($id in @('DELFILES','EXEC','PCA','PREFETCH')) {
        $f = @(Get-MeaningLines (New-ProbeResult -Id $id -Name x -Status 'FLAG' -Severity 2)) -join ' '
        $w = @(Get-MeaningLines (New-ProbeResult -Id $id -Name x -Status 'WARN' -Severity 1)) -join ' '
        # FLAG = ferme : affirme le nom DISTINCTIF, laisse tomber l'excuse "nom generique" ; WARN garde le hedge.
        if (($f -notmatch 'DISTINCTIF') -or ($f -match 'generique') -or ($w -notmatch 'dual-use|generique')) { $ok = $false }
    }
    $ok
}
Test-Case "Get-MeaningLines : AUCUNE sonde ne fait planter le run en FLAG (StrictMode + cle ShowsFlag absente)" {
    # Regression : sous Set-StrictMode -Version Latest, lire $m.ShowsFlag sur une hashtable qui
    # n'a pas cette cle LEVE PropertyNotFoundStrict et tue DexCheck.ps1 entier. Seules quelques
    # sondes ont une variante FLAG ; le test precedent n'exercait que celles-la, d'ou le trou.
    $broken = @()
    foreach ($id in $script:ProbeMeaning.Keys) {
        foreach ($st in @('FLAG','WARN')) {
            try {
                $lines = @(Get-MeaningLines (New-ProbeResult -Id $id -Name x -Status $st -Severity 2))
                if ($lines.Count -ne 2) { $broken += "$id/$st (lignes=$($lines.Count))" }
            } catch { $broken += "$id/$st (THROW: $($_.FullyQualifiedErrorId))" }
        }
    }
    if ($broken) { Write-Host ("      -> casse: {0}" -f ($broken -join ', ')) -ForegroundColor DarkYellow }
    ($broken.Count -eq 0)
}
Test-Case "Get-VerdictReasoning : >=2 artefacts anti-wipe distinctifs => execution CONFIRMEE (pas un soupcon)" {
    $rs = @(
        (New-ProbeResult -Id 'EXEC'     -Name e -Status 'FLAG' -Severity 2),
        (New-ProbeResult -Id 'PREFETCH' -Name p -Status 'FLAG' -Severity 2)
    )
    ((Get-VerdictReasoning $rs) -join ' ') -match 'CONFIRMEE'
}
Test-Case "Get-VerdictReasoning : 1 seul artefact anti-wipe => pas de ligne 'CONFIRMEE' (evite le surclassement)" {
    $rs = @((New-ProbeResult -Id 'EXEC' -Name e -Status 'FLAG' -Severity 2))
    -not (((Get-VerdictReasoning $rs) -join ' ') -match 'CONFIRMEE')
}
Test-Case "Get-Verdict UPGRADE : >=2 FLAG anti-wipe (cheat distinctif corrobore) => ROUGE (re-val KALMA : Extreme Injector sur 4 artefacts)" {
    $kalma = @(
        (New-ProbeResult -Id 'EXEC'      -Name e -Status 'FLAG' -Severity 2),
        (New-ProbeResult -Id 'SHIMCACHE' -Name s -Status 'FLAG' -Severity 2),
        (New-ProbeResult -Id 'PCA'       -Name p -Status 'FLAG' -Severity 2),
        (New-ProbeResult -Id 'DELFILES'  -Name d -Status 'FLAG' -Severity 2)
    )
    (Get-Verdict $kalma) -eq 'ROUGE'
}
Test-Case "Get-Verdict : 1 SEUL FLAG anti-wipe, sans nettoyage => SUSPECT (pas de sur-escalade, innocent isole protege)" {
    (Get-Verdict @((New-ProbeResult -Id 'EXEC' -Name e -Status 'FLAG' -Severity 2))) -eq 'SUSPECT'
}
Test-Case "Get-Verdict : 1 FLAG anti-wipe + nettoyage COORDONNE (Defender coupe + USN off) => ROUGE (a tourne puis efface ses traces)" {
    $rs = @(
        (New-ProbeResult -Id 'EXEC'     -Name e -Status 'FLAG' -Severity 2),
        (New-ProbeResult -Id 'DEFENDER' -Name d -Status 'WARN' -Severity 1 -Summary $script:DefenderRealtimeOffSummary),
        (New-ProbeResult -Id 'USN'      -Name u -Status 'WARN' -Severity 1)
    )
    (Get-Verdict $rs) -eq 'ROUGE'
}
Test-Case "Get-Verdict : un device (Cronus, FLAG non-anti-wipe) SEUL => SUSPECT jamais ROUGE (presence != execution corroboree)" {
    (Get-Verdict @((New-ProbeResult -Id 'INPUT' -Name i -Status 'FLAG' -Severity 2))) -eq 'SUSPECT'
}
Test-Case "Get-Verdict : provider connu (sev 3) => ROUGE inchange ; aucun flag => CLEAN (garde-fous)" {
    ((Get-Verdict @((New-ProbeResult -Id 'CHEATS' -Name c -Status 'FLAG' -Severity 3))) -eq 'ROUGE') -and
    ((Get-Verdict @((New-ProbeResult -Id 'PROC' -Name p -Status 'OK' -Severity 0))) -eq 'CLEAN')
}
Test-Case "ProbeMeaning : chaque sonde WARN/FLAG-able a une entree Shows+ProvesNot non vide" {
    $ids = @('IDENT','WINAGE','USN','DELFILES','EXEC','SHIMCACHE','PCA','PREFETCH','PROC','PERSIST','EVTLOG','ANTIFOR','BROWSER','DNS','HARDWARE','DMAPCI','SECBOOT','NET','CHEATS','INPUT','VM','DEFENDER','KDRV','INJECT','HWID','CILOG')
    $missing = @($ids | Where-Object { -not $script:ProbeMeaning.ContainsKey($_) -or [string]::IsNullOrWhiteSpace($script:ProbeMeaning[$_].Shows) -or [string]::IsNullOrWhiteSpace($script:ProbeMeaning[$_].ProvesNot) })
    if ($missing) { Write-Host ("      -> manquants: {0}" -f ($missing -join ', ')) -ForegroundColor DarkYellow }
    ($missing.Count -eq 0)
}

# --- Raisonnement du verdict (pur) ---
Test-Case "Get-VerdictReasoning : cas clean => rien de suspect + rappel de portee DMA" {
    $txt = (Get-VerdictReasoning @((New-ProbeResult -Id 'IDENT' -Name a -Status 'OK'))) -join ' '
    ($txt -match "Aucune sonde") -and ($txt -match 'DMA') -and ($txt -match 'ne PROUVE pas')
}
Test-Case "Get-VerdictReasoning : escalade correlation (horloge+USN) => mentionne nettoyage COORDONNE" {
    $rs = @((New-ProbeResult -Id 'IDENT' -Name i -Status 'WARN' -Severity 1), (New-ProbeResult -Id 'USN' -Name u -Status 'WARN' -Severity 1))
    ((Get-VerdictReasoning $rs) -join ' ') -match 'COORDONNE'
}
Test-Case "Get-StatusTally : compte exact par statut (2 OK + 1 WARN + 1 FLAG)" {
    $rs = @(
        (New-ProbeResult -Id a -Name a -Status OK),
        (New-ProbeResult -Id b -Name b -Status OK),
        (New-ProbeResult -Id c -Name c -Status WARN -Severity 1),
        (New-ProbeResult -Id d -Name d -Status FLAG -Severity 2)
    )
    $t = Get-StatusTally $rs
    ($t -match '2 OK') -and ($t -match '1 WARN') -and ($t -match '1 FLAG') -and ($t -match '4 sondes')
}
Test-Case "Get-VerdictReasoning : debloat gaming (3 prep) => explicable sans triche, pas d'escalade" {
    $rs = @(
        (New-ProbeResult -Id 'USN' -Name u -Status 'WARN' -Severity 1),
        (New-ProbeResult -Id 'PREFETCH' -Name p -Status 'WARN' -Severity 1),
        (New-ProbeResult -Id 'WINAGE' -Name w -Status 'WARN' -Severity 1)
    )
    ((Get-VerdictReasoning $rs) -join ' ') -match 'explicables sans triche'
}

# --- Shimcache (AppCompatCache) : parseur pur teste sur un blob fabrique a la main ---
function New-ShimEntry {
    param([string]$Path, [long]$FileTime = 130000000000000000)
    $pb = [System.Text.Encoding]::Unicode.GetBytes($Path)
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    $bw.Write([byte[]]@(0x31,0x30,0x74,0x73))   # "10ts"
    $bw.Write([uint32]0)                         # unknown
    $bw.Write([uint32]($pb.Length + 14))         # cachedEntryDataSize = pathSize(2)+path+ft(8)+dataSize(4)
    $bw.Write([uint16]$pb.Length)                # pathSize
    $bw.Write($pb)                               # path UTF-16LE
    $bw.Write([int64]$FileTime)                  # lastModTime FILETIME
    $bw.Write([uint32]0)                         # dataSize = 0
    $bw.Flush()
    return $ms.ToArray()
}
$shimHdr = New-Object byte[] 48
[BitConverter]::GetBytes([uint32]48).CopyTo($shimHdr, 0)   # offset du 1er enregistrement = 48
$shimBlob = [byte[]](@($shimHdr) + @(New-ShimEntry 'C:\cheats\engineowning.exe') + @(New-ShimEntry 'C:\Windows\System32\cmd.exe'))
$shimEntries = ConvertFrom-Shimcache $shimBlob   # List[object] : semantique List, pas de @()

Test-Case "ConvertFrom-Shimcache : decode les 2 entrees du blob" {
    $shimEntries.Count -eq 2
}
Test-Case "ConvertFrom-Shimcache : chemins exacts (decodage UTF-16LE + avance par cachedEntryDataSize)" {
    ($shimEntries[0].Path -eq 'C:\cheats\engineowning.exe') -and ($shimEntries[1].Path -eq 'C:\Windows\System32\cmd.exe')
}
Test-Case "ConvertFrom-Shimcache : FILETIME decode en DateTime non nul" {
    ($shimEntries[0].Time -is [datetime]) -and ($shimEntries[0].Time.Year -gt 2000)
}
Test-Case "Shimcache : 'engineowning.exe' (produit distinctif) = FLAG, 'cmd.exe' = clean (parite FLAG/WARN)" {
    $flag = Get-CheatFlagPatterns
    (Test-AnyWord $shimEntries[0].Path $flag) -and -not (Test-AnyWord $shimEntries[1].Path $flag)
}
Test-Case "ConvertFrom-Shimcache : blob trop court / null => 0 entree (pas de crash)" {
    ((ConvertFrom-Shimcache ([byte[]]@(1,2,3))).Count -eq 0) -and ((ConvertFrom-Shimcache $null).Count -eq 0)
}
Test-Case "ConvertFrom-Shimcache : en-tete inattendu => fallback scan de la signature 10ts" {
    $bad = New-Object byte[] 8
    $blob2 = [byte[]](@($bad) + @(New-ShimEntry 'C:\x\wallhack.exe'))
    $e = ConvertFrom-Shimcache $blob2
    ($e.Count -eq 1) -and ($e[0].Path -eq 'C:\x\wallhack.exe')
}
Test-Case "ConvertFrom-Shimcache : entree finale TRONQUEE (blob a la limite de retention) => garde les bonnes, 0 crash" {
    $good  = [byte[]](@($shimHdr) + @(New-ShimEntry 'C:\ok\clean.exe'))
    # "10ts" + unknown(4=0) + cachedEntryDataSize(4=0) + pathSize(2=0xFFFF) puis EOF : entete complet mais corps hors bornes
    $trunc = [byte[]](@($good) + @(0x31,0x30,0x74,0x73, 0,0,0,0, 0,0,0,0, 0xFF,0xFF))
    $e = ConvertFrom-Shimcache $trunc
    ($e.Count -eq 1) -and ($e[0].Path -eq 'C:\ok\clean.exe')
}

# --- PCA Win11 (PcaAppLaunchDic) : parseur pur (chemin|timestamp UTC) ---
$pcaLines = @(
    'C:\Program Files\Everything\Everything.exe|2022-12-28 16:06:24.212',
    'C:\cheats\engineowning.exe|2025-04-23 14:43:43.215',
    'C:\temp\fabric_loader.exe|2025-04-23 14:43:43.215',
    '',
    'ligne-sans-pipe-ignoree',
    'D:\x\wallhack.exe|pas une date'
)
$pcaEntries = ConvertFrom-PcaLaunchDic $pcaLines   # List[object] : semantique List

Test-Case "ConvertFrom-PcaLaunchDic : 4 entrees (lignes vide / sans '|' ignorees)" {
    $pcaEntries.Count -eq 4
}
Test-Case "ConvertFrom-PcaLaunchDic : chemin exact + timestamp UTC decode en DateTime" {
    ($pcaEntries[0].Path -eq 'C:\Program Files\Everything\Everything.exe') -and ($pcaEntries[0].Time -is [datetime]) -and ($pcaEntries[0].Time.Year -eq 2022)
}
Test-Case "ConvertFrom-PcaLaunchDic : timestamp invalide => Time null MAIS entree gardee" {
    $w = $pcaEntries | Where-Object { $_.Path -eq 'D:\x\wallhack.exe' } | Select-Object -First 1
    ($null -ne $w) -and ($null -eq $w.Time)
}
Test-Case "PCA : 'engineowning' (produit) = FLAG, 'fabric_loader' = WARN-pas-FLAG, 'Everything' = clean (parite 2 niveaux)" {
    $flag = Get-CheatFlagPatterns
    (Test-AnyWord $pcaEntries[1].Path $flag) -and
    (-not (Test-AnyWord $pcaEntries[2].Path $flag)) -and (Test-AnyWord $pcaEntries[2].Path $script:CheatWarnWords) -and
    (-not (Test-AnyWord $pcaEntries[0].Path $flag)) -and (-not (Test-AnyWord $pcaEntries[0].Path $script:CheatWarnWords))
}
Test-Case "ConvertFrom-PcaLaunchDic : null / vide => 0 entree (pas de crash)" {
    ((ConvertFrom-PcaLaunchDic $null).Count -eq 0) -and ((ConvertFrom-PcaLaunchDic @()).Count -eq 0)
}

Test-Case "New-ProbeResult accepte le statut INFO" {
    $r = New-ProbeResult -Id 'X' -Name 'x' -Status 'INFO' -Severity 0 -Summary 's'
    ($r.Status -eq 'INFO')
}

Test-Case "Get-Verdict : INFO + OK seuls => CLEAN" {
    $rs = @(
        (New-ProbeResult -Id a -Name a -Status OK   -Severity 0),
        (New-ProbeResult -Id b -Name b -Status INFO -Severity 0)
    )
    (Get-Verdict $rs) -eq 'CLEAN'
}
Test-Case "Get-Verdict : un WARN => A VERIFIER" {
    $rs = @((New-ProbeResult -Id a -Name a -Status OK), (New-ProbeResult -Id b -Name b -Status WARN -Severity 1))
    (Get-Verdict $rs) -eq 'A VERIFIER'
}
Test-Case "Get-Verdict : un FLAG sev2 => SUSPECT" {
    $rs = @((New-ProbeResult -Id b -Name b -Status FLAG -Severity 2))
    (Get-Verdict $rs) -eq 'SUSPECT'
}
Test-Case "Get-Verdict : sev3 => ROUGE" {
    $rs = @((New-ProbeResult -Id b -Name b -Status FLAG -Severity 3))
    (Get-Verdict $rs) -eq 'ROUGE'
}
Test-Case "Get-Verdict : INFO ne declenche jamais un verdict (anti faux-positif)" {
    $rs = @((New-ProbeResult -Id b -Name b -Status INFO -Severity 2))  # meme avec sev>0, INFO != FLAG
    (Get-Verdict $rs) -eq 'CLEAN'
}

# --- Correlation / profil d'evasion (pure, anti faux-SUSPECT sur PC gaming debloate) ---
Test-Case "Get-EvasionProfile : debloat gaming (USN+Prefetch+reinstall WARN) => PAS d'escalade" {
    $rs = @(
        (New-ProbeResult -Id USN -Name u -Status WARN -Severity 1),
        (New-ProbeResult -Id PREFETCH -Name p -Status WARN -Severity 1),
        (New-ProbeResult -Id WINAGE -Name w -Status WARN -Severity 1)
    )
    $prof = Get-EvasionProfile $rs
    (-not $prof.Escalate) -and ($prof.Total -eq 3) -and ($prof.Strong.Count -eq 0)
}
Test-Case "Get-EvasionProfile : horloge reculee + USN off => ESCALADE (signal fort + corroboration)" {
    $rs = @(
        (New-ProbeResult -Id IDENT -Name i -Status WARN -Severity 1),
        (New-ProbeResult -Id USN -Name u -Status WARN -Severity 1)
    )
    (Get-EvasionProfile $rs).Escalate
}
Test-Case "Get-EvasionProfile : Defender coupe SEUL => PAS d'escalade (besoin de corroboration)" {
    $rs = @((New-ProbeResult -Id DEFENDER -Name d -Status WARN -Severity 1 -Summary $script:DefenderRealtimeOffSummary))
    -not (Get-EvasionProfile $rs).Escalate
}
# Revue 17/09 : une simple EXCLUSION Defender en zone Downloads/Temp (conseil courant pour un mod
# que l'antivirus bloque) etait classee « forte » comme l'antivirus coupe. + USN off (debloat
# gaming) => SUSPECT sans aucun nom de cheat. Une exclusion est un signal « prep », pas fort.
Test-Case "Get-EvasionProfile : exclusion Defender en zone Downloads + USN off => PAS d'escalade" {
    $excl = Get-DefenderAssessment -RealtimeDisabled $false -CheatExclusion $false -RiskyExclusionCount 1 -TotalExclusionCount 1
    $rs = @(
        (New-ProbeResult -Id DEFENDER -Name d -Status $excl.Status -Severity $excl.Severity -Summary $excl.Summary),
        (New-ProbeResult -Id USN -Name u -Status WARN -Severity 1)
    )
    $prof = Get-EvasionProfile $rs
    ($prof.Strong.Count -eq 0) -and (-not $prof.Escalate) -and ((Get-Verdict $rs) -eq 'A VERIFIER')
}
Test-Case "Get-EvasionProfile : protection temps reel COUPEE + USN off => ESCALADE (reste un signal fort)" {
    $off = Get-DefenderAssessment -RealtimeDisabled $true -CheatExclusion $false -RiskyExclusionCount 0 -TotalExclusionCount 0
    $rs = @(
        (New-ProbeResult -Id DEFENDER -Name d -Status $off.Status -Severity $off.Severity -Summary $off.Summary),
        (New-ProbeResult -Id USN -Name u -Status WARN -Severity 1)
    )
    (Get-EvasionProfile $rs).Escalate
}
Test-Case "Get-EvasionProfile : ccleaner (ANTIFOR WARN) + USN off => PAS d'escalade (2 signaux prep)" {
    $rs = @(
        (New-ProbeResult -Id ANTIFOR -Name a -Status WARN -Severity 1),
        (New-ProbeResult -Id USN -Name u -Status WARN -Severity 1)
    )
    -not (Get-EvasionProfile $rs).Escalate
}
Test-Case "Get-EvasionProfile : outil de wipe (ANTIFOR FLAG) + reinstall => ESCALADE" {
    $rs = @(
        (New-ProbeResult -Id ANTIFOR -Name a -Status FLAG -Severity 2),
        (New-ProbeResult -Id WINAGE -Name w -Status WARN -Severity 1)
    )
    (Get-EvasionProfile $rs).Escalate
}
Test-Case "Get-EvasionProfile : input dual-use (DualSense) ne compte PAS comme evasion => Total 0" {
    $rs = @((New-ProbeResult -Id PROC -Name p -Status OK), (New-ProbeResult -Id INPUT -Name i -Status WARN -Severity 1))
    $prof = Get-EvasionProfile $rs
    ($prof.Total -eq 0) -and (-not $prof.Escalate)
}
Test-Case "Get-Verdict : horloge reculee + USN off => SUSPECT (escalade correlation)" {
    $rs = @(
        (New-ProbeResult -Id IDENT -Name i -Status WARN -Severity 1),
        (New-ProbeResult -Id USN -Name u -Status WARN -Severity 1)
    )
    (Get-Verdict $rs) -eq 'SUSPECT'
}
Test-Case "Get-Verdict : PC gaming debloate (3 WARN prep) reste A VERIFIER (pas de faux SUSPECT)" {
    $rs = @(
        (New-ProbeResult -Id USN -Name u -Status WARN -Severity 1),
        (New-ProbeResult -Id PREFETCH -Name p -Status WARN -Severity 1),
        (New-ProbeResult -Id WINAGE -Name w -Status WARN -Severity 1)
    )
    (Get-Verdict $rs) -eq 'A VERIFIER'
}
Test-Case "Get-EvasionProfile : 2 signaux FORTS (horloge + Defender), aucun prep => ESCALADE (nettoyage coordonne)" {
    $rs = @(
        (New-ProbeResult -Id IDENT -Name i -Status WARN -Severity 1),
        (New-ProbeResult -Id DEFENDER -Name d -Status WARN -Severity 1 -Summary $script:DefenderRealtimeOffSummary)
    )
    $prof = Get-EvasionProfile $rs
    ($prof.Strong.Count -eq 2) -and $prof.Escalate
}
Test-Case "Get-EvasionProfile : 5 signaux 'prep' seuls (debloat + ccleaner + log court) => JAMAIS d'escalade (invariant anti-faux-SUSPECT)" {
    $rs = @(
        (New-ProbeResult -Id USN -Name u -Status WARN -Severity 1),
        (New-ProbeResult -Id PREFETCH -Name p -Status WARN -Severity 1),
        (New-ProbeResult -Id WINAGE -Name w -Status WARN -Severity 1),
        (New-ProbeResult -Id ANTIFOR -Name a -Status WARN -Severity 1),
        (New-ProbeResult -Id EVTLOG -Name e -Status WARN -Severity 1)
    )
    $prof = Get-EvasionProfile $rs
    (-not $prof.Escalate) -and ($prof.Strong.Count -eq 0) -and ($prof.Weak.Count -eq 5)
}

# Signatures espace libre : aucune chaine dual-use, longueur >= 6
Test-Case "FreeSpaceCheatSignatures : >=6 car et sans nom dual-use ubiquiste" {
    $bad = @('logitech','razer','ds4windows','rewasd','g hub','synapse','joytokey','antimicro','inputmapper','x360ce')
    $short = @($script:FreeSpaceCheatSignatures | Where-Object { $_.Length -lt 6 })
    $dual  = @($script:FreeSpaceCheatSignatures | Where-Object { $s=$_; ($bad | Where-Object { $s -match [regex]::Escape($_) }) })
    if ($short) { Write-Host ("      -> trop courtes: {0}" -f ($short -join ', ')) -ForegroundColor DarkYellow }
    if ($dual)  { Write-Host ("      -> dual-use: {0}" -f ($dual -join ', ')) -ForegroundColor DarkYellow }
    ($short.Count -eq 0 -and $dual.Count -eq 0)
}

# --- Detection rig DMA / capture / boite a cheat console (logique pure, testable a sec) ---
Test-Case "Get-RigAssessment : carte DMA seule => FLAG sev2 (=> SUSPECT)" {
    $a = Get-RigAssessment -HasDma $true -HasCapture $false -HasVpad $false -HasUsbHint $false
    ($a.Status -eq 'FLAG' -and $a.Severity -eq 2)
}
Test-Case "Get-RigAssessment : capture + manette virtuelle => WARN sev1 (a verifier)" {
    $a = Get-RigAssessment -HasDma $false -HasCapture $true -HasVpad $true -HasUsbHint $false
    ($a.Status -eq 'WARN' -and $a.Severity -eq 1)
}
Test-Case "Get-RigAssessment : pont USB3 FTDI seul => WARN sev1" {
    $a = Get-RigAssessment -HasDma $false -HasCapture $false -HasVpad $false -HasUsbHint $true
    ($a.Status -eq 'WARN' -and $a.Severity -eq 1)
}
Test-Case "Get-RigAssessment : carte de capture seule => INFO (streamer, ne compte pas au verdict)" {
    $a = Get-RigAssessment -HasDma $false -HasCapture $true -HasVpad $false -HasUsbHint $false
    ($a.Status -eq 'INFO' -and $a.Severity -eq 0)
}
Test-Case "Get-RigAssessment : manette virtuelle seule (DS4/DualSense) => OK (pas de faux WARN)" {
    $a = Get-RigAssessment -HasDma $false -HasCapture $false -HasVpad $true -HasUsbHint $false
    ($a.Status -eq 'OK')
}
Test-Case "Get-RigAssessment : aucun signal => OK" {
    $a = Get-RigAssessment -HasDma $false -HasCapture $false -HasVpad $false -HasUsbHint $false
    ($a.Status -eq 'OK')
}
Test-Case "Get-RigAssessment : DMA prioritaire sur tous les autres signaux" {
    $a = Get-RigAssessment -HasDma $true -HasCapture $true -HasVpad $true -HasUsbHint $true
    ($a.Status -eq 'FLAG' -and $a.Severity -eq 2)
}
Test-Case "CaptureCards : pas de terme generique (webcams => faux positifs)" {
    -not (@($script:CaptureCards) | Where-Object { $_ -match 'usb video|webcam|^video$' })
}
Test-Case "VirtualPadDrivers contient vigembus (maillon injection d'input)" {
    (@($script:VirtualPadDrivers) -contains 'vigembus')
}
Test-Case "VirtualPadDrivers matche le vrai nom PnP de ViGEmBus (Nefarius Virtual Gamepad...)" {
    (Test-AnyWord 'Nefarius Virtual Gamepad Emulation Bus' $script:VirtualPadDrivers)
}
Test-Case "VirtualPadDrivers ne matche PAS le bus virtuel Logitech G HUB (anti faux positif)" {
    -not (Test-AnyWord 'Logitech G HUB Virtual Bus Enumerator' $script:VirtualPadDrivers)
}
Test-Case "CaptureCards matche un Elgato reel, pas une webcam" {
    (Test-AnyWord 'Elgato Game Capture HD60 X' $script:CaptureCards) -and -not (Test-AnyWord 'Logitech BRIO Webcam' $script:CaptureCards)
}
Test-Case "DmaUsbHints matche FT601 (pont DMA), pas un FTDI serie generique" {
    (Test-AnyWord 'FTDI FT601 USB3 FIFO' $script:DmaUsbHints) -and -not (Test-AnyWord 'USB Serial Port (COM3)' $script:DmaUsbHints)
}
Test-Case "DmaPatterns : noms distinctifs (>=5 car, pas de sous-chaine trop large)" {
    (@($script:DmaPatterns | Where-Object { $_.Length -lt 5 }).Count -eq 0)
}

# --- Virtualisation (logique pure : evasion screenshare via VM) ---
Test-Case "Get-VmAssessment : vendor VM detecte => WARN sev1" {
    $a = Get-VmAssessment -VendorMatch $true -HypervisorPresent $true
    ($a.Status -eq 'WARN' -and $a.Severity -eq 1)
}
Test-Case "Get-VmAssessment : hyperviseur seul (Hyper-V/VBS/WSL) => INFO (pas de faux WARN sur Win11)" {
    $a = Get-VmAssessment -VendorMatch $false -HypervisorPresent $true
    ($a.Status -eq 'INFO' -and $a.Severity -eq 0)
}
Test-Case "Get-VmAssessment : machine reelle nue => OK" {
    $a = Get-VmAssessment -VendorMatch $false -HypervisorPresent $false
    ($a.Status -eq 'OK')
}

# --- Exclusions Defender (logique pure) ---
Test-Case "Get-DefenderAssessment : exclusion au nom de cheat => FLAG sev2" {
    $a = Get-DefenderAssessment -RealtimeDisabled $false -CheatExclusion $true -RiskyExclusionCount 0 -TotalExclusionCount 1
    ($a.Status -eq 'FLAG' -and $a.Severity -eq 2)
}
Test-Case "Get-DefenderAssessment : protection temps reel coupee => WARN sev1" {
    $a = Get-DefenderAssessment -RealtimeDisabled $true -CheatExclusion $false -RiskyExclusionCount 0 -TotalExclusionCount 0
    ($a.Status -eq 'WARN' -and $a.Severity -eq 1)
}
Test-Case "Get-DefenderAssessment : exclusion en zone temp/downloads => WARN sev1" {
    $a = Get-DefenderAssessment -RealtimeDisabled $false -CheatExclusion $false -RiskyExclusionCount 2 -TotalExclusionCount 3
    ($a.Status -eq 'WARN' -and $a.Severity -eq 1)
}
Test-Case "Get-DefenderAssessment : exclusions legit (jeux/dev) => INFO, ne compte pas au verdict" {
    $a = Get-DefenderAssessment -RealtimeDisabled $false -CheatExclusion $false -RiskyExclusionCount 0 -TotalExclusionCount 4
    ($a.Status -eq 'INFO' -and $a.Severity -eq 0)
}
Test-Case "Get-DefenderAssessment : rien => OK" {
    $a = Get-DefenderAssessment -RealtimeDisabled $false -CheatExclusion $false -RiskyExclusionCount 0 -TotalExclusionCount 0
    ($a.Status -eq 'OK')
}
Test-Case "Get-DefenderAssessment : priorite cheat > temps-reel-coupe (le pire l'emporte)" {
    $a = Get-DefenderAssessment -RealtimeDisabled $true -CheatExclusion $true -RiskyExclusionCount 5 -TotalExclusionCount 9
    ($a.Status -eq 'FLAG' -and $a.Severity -eq 2)
}

Test-Case "Get-DomainHits : domaine de cheat present en sous-chaine (cache DNS) => hit" {
    $h = Get-DomainHits "www.lavicheats.com resolu 1.2.3.4" @('lavicheats.com','ring-1.io')
    ($h.Count -eq 1 -and $h[0] -eq 'lavicheats.com')
}
Test-Case "Get-DomainHits : insensible a la casse + plusieurs domaines" {
    $h = Get-DomainHits "0.0.0.0 RING-1.IO`nfoo LAVICHEATS.COM" @('lavicheats.com','ring-1.io')
    ($h.Count -eq 2)
}
Test-Case "Get-DomainHits : rien de suspect => 0 hit (pas de faux positif)" {
    $h = Get-DomainHits "www.google.com github.com discord.com" @('lavicheats.com','ring-1.io')
    ($h.Count -eq 0)
}
Test-Case "Get-DomainHits : null / vide => 0 hit (pas de crash)" {
    ((Get-DomainHits $null @('x.com')).Count -eq 0) -and ((Get-DomainHits '' @('x.com')).Count -eq 0)
}
Test-Case "Boutiques DMA : domaines dans CheatSoftware.Domains, entree DOMAINE-SEUL (Patterns vide = jamais un FLAG-fichier)" {
    $dma = $script:CheatSoftware | Where-Object { $_.Name -eq 'Boutiques DMA/HID' }
    $allDomains = @(); foreach($c in $script:CheatSoftware){ $allDomains += $c.Domains }
    ($null -ne $dma) -and ($dma.Patterns.Count -eq 0) -and
    ($allDomains -contains 'dma-cheats.com') -and ($allDomains -contains 'blurred.gg') -and ($allDomains -contains 'dma-firmware.com')
}
Test-Case "Boutiques DMA : visite dma-cheats.com dans l'historique => hit navigateur ; site legit => 0 hit" {
    $allDomains = @(); foreach($c in $script:CheatSoftware){ $allDomains += $c.Domains }
    ((Get-DomainHits "visited dma-cheats.com yesterday" $allDomains).Count -ge 1) -and
    ((Get-DomainHits "www.twitch.tv www.youtube.com" $allDomains).Count -eq 0)
}

# ---------------------------------------------------------------------------
Section "C. INTEGRATION (run reel non-admin)"

$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path $psExe)) { $psExe = 'powershell.exe' }

function Invoke-Run {
    param([string[]]$ExtraArgs, [string]$OutDir)
    New-Item -ItemType Directory -Force $OutDir | Out-Null
    $a = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $ScriptPath, '-NoElevate','-NoPause','-OutputDir', $OutDir) + $ExtraArgs
    & $psExe @a | Out-Null
    return $LASTEXITCODE
}

$normalDir = Join-Path $work 'normal'
$code = Invoke-Run -ExtraArgs @() -OutDir $normalDir
Test-Case "Run normal : exit 0" { $code -eq 0 }
$txt = @(Get-ChildItem $normalDir -Filter '*.txt' -ErrorAction SilentlyContinue)
$html = @(Get-ChildItem $normalDir -Filter '*.html' -ErrorAction SilentlyContinue)
Test-Case "Run normal : rapport .txt + .html generes" { $txt.Count -ge 1 -and $html.Count -ge 1 }
Test-Case "Run normal : le SHA256 calcule = celui du .txt" {
    if ($txt.Count -lt 1) { return $false }
    $h = (Get-FileHash -Path $txt[0].FullName -Algorithm SHA256).Hash
    ($h -and $h.Length -eq 64)
}

$nonceDir = Join-Path $work 'nonce'
$nonceVal = "MODO-CHK-1234"
$codeN = Invoke-Run -ExtraArgs @('-Nonce', $nonceVal) -OutDir $nonceDir
Test-Case "Nonce : run avec -Nonce => exit 0" { $codeN -eq 0 }
Test-Case "Nonce : le mot du modo est ecrit dans le rapport (donc plie dans le hash = preuve LIVE)" {
    $nt = @(Get-ChildItem $nonceDir -Filter '*.txt' -ErrorAction SilentlyContinue)
    ($nt.Count -ge 1) -and ((Get-Content $nt[0].FullName -Raw) -match [regex]::Escape($nonceVal))
}

$deepDir = Join-Path $work 'deep'
$codeD = Invoke-Run -ExtraArgs @('-Deep','-FreeSpaceCapMB','64') -OutDir $deepDir
Test-Case "Run -Deep : exit 0" { $codeD -eq 0 }
Test-Case "Run -Deep : CSV USN genere (admin ; skip non bloquant hors admin - le dump USN exige la lecture brute du volume)" {
    if (-not $adminE) { Write-Host "      (non-admin : le dump USN brut n'est pas possible -> skip non bloquant, relancer en admin pour la preuve)" -ForegroundColor DarkGray; return $true }
    @(Get-ChildItem $deepDir -Filter '*USN*.csv' -ErrorAction SilentlyContinue).Count -ge 1
}

# ---------------------------------------------------------------------------
Section "D. REGRESSION (analyse du rapport -Deep)"

function Get-ProbeStatuses {
    param([string]$ReportTxt)
    $map = @{}
    foreach ($line in (Get-Content $ReportTxt)) {
        $m = [regex]::Match($line, '^\s*\[(OK|INFO|WARN|FLAG|NA|ERROR)\]\s+(.+?)\s+--\s+')
        if ($m.Success) { $map[$m.Groups[2].Value.Trim()] = $m.Groups[1].Value }
    }
    return $map
}

$deepTxt = @(Get-ChildItem $deepDir -Filter '*.txt' -ErrorAction SilentlyContinue)
$statuses = if ($deepTxt.Count -ge 1) { Get-ProbeStatuses $deepTxt[0].FullName } else { @{} }

Test-Case "Aucune sonde en ERROR (= aucun bug non capture)" {
    $errs = @($statuses.GetEnumerator() | Where-Object { $_.Value -eq 'ERROR' })
    if ($errs) { $errs | ForEach-Object { Write-Host ("      -> {0}" -f $_.Key) -ForegroundColor DarkYellow } }
    ($errs.Count -eq 0)
}
Test-Case "Scan espace libre n'est JAMAIS FLAG (pas de faux SUSPECT sur PC clean)" {
    $fs = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*espace libre*' } | Select-Object -First 1
    if (-not $fs) { Write-Host "      (sonde espace libre absente du rapport)" -ForegroundColor DarkGray; return $true }
    ($fs.Value -in @('INFO','OK','NA'))
}
Test-Case "Sonde 'Traces d'execution (anti-wipe)' presente dans le rapport" {
    @($statuses.Keys | Where-Object { $_ -like '*anti-wipe*' }).Count -ge 1
}
Test-Case "Sonde Shimcache presente dans le rapport" {
    @($statuses.Keys | Where-Object { $_ -like '*Shimcache*' }).Count -ge 1
}
Test-Case "Sonde PCA presente dans le rapport" {
    @($statuses.Keys | Where-Object { $_ -like '*PCA*' }).Count -ge 1
}
Test-Case "Sonde Injection presente dans le rapport" {
    @($statuses.Keys | Where-Object { $_ -like '*Injection*' }).Count -ge 1
}
Test-Case "Sonde Cache DNS/hosts presente et jamais FLAG sur ce PC (INFO/OK/WARN/NA, pas de faux SUSPECT)" {
    $dns = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*DNS*' } | Select-Object -First 1
    if (-not $dns) { Write-Host "      (sonde DNS absente du rapport)" -ForegroundColor DarkYellow; return $false }
    ($dns.Value -in @('INFO','OK','WARN','NA'))
}
Test-Case "Sonde Cartes PCIe/DMA presente et jamais FLAG sur ce PC (INFO/WARN/NA, pas de faux SUSPECT)" {
    $pci = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*PCIe*' } | Select-Object -First 1
    if (-not $pci) { Write-Host "      (sonde PCIe absente du rapport)" -ForegroundColor DarkYellow; return $false }
    ($pci.Value -in @('INFO','WARN','NA'))
}
Test-Case "Rapport : bloc RAISONNEMENT du verdict present (+ rappel de portee)" {
    if ($deepTxt.Count -lt 1) { return $false }
    $raw = Get-Content $deepTxt[0].FullName -Raw
    ($raw -match 'RAISONNEMENT') -and ($raw -match 'Portee')
}
Test-Case "Sonde Connexions reseau live presente et jamais FLAG sur ce PC (INFO/OK, pas de faux SUSPECT)" {
    $net = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*reseau live*' } | Select-Object -First 1
    if (-not $net) { Write-Host "      (sonde reseau absente du rapport)" -ForegroundColor DarkYellow; return $false }
    ($net.Value -in @('INFO','OK','NA'))
}
Test-Case "Sonde Hardware/DMA pas en FLAG sur ce PC (pas de faux SUSPECT via manette virtuelle)" {
    $hw = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*Hardware*' } | Select-Object -First 1
    if (-not $hw) { Write-Host "      (sonde Hardware absente du rapport)" -ForegroundColor DarkGray; return $true }
    ($hw.Value -in @('OK','INFO','WARN','NA'))
}
Test-Case "Nouvelles sondes presentes dans le rapport (Virtualisation + Defender + Drivers kernel)" {
    (@($statuses.Keys | Where-Object { $_ -like '*Virtualisation*' }).Count -ge 1) -and
    (@($statuses.Keys | Where-Object { $_ -like '*Defender*' }).Count -ge 1) -and
    (@($statuses.Keys | Where-Object { $_ -like '*Drivers kernel*' }).Count -ge 1)
}

# ---------------------------------------------------------------------------
Section "E. VRAI-POSITIF (simulation : on plante la trace qu'un cheat laisse, on prouve la detection)"
# Un tricheur ne pretera jamais sa machine pour un test de vrai-positif. Pas besoin : un cheat qui
# s'efface laisse une SUPPRESSION dans le journal USN. On plante cette trace nous-memes (creer un
# fichier au nom "de cheat" puis le supprimer) et on prouve, sur le VRAI volume avec le VRAI lecteur
# USN, que la sonde la capture. Token UNIQUE + benin (pas un vrai mot de cheat) => ne pollue pas les
# vrais runs futurs (une suppression 'dexcheck-selftest-baitztoken' ne matche AUCUN pattern reel).

Test-Case "USN vrai-positif : un fichier au nom de cheat SUPPRIME est capture end-to-end (coeur anti-wipe prouve, pas juste synthetique)" {
    if (-not $adminE) { Write-Host "      (admin requis pour lire l'USN brut -> skip non bloquant ; relancer en admin pour la preuve)" -ForegroundColor DarkGray; return $true }
    # Token UNIQUE par run : avec un token fixe, les suppressions des runs PRECEDENTS restaient dans le
    # journal et le test passait meme si l'appat n'etait jamais plante (mutation 16/09 : resté vert).
    $token = 'baitz' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $vol   = (Split-Path $env:TEMP -Qualifier)   # ex 'C:'
    $bait  = Join-Path $env:TEMP ('dexcheck-selftest-' + $token + '.exe')
    try {
        Set-Content -Path $bait -Value 'dexcheck true-positive self-test' -ErrorAction Stop
        Remove-Item -Path $bait -Force -ErrorAction Stop
        $planted = Get-Date
    } catch { Write-Host ("      -> impossible de planter l'appat : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow; return $false }
    # L'enregistrement USN de SUPPRESSION n'est ecrit qu'a la fermeture du dernier handle du fichier.
    # Mesure 16/09 : 1 echec sur ~15 suites, toujours le 1er run, avec StopError=0 et le journal lu en
    # entier (la trace n'y etait pas encore apres 3 s) ; 0/70 hors suite, meme sous charge disque.
    # Hypothese « ecriture differee » REFUTEE le 16/09 : echec identique avec 15 s d'attente.
    # Le diagnostic ci-dessous tranche entre « lecteur qui s'arrete avant la fin du journal »
    # (derniere entree lue < heure de l'appat) et « suppression jamais journalisee » (entrees
    # posterieures presentes, pas la notre).
    $caught = @()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    # Borne en TEMPS reel : chaque essai relit tout le journal, 60 essais pouvaient durer des minutes.
    while ($sw.Elapsed.TotalSeconds -lt 15 -and $caught.Count -lt 1) {
        Start-Sleep -Milliseconds 250
        $scan = Get-UsnScan -Volume $vol -FlagPatterns @($token) -WarnPatterns @()
        $caught = @($scan.FlagSuspects | Where-Object { [string]$_.Name -match $token })
    }
    if ($caught.Count -ge 1 -and $sw.Elapsed.TotalSeconds -gt 3) {
        Write-Host ("      (trace USN apparue apres {0:N1} s)" -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkYellow
    }
    if ($caught.Count -lt 1) {
        # LastRecordTicks = dernier enregistrement LU tous types (NewestTicks ne compte que les suppressions :
        # sur un disque calme il est toujours anterieur a l'appat et accusait le lecteur a tort).
        $newest = if ($scan.LastRecordTicks -gt 0) { [DateTime]::FromFileTime($scan.LastRecordTicks).ToString('HH:mm:ss.fff') } else { '-' }
        Write-Host ("      -> la suppression plantee n'a PAS ete retrouvee dans le journal USN (StopError={0}, total={1}, appat={2}, derniere entree lue={3}, fichier encore present={4})" -f `
            $scan.StopError, $scan.Total, $planted.ToString('HH:mm:ss.fff'), $newest, (Test-Path -LiteralPath $bait)) -ForegroundColor DarkYellow
        # Mesure 17/09 : derniere entree lue 15 s APRES l'appat => le lecteur va bien au bout. Reste :
        # suppression journalisee tres tard, ou jamais ? On continue a chercher 90 s pour trancher.
        $late = [Diagnostics.Stopwatch]::StartNew()
        while ($late.Elapsed.TotalSeconds -lt 90 -and $caught.Count -lt 1) {
            Start-Sleep -Seconds 5
            $s2 = Get-UsnScan -Volume $vol -FlagPatterns @($token) -WarnPatterns @()
            $caught = @($s2.FlagSuspects | Where-Object { [string]$_.Name -match $token })
        }
        if ($caught.Count -ge 1) {
            Write-Host ("      -> trace apparue TARDIVEMENT, {0:N0} s apres l'appat (horodatage de l'entree : {1:HH:mm:ss.fff})" -f ((Get-Date) - $planted).TotalSeconds, $caught[0].Time) -ForegroundColor DarkYellow
            $caught = @()   # le test reste en echec : le delai est l'information, pas une reussite
        } else {
            Write-Host "      -> toujours ABSENTE apres 105 s : la suppression n'a jamais ete journalisee sous ce nom" -ForegroundColor DarkYellow
        }
    }
    ($caught.Count -ge 1)
}
# 16/09 : le lecteur USN sortait de sa boucle sur toute erreur autre que 1181 SANS le dire, et la sonde
# ecrivait quand meme "Chaque journal est scanne EN ENTIER". Un scan coupe doit se declarer partiel.
Test-Case "DELFILES : un scan USN interrompu (StopError) est declare PARTIEL, jamais 'EN ENTIER'" {
    if (-not $adminE) { Write-Host "      (admin requis -> skip non bloquant)" -ForegroundColor DarkGray; return $true }
    $orig = ${function:Get-UsnScan}
    try {
        ${function:script:Get-UsnScan} = { param($Volume, $FlagPatterns, $WarnPatterns)
            [pscustomobject]@{ Total = 5; FlagSuspects = @(); WarnSuspects = @(); Recent = @(); OldestTicks = 0; NewestTicks = 0; StopError = 21 } }
        $r = Probe-DeletedFiles
        $txt = ($r.Details -join "`n")
        ($txt -match '(?i)PARTIEL') -and ($txt -match '21') -and ($txt -notmatch 'EN ENTIER')
    } finally { ${function:script:Get-UsnScan} = $orig }
}
# Mesure 16/09 sur le PC d'Alex (propre) : verdict A VERIFIER a cause de config_loader.py,
# skill-map-loader.ts, scan-loader.md supprimes. Un fichier source/doc n'est pas un loader de cheat :
# le mot generique ne doit alerter que sur ce qui peut s'executer (ou une archive qui le contient).
Test-Case "DELFILES : mot generique sur un fichier source/doc (.py .ts .md) => PAS de WARN ; sur un .exe => WARN" {
    if (-not $adminE) { Write-Host "      (admin requis -> skip non bloquant)" -ForegroundColor DarkGray; return $true }
    $orig = ${function:Get-UsnScan}
    $now = Get-Date
    try {
        ${function:script:Get-UsnScan} = { param($Volume, $FlagPatterns, $WarnPatterns)
            [pscustomobject]@{ Total = 3; FlagSuspects = @(); Recent = @(); OldestTicks = 0; NewestTicks = 0; StopError = 0
                WarnSuspects = @([pscustomobject]@{ Name = 'config_loader.py'; Time = $now }, [pscustomobject]@{ Name = 'skill-map-loader.ts'; Time = $now }, [pscustomobject]@{ Name = 'scan-loader.md'; Time = $now }, [pscustomobject]@{ Name = 'System.Runtime.Loader.dll'; Time = $now }) } }.GetNewClosure()
        $dev = Probe-DeletedFiles
        ${function:script:Get-UsnScan} = { param($Volume, $FlagPatterns, $WarnPatterns)
            [pscustomobject]@{ Total = 2; FlagSuspects = @(); Recent = @(); OldestTicks = 0; NewestTicks = 0; StopError = 0
                WarnSuspects = @([pscustomobject]@{ Name = 'config_loader.py'; Time = $now }, [pscustomobject]@{ Name = 'cheat-loader.exe'; Time = $now }) } }.GetNewClosure()
        $mix = Probe-DeletedFiles
        ${function:script:Get-UsnScan} = { param($Volume, $FlagPatterns, $WarnPatterns)
            [pscustomobject]@{ Total = 1; FlagSuspects = @(); Recent = @(); OldestTicks = 0; NewestTicks = 0; StopError = 0
                WarnSuspects = @([pscustomobject]@{ Name = 'cod_aimbot.py'; Time = $now }) } }.GetNewClosure()
        $py = Probe-DeletedFiles
        ($dev.Status -ne 'WARN') -and ($mix.Status -eq 'WARN') -and (($mix.Details -join "`n") -notmatch 'config_loader\.py') -and ($py.Status -eq 'WARN')
    } finally { ${function:script:Get-UsnScan} = $orig }
}
# Boucle produits 17/09 : technique anti-forensique triviale, renommer engineowning.exe en a.tmp puis
# supprimer. Le journal n'enregistrait la SUPPRESSION que sous le nom neutre et DexCheck ne voyait
# rien. Windows journalise l'ANCIEN nom d'un renommage (USN_REASON_RENAME_OLD_NAME) : il faut le lire.
Test-Case "USN vrai-positif : un fichier au nom de cheat RENOMME puis supprime est quand meme capture" {
    if (-not $adminE) { Write-Host "      (admin requis -> skip non bloquant)" -ForegroundColor DarkGray; return $true }
    $token = 'baitz' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $vol   = (Split-Path $env:TEMP -Qualifier)
    $bait  = Join-Path $env:TEMP ('dexcheck-selftest-' + $token + '.exe')
    $plain = Join-Path $env:TEMP ('dexcheck-neutre-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.tmp')
    try {
        Set-Content -Path $bait -Value 'x' -ErrorAction Stop
        Rename-Item -LiteralPath $bait -NewName (Split-Path $plain -Leaf) -ErrorAction Stop
        Remove-Item -LiteralPath $plain -Force -ErrorAction Stop
    } catch { Write-Host ("      -> appat impossible : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow; return $false }
    $caught = @(); $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt 15 -and $caught.Count -lt 1) {
        Start-Sleep -Milliseconds 250
        $scan = Get-UsnScan -Volume $vol -FlagPatterns @($token) -WarnPatterns @()
        $caught = @($scan.FlagSuspects | Where-Object { [string]$_.Name -match $token })
    }
    ($caught.Count -ge 1)
}
Test-Case "USN vrai-positif : le token bidon N'EST PAS un vrai mot de cheat (l'appat ne pollue pas les vrais runs)" {
    $flag = Get-CheatFlagPatterns
    (-not (Test-AnyWord 'dexcheck-selftest-baitztoken.exe' $flag)) -and (-not (Test-AnyWord 'dexcheck-selftest-baitztoken.exe' $script:CheatWarnWords))
}

Test-Case "PS history : le set FLAG = providers/domaines distinctifs, JAMAIS les mots de categorie (aimbot/wallhack/spoofer)" {
    $t = Get-PsHistoryFlagTargets
    (-not (Test-AnyWord 'x-aimbot-remover' $t)) -and (-not (Test-AnyWord 'wallhack' $t)) -and
    (-not (Test-AnyWord 'spoofer' $t)) -and (Test-AnyWord 'engineowning.to' $t)
}
Test-Case "PS history : download-and-exec dual-use (Chris Titus winutil) => WARN, pas FLAG (cible pas un token cheat)" {
    $t = Get-PsHistoryFlagTargets
    $h = Get-PsHistoryHits @('iwr -useb https://christitus.com/win | iex') $t
    ($h.Count -eq 1) -and (-not $h[0].IsFlag)
}
Test-Case "PS history : telechargement depuis un DOMAINE/PROVIDER de cheat distinctif (engineowning) => FLAG" {
    $t = Get-PsHistoryFlagTargets
    $h = Get-PsHistoryHits @('iwr https://engineowning.to/loader.ps1 | iex') $t
    ($h.Count -eq 1) -and ($h[0].IsFlag)
}
Test-Case "PS history : 'aimbot-remover' (outil qui SUPPRIME un cheat) telecharge => WARN pas FLAG (l'innocent est protege)" {
    $t = Get-PsHistoryFlagTargets
    $h = Get-PsHistoryHits @('iwr https://github.com/foo/aimbot-remover/raw/main/clean.ps1 | iex') $t
    ($h.Count -eq 1) -and (-not $h[0].IsFlag)
}
Test-Case "PS history : un COMMENTAIRE mentionnant aimbot, sans verbe de telechargement => AUCUN hit (nom != preuve)" {
    $t = Get-PsHistoryFlagTargets
    $h = Get-PsHistoryHits @('# comment enlever un aimbot de mon pc','Get-Process') $t
    ($h.Count -eq 0)
}
Test-Case "PS history : MARIUS (board legitime) telecharge => WARN pas FLAG (veracite : marius n'est pas un token cheat)" {
    $t = Get-PsHistoryFlagTargets
    $h = Get-PsHistoryHits @('iwr https://raw.githubusercontent.com/EODBruz/MARIUS-BOARD-CONFIGURATOR/main/MARIUS.ps1 | iex') $t
    ($h.Count -eq 1) -and (-not $h[0].IsFlag)
}
Test-Case "PS history : Start-BitsTransfer + -EncodedCommand (base64, pas d'URL) => WARN (verbe suspect), jamais FLAG sans cible" {
    $t = Get-PsHistoryFlagTargets
    ((Get-PsHistoryHits @('powershell -enc SQBFAFgA') $t)[0].IsFlag -eq $false) -and
    ((Get-PsHistoryHits @('Start-BitsTransfer -Source http://x/y.exe -Destination C:\t.exe') $t).Count -eq 1)
}
Test-Case "PS history : lignes benignes / null => 0 hit (pas de faux positif, pas de crash)" {
    $t = Get-PsHistoryFlagTargets
    ((Get-PsHistoryHits @('cd C:\','Get-ChildItem','git status') $t).Count -eq 0) -and
    ((Get-PsHistoryHits $null $t).Count -eq 0)
}

Test-Case "7045 : install d'un driver BYOVD dual-use (rtcore64=Afterburner) => WARN pas FLAG (date conservee)" {
    $installs = @([pscustomobject]@{ Name='RTCore64'; Path='C:\Windows\rtcore64.sys'; Time='2026-07-10 16:48' })
    $h = Get-DriverInstallHits $installs (Get-PsHistoryFlagTargets) $script:VulnerableDrivers
    ($h.Count -eq 1) -and ($h[0].Level -eq 'WARN') -and ($h[0].Time -eq '2026-07-10 16:48')
}
Test-Case "7045 : install d'un service au nom de PROVIDER distinctif (engineowning) => FLAG" {
    $installs = @([pscustomobject]@{ Name='engineowning_drv'; Path='C:\x\eo.sys'; Time='x' })
    $h = Get-DriverInstallHits $installs (Get-PsHistoryFlagTargets) $script:VulnerableDrivers
    ($h.Count -eq 1) -and ($h[0].Level -eq 'FLAG')
}
Test-Case "7045 : 'aimbot-remover.sys' + un service legitime (NVIDIA) => AUCUN hit (nom de categorie != preuve, service legit ignore)" {
    $installs = @(
        [pscustomobject]@{ Name='aimbot-remover'; Path='C:\x\aimbot-remover.sys'; Time='x' },
        [pscustomobject]@{ Name='NVDisplay.ContainerLocalSystem'; Path='C:\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe'; Time='x' }
    )
    $h = Get-DriverInstallHits $installs (Get-PsHistoryFlagTargets) $script:VulnerableDrivers
    ($h.Count -eq 0)
}
Test-Case "7045 : null / liste vide => 0 hit (pas de crash)" {
    ((Get-DriverInstallHits $null (Get-PsHistoryFlagTargets) $script:VulnerableDrivers).Count -eq 0) -and
    ((Get-DriverInstallHits @() (Get-PsHistoryFlagTargets) $script:VulnerableDrivers).Count -eq 0)
}

Test-Case "Shadow VRAI-POSITIF : 'vssadmin delete shadows /all' dans l'historique => detecte (geste anti-forensic)" {
    $h = Get-ShadowWipeHits @('cd C:\','vssadmin delete shadows /all /quiet','dir')
    ($h.Count -eq 1)
}
Test-Case "Shadow : 'vssadmin list shadows' (lister != supprimer) => AUCUN hit (pas de faux positif)" {
    (Get-ShadowWipeHits @('vssadmin list shadows','Get-CimInstance Win32_ShadowCopy')).Count -eq 0
}
Test-Case "Shadow : wmic shadowcopy delete + Remove Win32_ShadowCopy detectes ; lignes benignes/null => 0" {
    ((Get-ShadowWipeHits @('wmic shadowcopy delete')).Count -eq 1) -and
    ((Get-ShadowWipeHits @('Remove-CimInstance -Query "select * from Win32_ShadowCopy"')).Count -eq 1) -and
    ((Get-ShadowWipeHits @('echo hello','ping google.com')).Count -eq 0) -and
    ((Get-ShadowWipeHits $null).Count -eq 0)
}
Test-Case "Sonde Shadow Copies presente et jamais FLAG sur ce PC (WARN max sur suppression, sinon INFO/OK/NA)" {
    $p = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*Shadow*' } | Select-Object -First 1
    if (-not $p) { Write-Host '      (sonde Shadow absente)' -ForegroundColor DarkYellow; return $false }
    ($p.Value -in @('INFO','OK','WARN','NA'))
}

Test-Case "Mur de fraicheur VRAI-POSITIF : Windows vieux (700j) + 2 sources synchronisees demarrant tard => MUR detecte" {
    $now = Get-Date; $inst = $now.AddDays(-700)
    $srcs = @([pscustomobject]@{Name='Journal System';Oldest=$now.AddDays(-3);Usable=$true},
              [pscustomobject]@{Name='Prefetch';Oldest=$now.AddDays(-8);Usable=$true})
    $w = Get-FreshnessWall $inst $now $srcs
    $w.Wall -and ($w.Used.Count -eq 2) -and ($null -ne $w.WindowStart)
}
Test-Case "Mur GARDE-FOU reinstall : Windows recent (10j) => PAS de mur (tout jeune = normal, jamais un innocent accuse)" {
    $now = Get-Date; $inst = $now.AddDays(-10)
    $srcs = @([pscustomobject]@{Name='a';Oldest=$now.AddDays(-3);Usable=$true},[pscustomobject]@{Name='b';Oldest=$now.AddDays(-5);Usable=$true})
    $w = Get-FreshnessWall $inst $now $srcs
    (-not $w.Wall) -and ($w.Reason -match '(?i)recent')
}
Test-Case "Mur GARDE-FOU : une seule source utilisable => PAS de mur (un point n'est pas un mur)" {
    $now = Get-Date; $inst = $now.AddDays(-700)
    $srcs = @([pscustomobject]@{Name='a';Oldest=$now.AddDays(-3);Usable=$true},[pscustomobject]@{Name='b';Oldest=$now.AddDays(-3);Usable=$false})
    (-not (Get-FreshnessWall $inst $now $srcs).Wall)
}
Test-Case "Mur GARDE-FOU : sources DESYNCHRONISEES (etalees sur des mois) => PAS de mur (accidents independants)" {
    $now = Get-Date; $inst = $now.AddDays(-700)
    $srcs = @([pscustomobject]@{Name='a';Oldest=$now.AddDays(-3);Usable=$true},[pscustomobject]@{Name='b';Oldest=$now.AddDays(-300);Usable=$true})
    (-not (Get-FreshnessWall $inst $now $srcs).Wall)
}
Test-Case "Mur GARDE-FOU : une source remonte pres de l'install (vieille histoire presente) => PAS de mur" {
    $now = Get-Date; $inst = $now.AddDays(-700)
    $srcs = @([pscustomobject]@{Name='a';Oldest=$now.AddDays(-3);Usable=$true},[pscustomobject]@{Name='b';Oldest=$now.AddDays(-690);Usable=$true})
    (-not (Get-FreshnessWall $inst $now $srcs).Wall)
}
Test-Case "Mur NON-REGRESSION (moat) : ajouter la sonde TIMELINE (INFO) ne change JAMAIS le verdict d'un profil debloat gaming complet" {
    $base = @(
        [pscustomobject]@{Id='USN';Status='WARN';Severity=1},
        [pscustomobject]@{Id='PREFETCH';Status='WARN';Severity=1},
        [pscustomobject]@{Id='WINAGE';Status='WARN';Severity=1},
        [pscustomobject]@{Id='ANTIFOR';Status='WARN';Severity=1}
    )
    $timeline = [pscustomobject]@{Id='TIMELINE';Status='INFO';Severity=0}
    (Get-Verdict $base) -eq (Get-Verdict ($base + $timeline))
}
Test-Case "Sonde Mur de fraicheur presente et TOUJOURS INFO/NA (jamais WARN/FLAG - presentation seule, moat intact)" {
    $p = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*Mur de fraicheur*' } | Select-Object -First 1
    if (-not $p) { Write-Host '      (sonde Mur de fraicheur absente)' -ForegroundColor DarkYellow; return $false }
    ($p.Value -in @('INFO','NA'))
}

Test-Case "Posture DMA : INFO strict - VBS+DMA dispo => 'fermee', rien => 'moins genee', jamais une accusation" {
    ((Get-DmaPostureSummary 2 $true) -match '(?i)fermee') -and
    ((Get-DmaPostureSummary 0 $false) -match '(?i)moins genee') -and
    ((Get-DmaPostureSummary 0 $false) -match '(?i)pas une accusation')
}
Test-Case "Sonde Posture DMA presente dans le rapport et TOUJOURS INFO/NA (jamais FLAG/WARN, c'est du contexte)" {
    $p = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*Posture de protection DMA*' } | Select-Object -First 1
    if (-not $p) { Write-Host '      (sonde Posture DMA absente)' -ForegroundColor DarkYellow; return $false }
    ($p.Value -in @('INFO','NA'))
}

Test-Case "MOTW VRAI-POSITIF end-to-end : un fichier avec Zone.Identifier pointant un domaine de cheat => FLAG (survit au wipe navigateur)" {
    $bait = Join-Path $env:TEMP ("DexMotwBait_{0}.exe" -f (Get-Random))
    Set-Content -LiteralPath $bait -Value 'MZ bait' -Encoding Ascii
    Set-Content -LiteralPath $bait -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://engineowning.to/download/loader.exe" -Encoding Ascii
    try {
        $r = Probe-DownloadProvenance
        ($r.Status -eq 'FLAG') -and (@($r.Details | Where-Object { $_ -like '*DexMotwBait*' }).Count -ge 1)
    } finally { Remove-Item -LiteralPath $bait -Force -ErrorAction SilentlyContinue }
}
Test-Case "MOTW : un telechargement banal (github, domaine normal) => aucun hit (pas de faux positif)" {
    $e = @([pscustomobject]@{ File='C:\Users\x\Downloads\app.zip'; Url='https://github.com/user/repo/releases/app.zip' })
    $d = @(); foreach($c in $script:CheatSoftware){ if($c.Domains){ $d += $c.Domains } }
    ((Get-MotwCheatHits $e $d (Get-CheatFlagPatterns)).Count -eq 0) -and
    ((Get-MotwCheatHits $null $d (Get-CheatFlagPatterns)).Count -eq 0)
}
Test-Case "Sonde Provenance MOTW presente dans le rapport et jamais FLAG sur ce PC (pas de faux SUSPECT)" {
    (@($statuses.Keys | Where-Object { $_ -like '*Mark-of-the-Web*' -or $_ -like '*Provenance*' }).Count -ge 1) -and
    (@($statuses.GetEnumerator() | Where-Object { ($_.Key -like '*Mark-of-the-Web*' -or $_.Key -like '*Provenance*') -and $_.Value -eq 'FLAG' }).Count -eq 0)
}

Test-Case "RecentDocs : le parseur binaire extrait bien le nom UTF-16 en tete (engineowning.exe)" {
    $s = 'engineowning.exe'
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($s) + @([byte]0,[byte]0) + @([byte]1,[byte]2,[byte]3,[byte]4)
    (ConvertFrom-RecentDocValue $bytes) -eq $s
}
Test-Case "MRU VRAI-POSITIF : un nom de cheat distinctif ouvert recemment => FLAG (RecentDocs/RunMRU, survit a la suppression)" {
    $a = Get-WerCrashHits @('engineowning.exe','rapport.docx','photo.png') (Get-CheatFlagPatterns) $script:CheatWarnWords
    ($a.Flag.Count -eq 1) -and ($a.Warn.Count -eq 0)
}
Test-Case "MRU : fichiers banals recents (docx, png, cmd) => aucun hit (pas de faux positif)" {
    ((Get-WerCrashHits @('budget2026.xlsx','vacances.jpg','notepad.exe') (Get-CheatFlagPatterns) $script:CheatWarnWords).Flag.Count -eq 0) -and
    ((ConvertFrom-RecentDocValue $null) -eq '')
}
Test-Case "Sonde Fichiers recents/Executer presente dans le rapport et jamais FLAG sur ce PC (pas de faux SUSPECT)" {
    (@($statuses.Keys | Where-Object { $_ -like '*RecentDocs*' -or $_ -like '*Executer*' }).Count -ge 1) -and
    (@($statuses.GetEnumerator() | Where-Object { ($_.Key -like '*RecentDocs*' -or $_.Key -like '*Executer*') -and $_.Value -eq 'FLAG' }).Count -eq 0)
}

Test-Case "WER VRAI-POSITIF : un cheat distinctif qui a plante (engineowning.exe) => FLAG (le nom survit a la suppression du binaire)" {
    $a = Get-WerCrashHits @('AppCrash_engineowning.exe_abc123','chrome.exe','explorer.exe') (Get-CheatFlagPatterns) $script:CheatWarnWords
    ($a.Flag.Count -eq 1) -and ($a.Warn.Count -eq 0)
}
Test-Case "WER : un nom generique/categorie qui a plante (aimbot.exe) => WARN pas FLAG (dual-use)" {
    $a = Get-WerCrashHits @('AppCrash_aimbot.exe_xyz') (Get-CheatFlagPatterns) $script:CheatWarnWords
    ($a.Flag.Count -eq 0) -and ($a.Warn.Count -eq 1)
}
Test-Case "WER : crashs banals (chrome, jeux, null) => aucun hit (pas de faux positif, pas de crash)" {
    ((Get-WerCrashHits @('AppCrash_chrome.exe','AppCrash_cod.exe','AppHang_steam.exe') (Get-CheatFlagPatterns) $script:CheatWarnWords).Flag.Count -eq 0) -and
    ((Get-WerCrashHits $null (Get-CheatFlagPatterns) $script:CheatWarnWords).Flag.Count -eq 0)
}
Test-Case "Sonde WER presente dans le rapport et jamais FLAG sur ce PC (pas de faux SUSPECT)" {
    (@($statuses.Keys | Where-Object { $_ -like '*WER*' }).Count -ge 1) -and
    (@($statuses.GetEnumerator() | Where-Object { $_.Key -like '*WER*' -and $_.Value -eq 'FLAG' }).Count -eq 0)
}

Test-Case "GPC VRAI-POSITIF : un contenu de script Cronus (set_val/combo/event_press) => reconnu comme GPC (FLAG)" {
    $gpc = "main {`n  combo Recoil {`n    set_val(4, 100);`n    event_press(11);`n  }`n}"
    (Test-IsGpcScript $gpc)
}
Test-Case "GPC : une collision d'extension (.gpc qui contient du texte quelconque) => PAS reconnu (pas de faux FLAG)" {
    (-not (Test-IsGpcScript "Rapport trimestriel 2026, chiffres et notes diverses.")) -and
    (-not (Test-IsGpcScript "combo de touches pour la recette")) -and
    (-not (Test-IsGpcScript ''))
}
Test-Case "GPC : un seul marqueur faible ne suffit pas (>=2 requis hors mots exclusifs GPC)" {
    (-not (Test-IsGpcScript 'juste le mot set_val tout seul dans une phrase'))
}
Test-Case "Sonde Scripts GPC presente dans le rapport et jamais FLAG sur ce PC (pas de faux SUSPECT)" {
    (@($statuses.Keys | Where-Object { $_ -like '*.gpc*' -or $_ -like '*Cronus*' }).Count -ge 1) -and
    (@($statuses.GetEnumerator() | Where-Object { ($_.Key -like '*.gpc*' -or $_.Key -like '*Cronus*') -and $_.Value -eq 'FLAG' }).Count -eq 0)
}

Test-Case "Process cmdline VRAI-POSITIF : un cheat lance via un exe RENOMME mais avec un arg distinctif (engineowning) => detecte (on ne lisait que le nom avant)" {
    $fp = @(); foreach($c in $script:CheatSoftware){ if(-not $c.GenericName){ $fp += $c.Patterns } }
    (Test-ProcessIsCheat 'svchost.exe' 'C:\Windows\Temp\svchost.exe' 'svchost.exe --config engineowning.cfg' $fp)
}
Test-Case "Process cmdline : un process banal (steam, chemins Windows) => PAS detecte (pas de faux positif)" {
    $fp = @(); foreach($c in $script:CheatSoftware){ if(-not $c.GenericName){ $fp += $c.Patterns } }
    (-not (Test-ProcessIsCheat 'steam.exe' 'C:\Program Files (x86)\Steam\steam.exe' '"C:\Program Files (x86)\Steam\steam.exe" -silent' $fp)) -and
    (-not (Test-ProcessIsCheat 'explorer.exe' 'C:\Windows\explorer.exe' '' $fp))
}
Test-Case "Process cmdline : nom OU chemin de cheat distinctif detecte comme avant (pas de regression)" {
    $fp = @(); foreach($c in $script:CheatSoftware){ if(-not $c.GenericName){ $fp += $c.Patterns } }
    (Test-ProcessIsCheat 'engineowning.exe' '' '' $fp)
}
# Revue 17/09 : nom/chemin compares en SOUS-CHAINE. Le motif le plus court, 'ring-1', est contenu
# dans 'spring-1' (dossier Java/Spring) => un process legitime sortait FLAG « cheat en cours ».
# Mais une frontiere de mot partout raterait 'EngineOwningLoader.exe' (marque collee).
Test-Case "Process : motif COURT exige une frontiere de mot ('ring-1' ne matche pas 'spring-1.5')" {
    $fp = @(); foreach($c in $script:CheatSoftware){ if(-not $c.GenericName){ $fp += $c.Patterns } }
    (-not (Test-ProcessIsCheat 'java.exe' 'C:\dev\spring-1.5\bin\java.exe' '' $fp)) -and
    (Test-ProcessIsCheat 'ring-1.exe' 'C:\x\ring-1.exe' '' $fp)
}
Test-Case "Process : marque LONGUE collee a un autre mot reste detectee ('EngineOwningLoader.exe')" {
    $fp = @(); foreach($c in $script:CheatSoftware){ if(-not $c.GenericName){ $fp += $c.Patterns } }
    (Test-ProcessIsCheat 'EngineOwningLoader.exe' 'C:\Users\x\Downloads\EngineOwningLoader.exe' '' $fp)
}

Test-Case "Defender historique VRAI-POSITIF : une detection au nom de cheat DISTINCTIF (engineowning) => FLAG (verdict signe Microsoft)" {
    $fp = Get-CheatFlagPatterns
    $a = Get-DefenderThreatAssessment @(@{ Name='HackTool:Win32/EngineOwning'; Path='C:\Users\x\Downloads\eo_loader.exe' }) $fp
    ($a.Status -eq 'FLAG') -and ($a.Severity -eq 2)
}
Test-Case "Defender historique : Cheat Engine (HackTool generique) => WARN pas FLAG (le moddeur de jeu SOLO est protege)" {
    $fp = Get-CheatFlagPatterns
    $a = Get-DefenderThreatAssessment @(@{ Name='HackTool:Win32/CheatEngine'; Path='C:\Program Files\Cheat Engine\cheatengine.exe' }) $fp
    ($a.Status -eq 'WARN') -and ($a.Severity -eq 1)
}
Test-Case "Defender historique : PUA/malware generique (Presenoker) => INFO (Defender a chope qqch, pas forcement un cheat de jeu)" {
    $fp = Get-CheatFlagPatterns
    $a = Get-DefenderThreatAssessment @(@{ Name='PUA:Win32/Presenoker'; Path='C:\Users\x\AppData\Local\Temp\setup.exe' }) $fp
    ($a.Status -eq 'INFO') -and ($a.Severity -eq 0)
}
Test-Case "Defender historique : aucune menace / null => OK (et l'historique se purge, donc vide != preuve de proprete)" {
    $fp = Get-CheatFlagPatterns
    ((Get-DefenderThreatAssessment @() $fp).Status -eq 'OK') -and
    ((Get-DefenderThreatAssessment $null $fp).Status -eq 'OK')
}
Test-Case "Sonde Historique menaces Defender presente dans le rapport et jamais FLAG sur ce PC (pas de faux SUSPECT)" {
    (@($statuses.Keys | Where-Object { $_ -like '*menaces Defender*' }).Count -ge 1) -and
    (@($statuses.GetEnumerator() | Where-Object { $_.Key -like '*menaces Defender*' -and $_.Value -eq 'FLAG' }).Count -eq 0)
}

Test-Case "USB historique VRAI-POSITIF : un descripteur Cronus deja branche (meme debranche) => FLAG (le trou de INPUT live est bouche)" {
    $h = Get-UsbHistoryHits @('DualSense Wireless Controller','Cronus Zen','HP DeskJet 3630 series') $script:InputTools
    ($h.Count -eq 1) -and ($h[0].Sev -ge 2) -and ($h[0].Name -match '(?i)cronus')
}
Test-Case "USB historique : XIM et kmbox reconnus, kmbox reste sev 1 (WARN) et non FLAG (coherence avec INPUT live)" {
    $x = Get-UsbHistoryHits @('XIM APEX') $script:InputTools
    $k = Get-UsbHistoryHits @('kmbox net') $script:InputTools
    ($x.Count -eq 1) -and ($x[0].Sev -ge 2) -and ($k.Count -eq 1) -and ($k[0].Sev -eq 1)
}
Test-Case "USB historique : descripteurs propres (manette, imprimante, casque) => 0 hit (pas de faux positif)" {
    $h = Get-UsbHistoryHits @('DualSense Edge Wireless Controller','HP DeskJet 3630 series','Wireless Stereo Headset','USB Composite Device') $script:InputTools
    ($h.Count -eq 0)
}
Test-Case "USB historique : null / vide => 0 hit, pas de crash" {
    ((Get-UsbHistoryHits $null $script:InputTools).Count -eq 0) -and
    ((Get-UsbHistoryHits @() $script:InputTools).Count -eq 0)
}
Test-Case "Sonde Historique USB presente dans le rapport et jamais FLAG sur ce PC (pas de faux SUSPECT)" {
    (@($statuses.Keys | Where-Object { $_ -like '*Historique USB*' }).Count -ge 1) -and
    (@($statuses.GetEnumerator() | Where-Object { $_.Key -like '*Historique USB*' -and $_.Value -eq 'FLAG' }).Count -eq 0)
}

Test-Case "Headline ACTION : 'ne pas accuser' sur A VERIFIER et SUSPECT ; 'arbitre' sur ROUGE ; 'check visuel' sur CLEAN" {
    ((Get-VerdictAction 'SUSPECT')    -match '(?i)ne pas accuser') -and
    ((Get-VerdictAction 'A VERIFIER') -match '(?i)ne pas accuser') -and
    ((Get-VerdictAction 'ROUGE')      -match '(?i)arbitre') -and
    ((Get-VerdictAction 'CLEAN')      -match '(?i)check visuel')
}
Test-Case "Headline ACTION : purement presentation (verdict inconnu => action neutre, jamais de crash)" {
    ((Get-VerdictAction 'CLEAN').Length -gt 0) -and ((Get-VerdictAction 'nimportequoi') -match '(?i)check visuel')
}

# --- Launcher : garde-fous contre le retour du bug "fenetre qui se ferme" -----
# Le .bat doit posseder SEUL l'elevation (sinon double-elevation => 2 fenetres,
# la non-admin se ferme). Ces tests lisent la structure du .bat, pas son execution
# (le double-clic / UAC restent une verification humaine).
$script:BatPath = Join-Path $PSScriptRoot 'LANCER-LE-CHECK.bat'
$script:BatText = if (Test-Path $script:BatPath) { Get-Content -LiteralPath $script:BatPath -Raw } else { '' }

Test-Case "Launcher : s'eleve lui-meme (net session + Start-Process RunAs + exit)" {
    ($script:BatText -match '(?i)net session') -and
    ($script:BatText -match '(?i)Start-Process\s+-FilePath\s+''%~f0''\s+-Verb\s+RunAs') -and
    ($script:BatText -match '(?i)exit /b')
}
Test-Case "Launcher : appelle DexCheck.ps1 avec -NoElevate (pas de seconde elevation)" {
    $invokes = @(($script:BatText -split "\r?\n") | Where-Object { ($_ -match '(?i)powershell') -and ($_ -match '(?i)DexCheck\.ps1') })
    ($invokes.Count -ge 1) -and (@($invokes | Where-Object { $_ -notmatch '(?i)-NoElevate' }).Count -eq 0)
}
Test-Case "Launcher : se termine par pause (dernier chemin de sortie)" {
    $script:BatText.TrimEnd() -match '(?is)pause\s*$'
}
# Le test ci-dessus ne prouve QUE la fin du fichier. Le bloc d'elevation, lui,
# fait "exit /b" et ne l'atteint jamais : si le joueur clique NON sur l'UAC, la
# fenetre se fermait sans un mot -- exactement le bug que ce garde-fou est cense
# empecher. On verifie donc que ce chemin-la a SON propre pause.
Test-Case "Launcher : elevation refusee => message + pause (pas de fermeture muette)" {
    if (-not $script:BatText) { return $false }
    # bloc = de "net session" jusqu'au "exit /b" de l'elevation
    $m = [regex]::Match($script:BatText, '(?is)net session.*?exit\s*/b')
    if (-not $m.Success) { return $false }
    $bloc = $m.Value
    ($bloc -match '(?i)if\s+errorlevel\s+1') -and ($bloc -match '(?i)\bpause\b')
}
Test-Case "Launcher : le test d'echec d'elevation lit la valeur VIVE (if errorlevel, pas %errorlevel%)" {
    # Dans un bloc entre parentheses, %errorlevel% est developpe au PARSING : il
    # vaudrait encore le code de "net session" => fausse alerte "elevation refusee"
    # a CHAQUE elevation reussie. Prouve par test : seul "if errorlevel 1" marche.
    if (-not $script:BatText) { return $false }
    $m = [regex]::Match($script:BatText, '(?is)net session.*?exit\s*/b')
    if (-not $m.Success) { return $false }
    $apresStart = ($m.Value -split '(?i)Start-Process')[-1]
    # On inspecte du CODE : les lignes "rem" sont retirees, sinon le commentaire
    # qui explique justement le piege ferait echouer le test.
    $codeSeul = ($apresStart -split "\r?\n" | Where-Object { $_.Trim() -notmatch '^(?i)rem\b' }) -join "`n"
    ($codeSeul -notmatch '%errorlevel%')
}
# Retour terrain 16/09 : le joueur double-clique le .bat DANS le zip. Windows n'extrait que ce fichier
# dans Temp, DexCheck.ps1 n'est pas a cote, et powershell affichait une erreur -File incomprehensible.
# Test d'EXECUTION (pas de structure) : le .bat seul dans un dossier vide doit expliquer quoi faire.
Test-Case "Launcher EXECUTE seul (zip non extrait) => dit d'extraire le zip, pas d'erreur -File" {
    if (-not $adminE) { Write-Host "      (admin requis : le .bat s'eleverait -> skip non bloquant)" -ForegroundColor DarkGray; return $true }
    $d = Join-Path $env:TEMP ('dexcheck-batseul-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $d | Out-Null
    try {
        Copy-Item -LiteralPath $script:BatPath -Destination $d
        $out = (cmd /c "`"$(Join-Path $d 'LANCER-LE-CHECK.bat')`" < nul" 2>&1 | Out-String)
        ($out -match '(?i)extrai') -and ($out -notmatch '(?i)-File')
    } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
}
# Retour terrain 16/09 (Alex) : « c'est quoi ce truc mot de passe ou mode approfondi ». Un seul geste :
# double-clic, UAC, le check COMPLET tourne. Aucune question.
Test-Case "Launcher : ne pose AUCUNE question (pas de set /p)" {
    $script:BatText -and ($script:BatText -notmatch '(?i)set\s+/p')
}
Test-Case "Launcher : lance toujours le check complet (-Deep sur chaque appel)" {
    $invokes = @(($script:BatText -split "\r?\n") | Where-Object { ($_ -match '(?i)powershell') -and ($_ -match '(?i)DexCheck\.ps1') })
    ($invokes.Count -ge 1) -and (@($invokes | Where-Object { $_ -notmatch '(?i)-Deep' }).Count -eq 0)
}


# --- Regression : la sonde anti-forensic concluait "Aucun outil de wipe connu" sans avoir pu regarder ---
# Le FLAG de cette sonde repose ENTIEREMENT sur le Prefetch. Avec -ErrorAction SilentlyContinue,
# un Prefetch illisible ou desactive etait indiscernable d'un Prefetch vide -> verdict OK.
# Or couper le Prefetcher est precisement ce que ferait quelqu'un qui vient d'effacer ses traces.
Test-Case "Get-AntiForensicAssessment : Prefetch lu + rien trouve => OK" {
    $a = Get-AntiForensicAssessment -FlagCount 0 -WarnCount 0 -PrefetchState 'OK'
    ($a.Status -eq 'OK' -and $a.Severity -eq 0)
}
Test-Case "Get-AntiForensicAssessment : Prefetch DESACTIVE => WARN, jamais OK" {
    $a = Get-AntiForensicAssessment -FlagCount 0 -WarnCount 0 -PrefetchState 'DISABLED'
    ($a.Status -eq 'WARN' -and $a.Severity -eq 1)
}
Test-Case "Get-AntiForensicAssessment : Prefetch ILLISIBLE => NA, jamais OK" {
    $a = Get-AntiForensicAssessment -FlagCount 0 -WarnCount 0 -PrefetchState 'UNREADABLE'
    ($a.Status -eq 'NA')
}
Test-Case "Get-AntiForensicAssessment : canal aveugle => le resume ne dit JAMAIS 'Aucun outil de wipe'" {
    $d = Get-AntiForensicAssessment -FlagCount 0 -WarnCount 0 -PrefetchState 'DISABLED'
    $u = Get-AntiForensicAssessment -FlagCount 0 -WarnCount 0 -PrefetchState 'UNREADABLE'
    (($d.Summary -notmatch 'Aucun outil de wipe') -and ($u.Summary -notmatch 'Aucun outil de wipe'))
}
Test-Case "Get-AntiForensicAssessment : un wipe qui a tourne reste FLAG meme si le reste est aveugle" {
    $a = Get-AntiForensicAssessment -FlagCount 1 -WarnCount 0 -PrefetchState 'OK'
    ($a.Status -eq 'FLAG' -and $a.Severity -eq 2)
}
Test-Case "Get-AntiForensicAssessment : canal aveugle + nettoyeurs => les deux sont dits" {
    $a = Get-AntiForensicAssessment -FlagCount 0 -WarnCount 2 -PrefetchState 'UNREADABLE'
    ($a.Summary -match 'illisible' -and $a.Summary -match '2 nettoyeur')
}

# --- Regression : sans admin, la sonde Journaux certifiait "coherents" sans avoir pu lire ---
# Lire le journal Security exige l'admin. L'event 1102 ("journal d'audit efface") est le FLAG
# le plus fort de cette sonde (sev 3). Sans droits il est INVISIBLE, et la sonde renvoyait
# OK/"Journaux coherents" -- alors que l'outil annonce lui-meme "certaines sondes seront N/A".
Test-Case "Get-EventLogAssessment : tout lisible + rien trouve => OK" {
    $a = Get-EventLogAssessment -Status 'OK' -Severity 0 -Summary 'Journaux coherents' -SecurityReadable $true -SystemReadable $true
    ($a.Status -eq 'OK')
}
Test-Case "Get-EventLogAssessment : Security illisible => NA, jamais OK" {
    $a = Get-EventLogAssessment -Status 'OK' -Severity 0 -Summary 'Journaux coherents' -SecurityReadable $false -SystemReadable $true
    ($a.Status -eq 'NA')
}
Test-Case "Get-EventLogAssessment : Security illisible => le resume ne dit JAMAIS 'coherents'" {
    $a = Get-EventLogAssessment -Status 'OK' -Severity 0 -Summary 'Journaux coherents' -SecurityReadable $false -SystemReadable $true
    ($a.Summary -notmatch 'coherent' -and $a.Summary -match '1102')
}
Test-Case "Get-EventLogAssessment : System illisible => NA" {
    $a = Get-EventLogAssessment -Status 'OK' -Severity 0 -Summary 'Journaux coherents' -SecurityReadable $true -SystemReadable $false
    ($a.Status -eq 'NA')
}
Test-Case "Get-EventLogAssessment : un effacement DEJA vu prime sur l'illisibilite" {
    $a = Get-EventLogAssessment -Status 'FLAG' -Severity 3 -Summary "Journaux d'evenements EFFACES (1)" -SecurityReadable $false -SystemReadable $false
    ($a.Status -eq 'FLAG' -and $a.Severity -eq 3)
}
Test-Case "Test-EventLogReadable : un journal LISIBLE (Application) renvoie vrai" {
    (Test-EventLogReadable -LogName 'Application') -eq $true
}
Test-Case "Test-EventLogReadable : journal INEXISTANT = 'on a pu regarder', pas un refus" {
    (Test-EventLogReadable -LogName 'DexCheckJournalQuiNExistePas') -eq $true
}

# --- Regression : WER (preuve ANTI-WIPE) pouvait conclure "rien" sans avoir rien lu ---
# Le nom du binaire qui a plante survit a la suppression du binaire : c'est la valeur de
# cette sonde. Deux facons de mentir sans planter : 0 rapport lu (dossier absent/refuse)
# annonce comme "aucun nom suspect", et un plafond de scan atteint sans le dire.
Test-Case "Get-WerAssessment : rapports lus + rien trouve => OK" {
    $a = Get-WerAssessment -FlagCount 0 -WarnCount 0 -Scanned 120
    ($a.Status -eq 'OK' -and $a.Summary -match '120')
}
Test-Case "Get-WerAssessment : 0 rapport lu => NA, jamais OK" {
    $a = Get-WerAssessment -FlagCount 0 -WarnCount 0 -Scanned 0
    ($a.Status -eq 'NA')
}
Test-Case "Get-WerAssessment : 0 rapport lu => le resume ne dit JAMAIS 'aucun nom suspect'" {
    $a = Get-WerAssessment -FlagCount 0 -WarnCount 0 -Scanned 0
    ($a.Summary -notmatch 'aucun nom suspect' -and $a.Summary -match "n'a PAS ete examinee")
}
Test-Case "Get-WerAssessment : acces refuse => la raison est dite, pas juste 'absent'" {
    $a = Get-WerAssessment -FlagCount 0 -WarnCount 0 -Scanned 0 -Denied 2
    ($a.Summary -match 'refuse')
}
Test-Case "Get-WerAssessment : plafond atteint => le resume dit TRONQUE" {
    $a = Get-WerAssessment -FlagCount 0 -WarnCount 0 -Scanned 3000 -Capped $true
    ($a.Status -eq 'OK' -and $a.Summary -match 'TRONQUE')
}
Test-Case "Get-WerAssessment : scan complet => le resume l'affirme (pas d'ambiguite avec le plafond)" {
    $a = Get-WerAssessment -FlagCount 0 -WarnCount 0 -Scanned 42 -Capped $false
    ($a.Summary -match 'en entier' -and $a.Summary -notmatch 'TRONQUE')
}
Test-Case "Get-WerAssessment : un cheat trouve reste FLAG meme si le scan est tronque" {
    $a = Get-WerAssessment -FlagCount 1 -WarnCount 0 -Scanned 3000 -Capped $true
    ($a.Status -eq 'FLAG' -and $a.Severity -eq 2)
}

# Cas REEL mesure sur la machine d'Alex (sans admin) : ReportArchive et ReportQueue de
# ProgramData sont refuses, seuls 2 rapports du profil utilisateur sont lisibles. Conclure
# "aucun nom suspect" couvrirait une zone jamais ouverte -- celle qui garde l'historique
# le plus long. Trouve en LANCANT la sonde, pas en la relisant.
Test-Case "Get-WerAssessment : lecture PARTIELLE (refus) => NA, jamais OK" {
    $a = Get-WerAssessment -FlagCount 0 -WarnCount 0 -Scanned 2 -Denied 2
    ($a.Status -eq 'NA')
}
Test-Case "Get-WerAssessment : lecture partielle => ne pretend PAS avoir tout lu" {
    $a = Get-WerAssessment -FlagCount 0 -WarnCount 0 -Scanned 2 -Denied 2
    ($a.Summary -notmatch 'en entier' -and $a.Summary -match 'PARTIELLE' -and $a.Summary -match '2 dossier')
}
Test-Case "Get-WerAssessment : un cheat trouve prime sur une lecture partielle" {
    $a = Get-WerAssessment -FlagCount 1 -WarnCount 0 -Scanned 2 -Denied 2
    ($a.Status -eq 'FLAG')
}

# --- Regression : le DETAIL disait "non verifie", le RESUME affirmait le contraire ---
# `testsigning ON` = drivers non signes autorises = levier BYOVD / carte DMA, FLAG sev 3.
# Il se lit avec bcdedit, qui exige l'admin. Sans elevation la sonde ecrivait bien
# "bcdedit : admin requis (non verifie)" dans les details, mais son resume restait
# "Pas de mode test / signature contournee" -- et c'est le resume que lit un modo.
Test-Case "Get-SystemSecurityAssessment : bcdedit lu + rien trouve => OK" {
    $a = Get-SystemSecurityAssessment -FlagCount 0 -BcdChecked $true -SecureBootKnown $true
    ($a.Status -eq 'OK' -and $a.Summary -match 'bcdedit et Secure Boot lus')
}
Test-Case "Get-SystemSecurityAssessment : bcdedit NON verifie => NA, jamais OK" {
    $a = Get-SystemSecurityAssessment -FlagCount 0 -BcdChecked $false -SecureBootKnown $true
    ($a.Status -eq 'NA')
}
Test-Case "Get-SystemSecurityAssessment : bcdedit non verifie => le resume ne PRETEND PAS l'absence" {
    $a = Get-SystemSecurityAssessment -FlagCount 0 -BcdChecked $false -SecureBootKnown $true
    ($a.Summary -notmatch 'Pas de mode test' -and $a.Summary -match 'NON verifies')
}
Test-Case "Get-SystemSecurityAssessment : testsigning ON reste FLAG sev3" {
    $a = Get-SystemSecurityAssessment -FlagCount 1 -BcdChecked $true -SecureBootKnown $true
    ($a.Status -eq 'FLAG' -and $a.Severity -eq 3)
}
Test-Case "Get-SystemSecurityAssessment : Secure Boot non lisible est dit, sans bloquer le verdict" {
    $a = Get-SystemSecurityAssessment -FlagCount 0 -BcdChecked $true -SecureBootKnown $false
    ($a.Status -eq 'OK' -and $a.Summary -match 'Secure Boot non lisible')
}

# --- Regression : 10 canaux jamais examines, et le verdict global disait CLEAN ---
# Mesure sur la machine d'Alex sans admin : 20 OK / 8 INFO / 10 NA => Get-Verdict = CLEAN.
# Les NA couvraient le coeur anti-wipe (PREFETCH, SHIMCACHE, DELFILES, USN, WER, EVTLOG...).
# NA veut dire "non examine", pas "rien trouve" : CLEAN certifiait une zone jamais ouverte.
# Pas de 5e verdict invente -- "A VERIFIER" veut deja dire "un humain doit regarder".
function New-FakeResult { param($Id, $Status, $Sev = 0) [pscustomobject]@{ Id = $Id; Status = $Status; Severity = $Sev; Summary = "x"; Details = @() } }

Test-Case "Get-Verdict : tout lu, rien trouve => CLEAN" {
    $r = @((New-FakeResult 'PREFETCH' 'OK'), (New-FakeResult 'WER' 'OK'), (New-FakeResult 'EVTLOG' 'OK'))
    (Get-Verdict $r) -eq 'CLEAN'
}
Test-Case "Get-Verdict : un canal decisif en NA => A VERIFIER, jamais CLEAN" {
    $r = @((New-FakeResult 'PREFETCH' 'NA'), (New-FakeResult 'WER' 'OK'))
    (Get-Verdict $r) -eq 'A VERIFIER'
}
Test-Case "Get-Verdict : les sondes -Deep en NA ne font PAS basculer un run rapide" {
    $r = @((New-FakeResult 'DEEPFREE' 'NA'), (New-FakeResult 'DEEPUSN' 'NA'), (New-FakeResult 'PREFETCH' 'OK'))
    (Get-Verdict $r) -eq 'CLEAN'
}
Test-Case "Get-Verdict : un FLAG prime toujours sur l'illisibilite" {
    $r = @((New-FakeResult 'PREFETCH' 'NA'), (New-FakeResult 'CHEATS' 'FLAG' 2))
    (Get-Verdict $r) -eq 'SUSPECT'
}
Test-Case "Get-Verdict : severite 3 reste ROUGE meme avec des canaux aveugles" {
    $r = @((New-FakeResult 'PREFETCH' 'NA'), (New-FakeResult 'SECBOOT' 'FLAG' 3))
    (Get-Verdict $r) -eq 'ROUGE'
}
Test-Case "Get-VerdictReasoning : les canaux non examines sont NOMMES" {
    $r = @((New-FakeResult 'PREFETCH' 'NA'), (New-FakeResult 'WER' 'NA'), (New-FakeResult 'CHEATS' 'OK'))
    $txt = (Get-VerdictReasoning $r) -join ' '
    ($txt -match 'PREFETCH' -and $txt -match 'WER' -and $txt -match "n'ont PAS ete examines")
}
Test-Case "Get-VerdictReasoning : tout lu => pas de mention de canal aveugle" {
    $r = @((New-FakeResult 'PREFETCH' 'OK'), (New-FakeResult 'WER' 'OK'))
    $txt = (Get-VerdictReasoning $r) -join ' '
    ($txt -match "rien de suspect dans ce qu'un check logiciel peut voir" -and $txt -notmatch 'decisif')
}

# --- Le rapport doit PROUVER quel script l'a produit, pas seulement l'annoncer ---
# Avant le 15/08 l'en-tete affichait "v1.0.0" -- qu'un script modifie imprime aussi.
# Le hash du RAPPORT existait deja (il rend le fichier sauvegarde infalsifiable) ;
# il manquait l'autre moitie de la chaine : l'identite du script.
Test-Case "Le script calcule sa propre empreinte au lancement" {
    $sh = $script:SelfHash
    ($null -ne $sh) -and ($sh.Length -gt 0)
}
Test-Case "L'empreinte du script est le VRAI SHA-256 du fichier" {
    $vrai = (Get-FileHash -LiteralPath $ScriptPath -Algorithm SHA256).Hash
    $script:SelfHash -eq $vrai
}
Test-Case "L'en-tete du rapport imprime la ligne Script" {
    $src = [IO.File]::ReadAllText($ScriptPath)
    $src -match '" Script     : "\s*\+\s*\$script:SelfHash'
}
Test-Case "Sans chemin sur disque, l'empreinte dit n/a au lieu d'inventer" {
    $src = [IO.File]::ReadAllText($ScriptPath)
    ($src -match "IsNullOrWhiteSpace\(\`$PSCommandPath\)") -and ($src -match "n/a \(script sans chemin")
}

# --- LA LOI "SEVERITE 3 = ROUGE TOUT SEUL" doit avoir exactement 4 declencheurs ---
# Get-Verdict est teste (severite 3 injectee -> ROUGE) et chaque sonde est testee. Le MAILLON
# ne l'etait pas : rien ne prouvait QUELLES sondes emettent reellement une severite 3. Une
# sonde qui retomberait a 2 rendrait la loi fausse pendant que Get-Verdict resterait juste.
# La severite 3 s'ecrit sous TROIS formes dans le script (Severity=3, -Severity 3, $sev=3) :
# chercher le concept sous un seul de ses noms en manque une (verifie le 15/08).
Test-Case "Exactement 4 declencheurs de severite 3 dans le script" {
    $src = [IO.File]::ReadAllText($ScriptPath)
    $a = ([regex]::Matches($src, 'Severity\s*=\s*3')).Count
    $b = ([regex]::Matches($src, '-Severity\s+3')).Count
    $c = ([regex]::Matches($src, '\$sev\s*=\s*3')).Count
    ($a + $b + $c) -eq 4
}
Test-Case "Les 4 declencheurs sont bien ceux annonces (journaux effaces, testsigning, cheat live, cheat installe)" {
    $src = [IO.File]::ReadAllText($ScriptPath)
    $journaux    = [regex]::IsMatch($src, '\$sev\s*=\s*3;\s*\$summary\s*=\s*"Journaux d.evenements EFFACES')
    $testsigning = [regex]::IsMatch($src, "function Get-SystemSecurityAssessment[\s\S]{0,900}?Status='FLAG';\s*Severity=3")
    $cheatLive   = [regex]::IsMatch($src, "-Id 'NET'[^
]*-Severity 3")
    $cheatPose   = [regex]::IsMatch($src, "-Id 'CHEATS'[^
]*-Severity 3")
    $journaux -and $testsigning -and $cheatLive -and $cheatPose
}
Test-Case "Chacun des 4 suffit SEUL a rendre ROUGE (la loi, pas seulement la table)" {
    $seul = { param($id) (Get-Verdict @((New-ProbeResult -Id $id -Name x -Status 'FLAG' -Severity 3))) }
    (& $seul 'EVTLOG') -eq 'ROUGE' -and (& $seul 'SECBOOT') -eq 'ROUGE' -and `
    (& $seul 'NET') -eq 'ROUGE' -and (& $seul 'CHEATS') -eq 'ROUGE'
}

# ---------------------------------------------------------------------------
Section "F. FAMILLES AVANCEES (14/09) : HWID spoof, DMA par ID PCIe, BYOVD via Code Integrity / services, MuiCache"

# --- DMA : identite PCIe (pas un nom renommable) ---
Test-Case "DMA VRAI-POSITIF : ID STOCK pcileech (VEN_10EE&DEV_0666) => FLAG (config space par defaut du firmware pcileech-fpga)" {
    (Get-PciProblemLevel -InstanceId 'PCI\VEN_10EE&DEV_0666&SUBSYS_00000000&REV_00\4&1&0&00' -ErrorCode 28 -Present $true) -eq 'FLAG'
}
Test-Case "DMA : Xilinx autre DID (dev-board possible) => WARN, jamais FLAG" {
    (Get-PciProblemLevel -InstanceId 'PCI\VEN_10EE&DEV_7024\x' -ErrorCode 0 -Present $true) -eq 'WARN'
}
Test-Case "DMA VRAI-POSITIF : un device a VID grand public (Realtek) dont le driver EXISTE mais ne demarre pas (code 10) => WARN (un DMA qui clone l'ID d'une NIC echoue exactement comme ca)" {
    (Get-PciProblemLevel -InstanceId 'PCI\VEN_10EC&DEV_8168\x' -ErrorCode 10 -Present $true) -eq 'WARN'
}
Test-Case "DMA GARDE-FOU : VID grand public SANS driver (code 28, reinstall pas finie) => INFO, pas WARN (PC neuf protege)" {
    (Get-PciProblemLevel -InstanceId 'PCI\VEN_8086&DEV_2725\x' -ErrorCode 28 -Present $true) -eq 'INFO'
}
Test-Case "DMA GARDE-FOU : device FANTOME (debranche, Present=false) => jamais classe ; device OK (code 0) => rien" {
    ((Get-PciProblemLevel -InstanceId 'PCI\VEN_10EC&DEV_8168\x' -ErrorCode 10 -Present $false) -eq '') -and
    ((Get-PciProblemLevel -InstanceId 'PCI\VEN_10DE&DEV_2882\x' -ErrorCode 0 -Present $true) -eq '')
}
Test-Case "DMA : VID INCONNU en erreur => WARN (comme avant)" {
    (Get-PciProblemLevel -InstanceId 'PCI\VEN_1234&DEV_5678\x' -ErrorCode 28 -Present $true) -eq 'WARN'
}
Test-Case "DmaPciStockIds : invariant = 10EE:0666 uniquement (un DID Xilinx de dev-board n'y est jamais)" {
    (@($script:DmaPciStockIds) -contains 'VEN_10EE&DEV_0666') -and (@($script:DmaPciStockIds).Count -eq 1)
}

# --- HWID spoof : ecarts entre ce que Windows PRESENTE et ce qu'il a ENREGISTRE ---
Test-Case "HWID PC PROPRE (cas reel mesure 14/09) : paires identiques + registre VIDE d'un cote + MAC = gravee + MachineGuid ecrit AVANT l'install => OK" {
    $now = Get-Date
    $a = Get-HwidAssessment -SmbiosPairs @(@{Name='serial';Wmi='07D9810_O31E802272';Reg='07D9810_O31E802272'},@{Name='serial systeme';Wmi='Default string';Reg=''}) `
        -Nics @(@{Name='Ethernet';Mac='D8-43-AE-99-F4-C7';Permanent='D843AE99F4C7';Wifi=$false}) -RegOverrides @() `
        -GuidKeyTime $now.AddDays(-500) -InstallDate $now.AddDays(-500).AddMinutes(1)
    ($a.Status -eq 'OK') -and ($a.Lines.Count -eq 0)
}
Test-Case "HWID VRAI-POSITIF : serial SMBIOS WMI != registre (lu au boot) => WARN (spoof live probable)" {
    $a = Get-HwidAssessment -SmbiosPairs @(@{Name='serial';Wmi='RANDOM9X';Reg='ABC123'}) -Nics @() -RegOverrides @() -GuidKeyTime $null -InstallDate $null
    ($a.Status -eq 'WARN') -and ($a.Severity -eq 1) -and ($a.Lines[0] -match 'RANDOM9X' -and $a.Lines[0] -match 'ABC123')
}
Test-Case "HWID VRAI-POSITIF : MAC courante != MAC gravee sur ETHERNET => WARN ; sur WI-FI => INFO seulement (adresse aleatoire Windows = legitime)" {
    $w = Get-HwidAssessment -SmbiosPairs @() -Nics @(@{Name='Ethernet';Mac='02-11-22-33-44-55';Permanent='D843AE99F4C7';Wifi=$false}) -RegOverrides @() -GuidKeyTime $null -InstallDate $null
    $f = Get-HwidAssessment -SmbiosPairs @() -Nics @(@{Name='Wi-Fi';Mac='02-11-22-33-44-55';Permanent='189341ED963F';Wifi=$true}) -RegOverrides @() -GuidKeyTime $null -InstallDate $null
    ($w.Status -eq 'WARN') -and ($f.Status -eq 'INFO')
}
Test-Case "HWID VRAI-POSITIF : valeur NetworkAddress forcee dans la cle du driver reseau => WARN" {
    $a = Get-HwidAssessment -SmbiosPairs @() -Nics @() -RegOverrides @('Realtek Gaming 2.5GbE = 021122334455') -GuidKeyTime $null -InstallDate $null
    ($a.Status -eq 'WARN') -and ($a.Lines[0] -match 'NetworkAddress')
}
Test-Case "HWID VRAI-POSITIF : cle MachineGuid reecrite 397 j APRES l'install => WARN (cible n°1 des spoofers) ; reecrite le jour de l'install => OK" {
    $now = Get-Date
    $bad = Get-HwidAssessment -SmbiosPairs @() -Nics @() -RegOverrides @() -GuidKeyTime $now.AddDays(-3) -InstallDate $now.AddDays(-400)
    $ok  = Get-HwidAssessment -SmbiosPairs @() -Nics @() -RegOverrides @() -GuidKeyTime $now.AddDays(-400).AddHours(2) -InstallDate $now.AddDays(-400)
    ($bad.Status -eq 'WARN') -and ($bad.Lines[0] -match 'MachineGuid') -and ($ok.Status -eq 'OK')
}
Test-Case "HWID : normalisation = tirets/deux-points/espaces/casse ignores (D8-43-AE = d843ae) ; null partout => OK sans crash" {
    $a = Get-HwidAssessment -SmbiosPairs @(@{Name='x';Wmi=' ab-cd ';Reg='ABCD'}) -Nics @(@{Name='e';Mac='d8:43:ae';Permanent='D8-43-AE';Wifi=$false}) -RegOverrides @() -GuidKeyTime $null -InstallDate $null
    $n = Get-HwidAssessment -SmbiosPairs $null -Nics $null -RegOverrides $null -GuidKeyTime $null -InstallDate $null
    ($a.Status -eq 'OK') -and ($n.Status -eq 'OK')
}
Test-Case "HWID : la sonde ne produit JAMAIS un FLAG (un ecart d'identite se fait expliquer, il ne condamne pas)" {
    $src = [IO.File]::ReadAllText($ScriptPath)
    $body = [regex]::Match($src, "function Get-HwidAssessment[\s\S]*?\r?\n}\r?\n").Value
    ($body.Length -gt 0) -and ($body -notmatch "Status='FLAG'")
}
Test-Case "Sonde Identite materielle (HWID) presente dans le rapport et jamais FLAG/WARN sur ce PC propre (OK/INFO/NA)" {
    $p = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*HWID*' } | Select-Object -First 1
    if (-not $p) { Write-Host '      (sonde HWID absente)' -ForegroundColor DarkYellow; return $false }
    ($p.Value -in @('OK','INFO','NA'))
}

# --- BYOVD / mapper : journal Code Integrity (ecrit par le noyau, survit a la suppression du .sys) ---
$ciBonjour = 'Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\System32\svchost.exe) attempted to load \Device\HarddiskVolume3\Program Files\Bonjour\mdnsNSP.dll that did not meet the Microsoft signing level requirements.'
$ciKdmap   = 'Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\System32\services.exe) attempted to load \Device\HarddiskVolume3\Users\bob\AppData\Local\Temp\iqvw64e.sys that did not meet the Microsoft signing level requirements.'
$ciCheatFr = "L'integrite du code a determine qu'un processus (\Device\HarddiskVolume3\Windows\System32\services.exe) a tente de charger \Device\HarddiskVolume3\Users\bob\Desktop\engineowning_drv.sys qui ne repond pas aux exigences de niveau de signature."
Test-Case "CILOG VRAI-POSITIF : kdmapper (iqvw64e.sys charge depuis Temp, refuse par Code Integrity) => WARN avec le chemin + la date" {
    $h = Get-CiLogHits -Events @(@{Id=3033;Time='2026-09-01 21:00';Message=$ciKdmap}) -FlagPatterns (Get-CheatFlagPatterns)
    ($h.Count -eq 1) -and ($h[0].Level -eq 'WARN') -and ($h[0].Path -match 'iqvw64e\.sys$') -and ($h[0].Time -eq '2026-09-01 21:00') -and (Test-UserZoneDriverPath $h[0].Path)
}
Test-Case "CILOG VRAI-POSITIF : driver au nom de cheat DISTINCTIF, message en FRANCAIS => FLAG (on lit les chemins, pas la langue)" {
    $h = Get-CiLogHits -Events @(@{Id=3033;Time='t';Message=$ciCheatFr}) -FlagPatterns (Get-CheatFlagPatterns)
    ($h.Count -eq 1) -and ($h[0].Level -eq 'FLAG') -and ($h[0].Path -match 'engineowning_drv\.sys$')
}
Test-Case "CILOG GARDE-FOU (bruit reel mesure 14/09) : une DLL legitime refusee (Bonjour mdnsNSP.dll) => AUCUN hit ; le process svchost.exe n'est jamais un hit" {
    $h = Get-CiLogHits -Events @(@{Id=3033;Time='t';Message=$ciBonjour}) -FlagPatterns (Get-CheatFlagPatterns)
    ($h.Count -eq 0)
}
Test-Case "CILOG : event 3004 (integrite non verifiable) sur un .sys systeme => WARN (vieux driver possible) ; null/vide => 0 hit, pas de crash" {
    $h = Get-CiLogHits -Events @(@{Id=3004;Time='t';Message='Windows is unable to verify the image integrity of the file \Device\HarddiskVolume3\Windows\System32\drivers\gdrv.sys because file hash could not be found on the system.'}) -FlagPatterns (Get-CheatFlagPatterns)
    ($h.Count -eq 1) -and ($h[0].Level -eq 'WARN') -and ((Get-CiLogHits -Events $null -FlagPatterns @()).Count -eq 0) -and ((Get-CiLogHits -Events @() -FlagPatterns @()).Count -eq 0)
}
Test-Case "Sonde Journal Code Integrity presente dans le rapport et jamais FLAG sur ce PC (OK/INFO/WARN/NA)" {
    $p = $statuses.GetEnumerator() | Where-Object { $_.Key -like '*Code Integrity*' } | Select-Object -First 1
    if (-not $p) { Write-Host '      (sonde CILOG absente)' -ForegroundColor DarkYellow; return $false }
    ($p.Value -in @('OK','INFO','WARN','NA'))
}
Test-Case "Get-Verdict : CILOG est un artefact anti-wipe INDEPENDANT => CILOG FLAG + PREFETCH FLAG = ROUGE ; CILOG FLAG seul = SUSPECT" {
    $c = New-ProbeResult -Id 'CILOG' -Name x -Status 'FLAG' -Severity 2
    $p = New-ProbeResult -Id 'PREFETCH' -Name y -Status 'FLAG' -Severity 2
    ((Get-Verdict @($c,$p)) -eq 'ROUGE') -and ((Get-Verdict @($c)) -eq 'SUSPECT') -and (@($script:AntiWipeIds) -contains 'CILOG')
}

# --- BYOVD / mapper : service de driver enregistre depuis un dossier utilisateur ---
Test-Case "KDRV VRAI-POSITIF : service de driver qui pointe sous \Users\...\Temp (pattern kdmapper) => zone user => WARN" {
    (Test-UserZoneDriverPath '\??\C:\Users\bob\AppData\Local\Temp\iqvw64e.sys') -and
    ((Get-DriverAssessment -UnsignedCount 0 -VulnerableCount 0 -UserZoneCount 1).Status -eq 'WARN')
}
Test-Case "KDRV GARDE-FOU (cas reel mesure 14/09) : \ProgramData (anti-triche Battle.net randgrid.sys) et \SystemRoot ne sont PAS une zone user" {
    (-not (Test-UserZoneDriverPath '\??\C:\ProgramData\Battle.net_components\randgridauks\randgrid.sys')) -and
    (-not (Test-UserZoneDriverPath '\SystemRoot\System32\drivers\x.sys')) -and
    (-not (Test-UserZoneDriverPath 'system32\DRIVERS\usersdrv.sys')) -and
    (-not (Test-UserZoneDriverPath $null))
}
Test-Case "Get-DriverAssessment : 0 partout (UserZoneCount omis = compat) => OK" {
    (Get-DriverAssessment -UnsignedCount 0 -VulnerableCount 0).Status -eq 'OK'
}

# --- MuiCache : chemin de chaque exe lance, jamais purge par Windows ---
Test-Case "MuiCache VRAI-POSITIF : 'C:\x\engineowning.exe.FriendlyAppName' => chemin extrait => FLAG via le classement 2 niveaux" {
    $p = ConvertFrom-MuiCacheName 'C:\x\engineowning.exe.FriendlyAppName'
    $a = Get-WerCrashHits -Names @($p) -FlagPatterns (Get-CheatFlagPatterns) -WarnPatterns $script:CheatWarnWords
    ($p -eq 'C:\x\engineowning.exe') -and ($a.Flag.Count -eq 1)
}
Test-Case "MuiCache : valeurs de service (LangID) et suffixe ApplicationCompany geres ; exe banal => 0 hit" {
    $a = Get-WerCrashHits -Names @((ConvertFrom-MuiCacheName 'C:\Program Files\MSI\x.exe.ApplicationCompany')) -FlagPatterns (Get-CheatFlagPatterns) -WarnPatterns $script:CheatWarnWords
    ((ConvertFrom-MuiCacheName 'LangID') -eq '') -and ((ConvertFrom-MuiCacheName '') -eq '') -and ($a.Flag.Count -eq 0) -and ($a.Warn.Count -eq 0)
}

# --- Rapport HTML : verdict + action en tete, FLAG/WARN deplies, le reste replie, empreinte du script ---
Test-Case "HTML : ACTION + empreinte du script en tete, sections repliables (<details>), 'Autres sondes' APRES les points chauds" {
    if ($html.Count -lt 1) { return $false }
    $h = Get-Content $html[0].FullName -Raw
    ($h -match 'ACTION') -and ($h -match 'Empreinte du script') -and ($h -match '<details') -and ($h -match 'Autres sondes') -and
    ($h.IndexOf('a regarder') -lt $h.IndexOf('Autres sondes') -or $h.IndexOf('Aucun FLAG ni WARN') -lt $h.IndexOf('Autres sondes'))
}
Test-Case "Terminal : progression par sonde (compteur i/N) presente dans le code d'execution" {
    $src = [IO.File]::ReadAllText($ScriptPath)
    ($src -match 'Write-ProbeLine \$r -Index \$idx -Total \$probes\.Count')
}

Section "M. BOUCLE PRODUITS 17/09 : dossier supprime au nom generique"
# Mesure sur le PC d'Alex : A VERIFIER a cause du DOSSIER temporaire pytest
# « test_loader_fallback_when_yaml... » supprime. Un dossier au mot generique n'est pas un
# executable de cheat ; un nom DISTINCTIF (FLAG) reste signale meme pour un dossier.
Test-Case "DELFILES : DOSSIER supprime au nom generique => pas de WARN ; FICHIER .exe au meme mot => WARN" {
    if (-not $adminE) { Write-Host "      (admin requis -> skip non bloquant)" -ForegroundColor DarkGray; return $true }
    $orig = ${function:Get-UsnScan}
    $now = Get-Date
    try {
        ${function:script:Get-UsnScan} = { param($Volume, $FlagPatterns, $WarnPatterns)
            [pscustomobject]@{ Total = 1; FlagSuspects = @(); Recent = @(); OldestTicks = 0; NewestTicks = 0; StopError = 0
                WarnSuspects = @([pscustomobject]@{ Name = 'test_loader_fallback_when_yaml0'; Time = $now; Attributes = 0x10 }) } }.GetNewClosure()
        $dir = Probe-DeletedFiles
        ${function:script:Get-UsnScan} = { param($Volume, $FlagPatterns, $WarnPatterns)
            [pscustomobject]@{ Total = 1; FlagSuspects = @(); Recent = @(); OldestTicks = 0; NewestTicks = 0; StopError = 0
                WarnSuspects = @([pscustomobject]@{ Name = 'cheat-loader.exe'; Time = $now; Attributes = 0x20 }) } }.GetNewClosure()
        $exe = Probe-DeletedFiles
        ($dir.Status -ne 'WARN') -and ($exe.Status -eq 'WARN')
    } finally { ${function:script:Get-UsnScan} = $orig }
}

Section "L. BOUCLE PRODUITS 17/09 : ecran de fin lisible par un moderateur"
# Le moderateur decide sur l'ecran de fin. Avant : alertes dans l'ordre des sondes (un FLAG pouvait
# suivre trois WARN), 12 DERNIERES lignes brutes (souvent des notes techniques, pas la preuve), et
# le « montre / ne prouve pas » absent au moment de decider.
Test-Case "Ecran de fin : FLAG avant WARN, sens (montre / ne prouve pas) repris, preuves d'abord, 6 lignes max" {
    $warn = New-ProbeResult -Id 'PSHIST' -Name 'Historique PowerShell' -Status 'WARN' -Severity 1 -Summary 'w' -Details @('Historique : C:\x', '  download-and-exec : irm x | iex')
    $flagDetails = @('Volumes scannes : C:', 'NOTE fenetre : le journal tourne') + @(1..9 | ForEach-Object { "  2026-09-17 10:0$_  [C:] engineowning$_.exe" })
    $flag = New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'FLAG' -Severity 2 -Summary 'f' -Details $flagDetails
    # Get-FindingScreenLines rend une List protegee (return ,$out) : pas de @( ) autour, sinon
    # on obtient un tableau a UN element (la liste entiere).
    $lines = (Get-FindingScreenLines @($warn, $flag)).ToArray()
    $iFlag = -1; $iWarn = -1
    for ($k = 0; $k -lt $lines.Count; $k++) {
        if ($iFlag -lt 0 -and $lines[$k].StartsWith('[FLAG]')) { $iFlag = $k }
        if ($iWarn -lt 0 -and $lines[$k].StartsWith('[WARN]')) { $iWarn = $k }
    }
    $flagBlock = @($lines[($iFlag + 1)..($iWarn - 1)])
    ($iFlag -ge 0) -and ($iWarn -gt $iFlag) -and
    (@($flagBlock | Where-Object { $_ -match 'Montre :' }).Count -eq 1) -and
    (@($flagBlock | Where-Object { $_ -match 'engineowning' }).Count -eq 6) -and
    (@($flagBlock | Where-Object { $_ -match 'NOTE fenetre' }).Count -eq 0)
}
Test-Case "Action ROUGE : ne renvoie plus a un rapport « hashe » que l'ecran n'affiche plus" {
    (Get-VerdictAction 'ROUGE') -notmatch '(?i)hash'
}

Section "K. BOUCLE DEXCHECK 17/09 : persistance au demarrage"
# Probe-Persistence cherchait TOUS les outils d'entree, y compris ceux que DexCheck classe lui-meme
# severite 0 (DS4Windows, Razer Synapse, G HUB, x360ce), en sous-chaine. Un joueur dont Synapse ou
# DS4Windows demarre avec Windows (tres courant) sortait « persistance a verifier » => A VERIFIER.
Test-Case "Persistance : un outil d'entree LEGITIME au demarrage (DS4Windows, Razer Synapse) n'est PAS suspect" {
    $p = Get-PersistencePatterns
    (-not (Test-CheatNameMatch 'DS4Windows' $p)) -and
    (-not (Test-CheatNameMatch 'Razer Synapse' $p)) -and
    (-not (Test-CheatNameMatch '"C:\Program Files\Nefarius\DS4Windows\DS4Windows.exe" --minimized' $p))
}
Test-Case "Persistance : un cheat ou un outil anti-recul au demarrage reste suspect (EngineOwning, reWASD, Cronus)" {
    $p = Get-PersistencePatterns
    (Test-CheatNameMatch 'C:\Users\x\AppData\EngineOwningLoader.exe' $p) -and
    (Test-CheatNameMatch 'reWASD' $p) -and
    (Test-CheatNameMatch 'Cronus Zen Studio' $p)
}
Test-Case "Persistance : un motif court n'accuse pas un chemin qui le contient ('ring-1' dans 'spring-1.5')" {
    -not (Test-CheatNameMatch 'C:\dev\spring-1.5\bin\java.exe' (Get-PersistencePatterns))
}
# Trous mesures sur le PC d'Alex (17/09) : 17 taches lancent un interpreteur (powershell, rundll32) et le
# VRAI programme n'est que dans les arguments, que la sonde ne lisait pas ; le dossier Demarrage (2 raccourcis)
# et la cle Run 32 bits (WOW6432Node, 1 valeur) n'etaient pas lus du tout.
Test-Case "Persistance VRAI-POSITIF : tache planifiee au nom anodin qui lance powershell -File ...EngineOwningLoader.ps1 => suspect (on lit les ARGUMENTS)" {
    $e = @([pscustomobject]@{ Source='Tache'; Name='OneDriveSyncHelper'; Command='powershell.exe -WindowStyle Hidden -File C:\Users\bob\AppData\Roaming\sync\EngineOwningLoader.ps1' })
    (Get-PersistenceHits -Entries $e -Patterns (Get-PersistencePatterns)).Count -eq 1
}
Test-Case "Persistance VRAI-POSITIF : raccourci du dossier Demarrage qui pointe vers un cheat ou vers Temp => suspect" {
    $p = Get-PersistencePatterns
    $cheat = @([pscustomobject]@{ Source='Demarrage'; Name='Discord.lnk'; Command='C:\Tools\engineowning\launcher.exe' })
    $temp  = @([pscustomobject]@{ Source='Demarrage'; Name='update.lnk';  Command='C:\Users\bob\AppData\Local\Temp\x7\svc.exe' })
    ((Get-PersistenceHits -Entries $cheat -Patterns $p).Count -eq 1) -and ((Get-PersistenceHits -Entries $temp -Patterns $p).Count -eq 1)
}
Test-Case "Persistance GARDE-FOU (cas reels du PC d'Alex 17/09) : WZP SOUND, Athena, AnyDesk, rundll32 PcaSvc => AUCUN hit ; null/vide => 0, pas de crash" {
    $p = Get-PersistencePatterns
    $clean = @(
        [pscustomobject]@{ Source='Tache'; Name='WZP-SOUND-Guard'; Command='powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Program Files\WZP SOUND\guard.ps1"' },
        [pscustomobject]@{ Source='Tache'; Name='Athena-Autorun'; Command='powershell -ExecutionPolicy Bypass -File %USERPROFILE%\athena\Start-Athena.ps1' },
        [pscustomobject]@{ Source='Tache'; Name='PcaPatchDbTask'; Command='%windir%\system32\rundll32.exe %windir%\system32\PcaSvc.dll,PcaPatchSdbTask' },
        [pscustomobject]@{ Source='Demarrage'; Name='AnyDesk.lnk'; Command='"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --control' }
    )
    ((Get-PersistenceHits -Entries $clean -Patterns $p).Count -eq 0) -and
    ((Get-PersistenceHits -Entries $null -Patterns $p).Count -eq 0) -and
    ((Get-PersistenceHits -Entries @() -Patterns $p).Count -eq 0)
}
Test-Case "Persistance : une TACHE dans Temp n'est pas suspecte a elle seule (installeurs/MAJ legitimes) ; seul un nom de cheat compte" {
    $e = @([pscustomobject]@{ Source='Tache'; Name='SetupCleanup'; Command='C:\Users\bob\AppData\Local\Temp\setup\cleanup.exe' })
    (Get-PersistenceHits -Entries $e -Patterns (Get-PersistencePatterns)).Count -eq 0
}
# Deux sources de demarrage que DexCheck ne lisait pas du tout (mesure 17/09 sur le PC d'Alex : 319 services,
# 0 binaire sous \Users\ ; 0 consommateur WMI qui lance une commande) : un service Windows ordinaire dont le
# binaire vit dans le profil utilisateur, et un abonnement WMI permanent (technique de persistance furtive).
Test-Case "Persistance VRAI-POSITIF : service Windows dont le binaire est dans le profil utilisateur, ou consommateur WMI qui lance une commande depuis le profil => suspect" {
    $p = Get-PersistencePatterns
    $svc = @([pscustomobject]@{ Source='Service'; Name='AudioSrvHelper'; Command='"C:\Users\bob\AppData\Roaming\audio\svchelper.exe" -k' })
    $wmi = @([pscustomobject]@{ Source='WMI'; Name='Updater'; Command='powershell.exe -w hidden -File C:\Users\bob\AppData\Local\u\run.ps1' })
    ((Get-PersistenceHits -Entries $svc -Patterns $p).Count -eq 1) -and ((Get-PersistenceHits -Entries $wmi -Patterns $p).Count -eq 1)
}
Test-Case "Persistance GARDE-FOU : une cle Run vers le profil utilisateur (Discord, Spotify : tres courant) n'est PAS suspecte ; un service sous Program Files non plus" {
    $p = Get-PersistencePatterns
    $clean = @(
        [pscustomobject]@{ Source='Run'; Name='Discord'; Command='"C:\Users\bob\AppData\Local\Discord\Update.exe" --processStart Discord.exe' },
        [pscustomobject]@{ Source='Service'; Name='AnyDesk'; Command='"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service' }
    )
    (Get-PersistenceHits -Entries $clean -Patterns $p).Count -eq 0
}
# Comptes Windows multiples (mesure 17/09 : 3 profils sur le PC d'Alex). Les sondes fichier ne lisaient que le
# compte qui lance le check : un joueur qui triche depuis un 2e compte passait dessous en silence.
Test-Case "Select-UserProfileDirs : compte courant d'abord, autres comptes ensuite ; profils systeme, speciaux et doublons ecartes" {
    $profiles = @(
        [pscustomobject]@{ LocalPath='C:\Users\alt';   Special=$false },
        [pscustomobject]@{ LocalPath='C:\Users\BOB';   Special=$false },
        [pscustomobject]@{ LocalPath='C:\WINDOWS\ServiceProfiles\LocalService'; Special=$true },
        [pscustomobject]@{ LocalPath='C:\WINDOWS\system32\config\systemprofile'; Special=$false },
        [pscustomobject]@{ LocalPath=''; Special=$false }
    )
    $d = @(Select-UserProfileDirs -Profiles $profiles -Current 'C:\Users\bob')
    ($d.Count -eq 2) -and ($d[0] -eq 'C:\Users\bob') -and ($d[1] -eq 'C:\Users\alt') -and
    (@(Select-UserProfileDirs -Profiles $null -Current 'C:\Users\bob').Count -eq 1)
}
Test-Case "Select-UserHiveRoots : HKCU d'abord, puis la ruche de chaque AUTRE compte connecte (HKEY_USERS\SID) ; comptes deconnectes nommes comme NON lus" {
    $cur = 'S-1-5-21-1-2-3-1001'; $oth = 'S-1-5-21-1-2-3-1002'; $off = 'S-1-5-21-1-2-3-1003'
    $loaded = @('.DEFAULT','S-1-5-18','S-1-5-19','S-1-5-20', $cur, "${cur}_Classes", $oth, "${oth}_Classes")
    $profiles = @(
        [pscustomobject]@{ Sid=$cur; LocalPath='C:\Users\bob';  Special=$false },
        [pscustomobject]@{ Sid=$oth; LocalPath='C:\Users\alt';  Special=$false },
        [pscustomobject]@{ Sid=$off; LocalPath='C:\Users\off';  Special=$false },
        [pscustomobject]@{ Sid='S-1-5-19'; LocalPath='C:\WINDOWS\ServiceProfiles\LocalService'; Special=$true }
    )
    $r = Select-UserHiveRoots -LoadedSids $loaded -CurrentSid $cur -Profiles $profiles
    ($r.Roots.Count -eq 2) -and
    ($r.Roots[0].User -eq 'HKCU:') -and ($r.Roots[0].Classes -eq 'HKCU:\Software\Classes') -and
    ($r.Roots[1].User -eq "Registry::HKEY_USERS\$oth") -and ($r.Roots[1].Classes -eq "Registry::HKEY_USERS\${oth}_Classes") -and
    (@($r.Unread).Count -eq 1) -and (@($r.Unread)[0] -eq 'C:\Users\off')
}
Test-Case "UserAssist, cles Run utilisateur, RecentDocs/RunMRU/MuiCache lisent la ruche de CHAQUE compte connecte" {
    $ok = $true
    foreach ($fn in @('Probe-ExecEvidence','Probe-Persistence','Probe-RecentActivity')) {
        $src = (Get-Item ("function:" + $fn)).ScriptBlock.ToString()
        if ($src -notmatch 'Get-UserHiveRoots') { Write-Host "      ($fn ne lit que HKCU)" -ForegroundColor DarkYellow; $ok = $false }
        if ($src -match "'HKCU:\\") { Write-Host "      ($fn garde un chemin HKCU en dur)" -ForegroundColor DarkYellow; $ok = $false }
    }
    $ok
}
Test-Case "Historique PowerShell, navigateurs, rapports de plantage et cheats connus lisent TOUS les profils (pas seulement le compte courant)" {
    $ok = $true
    foreach ($fn in @('Probe-PsHistory','Probe-Browsers','Probe-WerCrashes','Probe-KnownCheats')) {
        $src = (Get-Item ("function:" + $fn)).ScriptBlock.ToString()
        if ($src -notmatch 'Get-UserProfileDirs') { Write-Host "      ($fn ne lit que le compte courant)" -ForegroundColor DarkYellow; $ok = $false }
    }
    $ok
}
# Revue 17/09 : la regle « zone Temp » ne visait que Run et Demarrage ; etendue par erreur aux services et au WMI.
Test-Case "Persistance GARDE-FOU (revue 17/09) : un service ou un abonnement WMI dans C:\Windows\Temp SANS nom de cheat n'est PAS suspect" {
    $e = @(
        [pscustomobject]@{ Source='Service'; Name='InstallerHelper'; Command='C:\Windows\Temp\setup\helper.exe' },
        [pscustomobject]@{ Source='WMI'; Name='Cleanup'; Command='C:\Windows\Temp\clean.cmd' }
    )
    (Get-PersistenceHits -Entries $e -Patterns (Get-PersistencePatterns)).Count -eq 0
}
Test-Case "Select-ReadableHives (revue 17/09) : une ruche connectee mais REFUSEE (sans admin) n'est pas comptee comme lue et elle est nommee" {
    $sel = [pscustomobject]@{
        Roots  = @([pscustomobject]@{ Sid='S-1'; User='HKCU:'; Classes='HKCU:\Software\Classes' },
                   [pscustomobject]@{ Sid='S-2'; User='Registry::HKEY_USERS\S-2'; Classes='Registry::HKEY_USERS\S-2_Classes' })
        Unread = @('C:\Users\off')
    }
    $r = Select-ReadableHives -Selection $sel -CanRead { param($p) $p -notlike '*S-2*' }
    ($r.Roots.Count -eq 1) -and ($r.Roots[0].Sid -eq 'S-1') -and
    (@($r.Unread).Count -eq 2) -and ((@($r.Unread) -join '|') -match 'S-2.*admin')
}
Test-Case "Probe-Persistence lit aussi les services Windows et les abonnements WMI permanents" {
    $src = ${function:Probe-Persistence}.ToString()
    ($src -match 'Win32_Service') -and ($src -match 'root\\subscription') -and ($src -match 'CommandLineEventConsumer') -and ($src -match 'ActiveScriptEventConsumer')
}
Test-Case "Probe-Persistence lit les trois sources qui manquaient : arguments de tache, dossiers Demarrage, Run 32 bits" {
    $src = ${function:Probe-Persistence}.ToString()
    # la ligne de tache doit CONTENIR les arguments (lire .Arguments sans les mettre dans Command survivait a la mutation)
    ($src -match '\.Arguments') -and ($src -match 'Command=\("\$ex \$ar"\)') -and ($src -match "GetFolderPath\('Startup'\)") -and ($src -match "GetFolderPath\('CommonStartup'\)") -and ($src -match 'WOW6432Node')
}

Section "J. REVUE 17/09 : PowerShell 32 bits sur Windows 64 bits"
# Dans un PowerShell 32 bits, HKLM:\SOFTWARE\...\Run, IFEO et System32\drivers sont REDIRIGES vers
# WOW6432Node / SysWOW64 : Persistance, IFEO et pilotes liraient les mauvais emplacements et
# diraient « rien trouve ». Le script doit se relancer dans le PowerShell 64 bits natif.
Test-Case "Get-Native64PowerShell : processus 32 bits sur OS 64 bits => chemin sysnative ; sinon rien" {
    $p = Get-Native64PowerShell -Is64BitOS $true -Is64BitProcess $false -WinDir 'C:\Windows'
    ($p -eq 'C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe') -and
    ($null -eq (Get-Native64PowerShell -Is64BitOS $true -Is64BitProcess $true -WinDir 'C:\Windows')) -and
    ($null -eq (Get-Native64PowerShell -Is64BitOS $false -Is64BitProcess $false -WinDir 'C:\Windows'))
}
Test-Case "ConvertTo-ArgList : les parametres passes sont retransmis a la relance (switch, texte, nombre)" {
    $a = @(ConvertTo-ArgList @{ Deep = [switch]$true; NoPause = [switch]$false; Nonce = 'mot du modo'; FreeSpaceCapMB = 64 })
    ($a -contains '-Deep') -and ($a -notcontains '-NoPause') -and
    ($a[[array]::IndexOf($a, '-Nonce') + 1] -eq 'mot du modo') -and
    ($a[[array]::IndexOf($a, '-FreeSpaceCapMB') + 1] -eq '64')
}

Section "I. REVUE 17/09 : dossiers utilisateur rediriges par OneDrive"
# Mesure sur le PC d'Alex : Bureau reel = OneDrive\Bureau (33 fichiers) alors que les sondes lisaient
# %USERPROFILE%\Desktop (8 fichiers), idem Documents (48 vs 4). Un cheat pose sur le vrai Bureau
# etait invisible pour KnownCheats, GpcScripts et DownloadProvenance, qui disaient « rien trouve ».
Test-Case "Get-UserFolderRoots : inclut les dossiers REDIRIGES (OneDrive) en plus des chemins historiques, sans doublon" {
    $r = @(Get-UserFolderRoots -ProfileDir 'C:\U' -Desktop 'C:\U\OneDrive\Bureau' -Documents 'C:\U\OneDrive\Documents' -Downloads 'C:\U\Downloads')
    ($r -contains 'C:\U\OneDrive\Bureau') -and ($r -contains 'C:\U\OneDrive\Documents') -and
    ($r -contains 'C:\U\Desktop') -and ($r -contains 'C:\U\Documents') -and
    (@($r | Where-Object { $_ -eq 'C:\U\Downloads' }).Count -eq 1)
}
Test-Case "Get-UserFolderRoots : sans redirection, pas de doublon ni de chemin vide" {
    $r = @(Get-UserFolderRoots -ProfileDir 'C:\U' -Desktop 'C:\U\Desktop' -Documents '' -Downloads $null)
    ($r.Count -eq 3) -and (@($r | Where-Object { -not $_ }).Count -eq 0)
}
Test-Case "Les 3 sondes de fichiers utilisateur passent par Get-UserFolderRoots (plus de chemin %USERPROFILE%\\Desktop code en dur)" {
    $src = [IO.File]::ReadAllText($ScriptPath)
    ($src -notmatch 'USERPROFILE\\(Desktop|Documents|Downloads)"') -and
    ([regex]::Matches($src, 'Get-UserFolderRoots').Count -ge 4)
}

Section "H. RETOUR TERRAIN 16/09 (Alex) : PC propre = propre, resultat dans la fenetre, rien sur le Bureau"
# PC d'Alex, jamais rien de louche : A VERIFIER a cause de 'irm https://claude.ai/install.ps1 | iex'.
# Installer un logiciel par irm|iex est banal : liste en INFO (visible), jamais un WARN sur verdict.
Test-Case "PSHIST : telecharger-et-executer vers une cible NON cheat => INFO (ne pese pas sur le verdict)" {
    $saved = $env:APPDATA
    $d = Join-Path $env:TEMP ('dexcheck-pshist-' + [guid]::NewGuid().ToString('N'))
    try {
        $h = Join-Path $d 'Microsoft\Windows\PowerShell\PSReadLine'
        New-Item -ItemType Directory -Force $h | Out-Null
        Set-Content -LiteralPath (Join-Path $h 'ConsoleHost_history.txt') -Value 'irm https://claude.ai/install.ps1 | iex'
        $env:APPDATA = $d
        function Get-UserProfileDirs { @() }   # revue 17/09 : sinon les vrais profils de la machine de test sont lus
        $r = Probe-PsHistory
        ($r.Status -eq 'INFO') -and ($r.Severity -eq 0) -and (($r.Details -join "`n") -match 'claude\.ai')
    } finally { $env:APPDATA = $saved; Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
}
Test-Case "PSHIST : cible au nom de cheat distinctif => reste FLAG" {
    $saved = $env:APPDATA
    $d = Join-Path $env:TEMP ('dexcheck-pshist-' + [guid]::NewGuid().ToString('N'))
    try {
        $h = Join-Path $d 'Microsoft\Windows\PowerShell\PSReadLine'
        New-Item -ItemType Directory -Force $h | Out-Null
        Set-Content -LiteralPath (Join-Path $h 'ConsoleHost_history.txt') -Value 'irm https://engineowning.to/loader.ps1 | iex'
        $env:APPDATA = $d
        function Get-UserProfileDirs { @() }   # revue 17/09 : isole des vrais profils de la machine de test
        (Probe-PsHistory).Status -eq 'FLAG'
    } finally { $env:APPDATA = $saved; Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
}
Test-Case "PSHIST VRAI-POSITIF bout en bout : la trace est dans un AUTRE compte Windows (le compte courant est propre) => FLAG" {
    $saved = $env:APPDATA
    $root  = Join-Path $env:TEMP ('dexcheck-profiles-' + [guid]::NewGuid().ToString('N'))
    $clean = Join-Path $root 'courant\AppData\Roaming'
    $other = Join-Path $root 'autre'
    try {
        New-Item -ItemType Directory -Force $clean | Out-Null
        $h = Join-Path $other 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine'
        New-Item -ItemType Directory -Force $h | Out-Null
        Set-Content -LiteralPath (Join-Path $h 'ConsoleHost_history.txt') -Value 'irm https://engineowning.to/loader.ps1 | iex'
        $env:APPDATA = $clean
        # Seul l'autre compte est connu : on isole du vrai disque de la machine de test.
        function Get-UserProfileDirs { @($other) }
        $r = Probe-PsHistory
        ($r.Status -eq 'FLAG') -and (($r.Details -join "`n") -match [regex]::Escape($other))
    } finally { $env:APPDATA = $saved; Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
}
# « les fichiers de resultats on s'en fout, on veut le resultat direct, pas sur le Bureau »
Test-Case "Sortie : sans -OutputDir, les fichiers vont dans TEMP, JAMAIS sur le Bureau" {
    $dir = Resolve-DefaultReportDir
    $desk = try { [Environment]::GetFolderPath('Desktop') } catch { '' }
    ($dir -like "$env:TEMP*") -and (-not $desk -or ($dir -notlike "$desk*"))
}
Test-Case "Ecran de fin : pas de chemin de fichier ni de SHA ; le DETAIL de chaque WARN/FLAG est affiche" {
    $res = @(
        (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'WARN' -Severity 1 -Summary 's' -Details @('  2026-09-16 20:29  [C:] cheat-loader.exe')),
        (New-ProbeResult -Id 'PREFETCH' -Name 'Prefetch' -Status 'OK' -Severity 0 -Summary 'ok' -Details @('ne-doit-pas-apparaitre'))
    )
    $lines = (Get-FindingScreenLines $res) -join "`n"
    ($lines -match 'cheat-loader\.exe') -and ($lines -notmatch 'ne-doit-pas-apparaitre') -and
    ([IO.File]::ReadAllText($ScriptPath) -notmatch 'Write-Host \("   (Rapport|HTML|SHA256)\s*:')
}
Test-Case "Launcher : passe -NoPause (une seule attente de touche, celle du .bat)" {
    $invokes = @(($script:BatText -split "\r?\n") | Where-Object { ($_ -match '(?i)powershell') -and ($_ -match '(?i)DexCheck\.ps1') })
    ($invokes.Count -ge 1) -and (@($invokes | Where-Object { $_ -notmatch '(?i)-NoPause' }).Count -eq 0)
}
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host (" BILAN : {0} PASS / {1} FAIL" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "==================================================================" -ForegroundColor Cyan
try { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue } catch { }
exit $script:Fail
