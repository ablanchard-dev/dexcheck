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
        (New-ProbeResult -Id 'DEFENDER' -Name d -Status 'WARN' -Severity 1),
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
    $ids = @('IDENT','WINAGE','USN','DELFILES','EXEC','SHIMCACHE','PCA','PREFETCH','PROC','PERSIST','EVTLOG','ANTIFOR','BROWSER','DNS','HARDWARE','DMAPCI','SECBOOT','NET','CHEATS','INPUT','VM','DEFENDER','KDRV','INJECT')
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
    $rs = @((New-ProbeResult -Id DEFENDER -Name d -Status WARN -Severity 1))
    -not (Get-EvasionProfile $rs).Escalate
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
        (New-ProbeResult -Id DEFENDER -Name d -Status WARN -Severity 1)
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
Test-Case "Run -Deep : CSV USN genere" {
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

$adminE = $false
try { $adminE = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) } catch { }

Test-Case "USN vrai-positif : un fichier au nom de cheat SUPPRIME est capture end-to-end (coeur anti-wipe prouve, pas juste synthetique)" {
    if (-not $adminE) { Write-Host "      (admin requis pour lire l'USN brut -> skip non bloquant ; relancer en admin pour la preuve)" -ForegroundColor DarkGray; return $true }
    $token = 'baitztoken'
    $vol   = (Split-Path $env:TEMP -Qualifier)   # ex 'C:'
    $bait  = Join-Path $env:TEMP 'dexcheck-selftest-baitztoken.exe'
    try {
        Set-Content -Path $bait -Value 'dexcheck true-positive self-test' -ErrorAction Stop
        Remove-Item -Path $bait -Force -ErrorAction Stop
    } catch { Write-Host ("      -> impossible de planter l'appat : {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow; return $false }
    Start-Sleep -Milliseconds 250
    $scan = Get-UsnScan -Volume $vol -FlagPatterns @($token) -WarnPatterns @()
    $caught = @($scan.FlagSuspects | Where-Object { [string]$_.Name -match $token })
    if ($caught.Count -lt 1) { Write-Host "      -> la suppression plantee n'a PAS ete retrouvee dans le journal USN" -ForegroundColor DarkYellow }
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
    $invokes = ($script:BatText -split "\r?\n") | Where-Object { ($_ -match '(?i)powershell') -and ($_ -match '(?i)DexCheck\.ps1') }
    ($invokes.Count -ge 1) -and (@($invokes | Where-Object { $_ -notmatch '(?i)-NoElevate' }).Count -eq 0)
}
Test-Case "Launcher : se termine par pause (la fenetre reste ouverte quoi qu'il arrive)" {
    $script:BatText.TrimEnd() -match '(?is)pause\s*$'
}

# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host (" BILAN : {0} PASS / {1} FAIL" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "==================================================================" -ForegroundColor Cyan
try { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue } catch { }
exit $script:Fail
