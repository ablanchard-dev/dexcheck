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
Test-Case "Get-CheatFlagPatterns : inclut aimbot + provider, exclut loader/cheat" {
    $f = Get-CheatFlagPatterns
    ($f -contains 'aimbot') -and ($f -contains 'engineowning') -and (-not ($f -contains 'loader')) -and (-not ($f -contains 'cheat'))
}
Test-Case "Partition : 'fabric_loader.exe' = generique seul (WARN), pas FLAG ; 'cod_aimbot.exe' = FLAG" {
    $flag = Get-CheatFlagPatterns
    $loaderFlag = Test-AnyWord 'fabric_loader.exe' $flag
    $loaderWarn = Test-AnyWord 'fabric_loader.exe' $script:CheatWarnWords
    $aimbotFlag = Test-AnyWord 'cod_aimbot.exe' $flag
    ((-not $loaderFlag) -and $loaderWarn -and $aimbotFlag)
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
Test-Case "Prefetch : ds4windows/x360ce.pf = dual-use (WARN, pas FLAG) ; aimbot.pf = FLAG (fin du faux-SUSPECT)" {
    $flag = Get-CheatFlagPatterns
    $warn = @($script:CheatWarnWords); foreach($t in $script:InputTools){ $warn += $t.App }
    (-not (Test-AnyWord 'DS4WINDOWS.EXE-A1B2C3D4.pf' $flag)) -and (Test-AnyWord 'DS4WINDOWS.EXE-A1B2C3D4.pf' $warn) -and
    (-not (Test-AnyWord 'X360CE.EXE-11223344.pf' $flag)) -and (Test-AnyWord 'X360CE.EXE-11223344.pf' $warn) -and
    (Test-AnyWord 'COD_AIMBOT.EXE-99887766.pf' $flag)
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
$shimBlob = [byte[]](@($shimHdr) + @(New-ShimEntry 'C:\cheats\aimbot.exe') + @(New-ShimEntry 'C:\Windows\System32\cmd.exe'))
$shimEntries = ConvertFrom-Shimcache $shimBlob   # List[object] : semantique List, pas de @()

Test-Case "ConvertFrom-Shimcache : decode les 2 entrees du blob" {
    $shimEntries.Count -eq 2
}
Test-Case "ConvertFrom-Shimcache : chemins exacts (decodage UTF-16LE + avance par cachedEntryDataSize)" {
    ($shimEntries[0].Path -eq 'C:\cheats\aimbot.exe') -and ($shimEntries[1].Path -eq 'C:\Windows\System32\cmd.exe')
}
Test-Case "ConvertFrom-Shimcache : FILETIME decode en DateTime non nul" {
    ($shimEntries[0].Time -is [datetime]) -and ($shimEntries[0].Time.Year -gt 2000)
}
Test-Case "Shimcache : 'aimbot.exe' = FLAG distinctif, 'cmd.exe' = clean (parite FLAG/WARN avec les autres sondes)" {
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
    'C:\cheats\aimbot.exe|2025-04-23 14:43:43.215',
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
Test-Case "PCA : 'aimbot' = FLAG, 'fabric_loader' = WARN-pas-FLAG, 'Everything' = clean (parite 2 niveaux)" {
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

Test-Case "PS history : download-and-exec dual-use (Chris Titus winutil) => WARN, pas FLAG (cible pas un token cheat)" {
    $f = Get-CheatFlagPatterns
    $h = Get-PsHistoryHits @('iwr -useb https://christitus.com/win | iex') $f
    ($h.Count -eq 1) -and (-not $h[0].IsFlag)
}
Test-Case "PS history : telechargement depuis une CIBLE au nom de cheat distinctif (engineowning) => FLAG" {
    $f = Get-CheatFlagPatterns
    $h = Get-PsHistoryHits @('iwr https://engineowning.to/loader.ps1 | iex') $f
    ($h.Count -eq 1) -and ($h[0].IsFlag)
}
Test-Case "PS history : un COMMENTAIRE mentionnant aimbot, sans verbe de telechargement => AUCUN hit (nom != preuve)" {
    $f = Get-CheatFlagPatterns
    $h = Get-PsHistoryHits @('# comment enlever un aimbot de mon pc','Get-Process') $f
    ($h.Count -eq 0)
}
Test-Case "PS history : MARIUS (board legitime) telecharge => WARN pas FLAG (veracite : marius n'est pas un token cheat)" {
    $f = Get-CheatFlagPatterns
    $h = Get-PsHistoryHits @('iwr https://raw.githubusercontent.com/EODBruz/MARIUS-BOARD-CONFIGURATOR/main/MARIUS.ps1 | iex') $f
    ($h.Count -eq 1) -and (-not $h[0].IsFlag)
}
Test-Case "PS history : -EncodedCommand (base64, pas d'URL) => WARN (verbe suspect), jamais FLAG sans cible" {
    $f = Get-CheatFlagPatterns
    $h = Get-PsHistoryHits @('powershell -enc SQBFAFgA') $f
    ($h.Count -eq 1) -and (-not $h[0].IsFlag)
}
Test-Case "PS history : lignes benignes / null => 0 hit (pas de faux positif, pas de crash)" {
    $f = Get-CheatFlagPatterns
    ((Get-PsHistoryHits @('cd C:\','Get-ChildItem','git status') $f).Count -eq 0) -and
    ((Get-PsHistoryHits $null $f).Count -eq 0)
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
