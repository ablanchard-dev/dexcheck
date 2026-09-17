<#
    DexCheck.ps1 - PC check forensic anti-triche (CoD/Warzone)
    Auteur : Alexandre Blanchard (DrDexter). Deploye pour la communaute Warzup.
    Usage joueur : double-clic sur LANCER-LE-CHECK.bat (check complet, aucune question).
    Le script s'auto-eleve en admin (UAC). En screenshare, le resultat defile en direct et
    le detail de chaque alerte s'affiche a la fin : c'est CA la preuve. Confiance = le MODO
    fournit le script et regarde le direct, le joueur ne se check pas avec un script qu'il
    a apporte.

    Switches :
      -Deep       analyse approfondie (plus lent, pour un joueur deja suspect)
      -Nonce      mot dicte par le modo au moment du check : imprime a l'ecran + dans le
                  rapport, donc plie dans le hash SHA256. Prouve que le rapport a ete
                  genere LIVE pour CETTE session (anti-rapport-prefabrique / anti-rejeu).
      -NoElevate  ne pas tenter l'elevation UAC (tests)
      -NoPause    ne pas attendre une touche a la fin (tests / automation)
      -OutputDir  dossier des fichiers de trace txt/html/csv (defaut : %TEMP%\DexCheck)

    Concu pour Windows 10/11, PowerShell 5.1+, 100% natif (aucune dependance).
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Deep,
    [switch]$NoElevate,
    [switch]$NoPause,
    [string]$OutputDir,
    [string]$Nonce,   # mot dicte par le modo au moment du check : imprime + plie dans le hash => preuve que le run est LIVE (anti-rapport-prefabrique)
    [int]$FreeSpaceCapMB = 1024,
    [switch]$NoRun   # charge les fonctions sans lancer le check (tests unitaires : . DexCheck.ps1 -NoRun)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$script:Version  = '1.2.0'
# Empreinte du script lui-meme, calculee au lancement et imprimee dans le rapport.
# `n/a` si le script est dot-source ou colle dans la console (pas de chemin sur disque) :
# on prefere le dire plutot qu'afficher une valeur qui ne veut rien dire.
$script:SelfHash = try {
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) { 'n/a (script sans chemin sur disque)' }
    else { (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256 -ErrorAction Stop).Hash }
} catch { 'n/a (illisible)' }
$script:SysDrive = $env:SystemDrive
if ([string]::IsNullOrWhiteSpace($script:SysDrive)) { $script:SysDrive = 'C:' }

# ============================================================================
# COUCHE 0 - TABLES DE SIGNATURES (faciles a completer)
# ============================================================================

# Cheats logiciels. GenericName=$true => on ne matche QUE sur domaine/installeur
# (pas sur sous-chaine de nom de process) pour eviter les faux positifs.
$script:CheatSoftware = @(
    @{ Name='EngineOwning'; Patterns=@('engineowning','enginowning'); Domains=@('engineowning.to','engineowning.com'); GenericName=$false }
    @{ Name='PhantomOverlay'; Patterns=@('phantomoverlay','phantom overlay'); Domains=@('phantomoverlay.com'); GenericName=$false }
    @{ Name='Lavicheats'; Patterns=@('lavicheats'); Domains=@('lavicheats.com'); GenericName=$false }
    @{ Name='Skript.gg'; Patterns=@('skript.gg','skriptgg'); Domains=@('skript.gg'); GenericName=$false }
    @{ Name='Interwebz'; Patterns=@('interwebz'); Domains=@('interwebz.cc','interwebz.gg'); GenericName=$false }
    @{ Name='Memesense'; Patterns=@('memesense'); Domains=@('memesense.com','memesense.org'); GenericName=$false }
    @{ Name='Ring-1'; Patterns=@('ring-1','ring1cheats'); Domains=@('ring-1.io'); GenericName=$false }
    @{ Name='Fecurity'; Patterns=@('fecurity'); Domains=@('fecurity.com','fecurity.net'); GenericName=$false }
    @{ Name='Disconnect.gg'; Patterns=@('disconnect.gg'); Domains=@('disconnect.gg'); GenericName=$false }
    @{ Name='Coldware/ColdVision'; Patterns=@('coldware','coldvision'); Domains=@('coldware.io','coldvision.io'); GenericName=$false }
    @{ Name='Hypervision'; Patterns=@('hypervision','hypercheats'); Domains=@('hypercheats.ru','hypervision.io'); GenericName=$false }
    # Noms generiques (mots courants) -> domaine/installeur uniquement
    @{ Name='Cobra'; Patterns=@('cobraaim','cobracheats'); Domains=@('cobracheats.com'); GenericName=$true }
    @{ Name='Susano'; Patterns=@('susanocheats'); Domains=@('susano.gg'); GenericName=$true }
    @{ Name='Abstract/Abstrakt'; Patterns=@('abstrakt'); Domains=@('abstrakt.cc'); GenericName=$true }
    @{ Name='Klar'; Patterns=@('klarcheats'); Domains=@('klar.gg'); GenericName=$true }
    # Boutiques hardware DMA/HID (aimbot sur 2e PC, meta 2025) : DOMAINE SEUL (Patterns vide) ->
    # ne touche QUE l'historique navigateur, jamais un match de nom de fichier. Une visite = WARN
    # a corroborer (visite != achat != usage). Sources : dma-cheats.com, blurred.gg, dma-firmware.com.
    @{ Name='Boutiques DMA/HID'; Patterns=@(); Domains=@('dma-cheats.com','blurred.gg','dma-firmware.com'); GenericName=$true }
)

# Outils de manipulation d'input / anti-recoil / hardware. Dual-use. Severity :
# 0=presence informative (suites ubiquistes), 1=WARN (a verifier), 2=FLAG (hardware).
# Escalade = par IDENTITE hardware (device Cronus/XIM/Titan), pas par inspection de macro.
# Tokens USB = mots distinctifs (matches en frontiere de mot \b cote sonde) pour eviter
# les faux positifs (Ryzen/Zenbook, Maxim, NVIDIA TITAN...).
$script:InputTools = @(
    @{ Name='Cronus Zen / CronusMAX'; App=@('cronus zen','cronusmax','cronus'); Driver=@(); Usb=@('cronus'); Severity=2 }
    @{ Name='XIM (Apex/Matrix/Nexus)'; App=@('xim manager','xim apex','xim matrix','xim nexus'); Driver=@(); Usb=@('xim'); Severity=2 }
    @{ Name='Titan Two / Titan One'; App=@('gtuner','titan two','titan one','consoletuner'); Driver=@(); Usb=@('titan two','titan one','consoletuner'); Severity=2 }
    @{ Name='ReaSnow S1'; App=@('reasnow'); Driver=@(); Usb=@('reasnow'); Severity=2 }
    @{ Name='Strike Pack (Collective Minds)'; App=@('strike pack','collective minds'); Driver=@(); Usb=@('strike pack','collective minds'); Severity=2 }
    # Injection HID (aimbot 2e PC, meta 2025) : noms de PRODUIT distinctifs. Base WARN (presence a
    # corroborer, jamais FLAG-sur-presence). Sources : dma-cheats.com/hid, lonelyshop. La puce
    # sous-jacente (ch340/ch9329/teensy/arduino) n'est JAMAIS un token (dual-use = faux positifs).
    # 'ferrum' EXCLU : collision Ferrum Audio (DAC/amplis USB haut de gamme) -> a sourcer un token propre.
    @{ Name='kmbox / makcu (injection HID)'; App=@('kmbox','kmboxnet','makcu'); Driver=@(); Usb=@('kmbox','kmboxnet','makcu'); Severity=1 }
    @{ Name='reWASD'; App=@('rewasd'); Driver=@('rewasd'); Usb=@(); Severity=1 }
    @{ Name='DS4Windows / x360ce'; App=@('ds4windows','x360ce'); Driver=@('vigembus','scpvbus'); Usb=@(); Severity=0 }
    @{ Name='Logitech G HUB / LGS'; App=@('logitech g hub','logitech gaming software'); Driver=@(); Usb=@(); Severity=0 }
    @{ Name='Razer Synapse'; App=@('razer synapse'); Driver=@(); Usb=@(); Severity=0 }
    @{ Name='JoyToKey / AntiMicro / InputMapper'; App=@('joytokey','antimicro','inputmapper'); Driver=@(); Usb=@(); Severity=1 }
)

# Outils anti-forensic / wipe -> FLAG (effacement securise). 'cipher' retire (outil
# Windows natif, indistinguable d'un usage benin via prefetch).
$script:AntiForensicTools = @('bleachbit','privazer','sdelete','eraser','disk wipe','diskwipe','wipefile','o&o safeerase','hardwipe')
# Nettoyeurs courants dual-use -> WARN seulement (installation seule != preuve).
$script:CleanerToolsWarn = @('ccleaner','wise disk cleaner','wise care')

# Cartes DMA / capture hardware de triche. Noms distinctifs uniquement. Retires :
# 'squirrel' (framework d'install Squirrel.Windows), 'fpga'/'pcie to' (trop larges).
# DMA = lecture directe de la RAM => wallhack/radar sur une 2e machine. FLAG (sev2).
$script:DmaPatterns = @('pcileech','screamer','leetdma','captaindma','enigma x1','raptordma','dma card')
# Pont USB3 FTDI FT60x = le lien qu'une carte DMA utilise pour parler a la 2e machine.
# Aussi present sur des dev boards FPGA legitimes => WARN (a verifier), pas FLAG.
$script:DmaUsbHints = @('ft601','ft60x','ft600','usb3 to fifo','superspeed-fifo')
# Cartes de CAPTURE (ingest HDMI). Seules = streamer (INFO). Combinees a une manette
# virtuelle = signature possible de "boite a cheat" CV/console (aimbot par vision). Marques
# distinctives uniquement (PAS 'usb video' generique = webcams partout = faux positifs).
$script:CaptureCards = @('elgato','avermedia','game capture','live gamer','cam link','magewell','blackmagic','ezcap')
# Pilotes de manette VIRTUELLE / injection d'input. Avec une carte de capture = la chaine
# complete d'une boite a cheat console (capture HDMI -> aimbot vision -> injection manette).
# Tokens cales sur les vrais FriendlyName PnP : ViGEmBus = "Nefarius Virtual Gamepad Emulation
# Bus". On EVITE 'virtual bus' seul (matcherait "Logitech G HUB Virtual Bus Enumerator" = FP).
$script:VirtualPadDrivers = @('vigembus','nefarius','virtual gamepad','vjoy','scpvbus','scp virtual','hidguardian','vmulti')

# Noms suspects (suppressions / executions / exclusions), en DEUX niveaux pour eviter les
# faux SUSPECT :
#  - CheatFlagWords = distinctifs, peu ambigus            -> FLAG (sev2).
#  - CheatWarnWords = generiques / dual-use (mod-loader, "cheat sheet", plugin Skript, hwid,
#                     cleaner, unlocker) seuls             -> WARN (sev1) : a verifier, pas un ban.
# Match en frontiere de mot (Test-AnyWord / WordMatch C#), '_' '.' '-' = separateurs.
# FLAG = uniquement des noms de PRODUIT/PROVIDER distinctifs (nom complet, peu ambigu). Les mots de
# CATEGORIE (aimbot/wallhack/triggerbot/spoofer/injector...) ont ete DEMUS vers CheatWarnWords : ils
# collisionnent avec des noms legitimes (aimbot-remover.exe, anti-aimbot, wallhack-detector, un
# injector de modding) = faux FLAG sur un innocent. 'extreme injector' (outil master131, github.com/
# master131/ExtremeInjector) est un nom de PRODUIT distinctif -> reste FLAG (portait le FLAG KALMA
# via l'ancien mot 'injector' ; promu en entree propre pour ne pas evider le moat en demouvant 'injector').
$script:CheatFlagWords = @(
    'engineowning','enginowning','phantomoverlay','lavicheats','interwebz','memesense',
    'fecurity','disconnect.gg','coldware','coldvision','hypervision','hypercheats',
    'ring-1','susano','abstrakt','klarcheats','cobraaim','cronus','xim',
    'bleachbit','privazer','skript.gg','extreme injector','extremeinjector','extreme_injector'
)
# reWASD = outil de remap LEGITIME (dual-use) -> WARN, jamais FLAG (decision Alex 03/07 : un mec
# clean ne doit pas ressortir SUSPECT ; seul un VRAI cheat FLAG). Cronus/XIM restent FLAG (hardware
# d'anti-recoil = vraie triche, sev2 dans InputTools).
# Mots generiques/dual-use ET mots de CATEGORIE (aimbot/wallhack...) : WARN, jamais FLAG seul. Un nom
# de fichier au mot de categorie est surfacE au modo (DeleteSuspectPatterns = union) mais ne condamne
# pas ; seul un nom de PRODUIT distinctif escalade en FLAG. Coherent avec la sonde historique PowerShell.
$script:CheatWarnWords = @('cheat','loader','skript','hwid','cleaner','unlocker','rewasd',
    'aimbot','wallhack','triggerbot','unlockall','unlock_all','spoofer','hwidspoofer','injector')
# Union (mots + patterns providers distinctifs) = scan grossier "suspect tout court ?" cote C#.
$script:DeleteSuspectPatterns = @($script:CheatFlagWords + $script:CheatWarnWords)
foreach ($c in $script:CheatSoftware) { if (-not $c.GenericName) { $script:DeleteSuspectPatterns += $c.Patterns } }
$script:DeleteSuspectPatterns = @($script:DeleteSuspectPatterns | Where-Object { $_ } | Select-Object -Unique)

# Drivers kernel connus ABUSABLES (BYOVD = "bring your own vulnerable driver") : vecteur DMA /
# desactivation d'anti-cheat / lecture-ecriture memoire kernel. Beaucoup ont AUSSI un usage
# LEGITIME (rtcore64=MSI Afterburner, winring0=HWiNFO/monitoring) => WARN (a verifier), jamais
# FLAG auto. Match par sous-chaine sur le nom de fichier .sys (tokens distinctifs >=5 car).
# Liste a maintenir (source : projets type LOLDrivers).
$script:VulnerableDrivers = @('mhyprot2','mhyprot3','rtcore64','iqvw64e','dbutil_2_3','winring0','winio64','asio64','capcom','procexp152','speedfan','phymem','gpcidrv','gdrv64','gdrv.sys','atillk64','nvflash')

# Signatures pour le SCAN D'ESPACE LIBRE (-Deep) UNIQUEMENT. Le match se fait en ASCII
# brut sur des clusters libres = AUCUNE frontiere de mot possible. Donc : seulement des
# chaines LONGUES (>=6 car) et tres DISTINCTIVES, cheat/DMA pur. ZERO nom dual-use
# (logitech/razer/ds4windows/rewasd...) qui sont ubiquistes => sinon faux positifs en serie.
# Un hit ici = INFO de corroboration, JAMAIS un verdict : un rapport/installeur/script
# supprime (y compris DexCheck lui-meme) contient deja ces mots en espace libre.
$script:FreeSpaceCheatSignatures = @(
    # Providers de cheats (noms produits + domaines)
    'engineowning','phantomoverlay','lavicheats','skript.gg','interwebz.cc',
    'memesense','fecurity','disconnect.gg','coldvision','coldware.io',
    'hypervision','hypercheats','ring-1.io','susano.gg','abstrakt.cc',
    'klarcheats','cobracheats','cobraaim',
    # Hardware / scripts de triche (anti-recoil / conversion MnK)
    'cronus zen','cronusmax','zen studio','xim apex','xim matrix','xim nexus',
    'titan two','consoletuner','gtuner',
    # Cartes DMA / capture hardware de triche
    'pcileech','leetdma','captaindma','enigma x1'
)

# Lecteur USN (P/Invoke) compile au runtime via Add-Type. Lit le change journal
# (FSCTL_READ_USN_JOURNAL) et rend les enregistrements USN_REASON_FILE_DELETE :
# nom + date + attributs des fichiers/dossiers supprimes. Requiert admin (handle volume).
$script:UsnCSharp = @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.ComponentModel;

public static class DexCheckUsnReader {
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
    const uint FSCTL_READ_USN_JOURNAL  = 0x000900bb;
    const uint USN_REASON_FILE_DELETE  = 0x00000200;
    const uint USN_REASON_RENAME_OLD_NAME = 0x00001000;
    static readonly IntPtr INVALID = new IntPtr(-1);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inBuf, int inSize, IntPtr outBuf, int outSize, out int returned, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    struct USN_JOURNAL_DATA_V0 {
        public ulong UsnJournalID; public long FirstUsn; public long NextUsn;
        public long LowestValidUsn; public long MaxUsn; public ulong MaximumSize; public ulong AllocationDelta;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct READ_USN_JOURNAL_DATA_V0 {
        public long StartUsn; public uint ReasonMask; public uint ReturnOnlyOnClose;
        public ulong Timeout; public ulong BytesToWaitFor; public ulong UsnJournalID;
    }
    public class Rec { public string Name; public DateTime Time; public uint Reason; public uint Attributes; }

    public static List<Rec> ReadDeletes(string volume, int maxRecords) {
        var list = new List<Rec>();
        IntPtr h = CreateFile("\\\\.\\" + volume, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == INVALID) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr qOut = IntPtr.Zero, inBuf = IntPtr.Zero, outBuf = IntPtr.Zero;
        try {
            int qSize = Marshal.SizeOf(typeof(USN_JOURNAL_DATA_V0));
            qOut = Marshal.AllocHGlobal(qSize);
            int qRet;
            if (!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, qOut, qSize, out qRet, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var jd = (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(qOut, typeof(USN_JOURNAL_DATA_V0));

            var r = new READ_USN_JOURNAL_DATA_V0();
            // FirstUsn (record lisible le plus ancien), pas LowestValidUsn qui peut etre purge -> 1181.
            r.StartUsn = jd.FirstUsn; r.ReasonMask = 0xFFFFFFFF; r.ReturnOnlyOnClose = 0;
            r.Timeout = 0; r.BytesToWaitFor = 0; r.UsnJournalID = jd.UsnJournalID;
            int inSize = Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V0));
            inBuf = Marshal.AllocHGlobal(inSize);
            int bufSize = 64 * 1024;
            outBuf = Marshal.AllocHGlobal(bufSize);

            int guard = 0; int requery = 0;
            while (list.Count < maxRecords && guard < 500000) {
                guard++;
                Marshal.StructureToPtr(r, inBuf, false);
                int got;
                if (!DeviceIoControl(h, FSCTL_READ_USN_JOURNAL, inBuf, inSize, outBuf, bufSize, out got, IntPtr.Zero)) {
                    if (Marshal.GetLastWin32Error() == 1181 && requery < 8 &&
                        DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, qOut, qSize, out qRet, IntPtr.Zero)) {
                        requery++;
                        jd = (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(qOut, typeof(USN_JOURNAL_DATA_V0));
                        r.StartUsn = jd.FirstUsn; r.UsnJournalID = jd.UsnJournalID;
                        continue;
                    }
                    break;
                }
                if (got <= 8) break;
                long next = Marshal.ReadInt64(outBuf, 0);
                int off = 8;
                while (off < got) {
                    if (off + 60 > got) break; // en-tete USN_RECORD_V2 (60 o) incomplet en fin de buffer
                    int recLen = Marshal.ReadInt32(outBuf, off);
                    if (recLen <= 0) { off = got; break; }
                    long ts = Marshal.ReadInt64(outBuf, off + 32);
                    uint reason = (uint)Marshal.ReadInt32(outBuf, off + 40);
                    uint attrs = (uint)Marshal.ReadInt32(outBuf, off + 52);
                    int nameLen = Marshal.ReadInt16(outBuf, off + 56) & 0xFFFF;
                    int nameOff = Marshal.ReadInt16(outBuf, off + 58) & 0xFFFF;
                    if ((reason & USN_REASON_FILE_DELETE) != 0 && nameLen > 0 &&
                        nameOff >= 60 && (long)off + nameOff + nameLen <= got) {
                        string nm = Marshal.PtrToStringUni(new IntPtr(outBuf.ToInt64() + off + nameOff), nameLen / 2);
                        DateTime dt; try { dt = DateTime.FromFileTime(ts); } catch { dt = DateTime.MinValue; }
                        list.Add(new Rec { Name = nm, Time = dt, Reason = reason, Attributes = attrs });
                        if (list.Count >= maxRecords) break;
                    }
                    off += recLen;
                }
                if (next == 0) break;
                r.StartUsn = next;
            }
        } finally {
            if (qOut != IntPtr.Zero) Marshal.FreeHGlobal(qOut);
            if (inBuf != IntPtr.Zero) Marshal.FreeHGlobal(inBuf);
            if (outBuf != IntPtr.Zero) Marshal.FreeHGlobal(outBuf);
            CloseHandle(h);
        }
        return list;
    }

    // ---- Scan COMPLET des suppressions : tout le journal, match nom en C# (frontiere
    //      de mot), suspects + N plus recents + fenetre temporelle. Corrige le biais du
    //      cap "8000 plus vieilles entrees" qui ratait les suppressions recentes. ----
    public class ScanResult {
        public long Total = 0;
        public List<Rec> FlagSuspects = new List<Rec>();  // nom de cheat DISTINCTIF
        public List<Rec> WarnSuspects = new List<Rec>();  // nom GENERIQUE / dual-use
        public List<Rec> Recent = new List<Rec>();
        public long OldestTicks = 0;
        public long NewestTicks = 0;
        public int StopError = 0;  // 0 = journal lu jusqu'au bout ; sinon code Win32 (-1 = garde de boucle)
        public long LastRecordTicks = 0;  // horodatage du dernier enregistrement LU, tous types (pas seulement suppressions)
    }
    static bool IsWordCh(char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); }
    static bool WordMatch(string hay, string pat) {
        if (pat.Length == 0) return false;
        int idx = 0;
        while ((idx = hay.IndexOf(pat, idx, StringComparison.Ordinal)) >= 0) {
            bool lOk = idx == 0 || !IsWordCh(hay[idx - 1]);
            int aft = idx + pat.Length;
            bool rOk = aft >= hay.Length || !IsWordCh(hay[aft]);
            if (lOk && rOk) return true;
            idx++;
        }
        return false;
    }
    public static ScanResult ScanDeletes(string volume, string[] flagPats, string[] warnPats, int maxFlag, int maxWarn, int maxRecent) {
        var res = new ScanResult();
        string[] fp = new string[flagPats.Length];
        for (int i = 0; i < flagPats.Length; i++) fp[i] = flagPats[i] == null ? "" : flagPats[i].ToLowerInvariant();
        string[] wp = new string[warnPats.Length];
        for (int i = 0; i < warnPats.Length; i++) wp[i] = warnPats[i] == null ? "" : warnPats[i].ToLowerInvariant();
        IntPtr h = CreateFile("\\\\.\\" + volume, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
        if (h == INVALID) throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr qOut = IntPtr.Zero, inBuf = IntPtr.Zero, outBuf = IntPtr.Zero;
        try {
            int qSize = Marshal.SizeOf(typeof(USN_JOURNAL_DATA_V0));
            qOut = Marshal.AllocHGlobal(qSize);
            int qRet;
            if (!DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, qOut, qSize, out qRet, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var jd = (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(qOut, typeof(USN_JOURNAL_DATA_V0));
            var r = new READ_USN_JOURNAL_DATA_V0();
            // DEMARRER a FirstUsn (le plus ancien record LISIBLE), PAS LowestValidUsn : sur un journal
            // qui a tourne, LowestValidUsn peut pointer sous FirstUsn (zone purgee) -> lire la
            // renvoie ERROR_JOURNAL_ENTRY_DELETED (1181) et le scan retournait 0 EN SILENCE (aveugle).
            r.StartUsn = jd.FirstUsn; r.ReasonMask = 0xFFFFFFFF; r.ReturnOnlyOnClose = 0;
            r.Timeout = 0; r.BytesToWaitFor = 0; r.UsnJournalID = jd.UsnJournalID;
            int inSize = Marshal.SizeOf(typeof(READ_USN_JOURNAL_DATA_V0));
            inBuf = Marshal.AllocHGlobal(inSize);
            int bufSize = 64 * 1024;
            outBuf = Marshal.AllocHGlobal(bufSize);
            int guard = 0; int requery = 0;
            while (guard < 500000) {
                guard++;
                Marshal.StructureToPtr(r, inBuf, false);
                int got;
                if (!DeviceIoControl(h, FSCTL_READ_USN_JOURNAL, inBuf, inSize, outBuf, bufSize, out got, IntPtr.Zero)) {
                    // 1181 = ERROR_JOURNAL_ENTRY_DELETED : StartUsn purge (journal qui tourne pendant
                    // le scan) -> on re-interroge et on repart du plus ancien record encore lisible.
                    int err = Marshal.GetLastWin32Error();
                    if (err == 1181 && requery < 8 &&
                        DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, qOut, qSize, out qRet, IntPtr.Zero)) {
                        requery++;
                        jd = (USN_JOURNAL_DATA_V0)Marshal.PtrToStructure(qOut, typeof(USN_JOURNAL_DATA_V0));
                        r.StartUsn = jd.FirstUsn; r.UsnJournalID = jd.UsnJournalID;
                        continue;
                    }
                    // Sortie sur erreur : scan PARTIEL. On le dit au lieu de rendre un resultat qui a l'air complet.
                    res.StopError = err == 0 ? -1 : err;
                    break;
                }
                if (got <= 8) break;
                long next = Marshal.ReadInt64(outBuf, 0);
                int off = 8;
                while (off < got) {
                    if (off + 60 > got) break; // en-tete USN_RECORD_V2 (60 o) incomplet en fin de buffer
                    int recLen = Marshal.ReadInt32(outBuf, off);
                    if (recLen <= 0) { off = got; break; }
                    long ts = Marshal.ReadInt64(outBuf, off + 32);
                    if (ts > res.LastRecordTicks) res.LastRecordTicks = ts;
                    uint reason = (uint)Marshal.ReadInt32(outBuf, off + 40);
                    uint attrs = (uint)Marshal.ReadInt32(outBuf, off + 52);
                    int nameLen = Marshal.ReadInt16(outBuf, off + 56) & 0xFFFF;
                    int nameOff = Marshal.ReadInt16(outBuf, off + 58) & 0xFFFF;
                    // RENAME_OLD_NAME : renommer engineowning.exe en a.tmp puis supprimer ne journalise la
                    // suppression que sous a.tmp. L'ancien nom reste lisible ici : on le juge comme un nom supprime.
                    bool isDel = (reason & USN_REASON_FILE_DELETE) != 0;
                    if ((isDel || (reason & USN_REASON_RENAME_OLD_NAME) != 0) && nameLen > 0 &&
                        nameOff >= 60 && (long)off + nameOff + nameLen <= got) {
                        string nm = Marshal.PtrToStringUni(new IntPtr(outBuf.ToInt64() + off + nameOff), nameLen / 2);
                        DateTime dt; try { dt = DateTime.FromFileTime(ts); } catch { dt = DateTime.MinValue; }
                        if (isDel) {
                            res.Total++;
                            if (ts > 0) {
                                if (res.OldestTicks == 0 || ts < res.OldestTicks) res.OldestTicks = ts;
                                if (ts > res.NewestTicks) res.NewestTicks = ts;
                            }
                            res.Recent.Add(new Rec { Name = nm, Time = dt, Reason = reason, Attributes = attrs });
                            if (res.Recent.Count > maxRecent) res.Recent.RemoveAt(0);
                        }
                        if (nm != null) {
                            string low = nm.ToLowerInvariant();
                            bool isFlag = false;
                            for (int k = 0; k < fp.Length; k++) { if (WordMatch(low, fp[k])) { isFlag = true; break; } }
                            if (isFlag) {
                                // FLAG = liste prioritaire : un flot de noms generiques ne peut PAS l'evincer.
                                if (res.FlagSuspects.Count < maxFlag) res.FlagSuspects.Add(new Rec { Name = nm, Time = dt, Reason = reason, Attributes = attrs });
                            } else {
                                for (int k = 0; k < wp.Length; k++) {
                                    if (WordMatch(low, wp[k])) { if (res.WarnSuspects.Count < maxWarn) res.WarnSuspects.Add(new Rec { Name = nm, Time = dt, Reason = reason, Attributes = attrs }); break; }
                                }
                            }
                        }
                    }
                    off += recLen;
                }
                if (next == 0) break;
                r.StartUsn = next;
            }
            if (guard >= 500000 && res.StopError == 0) res.StopError = -1;
        } finally {
            if (qOut != IntPtr.Zero) Marshal.FreeHGlobal(qOut);
            if (inBuf != IntPtr.Zero) Marshal.FreeHGlobal(inBuf);
            if (outBuf != IntPtr.Zero) Marshal.FreeHGlobal(outBuf);
            CloseHandle(h);
        }
        return res;
    }

    // ---- Scan signatures de l'espace libre (clusters libres via bitmap) ----
    const uint FSCTL_GET_VOLUME_BITMAP = 0x9006F;
    const uint FSCTL_GET_NTFS_VOLUME_DATA = 0x90064;
    public static long LastScannedBytes = 0;

    [StructLayout(LayoutKind.Sequential)]
    struct NTFS_VOLUME_DATA_BUFFER {
        public long VolumeSerialNumber; public long NumberSectors; public long TotalClusters;
        public long FreeClusters; public long TotalReserved; public uint BytesPerSector;
        public uint BytesPerCluster; public uint BytesPerFileRecordSegment; public uint ClustersPerFileRecordSegment;
        public long MftValidDataLength; public long MftStartLcn; public long Mft2StartLcn;
        public long MftZoneStart; public long MftZoneEnd;
    }
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool ReadFile(IntPtr h, byte[] buf, int toRead, out int read, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetFilePointerEx(IntPtr h, long dist, out long newPtr, uint method);

    public static List<string> ScanFreeSpace(string volume, long maxBytes, string[] sigs) {
        long scanned = 0;
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string[] lo = new string[sigs.Length];
        for (int k = 0; k < sigs.Length; k++) lo[k] = sigs[k] == null ? "" : sigs[k].ToLowerInvariant();
        IntPtr h = CreateFile("\\\\.\\" + volume, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == INVALID) throw new Win32Exception(Marshal.GetLastWin32Error());
        int hdr = 16;
        int bmpBytes = 1024 * 1024;
        IntPtr bmpOut = Marshal.AllocHGlobal(hdr + bmpBytes);
        IntPtr lcnIn = Marshal.AllocHGlobal(8);
        try {
            uint bpc = 4096;
            int vs = Marshal.SizeOf(typeof(NTFS_VOLUME_DATA_BUFFER));
            IntPtr vb = Marshal.AllocHGlobal(vs);
            try {
                int vr;
                if (DeviceIoControl(h, FSCTL_GET_NTFS_VOLUME_DATA, IntPtr.Zero, 0, vb, vs, out vr, IntPtr.Zero)) {
                    var vd = (NTFS_VOLUME_DATA_BUFFER)Marshal.PtrToStructure(vb, typeof(NTFS_VOLUME_DATA_BUFFER));
                    if (vd.BytesPerCluster > 0) bpc = vd.BytesPerCluster;
                }
            } finally { Marshal.FreeHGlobal(vb); }

            int maxRun = (int)Math.Max(1, (1024 * 1024) / (int)bpc);
            byte[] buf = new byte[maxRun * (int)bpc];
            long curLcn = 0;
            bool more = true;
            int sguard = 0;
            while (more && scanned < maxBytes) {
                if (++sguard > 200000) break;
                Marshal.WriteInt64(lcnIn, curLcn);
                int ret;
                bool ok = DeviceIoControl(h, FSCTL_GET_VOLUME_BITMAP, lcnIn, 8, bmpOut, hdr + bmpBytes, out ret, IntPtr.Zero);
                int err = Marshal.GetLastWin32Error();
                if (!ok && err != 234) break; // 234 = ERROR_MORE_DATA
                long startLcn = Marshal.ReadInt64(bmpOut, 0);
                long clusters = Marshal.ReadInt64(bmpOut, 8);
                if (clusters > 0) clusters = Math.Min(clusters, (long)(ret - hdr) * 8);
                if (clusters <= 0) break;
                long i = 0;
                while (i < clusters && scanned < maxBytes) {
                    int bi = (int)(i >> 3), bit = (int)(i & 7);
                    byte bb = Marshal.ReadByte(bmpOut, hdr + bi);
                    if (((bb >> bit) & 1) != 0) { i++; continue; }
                    long runStart = i; long runLen = 0;
                    while (i < clusters && runLen < maxRun) {
                        int bi2 = (int)(i >> 3), bit2 = (int)(i & 7);
                        byte bb2 = Marshal.ReadByte(bmpOut, hdr + bi2);
                        if (((bb2 >> bit2) & 1) != 0) break;
                        runLen++; i++;
                    }
                    long offset = (startLcn + runStart) * bpc;
                    long np;
                    if (SetFilePointerEx(h, offset, out np, 0)) {
                        int toRead = (int)(runLen * bpc);
                        int rd;
                        if (ReadFile(h, buf, toRead, out rd, IntPtr.Zero) && rd > 0) {
                            scanned += rd;
                            string txt = System.Text.Encoding.ASCII.GetString(buf, 0, rd).ToLowerInvariant();
                            for (int k = 0; k < lo.Length; k++)
                                if (lo[k].Length > 0 && txt.IndexOf(lo[k], StringComparison.Ordinal) >= 0) found.Add(sigs[k]);
                        }
                    }
                }
                if (ok) more = false; else curLcn = startLcn + clusters;
            }
        } finally {
            Marshal.FreeHGlobal(bmpOut);
            Marshal.FreeHGlobal(lcnIn);
            CloseHandle(h);
        }
        LastScannedBytes = scanned;
        return new List<string>(found);
    }
}
'@

# ============================================================================
# COUCHE 1 - HELPERS
# ============================================================================

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    } catch { return $false }
}

function Initialize-UsnReader {
    if (-not ('DexCheckUsnReader' -as [type])) {
        Add-Type -TypeDefinition $script:UsnCSharp -Language CSharp -ErrorAction Stop
    }
}

function Get-UsnDeletes {
    param([int]$Max = 8000)
    Initialize-UsnReader
    return [DexCheckUsnReader]::ReadDeletes($script:SysDrive, $Max)
}

function Get-UsnScan {
    # Scan COMPLET du journal : total + suppressions suspectes (sur 100% du journal) +
    # N plus recentes + fenetre temporelle. Remplace l'echantillon biaise de Get-UsnDeletes.
    param([string]$Volume = $script:SysDrive, [string[]]$FlagPatterns, [string[]]$WarnPatterns,
          [int]$MaxFlag = 1000, [int]$MaxWarn = 500, [int]$MaxRecent = 12)
    Initialize-UsnReader
    return [DexCheckUsnReader]::ScanDeletes($Volume, [string[]]$FlagPatterns, [string[]]$WarnPatterns, $MaxFlag, $MaxWarn, $MaxRecent)
}

function Get-FixedNtfsDrives {
    # Lettres des volumes NTFS FIXES (C:, D:, ...) pour scanner l'USN de TOUS les disques :
    # un cheat supprime sur un 2e SSD serait invisible si on ne regardait que le systeme.
    $drives = New-Object System.Collections.Generic.List[string]
    try {
        $vols = Get-CimInstance Win32_Volume -Filter "DriveType=3 AND FileSystem='NTFS'" -ErrorAction SilentlyContinue
        foreach ($v in $vols) {
            $dl = [string]$v.DriveLetter
            if ($dl -match '^[A-Za-z]:$') { $drives.Add($dl.ToUpper()) }
        }
    } catch { }
    if ($drives.Count -eq 0) { $drives.Add($script:SysDrive) }  # repli : au moins le systeme
    return @($drives | Select-Object -Unique)
}

function Get-CheatFlagPatterns {
    # Niveau FLAG = mots distinctifs + noms de providers connus (non generiques). Utilise par
    # les sondes suppressions / executions / exclusions pour distinguer FLAG (cheat avere) de
    # WARN (mot generique dual-use). Une seule source de verite.
    $p = @($script:CheatFlagWords)
    foreach ($c in $script:CheatSoftware) { if (-not $c.GenericName) { $p += $c.Patterns } }
    return @($p | Where-Object { $_ } | Select-Object -Unique)
}

# Explication honnete par sonde (rendue seulement sous un WARN/FLAG, au live ET au rapport).
# "Shows" = ce que le finding peut indiquer ; "ProvesNot" = le caveat honnete (trouve != prouve).
# Cle = Id de sonde. Une sonde sans entree n'affiche rien (pas de crash).
$script:ProbeMeaning = @{
    IDENT     = @{ Shows="l'horloge a peut-etre ete reculee pour vieillir des traces"; ProvesNot="un fuseau, une MAJ BIOS ou un dual-boot decalent aussi l'heure - a recouper" }
    WINAGE    = @{ Shows="une reinstallation juste avant le check peut effacer les traces"; ProvesNot="un PC neuf, un nouveau SSD ou une MAJ majeure reinitialisent aussi cette date" }
    USN       = @{ Shows="sans journal USN, plus d'historique date des suppressions"; ProvesNot="le debloat/optimisation gaming le desactive tres couramment" }
    DELFILES  = @{ Shows="des fichiers ont ete supprimes (nom + date visibles)"; ProvesNot="supprimer un fichier au nom generique n'est pas tricher ; le contenu n'est pas recuperable (SSD/TRIM)"; ShowsFlag="un fichier au nom de cheat DISTINCTIF (pas dual-use) a ete supprime - nom + date de suppression horodates"; ProvesNotFlag="le contenu efface n'est plus analysable (SSD/TRIM) ; mais le nom distinctif et la date de suppression, eux, sont bien la" }
    EXEC      = @{ Shows="un executable a bien tourne, meme s'il a ete efface ensuite"; ProvesNot="une trace d'execution n'est pas un usage en match ; un nom generique reste dual-use"; ShowsFlag="un executable au nom de cheat DISTINCTIF (pas dual-use) a bel et bien tourne sur cette machine, meme efface ensuite"; ProvesNotFlag="l'artefact prouve l'EXECUTION du cheat, pas le moment precis d'usage en partie ; le binaire efface n'est plus analysable - la trace, elle, a survecu" }
    SHIMCACHE = @{ Shows="un executable est/etait present (survit a la suppression du binaire)"; ProvesNot="Shimcache = presence, pas execution garantie ; ecrit a l'arret, donc les tout derniers lancements manquent" }
    PCA       = @{ Shows="un programme a ete lance (y compris depuis une cle USB / un partage reseau)"; ProvesNot="un lancement n'est pas une preuve d'usage en partie ; un nom generique = dual-use"; ShowsFlag="un cheat au nom DISTINCTIF a ete lance (capture aussi les exe lances depuis une cle USB / un partage reseau)"; ProvesNotFlag="un lancement horodate n'est pas la preuve du moment d'usage en partie ; il prouve bien que le cheat a tourne, meme efface ensuite" }
    PREFETCH  = @{ Shows="un executable a ete lance recemment"; ProvesNot="beaucoup d'outils listes sont dual-use (manette, remap) ; un prefetch vide peut venir d'un simple nettoyage"; ShowsFlag="un executable au nom de cheat DISTINCTIF (pas un remap/manette dual-use) a ete lance recemment"; ProvesNotFlag="le prefetch date le lancement, pas la duree d'usage en match ; il confirme bien l'execution du cheat" }
    PROC      = @{ Shows="un process au nom connu ou non signe en zone temp tourne en ce moment"; ProvesNot="pas d'inspection memoire ici ; non signe n'est pas malveillant en soi" }
    PERSIST   = @{ Shows="un cheat pourrait se relancer au demarrage"; ProvesNot="la plupart des entrees de demarrage sont legitimes (Steam, GPU, MAJ) - a recouper" }
    EVTLOG    = @{ Shows="des journaux Windows ont ete effaces ou tronques"; ProvesNot="un log plein qui tourne (rollover) est normal ; un effacement peut aussi etre de l'hygiene systeme" }
    ANTIFOR   = @{ Shows="un outil d'effacement securise ou de nettoyage est present / a tourne"; ProvesNot="CCleaner & co sont ultra courants et legitimes - presence n'est pas preuve de wipe de triche" }
    BROWSER   = @{ Shows="un domaine de site de cheat connu est dans l'historique"; ProvesNot="visiter ou lire un site n'est ni l'avoir achete ni l'avoir utilise" }
    PSHIST    = @{ Shows="une commande telecharger-et-executer (iwr|iex, DownloadString, -enc...) est dans l'historique PowerShell"; ProvesNot="telecharger-et-executer est dual-use : winutil (Chris Titus), winget, scripts d'optimisation legitimes le font aussi ; seule une CIBLE au nom de cheat distinctif escalade"; ShowsFlag="une commande a telecharge-et-execute depuis une URL au nom de cheat DISTINCTIF"; ProvesNotFlag="l'URL fetch porte un nom de cheat distinctif = tres suspect ; reste a confirmer que le binaire a tourne en match (VOD)" }
    DNS       = @{ Shows="un domaine de cheat a ete resolu (cache DNS, par n'importe quel process) ou est fige dans le fichier hosts"; ProvesNot="resoudre/pinger un domaine n'est ni l'avoir achete ni l'avoir utilise en match ; le cache DNS se vide au reboot / a l'expiration du TTL" }
    HARDWARE  = @{ Shows="un device type DMA / capture / rig est present"; ProvesNot="une carte de capture = streamer normal ; une carte DMA bien configuree usurpe ses IDs et peut passer -> check visuel obligatoire" }
    DMAPCI    = @{ Shows="une carte PCIe FPGA (Xilinx/pcileech) ou un device PCIe sans driver = support materiel possible d'un wallhack/radar DMA sur 2e machine"; ProvesNot="dev-boards FPGA et devices sans driver legitimes declenchent aussi ; une carte DMA bien firmware-spoofee usurpe ses IDs et reste INVISIBLE a ce scan read-only -> check visuel obligatoire" }
    SECBOOT   = @{ Shows="le PC autorise des drivers non signes (testsigning/nointegritychecks) = porte pour un cheat kernel"; ProvesNot="certains outils/dev legitimes l'activent aussi - c'est une porte ouverte, pas une preuve" }
    NET       = @{ Shows="un process parle a Internet pendant la session"; ProvesNot="quasi tout process legitime a des connexions ; seul un nom de cheat connu compte ici" }
    CHEATS    = @{ Shows="un provider de cheat connu est installe / present"; ProvesNot="presence du fichier n'est pas un usage prouve en match - a confirmer visuellement" }
    INPUT     = @{ Shows="un outil de remap/anti-recoil ou un device (Cronus/XIM) est present"; ProvesNot="manette et remap = dual-use legitime ; seul le hardware anti-recoil est un signal fort" }
    VM        = @{ Shows="le check tourne peut-etre dans une VM pendant qu'on joue sur l'hote (evasion screenshare)"; ProvesNot="Hyper-V/VBS/WSL sont presents sur des machines reelles Win11 - a confirmer visuellement" }
    DEFENDER  = @{ Shows="une exclusion ou une protection coupee peut cacher un cheat de l'antivirus"; ProvesNot="beaucoup d'exclusions sont legitimes (jeux, dev) - le contexte compte" }
    KDRV      = @{ Shows="un driver kernel non signe, connu abusable (BYOVD), ou enregistre depuis un dossier UTILISATEUR (Temp/Downloads = residu d'un mapper type kdmapper) = acces kernel possible pour un cheat/spoofer"; ProvesNot="ces drivers sont souvent dual-use (Afterburner/HWiNFO/monitoring) - a confirmer ; un service qui pointe vers Temp est en revanche rarement legitime" }
    DRVINST   = @{ Shows="un driver/service abusable (BYOVD) a ete installe, avec sa date - complete KDRV qui ne voit que les drivers charges maintenant"; ProvesNot="beaucoup de drivers legitimes s'installent en service (Afterburner/HWiNFO/anti-triche) ; la date d'install seule ne prouve pas un usage cheat"; ShowsFlag="un service/driver au nom de cheat DISTINCTIF a ete installe a telle date (trace SCM qui survit a la suppression du binaire)"; ProvesNotFlag="le nom distinctif + la date d'install sont solides ; reste a confirmer l'usage en match (VOD)" }
    INJECT    = @{ Shows="un point d'injection DLL (AppInit/AppCert/IFEO) est positionne = un overlay/cheat peut se charger dans le jeu"; ProvesNot="quelques outils legitimes en posent - valeur non vide = a verifier, pas a bannir" }
    USBHIST   = @{ Shows="un boitier anti-recoil / device d'injection a deja ete branche sur cette machine (historique USB), meme s'il est debranche maintenant"; ProvesNot="un branchement passe n'est pas un usage en match ; PC d'occasion, frere/coloc, revendu - le modo fait expliquer le device"; ShowsFlag="un boitier anti-recoil au descripteur DISTINCTIF (Cronus/XIM/Titan/ReaSnow) a ete physiquement branche sur cette machine (descripteur firmware, non renommable) ; il a pu etre debranche juste avant le check"; ProvesNotFlag="le descripteur prouve le branchement PHYSIQUE, pas l'usage en match ; un PC d'occasion ou prete peut porter cette trace - le modo demande au joueur d'expliquer ce device, il ne l'accuse pas" }
    DEFTHREAT = @{ Shows="Windows Defender a deja detecte / mis en quarantaine une menace sur cette machine (trace qui survit a la suppression du binaire)"; ProvesNot="Defender flagge aussi cracks, keygens et trainers de jeux SOLO ; l'historique se purge tout seul (~30 j) donc un historique vide ne prouve rien"; ShowsFlag="Defender a detecte un cheat au nom DISTINCTIF connu (engineowning, etc.) sur cette machine - detection signee Microsoft qui survit a la suppression du binaire"; ProvesNotFlag="la detection prouve la presence passee du cheat sur la machine, pas son usage en match ; reste a confirmer par la VOD" }
    GPC       = @{ Shows="un fichier .gpc (script de l'ecosysteme Cronus) est present"; ProvesNot="une extension .gpc seule peut etre une collision ; sans le contenu GPC ce n'est pas confirme"; ShowsFlag="un script GPC CONFIRME par son contenu (set_val/combo/event_press) = macro anti-recoil ecrite pour un boitier Cronus Zen/Max"; ProvesNotFlag="le script prouve la preparation d'un anti-recoil Cronus, pas son usage en match ; le boitier lui-meme se voit a l'USB / au check visuel" }
    SHADOW    = @{ Shows="une commande a supprime les points de restauration Windows (Shadow Copies) - la ou vivent des versions 'supprimees' de fichiers"; ProvesNot="supprimer les shadow copies est aussi une maintenance admin legitime (liberer de l'espace, reparer) ; la commande dans l'historique n'est pas une preuve de triche - a recouper" }
    WER       = @{ Shows="un programme a plante et Windows a garde son nom (WER)"; ProvesNot="un plantage n'est pas un usage en match ; tout plante sous Windows et un nom generique reste dual-use"; ShowsFlag="un cheat au nom DISTINCTIF a plante sur cette machine (WER l'a enregistre) = il tournait au moment du crash, meme efface depuis"; ProvesNotFlag="le crash prouve l'EXECUTION du cheat, pas le moment d'usage en partie ; le binaire efface n'est plus analysable - la trace WER, elle, a survecu" }
    MRU       = @{ Shows="un fichier a ete ouvert recemment (RecentDocs), une commande tapee dans Executer (RunMRU), ou un exe a ete lance (MuiCache garde son chemin)"; ProvesNot="ouvrir ou taper un nom n'est pas jouer avec ; un nom generique reste dual-use"; ShowsFlag="un fichier/commande/exe au nom de cheat DISTINCTIF a ete ouvert, tape dans Executer ou lance (traces HKCU RecentDocs/RunMRU/MuiCache qui survivent a la suppression du fichier)"; ProvesNotFlag="ca prouve un acces recent au fichier nomme, pas un usage en match ; a confirmer par la VOD" }
    MOTW      = @{ Shows="un fichier present a ete telecharge depuis un domaine de cheat (URL gardee par Windows)"; ProvesNot="telecharger n'est pas executer en match ; mais la provenance + le fichier present est un signal fort"; ShowsFlag="un fichier present a ete telecharge DEPUIS un domaine/provider de cheat connu (Mark-of-the-Web) - cette provenance survit a l'effacement de l'historique du navigateur, le joueur ne peut pas l'effacer en vidant Chrome"; ProvesNotFlag="la provenance prouve le telechargement du cheat depuis sa source, pas son usage en match ; a confirmer par la VOD" }
    HWID      = @{ Shows="l'identite materielle que Windows presente (SMBIOS, MAC, MachineGuid) ne colle pas avec ce que le firmware/registre a enregistre au boot ou a l'install = un spoofer HWID (contournement de ban) est peut-etre actif ou est passe par la"; ProvesNot="une MAC changee a la main, une 'adresse aleatoire' Wi-Fi ou une reinstall partielle produisent aussi un ecart ; un spoofer qui patche les DEUX cotes de facon coherente passe - c'est un ecart a faire expliquer, pas un ban" }
    CILOG     = @{ Shows="Windows (Code Integrity) a REFUSE de charger un driver kernel (.sys) non conforme : c'est la trace d'une tentative de BYOVD / driver mappe, avec sa date, ecrite par le systeme lui-meme"; ProvesNot="des drivers legitimes vieillissants (utilitaires carte mere, monitoring) se font aussi refuser sous HVCI ; un driver abusable est dual-use (Afterburner/HWiNFO) - la date + le chemin (Temp ?) font la difference"; ShowsFlag="un driver kernel au nom de cheat DISTINCTIF a tente de se charger sur cette machine (refus journalise par Windows, survit a la suppression du .sys)"; ProvesNotFlag="la tentative de chargement prouve que le loader a tourne ici, pas le moment d'usage en match ; a confirmer par la VOD" }
}

function Get-MeaningLines {
    # Rend les 2 lignes "Montre / Ne prouve pas" pour un WARN/FLAG ; vide sinon. Pur -> testable.
    param($r)
    if ($r.Status -notin @('WARN','FLAG')) { return @() }
    $m = $script:ProbeMeaning[$r.Id]
    if ($null -eq $m) { return @() }
    # Sur un FLAG (= nom de cheat DISTINCTIF par construction, jamais generique), on affiche une
    # formulation FERME quand elle existe : pas de hedge "dual-use" qui ne s'applique pas ici.
    # ContainsKey et pas $m.ShowsFlag : sous StrictMode, lire une cle absente d'une hashtable
    # LEVE PropertyNotFoundStrict et tue le run entier. Toutes les sondes n'ont pas de variante FLAG.
    $shows = if ($r.Status -eq 'FLAG' -and $m.ContainsKey('ShowsFlag'))     { $m.ShowsFlag }     else { $m.Shows }
    $pnot  = if ($r.Status -eq 'FLAG' -and $m.ContainsKey('ProvesNotFlag')) { $m.ProvesNotFlag } else { $m.ProvesNot }
    return @("> Montre : $shows", "> Ne prouve pas : $pnot")
}

function New-ProbeResult {
    param(
        [string]$Id,
        [string]$Name,
        [ValidateSet('OK','INFO','WARN','FLAG','NA','ERROR')] [string]$Status = 'OK',
        [int]$Severity = 0,
        [string]$Summary = '',
        $Details = @()
    )
    [pscustomobject]@{
        Id       = $Id
        Name     = $Name
        Status   = $Status
        Severity = $Severity
        Summary  = $Summary
        Details  = @($Details)
    }
}

function Write-ProbeLine {
    param($r, [int]$Index = 0, [int]$Total = 0)
    $map = @{
        OK    = @('[ OK ]','Green')
        INFO  = @('[INFO]','Cyan')
        WARN  = @('[WARN]','Yellow')
        FLAG  = @('[FLAG]','Red')
        NA    = @('[ NA ]','DarkGray')
        ERROR = @('[ERR ]','Magenta')
    }
    $entry = $map[$r.Status]
    if ($null -eq $entry) { $entry = @('[ ?? ]','Gray') }
    $tag   = $entry[0]
    $color = $entry[1]
    if ($Total -gt 0) { Write-Host ("  {0,2}/{1} " -f $Index, $Total) -ForegroundColor DarkGray -NoNewline } else { Write-Host "  " -NoNewline }
    Write-Host ("{0} {1,-30}" -f $tag, $r.Name) -ForegroundColor $color -NoNewline
    Write-Host (" {0}" -f $r.Summary) -ForegroundColor Gray
    foreach($ml in (Get-MeaningLines $r)){ Write-Host ("         {0}" -f $ml) -ForegroundColor DarkGray }
}

function Test-AnyPattern {
    # vrai si $text contient une des sous-chaines (insensible casse)
    param([string]$text, [string[]]$patterns)
    if ([string]::IsNullOrEmpty($text)) { return $false }
    foreach ($p in $patterns) {
        if ([string]::IsNullOrEmpty($p)) { continue }
        if ($text.IndexOf($p, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function Test-AnyWord {
    # vrai si $text contient un des patterns borne par des SEPARATEURS (tout ce qui n'est pas
    # [a-z0-9]). Evite les faux positifs de sous-chaine ('xim' ne matche pas "Maxim", 'zen' pas
    # "Ryzen") MAIS traite '_', '.', '-' comme des separateurs : 'aimbot' matche bien
    # "cod_aimbot_loader.exe". Aligne exactement sur WordMatch (C#) -> UNE seule semantique de
    # match dans tout l'outil (suppressions USN, traces d'execution, devices, exclusions Defender).
    # NB : \b en .NET considere '_' comme un caractere de mot et ratait donc ces noms obfusques.
    param([string]$text, [string[]]$patterns)
    if ([string]::IsNullOrEmpty($text)) { return $false }
    foreach ($p in $patterns) {
        if ([string]::IsNullOrEmpty($p)) { continue }
        $rx = '(?i)(?<![a-z0-9])' + [regex]::Escape($p) + '(?![a-z0-9])'
        if ([regex]::IsMatch($text, $rx)) { return $true }
    }
    return $false
}

function Get-FileBytesText {
    # lit jusqu'a 50 Mo d'un fichier (meme verrouille) en partage lecture, rend du texte ASCII.
    param([string]$path)
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $len = [Math]::Min($fs.Length, 50MB)
            $buf = New-Object byte[] ([int]$len)
            [void]$fs.Read($buf, 0, [int]$len)
        } finally { $fs.Dispose() }
        return [System.Text.Encoding]::ASCII.GetString($buf)
    } catch { return $null }
}

function ConvertFrom-Rot13 {
    # UserAssist stocke les noms en ROT13. Decode lettres A-Z/a-z, laisse le reste.
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return $s }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $c = [int][char]$ch
        if ($c -ge 65 -and $c -le 90)      { $c = (($c - 65 + 13) % 26) + 65 }
        elseif ($c -ge 97 -and $c -le 122) { $c = (($c - 97 + 13) % 26) + 97 }
        [void]$sb.Append([char]$c)
    }
    return $sb.ToString()
}

function Get-UninstallEntries {
    # DisplayName de tous les programmes installes (HKLM 64/32 + HKCU)
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($r in $roots) {
        try {
            if (-not (Test-Path $r)) { continue }
            Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $dn = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
                    if (-not [string]::IsNullOrWhiteSpace($dn)) { $names.Add([string]$dn) }
                } catch { }
            }
        } catch { }
    }
    return $names
}

# ============================================================================
# COUCHE 3 - SONDES
# ============================================================================

function Probe-Identity {
    $details = New-Object System.Collections.Generic.List[string]
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $now = Get-Date
    $boot = $os.LastBootUpTime
    $uptime = $now - $boot
    $details.Add("PC          : $env:COMPUTERNAME")
    $details.Add("Utilisateur : $env:USERNAME")
    if ($null -ne $cs) { $details.Add("Modele      : $($cs.Manufacturer) $($cs.Model)") }
    $details.Add("OS          : $($os.Caption) build $($os.BuildNumber)")
    $details.Add("Boot        : $boot  (uptime $([int]$uptime.TotalHours)h$($uptime.Minutes)m)")
    $tz = try { (Get-TimeZone -ErrorAction Stop).Id } catch { 'n/a' }
    $details.Add("Heure systeme : $now  (TZ $tz)")

    # heuristique horloge reculee : un fichier systeme ecrit "dans le futur" vs l'horloge
    $status='OK'; $sev=0; $summary="$env:COMPUTERNAME / $env:USERNAME, uptime $([int]$uptime.TotalHours)h"
    try {
        $newest = Get-ChildItem "$script:SysDrive\Windows\System32" -File -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($null -ne $newest -and $newest.LastWriteTime -gt $now.AddDays(1)) {
            $status='WARN'; $sev=1
            $summary="Horloge possiblement reculee (fichier systeme date du futur : $($newest.LastWriteTime))"
            $details.Add("ALERTE : $($newest.Name) ecrit le $($newest.LastWriteTime), apres l'heure systeme actuelle.")
        }
    } catch { }
    New-ProbeResult -Id 'IDENT' -Name 'Identite & horloge' -Status $status -Severity $sev -Summary $summary -Details $details
}

function Probe-WindowsAge {
    $details = New-Object System.Collections.Generic.List[string]
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $install = $os.InstallDate
    $age = (Get-Date) - $install
    $days = [int]$age.TotalDays
    $details.Add("Date d'installation Windows : $install  ($days jours)")
    try {
        $winDir = Get-Item "$script:SysDrive\Windows" -ErrorAction SilentlyContinue
        if ($null -ne $winDir) { $details.Add("Creation du dossier Windows : $($winDir.CreationTime)") }
    } catch { }

    $status='OK'; $sev=0; $summary="Windows installe il y a $days jours"
    if ($days -lt 7) {
        $status='WARN'; $sev=1
        $summary="Reinstallation tres recente ($days j) - juste avant le check ?"
        $details.Add("NOTE : neuf PC / nouveau SSD / mise a jour majeure peuvent aussi reinitialiser cette date. SUSPECT surtout si recoupe avec USN purge / event log efface / outil de wipe.")
    } elseif ($days -lt 30) {
        $status='WARN'; $sev=1
        $summary="Installation recente ($days jours) - a verifier"
    }
    New-ProbeResult -Id 'WINAGE' -Name 'Age de Windows' -Status $status -Severity $sev -Summary $summary -Details $details
}

function Probe-Usn {
    $details = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Admin)) {
        return (New-ProbeResult -Id 'USN' -Name 'USN Journal (etat)' -Status 'NA' -Severity 0 -Summary "etat non lisible sans admin (fsutil requiert l'elevation)" -Details $details)
    }
    $drives = Get-FixedNtfsDrives
    $active   = New-Object System.Collections.Generic.List[string]
    $inactive = New-Object System.Collections.Generic.List[string]
    $locked   = New-Object System.Collections.Generic.List[string]
    foreach ($drive in $drives) {
        $out = & cmd /c "fsutil usn queryjournal $drive 2>&1"
        $code = $LASTEXITCODE
        $text = ($out | Out-String).Trim()
        if ($code -eq 0) {
            $active.Add($drive)
            $details.Add("USN actif sur $drive :")
            foreach ($l in ($out)) { if ($l -match ':') { $details.Add(("    " + $l.Trim())) } }
        } elseif ($text -match '(?i)denied|refus|locked|verrouill|chiffr|bitlocker|encrypt') {
            # acces refuse / volume verrouille-chiffre : NON concluant, pas un signal de masquage
            $locked.Add($drive)
            $details.Add("USN non lu sur $drive (acces refuse / volume verrouille ou chiffre, non concluant) : $text")
        } else {
            $inactive.Add($drive)
            $details.Add("USN INACTIF sur $drive (code $code) : $text")
        }
    }
    $details.Add("Enumeration datee des suppressions par volume : sonde 'Fichiers supprimes' (lecteur USN).")
    if ($inactive.Count -gt 0) {
        $details.Add("Un journal USN DESACTIVE empeche l'historique date des suppressions : peut venir d'un debloat/optimisation gaming OU d'une volonte de masquer -> a recouper avec l'age Windows.")
        return (New-ProbeResult -Id 'USN' -Name 'USN Journal (etat)' -Status 'WARN' -Severity 1 -Summary "USN inactif sur : $($inactive -join ', ')  (actif : $($active -join ', '))" -Details $details)
    }
    if ($locked.Count -gt 0) {
        return (New-ProbeResult -Id 'USN' -Name 'USN Journal (etat)' -Status 'INFO' -Severity 0 -Summary "Actif : $($active -join ', ') ; non lu (verrouille/chiffre, non concluant) : $($locked -join ', ')" -Details $details)
    }
    New-ProbeResult -Id 'USN' -Name 'USN Journal (etat)' -Status 'OK' -Severity 0 -Summary "Journal actif sur : $($active -join ', ')" -Details $details
}

# USN_REASON_RENAME_OLD_NAME (0x1000) sans FILE_DELETE (0x200) : le nom a disparu par renommage.
function Get-UsnRenameTag($Rec) {
    $Reason = [uint32]0; try { $Reason = [uint32]$Rec.Reason } catch { }
    if (($Reason -band 0x1000) -ne 0 -and ($Reason -band 0x200) -eq 0) { return '  (ancien nom : renomme)' }
    return ''
}

function Probe-DeletedFiles {
    $details = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Admin)) {
        return (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'NA' -Severity 0 -Summary "admin requis (lecture brute du volume)" -Details @("Le lecteur USN ouvre un handle sur le volume : necessite l'elevation."))
    }
    try { Initialize-UsnReader } catch {
        return (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'NA' -Severity 0 -Summary "Compilation du lecteur USN impossible" -Details @($_.Exception.Message))
    }
    $drives = Get-FixedNtfsDrives
    $details.Add("Volumes NTFS fixes scannes : $($drives -join ', ') (disques fixes a lettre montee ; un cheat supprime sur un 2e SSD interne est couvert. Hors perimetre : USB/amovible et volumes sans lettre).")
    $flagPat = Get-CheatFlagPatterns
    $grandTotal = [int64]0
    $flagAll   = New-Object System.Collections.Generic.List[object]
    $warnAll   = New-Object System.Collections.Generic.List[object]
    $recentAll = New-Object System.Collections.Generic.List[object]
    $readAny = $false
    $partial = New-Object System.Collections.Generic.List[string]
    foreach ($drive in $drives) {
        $scan = $null
        try { $scan = Get-UsnScan -Volume $drive -FlagPatterns $flagPat -WarnPatterns $script:CheatWarnWords } catch { $details.Add("  $drive : USN illisible/inactif (ignore)"); continue }
        $readAny = $true
        if ([int]$scan.StopError -ne 0) {
            $partial.Add($drive)
            $details.Add(("  {0} : lecture du journal INTERROMPUE (code {1}) - scan PARTIEL, les suppressions non lues n'ont pas ete examinees" -f $drive, $scan.StopError))
        }
        $t = [int64]$scan.Total
        $grandTotal += $t
        if ($scan.OldestTicks -gt 0 -and $scan.NewestTicks -gt 0) {
            try {
                $o = [DateTime]::FromFileTime($scan.OldestTicks); $n = [DateTime]::FromFileTime($scan.NewestTicks); $sp = $n - $o
                $details.Add(("  {0} : {1} suppression(s), fenetre {2:yyyy-MM-dd HH:mm} -> {3:yyyy-MM-dd HH:mm} (~{4} j)" -f $drive, $t, $o, $n, [int]$sp.TotalDays))
            } catch { $details.Add("  $drive : $t suppression(s)") }
        } else { $details.Add("  $drive : $t suppression(s)") }
        foreach ($s in $scan.FlagSuspects) { $flagAll.Add([pscustomobject]@{ Time = $s.Time; Name = ("[$drive] " + [string]$s.Name); Tag = (Get-UsnRenameTag $s) }) }
        foreach ($s in $scan.WarnSuspects) {
            $attrs = 0; try { $attrs = [int]$s.Attributes } catch { }
            $warnAll.Add([pscustomobject]@{ Time = $s.Time; Name = ("[$drive] " + [string]$s.Name); Tag = (Get-UsnRenameTag $s); IsDir = (($attrs -band 0x10) -ne 0) })
        }
        foreach ($r in $scan.Recent) { $recentAll.Add([pscustomobject]@{ Time = $r.Time; Name = ("[$drive] " + [string]$r.Name) }) }
    }
    if (-not $readAny) {
        return (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'NA' -Severity 0 -Summary "Aucun journal USN lisible (inactif sur tous les volumes ?)" -Details $details)
    }
    if ($partial.Count -gt 0) {
        $details.Add("Total suppressions LUES : $grandTotal. Scan PARTIEL sur : $($partial -join ', ') ; ailleurs le journal est lu jusqu'au bout.")
    } else {
        $details.Add("Total suppressions (tous volumes) : $grandTotal. Chaque journal est scanne EN ENTIER ; le match suspect couvre 100%, pas un echantillon biaise vers les vieilles entrees.")
    }
    $details.Add("NOTE fenetre : le journal USN 'tourne' (wrap) a sa taille max = une fenetre courte est NORMALE sur machine active ; tres courte sur PC ancien et peu actif = a creuser (purge/recreation).")
    $recent = @($recentAll | Sort-Object Time -Descending | Select-Object -First 10)
    if ($recent.Count -gt 0) {
        $details.Add("Plus recentes (tous volumes) :")
        foreach ($d in $recent) { $details.Add(("  {0:yyyy-MM-dd HH:mm}  {1}" -f $d.Time, $d.Name)) }
    }
    $flagHits = @($flagAll | Sort-Object Time -Descending)
    # Un fichier source/doc supprime (config_loader.py, skill-map-loader.ts - mesure 16/09 sur un PC
    # propre) n'est pas un loader de cheat : seul un mot FORT le garde (un colorbot aimbot.py existe).
    $srcExt = '(?i)\.(py|pyc|ts|tsx|js|jsx|mjs|cjs|rs|go|java|kt|c|cc|cpp|h|hpp|cs|md|txt|json|yaml|yml|toml|xml|html|css|map|rkyv|lock)$'
    $strong = @('aimbot','wallhack','triggerbot','unlockall','unlock_all','spoofer','hwidspoofer','injector','cheat')
    $warnHits = @($warnAll | Where-Object {
        $n = [string]$_.Name
        # ponytail: assemblies .NET par prefixe (System.Runtime.Loader.dll) ; un cheat qui se nomme
        # Microsoft.X.dll passe en OK ici, mais reste visible dans EXEC/Prefetch s'il a tourne.
        # Un DOSSIER au mot generique (ex. dossier temporaire pytest « test_loader_... ») n'est pas
        # un executable de cheat (mesure 17/09). Les noms DISTINCTIFS passent par FLAG, pas ici.
        $isDir = $false; try { $isDir = [bool]$_.IsDir } catch { }
        $benign = $isDir -or ($n -match $srcExt) -or ($n -match '(?i)(^|[\s\\])(System|Microsoft)\.[\w.]+\.dll$')
        -not ($benign -and -not (Test-AnyWord $n $strong))
    } | Sort-Object Time -Descending)
    if ($flagHits.Count -gt 0) {
        $details.Add("SUPPRESSIONS AU NOM DE CHEAT (distinctif, tous volumes) :")
        foreach ($h in ($flagHits | Select-Object -First 25)) { $details.Add(("  {0:yyyy-MM-dd HH:mm}  {1}{2}" -f $h.Time, $h.Name, $h.Tag)) }
        if ($warnHits.Count -gt 0) { $details.Add("(+ $($warnHits.Count) suppression(s) au nom generique loader/cheat - listees a part)") }
        return (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) suppression(s) au nom de cheat distinctif" -Details $details)
    }
    if ($warnHits.Count -gt 0) {
        $details.Add("SUPPRESSIONS AU NOM GENERIQUE (loader/cheat/skript... = dual-use, a verifier, PAS un ban) :")
        foreach ($h in ($warnHits | Select-Object -First 25)) { $details.Add(("  {0:yyyy-MM-dd HH:mm}  {1}{2}" -f $h.Time, $h.Name, $h.Tag)) }
        return (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'WARN' -Severity 1 -Summary "$($warnHits.Count) suppression(s) au nom generique (mod-loader/cheat sheet ?) - a verifier" -Details $details)
    }
    if ($grandTotal -eq 0) {
        return (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'OK' -Severity 0 -Summary "Aucune suppression dans la retention USN (tous volumes)" -Details $details)
    }
    New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'OK' -Severity 0 -Summary "$grandTotal suppressions (tous volumes), aucun nom suspect" -Details $details
}

function Probe-ExecEvidence {
    # Traces d'execution qui SURVIVENT a la suppression du binaire :
    #  - BAM/DAM (ruche SYSTEM, admin) : chemin complet + DERNIERE execution par user.
    #  - UserAssist (HKCU, sans admin)  : lancements via l'Explorateur + compteur + derniere fois.
    # Coeur "anti-wipe" : prouve qu'un .exe a tourne meme s'il a ete efface ensuite.
    $details = New-Object System.Collections.Generic.List[string]
    $execs = New-Object System.Collections.Generic.List[object]

    if (Test-Admin) {
        foreach ($svc in @('bam','dam')) {
            foreach ($base in @("HKLM:\SYSTEM\CurrentControlSet\Services\$svc\State\UserSettings",
                                "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\UserSettings")) {
                try {
                    if (-not (Test-Path $base)) { continue }
                    foreach ($sidKey in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
                        try {
                            $props = Get-ItemProperty $sidKey.PSPath -ErrorAction SilentlyContinue
                            if ($null -eq $props) { continue }
                            foreach ($pp in $props.PSObject.Properties) {
                                $vn = $pp.Name
                                if ($vn -like 'PS*' -or $vn -eq 'Version' -or $vn -eq 'SequenceNumber') { continue }
                                $data = $pp.Value
                                if ($data -isnot [byte[]] -or $data.Length -lt 8) { continue }
                                $t = $null
                                try { $t = [DateTime]::FromFileTime([BitConverter]::ToInt64($data,0)) } catch { }
                                $execs.Add(@{ Path=[string]$vn; Time=$t; Src=$svc.ToUpper() })
                            }
                        } catch { }
                    }
                } catch { }
            }
        }
    }

    # UserAssist de CHAQUE compte connecte (HKCU puis HKEY_USERS\<SID>), pas seulement celui qui lance le check.
    $hives = Get-UserHiveRoots
    foreach ($hive in @($hives.Roots)) {
    $uaRoot = "$($hive.User)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    try {
        if (Test-Path $uaRoot) {
            foreach ($guidKey in (Get-ChildItem $uaRoot -ErrorAction SilentlyContinue)) {
                $countKey = Join-Path $guidKey.PSPath 'Count'
                try {
                    if (-not (Test-Path $countKey)) { continue }
                    $props = Get-ItemProperty $countKey -ErrorAction SilentlyContinue
                    if ($null -eq $props) { continue }
                    foreach ($pp in $props.PSObject.Properties) {
                        $vn = $pp.Name
                        if ($vn -like 'PS*') { continue }
                        $name = ConvertFrom-Rot13 $vn
                        if ([string]::IsNullOrWhiteSpace($name) -or ($name -notmatch '\.exe')) { continue }
                        $t = $null
                        $data = $pp.Value
                        if ($data -is [byte[]] -and $data.Length -ge 68) {
                            try { $t = [DateTime]::FromFileTime([BitConverter]::ToInt64($data,60)) } catch { }
                        }
                        $execs.Add(@{ Path=[string]$name; Time=$t; Src='UserAssist' })
                    }
                } catch { }
            }
        }
    } catch { }
    }

    $flagPat = Get-CheatFlagPatterns
    $warnPat = @($script:CheatWarnWords)

    $total = $execs.Count
    $details.Add("Traces d'execution lues : $total (BAM/DAM = derniere exec + chemin ; UserAssist = lancements GUI de $(@($hives.Roots).Count) compte(s) connecte(s)). Ces artefacts survivent a la suppression du binaire.")
    if (@($hives.Unread).Count -gt 0) { $details.Add("NOTE : UserAssist non lu pour $(@($hives.Unread).Count) compte(s) Windows non connecte(s) (ruche non chargee ; la charger serait une ecriture) : $(@($hives.Unread) -join ', '). BAM/DAM couvre toujours tous les comptes.") }
    if (-not (Test-Admin)) { $details.Add("NOTE : sans admin, BAM/DAM (ruche SYSTEM) non lus -> couverture reduite a UserAssist (HKCU).") }

    $flagHits = @($execs | Where-Object { Test-AnyWord ([string]$_.Path) $flagPat })
    $warnHits = @($execs | Where-Object { (Test-AnyWord ([string]$_.Path) $warnPat) -and -not (Test-AnyWord ([string]$_.Path) $flagPat) })
    if ($flagHits.Count -gt 0) {
        $details.Add("EXECUTIONS AU NOM DE CHEAT (distinctif, a survecu a la suppression) :")
        foreach ($h in (@($flagHits) | Sort-Object { $_.Time } -Descending | Select-Object -First 25)) {
            $ts = if ($null -ne $h.Time) { '{0:yyyy-MM-dd HH:mm}' -f $h.Time } else { 'date n/a' }
            $details.Add(("  [{0}] {1}  {2}" -f $h.Src, $ts, $h.Path))
        }
        return (New-ProbeResult -Id 'EXEC' -Name "Traces d'execution (anti-wipe)" -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) execution(s) au nom de cheat distinctif (a survecu a la suppression)" -Details $details)
    }
    if ($warnHits.Count -gt 0) {
        $details.Add("EXECUTIONS AU NOM GENERIQUE (loader/cheat/skript... dual-use, a verifier) :")
        foreach ($h in (@($warnHits) | Sort-Object { $_.Time } -Descending | Select-Object -First 25)) {
            $ts = if ($null -ne $h.Time) { '{0:yyyy-MM-dd HH:mm}' -f $h.Time } else { 'date n/a' }
            $details.Add(("  [{0}] {1}  {2}" -f $h.Src, $ts, $h.Path))
        }
        return (New-ProbeResult -Id 'EXEC' -Name "Traces d'execution (anti-wipe)" -Status 'WARN' -Severity 1 -Summary "$($warnHits.Count) execution(s) au nom generique (mod-loader ?) - a verifier" -Details $details)
    }
    if ($total -eq 0) {
        return (New-ProbeResult -Id 'EXEC' -Name "Traces d'execution (anti-wipe)" -Status 'NA' -Severity 0 -Summary "Aucune trace BAM/DAM/UserAssist lisible" -Details $details)
    }
    $recent = @($execs | Where-Object { $null -ne $_.Time } | Sort-Object { $_.Time } -Descending | Select-Object -First 8)
    if ($recent.Count -gt 0) {
        $details.Add("Executions les plus recentes (info, corroboration) :")
        foreach ($r in $recent) { $details.Add(("  [{0}] {1:yyyy-MM-dd HH:mm}  {2}" -f $r.Src, $r.Time, $r.Path)) }
    }
    New-ProbeResult -Id 'EXEC' -Name "Traces d'execution (anti-wipe)" -Status 'OK' -Severity 0 -Summary "$total traces d'execution lues, aucun nom suspect" -Details $details
}

function ConvertFrom-Shimcache {
    # Parse PUR (testable a sec) d'un blob AppCompatCache (Shimcache) Win8.1/10/11 en
    # entrees { Path; Time }. Format entree "10ts" : sig(4) + unknown(4) +
    # cachedEntryDataSize(4) + pathSize(2) + path(UTF-16LE) + lastModTime(FILETIME 8) +
    # dataSize(4) + data. On AVANCE via cachedEntryDataSize (= taille apres ce champ) : ca
    # rend le parseur tolerant a la taille d'en-tete (0x30/0x34 selon build) ET au champ
    # dataSize (largeur variable selon builds). Source : libyal winreg-kb / plaso appcompatcache.
    param([byte[]]$bytes, [int]$max = 4000)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $bytes -or $bytes.Length -lt 16) { return ,$out }
    $isSig = { param($b, $o) ($o + 4 -le $b.Length) -and $b[$o] -eq 0x31 -and $b[$o+1] -eq 0x30 -and $b[$o+2] -eq 0x74 -and $b[$o+3] -eq 0x73 }  # "10ts"
    # 1er enregistrement : uint32 a l'offset 0 = taille d'en-tete = offset des entrees.
    $start = [int]([BitConverter]::ToUInt32($bytes, 0))
    if ($start -lt 8 -or $start -gt $bytes.Length - 12 -or -not (& $isSig $bytes $start)) {
        $start = -1  # en-tete inattendu -> on cherche la 1ere signature "10ts"
        for ($i = 0; $i -le $bytes.Length - 4; $i++) { if (& $isSig $bytes $i) { $start = $i; break } }
        if ($start -lt 0) { return ,$out }
    }
    $off = [int]$start
    $guard = 0
    while (($off + 14) -le $bytes.Length -and $out.Count -lt $max -and $guard -lt 200000) {
        $guard++
        if (-not (& $isSig $bytes $off)) { break }
        $cached   = [int]([BitConverter]::ToUInt32($bytes, $off + 8))
        $pathSize = [int]([BitConverter]::ToUInt16($bytes, $off + 12))
        $pathStart = $off + 14
        if ($pathSize -gt 0 -and ($pathStart + $pathSize + 8) -le $bytes.Length) {
            $path = [System.Text.Encoding]::Unicode.GetString($bytes, $pathStart, $pathSize)
            $t = $null
            try { $ft = [BitConverter]::ToInt64($bytes, $pathStart + $pathSize); if ($ft -gt 0) { $t = [DateTime]::FromFileTime($ft) } } catch { }
            $out.Add([pscustomobject]@{ Path = $path; Time = $t })
        }
        if ($cached -le 0) { break }
        $next = $off + 12 + $cached
        if ($next -le $off) { break }
        $off = $next
    }
    return ,$out
}

function Probe-Shimcache {
    # AppCompatCache (Shimcache) : preuve qu'un binaire a ETE PRESENT sur la machine (le shim
    # engine l'a enumere), qui SURVIT a la suppression du fichier ET aux reboots (stocke dans
    # la ruche SYSTEM du registre live, pas de fichier verrouille a contourner). Complement de
    # BAM/DAM (fenetre courte) et UserAssist (GUI only). Admin requis (cle reservee SYSTEM).
    $details = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Admin)) {
        return (New-ProbeResult -Id 'SHIMCACHE' -Name 'Shimcache (AppCompatCache)' -Status 'NA' -Severity 0 -Summary "admin requis (cle registre reservee SYSTEM)" -Details @("La valeur AppCompatCache n'est lisible qu'avec l'elevation."))
    }
    $raw = $null
    try {
        $raw = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name 'AppCompatCache' -ErrorAction Stop).AppCompatCache
    } catch {
        return (New-ProbeResult -Id 'SHIMCACHE' -Name 'Shimcache (AppCompatCache)' -Status 'NA' -Severity 0 -Summary "Valeur AppCompatCache illisible" -Details @($_.Exception.Message))
    }
    if ($raw -isnot [byte[]] -or $raw.Length -lt 16) {
        return (New-ProbeResult -Id 'SHIMCACHE' -Name 'Shimcache (AppCompatCache)' -Status 'NA' -Severity 0 -Summary "AppCompatCache vide ou format inattendu" -Details $details)
    }
    $entries = ConvertFrom-Shimcache $raw   # renvoie un List[object] (semantique List, pas de @())
    $total = $entries.Count
    $details.Add("Entrees Shimcache decodees : $total (chemin + date de derniere modif du binaire). Survit a la suppression du fichier ET aux reboots.")
    $details.Add("NOTE : Shimcache n'est ECRIT dans le registre qu'a l'arret du PC -> une execution depuis le dernier demarrage peut ne pas encore y figurer. Presence = le fichier a ete vu sur la machine (execution non garantie sur Win10, mais il etait la).")
    if ($total -eq 0) {
        return (New-ProbeResult -Id 'SHIMCACHE' -Name 'Shimcache (AppCompatCache)' -Status 'NA' -Severity 0 -Summary "Aucune entree Shimcache decodee (format non reconnu ?)" -Details $details)
    }
    $flagPat = Get-CheatFlagPatterns
    $warnPat = @($script:CheatWarnWords)
    $flagHits = @($entries | Where-Object { Test-AnyWord ([string]$_.Path) $flagPat })
    $warnHits = @($entries | Where-Object { (Test-AnyWord ([string]$_.Path) $warnPat) -and -not (Test-AnyWord ([string]$_.Path) $flagPat) })
    if ($flagHits.Count -gt 0) {
        $details.Add("ENTREES AU NOM DE CHEAT (distinctif, a survecu a la suppression + reboot) :")
        foreach ($h in ($flagHits | Select-Object -First 25)) {
            $ts = if ($null -ne $h.Time) { '{0:yyyy-MM-dd HH:mm}' -f $h.Time } else { 'date n/a' }
            $details.Add(("  {0}  {1}" -f $ts, $h.Path))
        }
        return (New-ProbeResult -Id 'SHIMCACHE' -Name 'Shimcache (AppCompatCache)' -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) entree(s) Shimcache au nom de cheat distinctif" -Details $details)
    }
    if ($warnHits.Count -gt 0) {
        $details.Add("ENTREES AU NOM GENERIQUE (loader/cheat/skript... dual-use, a verifier) :")
        foreach ($h in ($warnHits | Select-Object -First 25)) {
            $ts = if ($null -ne $h.Time) { '{0:yyyy-MM-dd HH:mm}' -f $h.Time } else { 'date n/a' }
            $details.Add(("  {0}  {1}" -f $ts, $h.Path))
        }
        return (New-ProbeResult -Id 'SHIMCACHE' -Name 'Shimcache (AppCompatCache)' -Status 'WARN' -Severity 1 -Summary "$($warnHits.Count) entree(s) Shimcache au nom generique (mod-loader ?) - a verifier" -Details $details)
    }
    New-ProbeResult -Id 'SHIMCACHE' -Name 'Shimcache (AppCompatCache)' -Status 'OK' -Severity 0 -Summary "$total entree(s) Shimcache, aucun nom suspect" -Details $details
}

function ConvertFrom-PcaLaunchDic {
    # Parse PUR (testable a sec) des lignes de PcaAppLaunchDic.txt (Win11 22H2+, artefact PCA).
    # Chaque ligne : <chemin complet>|<yyyy-MM-dd HH:mm:ss.fff> (UTC). Le '|' etant illegal
    # dans un chemin Windows, on coupe sur le DERNIER '|'. L'heure UTC est convertie en local
    # (parite avec le reste de l'outil). Source : Sygnia / KapeFiles (EricZimmerman).
    param([string[]]$lines)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $lines) { return ,$out }
    $style = [Globalization.DateTimeStyles]::AssumeUniversal  # UTC en entree -> DateTime local en sortie
    $inv = [Globalization.CultureInfo]::InvariantCulture
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $idx = $line.LastIndexOf('|')
        if ($idx -lt 1) { continue }
        $path = $line.Substring(0, $idx)
        $tstr = $line.Substring($idx + 1).Trim()
        $t = $null; $dt = [datetime]::MinValue
        if ([datetime]::TryParseExact($tstr, 'yyyy-MM-dd HH:mm:ss.fff', $inv, $style, [ref]$dt)) { $t = $dt }
        elseif ([datetime]::TryParse($tstr, $inv, $style, [ref]$dt)) { $t = $dt }
        $out.Add([pscustomobject]@{ Path = $path; Time = $t })
    }
    return ,$out
}

function Probe-Pca {
    # PCA (Program Compatibility Assistant) Win11 22H2+ : PcaAppLaunchDic.txt = chemin +
    # DERNIERE execution par binaire. Nouvel artefact d'execution qui SURVIT a la suppression
    # du binaire, et qui logue AUSSI les exe lances depuis une CLE USB / un partage reseau.
    # Complement de BAM/DAM/UserAssist/Shimcache. En general lisible SANS admin (bonus en mode degrade).
    $details = New-Object System.Collections.Generic.List[string]
    $file = Join-Path $env:SystemRoot 'appcompat\pca\PcaAppLaunchDic.txt'
    if (-not (Test-Path -LiteralPath $file)) {
        return (New-ProbeResult -Id 'PCA' -Name 'PCA lancements (Win11, anti-wipe)' -Status 'NA' -Severity 0 -Summary "PcaAppLaunchDic absent (Windows < 11 22H2 ou PCA inactif)" -Details @("$file introuvable."))
    }
    $lines = $null
    try { $lines = [System.IO.File]::ReadAllLines($file, [System.Text.Encoding]::GetEncoding(1252)) } catch {
        return (New-ProbeResult -Id 'PCA' -Name 'PCA lancements (Win11, anti-wipe)' -Status 'NA' -Severity 0 -Summary "PcaAppLaunchDic illisible" -Details @($_.Exception.Message))
    }
    $entries = ConvertFrom-PcaLaunchDic $lines
    $total = $entries.Count
    $details.Add("Lancements PCA lus : $total (chemin + derniere execution). Survit a la suppression du binaire ; capture AUSSI les exe lances depuis une cle USB ou un partage reseau.")
    if ($total -eq 0) {
        return (New-ProbeResult -Id 'PCA' -Name 'PCA lancements (Win11, anti-wipe)' -Status 'NA' -Severity 0 -Summary "Aucun lancement PCA lisible" -Details $details)
    }
    $flagPat = Get-CheatFlagPatterns
    $warnPat = @($script:CheatWarnWords)
    $flagHits = @($entries | Where-Object { Test-AnyWord ([string]$_.Path) $flagPat })
    $warnHits = @($entries | Where-Object { (Test-AnyWord ([string]$_.Path) $warnPat) -and -not (Test-AnyWord ([string]$_.Path) $flagPat) })
    if ($flagHits.Count -gt 0) {
        $details.Add("LANCEMENTS AU NOM DE CHEAT (distinctif, a survecu a la suppression) :")
        foreach ($h in ($flagHits | Sort-Object { $_.Time } -Descending | Select-Object -First 25)) {
            $ts = if ($null -ne $h.Time) { '{0:yyyy-MM-dd HH:mm}' -f $h.Time } else { 'date n/a' }
            $details.Add(("  {0}  {1}" -f $ts, $h.Path))
        }
        return (New-ProbeResult -Id 'PCA' -Name 'PCA lancements (Win11, anti-wipe)' -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) lancement(s) PCA au nom de cheat distinctif" -Details $details)
    }
    if ($warnHits.Count -gt 0) {
        $details.Add("LANCEMENTS AU NOM GENERIQUE (loader/cheat/skript... dual-use, a verifier) :")
        foreach ($h in ($warnHits | Sort-Object { $_.Time } -Descending | Select-Object -First 25)) {
            $ts = if ($null -ne $h.Time) { '{0:yyyy-MM-dd HH:mm}' -f $h.Time } else { 'date n/a' }
            $details.Add(("  {0}  {1}" -f $ts, $h.Path))
        }
        return (New-ProbeResult -Id 'PCA' -Name 'PCA lancements (Win11, anti-wipe)' -Status 'WARN' -Severity 1 -Summary "$($warnHits.Count) lancement(s) PCA au nom generique (mod-loader ?) - a verifier" -Details $details)
    }
    New-ProbeResult -Id 'PCA' -Name 'PCA lancements (Win11, anti-wipe)' -Status 'OK' -Severity 0 -Summary "$total lancement(s) PCA, aucun nom suspect" -Details $details
}

function Probe-DeepUsnDump {
    if (-not (Test-Admin)) {
        return (New-ProbeResult -Id 'DEEPUSN' -Name '[-Deep] Dump USN (CSV)' -Status 'NA' -Severity 0 -Summary "admin requis")
    }
    try { Initialize-UsnReader } catch {
        return (New-ProbeResult -Id 'DEEPUSN' -Name '[-Deep] Dump USN (CSV)' -Status 'NA' -Severity 0 -Summary "Compilation lecteur USN impossible" -Details @($_.Exception.Message))
    }
    try {
        $dels = Get-UsnDeletes -Max 200000
        $csv = Join-Path $script:ReportDir ("DexCheck_USN_{0}_{1}.csv" -f $env:COMPUTERNAME, $script:RunStamp)
        $dels | Select-Object @{n='DateSuppression';e={$_.Time}}, Name, @{n='ReasonHex';e={'0x{0:X}' -f $_.Reason}}, @{n='Attributs';e={$_.Attributes}} |
            Sort-Object DateSuppression -Descending | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
        New-ProbeResult -Id 'DEEPUSN' -Name '[-Deep] Dump USN (CSV)' -Status 'OK' -Severity 0 -Summary "$(@($dels).Count) suppressions exportees" -Details @("CSV : $csv")
    } catch {
        New-ProbeResult -Id 'DEEPUSN' -Name '[-Deep] Dump USN (CSV)' -Status 'NA' -Severity 0 -Summary "Dump USN impossible" -Details @($_.Exception.Message)
    }
}

function Probe-DeepFreeSpaceScan {
    $details = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Admin)) {
        return (New-ProbeResult -Id 'DEEPFREE' -Name '[-Deep] Scan espace libre' -Status 'NA' -Severity 0 -Summary "admin requis (lecture brute du volume)")
    }
    try { Initialize-UsnReader } catch {
        return (New-ProbeResult -Id 'DEEPFREE' -Name '[-Deep] Scan espace libre' -Status 'NA' -Severity 0 -Summary "Compilation du lecteur impossible" -Details @($_.Exception.Message))
    }
    try {
        # Signatures cheat/DMA distinctives UNIQUEMENT (cf $script:FreeSpaceCheatSignatures).
        # Pas de noms dual-use ici : le match ASCII brut sur l'espace libre n'a pas de
        # frontiere de mot, donc tout terme court/commun = faux positif garanti.
        $sigArr = @($script:FreeSpaceCheatSignatures | Where-Object { $_ -and $_.Length -ge 6 } | Select-Object -Unique)
        $capMB = if ($FreeSpaceCapMB -gt 0) { $FreeSpaceCapMB } else { 1024 }
        $cap = [int64]$capMB * 1MB
        $hits = [DexCheckUsnReader]::ScanFreeSpace($script:SysDrive, $cap, [string[]]$sigArr)
        $scanned = [DexCheckUsnReader]::LastScannedBytes
        $details.Add(("Espace libre scanne : {0} Go (plafond {1} Mo, {2} signatures cheat/DMA distinctives)" -f [math]::Round($scanned/1GB,2), $capMB, $sigArr.Count))
        $details.Add("INFO de corroboration, PAS un verdict. Sur SSD+TRIM l'espace libre est souvent zeroe (faible rendement) ; et une chaine trouvee peut venir d'un rapport / installeur / script SUPPRIME (y compris DexCheck). A recouper avec l'historique navigateur, le prefetch et la timeline USN avant toute conclusion. Absence de hit != absence de cheat.")
        if (@($hits).Count -gt 0) {
            foreach ($x in $hits) { $details.Add("  INDICE BRUT : $x") }
            return (New-ProbeResult -Id 'DEEPFREE' -Name '[-Deep] Scan espace libre' -Status 'INFO' -Severity 0 -Summary "$(@($hits).Count) indice(s) brut(s) cheat/DMA en espace libre (a corroborer, ne compte pas au verdict)" -Details $details)
        }
        New-ProbeResult -Id 'DEEPFREE' -Name '[-Deep] Scan espace libre' -Status 'OK' -Severity 0 -Summary ("Aucun indice dans {0} Go scannes" -f [math]::Round($scanned/1GB,2)) -Details $details
    } catch {
        New-ProbeResult -Id 'DEEPFREE' -Name '[-Deep] Scan espace libre' -Status 'NA' -Severity 0 -Summary "Scan espace libre impossible" -Details @($_.Exception.Message)
    }
}

function Probe-Prefetch {
    $details = New-Object System.Collections.Generic.List[string]
    $pfDir = "$script:SysDrive\Windows\Prefetch"
    $enabled = $null
    try {
        $enabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction SilentlyContinue).EnablePrefetcher
    } catch { }
    if (-not (Test-Path $pfDir)) {
        return (New-ProbeResult -Id 'PREFETCH' -Name 'Prefetch' -Status 'WARN' -Severity 1 -Summary "Dossier Prefetch absent (vide/desactive ?)" -Details @("$pfDir introuvable. EnablePrefetcher=$enabled"))
    }
    $pf = @(Get-ChildItem $pfDir -Filter *.pf -File -ErrorAction SilentlyContinue)
    $details.Add("Fichiers .pf : $($pf.Count)   EnablePrefetcher=$enabled")
    $status='OK'; $sev=0; $summary="$($pf.Count) traces prefetch"
    if ($pf.Count -eq 0) {
        if (-not (Test-Admin)) {
            return (New-ProbeResult -Id 'PREFETCH' -Name 'Prefetch' -Status 'NA' -Severity 0 -Summary "lecture Prefetch impossible sans admin" -Details $details)
        }
        $status='WARN'; $sev=1; $summary="Prefetch vide - possiblement nettoye"
    } else {
        $oldest = ($pf | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
        $details.Add("Plus ancien .pf : $oldest")
        # Modele 2 niveaux (parite DELFILES/EXEC, anti faux-SUSPECT) : FLAG uniquement sur nom de
        # cheat DISTINCTIF (frontiere de mot), WARN sur nom generique + outil d'input DUAL-USE
        # (ds4windows/rewasd/x360ce... = ultra courant chez un joueur legitime, PAS un SUSPECT).
        $flagPat = Get-CheatFlagPatterns
        $warnPat = @($script:CheatWarnWords); foreach($t in $script:InputTools){ $warnPat += $t.App }
        $flagHits = @($pf | Where-Object { Test-AnyWord $_.Name $flagPat })
        $warnHits = @($pf | Where-Object { (Test-AnyWord $_.Name $warnPat) -and -not (Test-AnyWord $_.Name $flagPat) })
        if ($flagHits.Count -gt 0) {
            $status='FLAG'; $sev=2; $summary="Prefetch : $($flagHits.Count) trace(s) au nom de cheat distinctif"
            foreach($h in $flagHits){ $details.Add("  CHEAT : $($h.Name)  (exec le $($h.LastWriteTime))") }
            if ($warnHits.Count -gt 0){ $details.Add("(+ $($warnHits.Count) trace(s) au nom generique/dual-use, listees a part)") }
        } elseif ($warnHits.Count -gt 0) {
            $status='WARN'; $sev=1; $summary="Prefetch : $($warnHits.Count) trace(s) generique/outil dual-use - a verifier"
            foreach($h in $warnHits){ $details.Add("  dual-use : $($h.Name)  (exec le $($h.LastWriteTime))") }
        }
    }
    New-ProbeResult -Id 'PREFETCH' -Name 'Prefetch' -Status $status -Severity $sev -Summary $summary -Details $details
}

function Test-CheatNameMatch {
    # PUR. Un nom ou chemin porte-t-il un motif de cheat ? Marque LONGUE (>= 8) : sous-chaine,
    # pour attraper 'EngineOwningLoader.exe'. Motif COURT : frontiere de mot, sinon 'ring-1'
    # accuse 'spring-1.5'. Partage par les sondes Process et Persistence.
    param([string]$Text, [string[]]$Patterns)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $long  = @($Patterns | Where-Object { $_ -and $_.Length -ge 8 })
    $short = @($Patterns | Where-Object { $_ -and $_.Length -lt 8 })
    return ((Test-AnyPattern $Text $long) -or (Test-AnyWord $Text $short))
}

function Get-PersistencePatterns {
    # PUR. Cheats + outils d'entree SUSPECTS (severite >= 1). Les outils de severite 0
    # (DS4Windows, Razer Synapse, G HUB, x360ce) sont legitimes : qu'ils demarrent avec
    # Windows ne doit pas faire monter un PC propre en A VERIFIER (boucle 17/09).
    $pat = @()
    foreach ($c in $script:CheatSoftware) { $pat += $c.Patterns }
    foreach ($t in $script:InputTools) { if ([int]$t.Severity -ge 1) { $pat += $t.App } }
    return @($pat | Where-Object { $_ } | Select-Object -Unique)
}

function Test-ProcessIsCheat {
    # Pur -> testable. Un process EN COURS dont le nom, le chemin OU la ligne de commande porte un
    # token de cheat DISTINCTIF = execution en cours prouvee. La ligne de commande est matchee en
    # frontiere de mot (Test-AnyWord) : un cheat lance avec un exe renomme mais des args distinctifs
    # ('svchost.exe --config engineowning') est quand meme attrape. On ne lisait que le nom avant.
    param([string]$Name, [string]$Path, [string]$CommandLine, [string[]]$CheatPatterns)
    # Nom/chemin : une marque LONGUE (>= 8) matche en sous-chaine pour attraper 'EngineOwningLoader.exe' ;
    # un motif COURT exige une frontiere de mot, sinon 'ring-1' accusait 'C:\dev\spring-1.5\java.exe'.
    foreach ($s in @($Name, $Path)) {
        if (Test-CheatNameMatch $s $CheatPatterns) { return $true }
    }
    if (Test-AnyWord $CommandLine $CheatPatterns) { return $true }
    return $false
}

function Probe-Processes {
    $details = New-Object System.Collections.Generic.List[string]
    $procs = Get-CimInstance Win32_Process -ErrorAction Stop
    $cheatPat = @(); foreach($c in $script:CheatSoftware){ if(-not $c.GenericName){ $cheatPat += $c.Patterns } }
    $suspect = New-Object System.Collections.Generic.List[string]
    $userDirs = @('\temp\','\downloads\','\appdata\local\temp\','\users\public\')
    foreach ($p in $procs) {
        $name = $p.Name; $path = $p.ExecutablePath
        $cmd = [string]$p.CommandLine
        if (Test-ProcessIsCheat $name $path $cmd $cheatPat) {
            $extra = ''
            if ($cmd) { $c = $cmd.Trim(); if ($c.Length -gt 160) { $c = $c.Substring(0,160) + '...' }; $extra = "  cmd: $c" }
            $suspect.Add("CHEAT? $name  ($path)$extra")
            continue
        }
        if (-not [string]::IsNullOrEmpty($path) -and (Test-AnyPattern $path $userDirs)) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                if ($null -ne $sig -and $sig.Status -ne 'Valid') {
                    $suspect.Add("Non signe en zone user : $name  ($path)")
                }
            } catch { }
        }
    }
    $details.Add("Processus actifs : $($procs.Count) (detection par nom/chemin ET ligne de commande + executables non signes en zone temp ; pas d'inspection d'injection DLL en memoire).")
    if ($suspect.Count -gt 0) {
        foreach($s in $suspect){ $details.Add("  $s") }
        $status = if ($suspect | Where-Object { $_ -like 'CHEAT?*' }) { 'FLAG' } else { 'WARN' }
        $sev = if ($status -eq 'FLAG') { 2 } else { 1 }
        New-ProbeResult -Id 'PROC' -Name 'Processus & injections' -Status $status -Severity $sev -Summary "$($suspect.Count) processus a verifier" -Details $details
    } else {
        New-ProbeResult -Id 'PROC' -Name 'Processus & injections' -Status 'OK' -Severity 0 -Summary "$($procs.Count) processus, rien de connu" -Details $details
    }
}

function Get-PersistenceHits {
    # PUR/testable. Entrees de demarrage = @{ Source ('Run'|'Tache'|'Demarrage'); Name; Command }.
    # Command = la LIGNE COMPLETE : pour une tache, Execute + Arguments. Sans les arguments, une tache
    # 'powershell.exe -File ...\EngineOwningLoader.ps1' ne montrait que 'powershell.exe' (mesure 17/09 :
    # 17 taches du PC d'Alex lancent un interpreteur, le vrai programme n'est que dans les arguments).
    # Zone Temp/Downloads : suspecte pour Run et Demarrage (un programme qui se relance depuis Temp),
    # PAS pour une tache seule (installeurs et MAJ legitimes en posent) : la il faut un nom de cheat.
    param($Entries, [string[]]$Patterns)
    $hits = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Entries) { return ,$hits }
    foreach ($e in $Entries) {
        if ($null -eq $e) { continue }
        $nm = [string]$e.Name; $cmd = [string]$e.Command; $src = [string]$e.Source
        if ((Test-CheatNameMatch $cmd $Patterns) -or (Test-CheatNameMatch $nm $Patterns)) { $hits.Add("${src}: $nm = $cmd") }
        elseif ($src -ne 'Tache' -and (Test-AnyPattern $cmd @('\temp\','\downloads\'))) { $hits.Add("$src en zone temp: $nm = $cmd") }
        # Service Windows ou abonnement WMI qui s'execute depuis le PROFIL utilisateur : rarement legitime
        # (un service s'installe sous Program Files). Pas pour Run : Discord/Spotify y pointent tous vers AppData.
        elseif ($src -in @('Service','WMI') -and (Test-UserZoneDriverPath $cmd)) { $hits.Add("$src depuis le profil utilisateur: $nm = $cmd") }
    }
    return ,$hits
}

function Probe-Persistence {
    $details = New-Object System.Collections.Generic.List[string]
    $pat = Get-PersistencePatterns
    $entries = New-Object System.Collections.Generic.List[object]
    # Cles Run, y compris la vue 32 bits (WOW6432Node) : un programme 32 bits s'y enregistre et la vue
    # 64 bits ne la montre pas.
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    # Cles Run de CHAQUE compte connecte (HKCU puis HKEY_USERS\<SID>).
    $hives = Get-UserHiveRoots
    foreach ($hive in @($hives.Roots)) {
        $runKeys += "$($hive.User)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "$($hive.User)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    foreach($rk in $runKeys){
        try {
            if (-not (Test-Path $rk)) { continue }
            $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
            foreach($p in $props.PSObject.Properties){
                if ($p.Name -like 'PS*') { continue }
                $entries.Add([pscustomobject]@{ Source='Run'; Name=$p.Name; Command=[string]$p.Value })
            }
        } catch { }
    }
    # Taches planifiees : executable ET arguments.
    $taskCount = 0
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach($tk in $tasks){
            $taskCount++
            foreach($a in $tk.Actions){
                $ex = ''; $ar = ''
                try { $ex = [string]$a.Execute } catch { }
                try { $ar = [string]$a.Arguments } catch { }
                $entries.Add([pscustomobject]@{ Source='Tache'; Name=$tk.TaskName; Command=("$ex $ar").Trim() })
            }
        }
    } catch { }
    # Dossiers Demarrage (utilisateur + commun) : un raccourci est lu jusqu'a sa CIBLE (lecture seule,
    # CreateShortcut n'ecrit rien sans Save()).
    $startupCount = 0
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($dir in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
        if ([string]::IsNullOrWhiteSpace($dir)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -Force -ErrorAction SilentlyContinue)) {
            if ($f.Name -eq 'desktop.ini') { continue }
            $startupCount++
            $cmd = $f.FullName
            if ($f.Extension -eq '.lnk' -and $shell) {
                try { $lnk = $shell.CreateShortcut($f.FullName); if ($lnk.TargetPath) { $cmd = ("$($lnk.TargetPath) $($lnk.Arguments)").Trim() } } catch { }
            }
            $entries.Add([pscustomobject]@{ Source='Demarrage'; Name=$f.Name; Command=$cmd })
        }
    }
    # Services Windows ordinaires (les drivers sont dans KDRV) : ligne de commande complete.
    $serviceCount = 0
    try {
        foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop)) {
            $serviceCount++
            $entries.Add([pscustomobject]@{ Source='Service'; Name=$s.Name; Command=[string]$s.PathName })
        }
    } catch { $details.Add("NOTE : services Windows non lisibles ($($_.Exception.Message.Split([char]10)[0])).") }
    # Abonnements WMI permanents (un filtre d'evenement qui relance une commande ou un script) : persistance
    # furtive, invisible dans Run, les taches et le dossier Demarrage.
    $wmiCount = 0
    try {
        foreach ($c in @(Get-CimInstance -Namespace 'root\subscription' -ClassName CommandLineEventConsumer -ErrorAction Stop)) {
            $wmiCount++
            $cmd = [string]$c.CommandLineTemplate; if (-not $cmd) { $cmd = [string]$c.ExecutablePath }
            $entries.Add([pscustomobject]@{ Source='WMI'; Name=$c.Name; Command=$cmd })
        }
        foreach ($c in @(Get-CimInstance -Namespace 'root\subscription' -ClassName ActiveScriptEventConsumer -ErrorAction Stop)) {
            $wmiCount++
            $cmd = [string]$c.ScriptFileName; if (-not $cmd) { $cmd = [string]$c.ScriptText }
            $entries.Add([pscustomobject]@{ Source='WMI'; Name=$c.Name; Command=$cmd })
        }
    } catch { $details.Add("NOTE : abonnements WMI (root\subscription) non lisibles ($($_.Exception.Message.Split([char]10)[0])).") }
    $suspect = Get-PersistenceHits -Entries $entries -Patterns $pat
    if (@($hives.Unread).Count -gt 0) { $details.Add("NOTE : cles Run non lues pour $(@($hives.Unread).Count) compte(s) Windows non connecte(s) (ruche non chargee) : $(@($hives.Unread) -join ', ').") }
    $details.Add("Inspecte : cles Run/RunOnce (64 et 32 bits, machine et $(@($hives.Roots).Count) compte(s) connecte(s)), $taskCount tache(s) planifiee(s) avec leurs arguments, $startupCount element(s) des dossiers Demarrage (cible des raccourcis), $serviceCount service(s) Windows, $wmiCount abonnement(s) WMI qui lancent une commande ou un script.")
    if ($suspect.Count -gt 0) {
        foreach($s in $suspect){ $details.Add("  $s") }
        New-ProbeResult -Id 'PERSIST' -Name 'Persistence' -Status 'WARN' -Severity 1 -Summary "$($suspect.Count) point(s) de persistence a verifier" -Details $details
    } else {
        New-ProbeResult -Id 'PERSIST' -Name 'Persistence' -Status 'OK' -Severity 0 -Summary "Aucune persistence suspecte" -Details $details
    }
}

function Get-EventLogAssessment {
    # Logique PURE testable. Point clef : lire le journal *Security* exige l'admin. Sans
    # droits, l'event 1102 ("le journal d'audit a ete efface") -- le FLAG le plus fort de
    # cette sonde, severite 3 -- est INVISIBLE. Conclure "Journaux coherents" reviendrait a
    # certifier ce qu'on n'a pas pu regarder, alors que l'outil annonce lui-meme
    # "certaines sondes seront N/A" en mode degrade. On tient cette promesse ici.
    param(
        [string]$Status, [int]$Severity, [string]$Summary,
        [bool]$SecurityReadable = $true, [bool]$SystemReadable = $true
    )
    # un effacement DEJA constate reste prioritaire : on a vu, donc on parle.
    if ($Status -ne 'OK') { return @{ Status=$Status; Severity=$Severity; Summary=$Summary } }
    if (-not $SecurityReadable) {
        return @{ Status='NA'; Severity=0; Summary="Journal Security ILLISIBLE (admin requis) : impossible de dire s'il a ete efface (event 1102 non verifiable)" }
    }
    if (-not $SystemReadable) {
        return @{ Status='NA'; Severity=0; Summary="Journal System illisible : impossible de verifier un effacement (event 104)" }
    }
    @{ Status='OK'; Severity=$Severity; Summary=$Summary }
}

function Test-EventLogReadable {
    # Get-WinEvent leve AUSSI une exception quand le journal est simplement VIDE. Confondre
    # "vide" et "refuse" rendrait N/A toute machine saine. Seul un refus d'acces compte.
    param([string]$LogName)
    try { Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop | Out-Null; return $true }
    catch {
        if ($_.Exception -is [System.UnauthorizedAccessException]) { return $false }
        return $true   # "aucun evenement", journal absent, etc. : on a pu regarder
    }
}

function Probe-EventLogs {
    $details = New-Object System.Collections.Generic.List[string]
    $status='OK'; $sev=0; $summary='Journaux coherents'
    $cleared = New-Object System.Collections.Generic.List[string]
    $secReadable = Test-EventLogReadable -LogName 'Security'
    $sysReadable = Test-EventLogReadable -LogName 'System'
    if (-not $secReadable) { $details.Add("Journal Security NON LISIBLE (droits admin requis) : l'effacement d'audit (1102) n'a pas pu etre verifie.") }
    if (-not $sysReadable) { $details.Add("Journal System NON LISIBLE : l'effacement (104) n'a pas pu etre verifie.") }
    # 1102 = Security log cleared, 104 = autre log cleared
    try {
        $e1102 = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue)
        foreach($e in $e1102){ $cleared.Add("Security efface le $($e.TimeCreated)") }
    } catch { }
    try {
        $e104 = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -MaxEvents 5 -ErrorAction SilentlyContinue)
        foreach($e in $e104){ $cleared.Add("Journal efface (104) le $($e.TimeCreated)") }
    } catch { }
    if ($cleared.Count -gt 0) {
        $status='FLAG'; $sev=3; $summary="Journaux d'evenements EFFACES ($($cleared.Count))"
        foreach($c in $cleared){ $details.Add("  $c") }
    }
    # plus ancien event System vs install : distinguer le ROLLOVER normal (log plein qui
    # ecrase les vieux events, ubiquiste) d'une vraie purge/troncature. Un log court n'est
    # suspect QUE s'il n'est PAS plein (sinon c'est juste la taille max atteinte).
    try {
        $oldest = Get-WinEvent -LogName System -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($null -ne $oldest) {
            $details.Add("Plus ancien event System : $($oldest.TimeCreated)")
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            $fill = $null; $maxMB = $null
            try {
                $li = Get-WinEvent -ListLog System -ErrorAction SilentlyContinue
                if ($null -ne $li -and $li.MaximumSizeInBytes -gt 0) {
                    $fill = $li.FileSize / [double]$li.MaximumSizeInBytes
                    $maxMB = [math]::Round($li.MaximumSizeInBytes/1MB,1)
                }
            } catch { }
            if ($null -ne $fill) { $details.Add(("Journal System rempli a {0:P0} de sa taille max ({1} Mo)." -f $fill, $maxMB)) }
            $shortHistory = ($null -ne $os -and $oldest.TimeCreated -gt $os.InstallDate.AddDays(2))
            if ($shortHistory -and $status -eq 'OK') {
                if ($null -eq $fill -or $fill -ge 0.5) {
                    $details.Add("Historique court explique par le ROLLOVER (log plein qui ecrase les plus vieux events) = normal sur une machine active, pas une purge.")
                } else {
                    $status='WARN'; $sev=1; $summary="Journal System court ET peu rempli (vide/tronque recemment ?)"
                    $details.Add("Le journal n'est PAS plein mais son historique est court : compatible avec un effacement/troncature recent non logge (1102/104). A recouper avec USN/install.")
                }
            }
        }
    } catch { }
    if ($status -eq 'OK' -and $details.Count -eq 0) { $details.Add("Aucun effacement de journal detecte.") }
    $a = Get-EventLogAssessment -Status $status -Severity $sev -Summary $summary -SecurityReadable $secReadable -SystemReadable $sysReadable
    New-ProbeResult -Id 'EVTLOG' -Name "Journaux d'evenements" -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
}

function Get-AntiForensicAssessment {
    # Logique PURE testable. Le FLAG de cette sonde repose ENTIEREMENT sur le Prefetch :
    # c'est la seule preuve qu'un outil de wipe a REELLEMENT tourne. Si ce canal est
    # aveugle, on ne peut pas conclure "rien" -- et surtout pas ecrire "Aucun outil de
    # wipe connu", qui se lit comme un blanc-seing.
    # PrefetchState : OK = lu / DISABLED = Prefetcher coupe (geste anti-forensic en soi,
    # donc WARN) / UNREADABLE = dossier absent ou refuse (on ne sait pas, donc NA).
    param(
        [int]$FlagCount, [int]$WarnCount,
        [ValidateSet('OK','DISABLED','UNREADABLE')] [string]$PrefetchState = 'OK'
    )
    if ($FlagCount -gt 0) {
        return @{ Status='FLAG'; Severity=2; Summary="$FlagCount outil(s) d'effacement securise QUI A TOURNE (wipe avant le check ?)" }
    }
    $suffix = ''
    if ($WarnCount -gt 0) { $suffix = " ; par ailleurs $WarnCount nettoyeur(s) installe(s) (dual-use)" }
    if ($PrefetchState -eq 'DISABLED') {
        return @{ Status='WARN'; Severity=1; Summary="Prefetch DESACTIVE : la preuve qu'un wipe a tourne est supprimee a la source -- couper le Prefetcher est lui-meme un geste anti-forensic$suffix" }
    }
    if ($PrefetchState -eq 'UNREADABLE') {
        return @{ Status='NA'; Severity=0; Summary="Prefetch illisible : impossible de dire si un outil de wipe a tourne (ce n'est PAS 'aucun')$suffix" }
    }
    if ($WarnCount -gt 0) {
        return @{ Status='WARN'; Severity=1; Summary="$WarnCount nettoyeur(s) courant(s) (dual-use, a verifier)" }
    }
    @{ Status='OK'; Severity=0; Summary='Aucun outil de wipe connu, et la trace d execution (Prefetch) a bien ete lue' }
}

function Probe-AntiForensic {
    $details = New-Object System.Collections.Generic.List[string]
    $flagHits = New-Object System.Collections.Generic.List[string]  # outils de wipe -> FLAG
    $warnHits = New-Object System.Collections.Generic.List[string]  # nettoyeurs courants -> WARN
    $names = Get-UninstallEntries
    $pf = @()
    # Le Prefetch est la SEULE source du FLAG ici : on doit savoir si on a pu le lire.
    # Un -ErrorAction SilentlyContinue rendait un dossier illisible indiscernable d'un
    # dossier vide -> la sonde concluait "Aucun outil de wipe connu" sans avoir regarde.
    $pfState = 'OK'
    try {
        $ep = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnablePrefetcher' -ErrorAction Stop).EnablePrefetcher
        if ($null -ne $ep -and [int]$ep -eq 0) { $pfState = 'DISABLED' }
    } catch { }   # valeur absente = defaut Windows = Prefetcher actif
    if ($pfState -eq 'OK') {
        try { $pf = @(Get-ChildItem "$script:SysDrive\Windows\Prefetch" -Filter *.pf -File -ErrorAction Stop) }
        catch { $pfState = 'UNREADABLE'; $details.Add("Prefetch non lisible : $($_.Exception.Message.Split([char]10)[0])") }
    } else {
        $details.Add("Prefetch DESACTIVE dans le registre (EnablePrefetcher = 0).")
    }
    # Present (installe) != preuve : un outil de wipe INSTALLE = WARN (dual-use, hygiene). Seul un
    # wipe qui a EFFECTIVEMENT TOURNE (trace prefetch) = FLAG = "efface juste avant le check".
    foreach($n in $names){
        if (Test-AnyPattern $n $script:AntiForensicTools) { $warnHits.Add("Installe (outil de wipe, present) : $n") }
        elseif (Test-AnyPattern $n $script:CleanerToolsWarn) { $warnHits.Add("Installe (nettoyeur) : $n") }
    }
    foreach($f in $pf){
        if (Test-AnyPattern $f.Name $script:AntiForensicTools) { $flagHits.Add("EXECUTE (wipe a tourne) : $($f.Name) le $($f.LastWriteTime)") }
        elseif (Test-AnyPattern $f.Name $script:CleanerToolsWarn) { $warnHits.Add("Execute nettoyeur (prefetch) : $($f.Name) le $($f.LastWriteTime)") }
    }
    foreach($h in $flagHits){ $details.Add("  $h") }
    foreach($h in $warnHits){ $details.Add("  $h") }
    $a = Get-AntiForensicAssessment -FlagCount $flagHits.Count -WarnCount $warnHits.Count -PrefetchState $pfState
    New-ProbeResult -Id 'ANTIFOR' -Name 'Outils anti-forensic/wipe' -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
}

function Get-ShadowWipeHits {
    # Pur -> testable. Detecte une commande de SUPPRESSION des points de restauration (Volume Shadow
    # Copies) dans l'historique - geste anti-forensic classique (on efface les sauvegardes ou vivent
    # des versions "supprimees" de fichiers). On exige un VERBE de suppression + la cible shadow :
    # LISTER n'est pas supprimer (vssadmin list shadows est ignore).
    param([string[]]$Lines)
    $hits = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Lines) { return ,$hits }
    foreach ($l in $Lines) {
        $s = [string]$l
        if ([string]::IsNullOrEmpty($s)) { continue }
        $low = $s.ToLowerInvariant()
        if (($low -match 'delete|remove') -and ($low -match 'shadow')) { $hits.Add($s.Trim()) }
    }
    return ,$hits
}

function Probe-ShadowCopies {
    $details = New-Object System.Collections.Generic.List[string]
    # 1) Commande de suppression des shadow copies dans l'historique PowerShell (par-user, sans admin).
    $lines = New-Object System.Collections.Generic.List[string]
    $hist = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path -LiteralPath $hist) {
        $txt = Get-FileBytesText $hist
        if ($txt) { foreach ($l in ($txt -split "\r?\n")) { $lines.Add($l) } }
    }
    $wipe = Get-ShadowWipeHits $lines
    # 2) Points de restauration presents (lecture read-only, admin ; NA propre sinon).
    $count = $null
    try { $count = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop).Count } catch { }
    if ($null -ne $count) { $details.Add("Points de restauration (Shadow Copies) presents : $count") }
    else { $details.Add("Liste des Shadow Copies non lisible (admin requis) - non bloquant.") }
    if ($wipe.Count -gt 0) {
        foreach ($w in $wipe) { $details.Add("SUPPRESSION de shadow copies dans l'historique : $w") }
        # WARN (pas FLAG) : supprimer les shadow copies est dual-use (maintenance admin legitime).
        # v1 = PAS cable dans Get-EvasionProfile (decision moat differee v2) : un WARN isole reste A VERIFIER.
        New-ProbeResult -Id 'SHADOW' -Name 'Points de restauration (Shadow Copies)' -Status 'WARN' -Severity 1 -Summary "$($wipe.Count) commande(s) de SUPPRESSION de shadow copies dans l'historique (anti-forensic ? a verifier)" -Details $details
    } elseif ($null -ne $count) {
        New-ProbeResult -Id 'SHADOW' -Name 'Points de restauration (Shadow Copies)' -Status 'INFO' -Severity 0 -Summary "$count point(s) de restauration ; aucune commande de suppression dans l'historique" -Details $details
    } else {
        New-ProbeResult -Id 'SHADOW' -Name 'Points de restauration (Shadow Copies)' -Status 'OK' -Severity 0 -Summary "Aucune commande de suppression de shadow copies dans l'historique" -Details $details
    }
}

function Probe-Browsers {
    $details = New-Object System.Collections.Generic.List[string]
    $hits = New-Object System.Collections.Generic.List[string]
    $domains = New-Object System.Collections.Generic.List[string]
    foreach($c in $script:CheatSoftware){ foreach($d in $c.Domains){ $domains.Add($d) } }
    # Tous les comptes Windows : le compte courant (variables d'environnement, qui suivent une eventuelle
    # redirection) puis chaque profil.
    $pairs = @(,@($env:LOCALAPPDATA, $env:APPDATA))
    foreach ($pd in @(Get-UserProfileDirs)) { $pairs += ,@((Join-Path $pd 'AppData\Local'), (Join-Path $pd 'AppData\Roaming')) }
    $dbs = @()
    foreach ($pr in $pairs) {
        $local = $pr[0]; $roaming = $pr[1]
        if (-not $local -or -not $roaming) { continue }
        $dbs += "$local\Google\Chrome\User Data\*\History",
            "$local\Microsoft\Edge\User Data\*\History",
            "$local\BraveSoftware\Brave-Browser\User Data\*\History",
            "$roaming\Mozilla\Firefox\Profiles\*\places.sqlite",
            "$roaming\Opera Software\Opera Stable\History"
    }
    $checked = 0
    $seenDb = @{}
    foreach($pattern in $dbs){
        $files = @(Get-ChildItem $pattern -File -ErrorAction SilentlyContinue)
        foreach($f in $files){
            if ($seenDb.ContainsKey($f.FullName.ToLowerInvariant())) { continue }
            $seenDb[$f.FullName.ToLowerInvariant()] = $true
            $checked++
            $details.Add("Base navigateur : $($f.FullName)  (modifiee $($f.LastWriteTime))")
            $text = Get-FileBytesText $f.FullName
            if ($null -eq $text) { $details.Add("  (verrouillee/illisible)"); continue }
            foreach($d in $domains){
                if ($text.IndexOf($d, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits.Add("$d  (dans $($f.Name))") }
            }
        }
    }
    if ($checked -eq 0) {
        New-ProbeResult -Id 'BROWSER' -Name 'Navigateurs (sites cheats)' -Status 'NA' -Severity 0 -Summary "Aucune base navigateur trouvee" -Details $details
    } elseif ($hits.Count -gt 0) {
        foreach($h in $hits){ $details.Add("  HIT: $h") }
        # Visiter/lire un site de cheat n'est pas l'avoir achete ni utilise -> WARN (a verifier), pas FLAG.
        New-ProbeResult -Id 'BROWSER' -Name 'Navigateurs (sites cheats)' -Status 'WARN' -Severity 1 -Summary "Domaine(s) de cheat dans l'historique : $($hits.Count) - a verifier (visite != usage)" -Details $details
    } else {
        New-ProbeResult -Id 'BROWSER' -Name 'Navigateurs (sites cheats)' -Status 'OK' -Severity 0 -Summary "$checked base(s), aucun domaine cheat connu" -Details $details
    }
}

function Get-DomainHits {
    # PUR/testable : rend les domaines (parmi $domains) presents en sous-chaine dans $haystack
    # (insensible a la casse). Meme semantique que la sonde Navigateurs (un domaine 'lavicheats.com'
    # est deja borne par des points) -> pas de Test-AnyWord ici. Rend une List (consommer sans @()).
    param([string]$haystack, [string[]]$domains)
    $hits = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrEmpty($haystack)) { return ,$hits }
    foreach($d in $domains){
        if ([string]::IsNullOrEmpty($d)) { continue }
        if ($haystack.IndexOf($d, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits.Add($d) }
    }
    return ,$hits
}

function Get-PsHistoryHits {
    # PUR/testable. Rend les lignes d'historique PowerShell qui font du "telecharger-et-executer".
    # Le VERBE (iwr|iex, DownloadString, -enc, bitsadmin, certutil -urlcache) est dual-use (winutil
    # de Chris Titus, winget... sont legitimes) => WARN. On ne monte en FLAG que si la CIBLE EXTRAITE
    # (l'URL reellement fetch) matche un token cheat DISTINCTIF par word-boundary -- JAMAIS le token
    # n'importe ou dans la ligne (un commentaire "# comment enlever un aimbot" ne doit rien declencher,
    # et il n'a de toute facon pas de verbe de telechargement). Rend une List (consommer sans @()).
    param([string[]]$lines, [string[]]$flagPatterns)
    $hits = New-Object System.Collections.Generic.List[object]
    if ($null -eq $lines) { return ,$hits }
    # ponytail: on couvre les verbes download-and-exec courants. Deux cas VOLONTAIREMENT ignores
    # (trop de faux positifs pour le gain) : le raccourci '-e'/'-en' de -EncodedCommand (bare '-e'
    # collisionne partout), et le telechargement-puis-lancement en DEUX etapes (iwr -OutFile x ;
    # Start-Process x) dont la regex serait fragile et bruyante. Tout reste WARN de toute facon.
    $verbs = @(
        '(?i)(iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b[^\r\n]*\|\s*(iex|invoke-expression)\b',
        '(?i)(iex|invoke-expression)\b[^\r\n]*(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring|net\.webclient)',
        '(?i)\.downloadstring\s*\(',
        '(?i)\s-e(nc|ncodedcommand)\b',
        '(?i)\bbitsadmin\b[^\r\n]*/transfer',
        '(?i)\bstart-bitstransfer\b',
        '(?i)\bcertutil\b[^\r\n]*-urlcache'
    )
    foreach ($ln in $lines) {
        if ([string]::IsNullOrWhiteSpace($ln)) { continue }
        $isVerb = $false
        foreach ($v in $verbs) { if ([regex]::IsMatch($ln, $v)) { $isVerb = $true; break } }
        if (-not $isVerb) { continue }
        # cible = la/les URL(s) reellement presentes dans la commande (host + chemin fetch).
        $target = ''
        $m = [regex]::Matches($ln, '(?i)https?://[^\s''"|)]+')
        if ($m.Count -gt 0) { $target = (($m | ForEach-Object { $_.Value }) -join ' ') }
        $isFlag = ($target -ne '') -and (Test-AnyWord $target $flagPatterns)
        $hits.Add([pscustomobject]@{ Line=$ln.Trim(); Target=$target; IsFlag=$isFlag })
    }
    return ,$hits
}

function Get-PsHistoryFlagTargets {
    # Set FLAG de la sonde historique = SEULEMENT des noms de PRODUIT/PROVIDER distinctifs + leurs
    # DOMAINES (non generiques). PAS les mots de categorie de CheatFlagWords (aimbot/wallhack/spoofer/
    # injector) : dans une URL, "aimbot" collisionne avec "aimbot-remover", "anti-aimbot-detector",
    # un injector de modding legitime... = faux FLAG sur un innocent. Ces mots de categorie restent au
    # plafond WARN de la sonde. Le signal FORT et NON AMBIGU pour une URL = un domaine/nom de provider
    # de cheat connu (engineowning.to, phantomoverlay...). Source unique, partagee probe + tests.
    $p = New-Object System.Collections.Generic.List[string]
    foreach ($c in $script:CheatSoftware) {
        if (-not $c.GenericName) {
            foreach ($x in $c.Patterns) { if ($x) { $p.Add($x) } }
            foreach ($d in $c.Domains)  { if ($d) { $p.Add($d) } }
        }
    }
    return @($p | Select-Object -Unique)
}

function Probe-PsHistory {
    $details = New-Object System.Collections.Generic.List[string]
    # PSReadLine journalise les commandes tapees par l'utilisateur (par-user, sans admin).
    # Tous les comptes Windows, pas seulement celui qui lance le check.
    $paths = @((Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'))
    foreach ($pd in @(Get-UserProfileDirs)) { $paths += (Join-Path $pd 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt') }
    $paths = @($paths | Where-Object { $_ } | Sort-Object { $_.ToLowerInvariant() } -Unique)
    $lines = New-Object System.Collections.Generic.List[string]
    $found = 0
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p) {
            $found++
            $details.Add("Historique : $p")
            $txt = Get-FileBytesText $p
            if ($txt) { foreach ($l in ($txt -split "\r?\n")) { $lines.Add($l) } }
        }
    }
    if ($found -eq 0) {
        return (New-ProbeResult -Id 'PSHIST' -Name 'Historique PowerShell' -Status 'NA' -Severity 0 -Summary "Aucun historique PSReadLine trouve" -Details $details)
    }
    $hits = Get-PsHistoryHits $lines (Get-PsHistoryFlagTargets)
    $flagHits = @($hits | Where-Object { $_.IsFlag })
    $warnHits = @($hits | Where-Object { -not $_.IsFlag })
    if ($flagHits.Count -gt 0) {
        foreach ($h in $flagHits) { $details.Add("  FLAG telechargement d'une cible cheat : $($h.Line)") }
        foreach ($h in $warnHits) { $details.Add("  (download-and-exec dual-use : $($h.Line))") }
        return (New-ProbeResult -Id 'PSHIST' -Name 'Historique PowerShell' -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) telechargement(s)-et-execution d'une cible au nom de cheat distinctif" -Details $details)
    } elseif ($warnHits.Count -gt 0) {
        foreach ($h in $warnHits) { $details.Add("  download-and-exec : $($h.Line)") }
        # INFO, pas WARN : installer un logiciel par irm|iex (Claude, winutil, scoop) est banal. Mesure 16/09 :
        # ce seul WARN mettait un PC propre en A VERIFIER. Seule une cible cheat distinctive pese (FLAG).
        return (New-ProbeResult -Id 'PSHIST' -Name 'Historique PowerShell' -Status 'INFO' -Severity 0 -Summary "$($warnHits.Count) commande(s) telecharger-et-executer, aucune vers une cible cheat connue" -Details $details)
    }
    New-ProbeResult -Id 'PSHIST' -Name 'Historique PowerShell' -Status 'OK' -Severity 0 -Summary "$($lines.Count) ligne(s), aucun telecharger-et-executer" -Details $details
}

function Probe-DnsCache {
    $details = New-Object System.Collections.Generic.List[string]
    $hits = New-Object System.Collections.Generic.List[string]
    $domains = New-Object System.Collections.Generic.List[string]
    foreach($c in $script:CheatSoftware){ foreach($d in $c.Domains){ $domains.Add($d) } }
    $dnsReadable = $false
    $hostsReadable = $false

    # 1) Cache DNS du resolveur : capte une resolution par N'IMPORTE quel process (pas que le navigateur).
    $dnsText = $null
    try {
        $cache = @(Get-DnsClientCache -ErrorAction Stop)
        $dnsReadable = $true
        $sb = New-Object System.Text.StringBuilder
        foreach($e in $cache){ [void]$sb.AppendLine("$($e.Entry) $($e.Data)") }
        $dnsText = $sb.ToString()
        $details.Add("Cache DNS : $($cache.Count) entrees (Get-DnsClientCache).")
    } catch {
        # Repli sur ipconfig si le module DnsClient n'est pas la : on scanne le texte brut.
        try {
            $raw = (ipconfig /displaydns 2>$null | Out-String)
            if (-not [string]::IsNullOrWhiteSpace($raw)) { $dnsText = $raw; $dnsReadable = $true; $details.Add("Cache DNS : lu via 'ipconfig /displaydns' (repli).") }
        } catch { }
    }
    if ($dnsReadable -and $dnsText) {
        foreach($h in (Get-DomainHits $dnsText $domains)){ $hits.Add("$h  (cache DNS)") }
    } elseif (-not $dnsReadable) {
        $details.Add("Cache DNS illisible.")
    }

    # 2) Fichier hosts : redirection statique -> survit a un effacement d'historique navigateur.
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsText = Get-FileBytesText $hostsPath
    if ($null -ne $hostsText) {
        $hostsReadable = $true
        $sb2 = New-Object System.Text.StringBuilder
        foreach($line in ($hostsText -split "`n")){
            $t = $line.Trim()
            if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }   # ignorer commentaires
            [void]$sb2.AppendLine($t)
        }
        $details.Add("Fichier hosts : $hostsPath (lu).")
        foreach($h in (Get-DomainHits $sb2.ToString() $domains)){ $hits.Add("$h  (fichier hosts)") }
    } else {
        $details.Add("Fichier hosts illisible : $hostsPath")
    }

    if (-not $dnsReadable -and -not $hostsReadable) {
        return (New-ProbeResult -Id 'DNS' -Name 'Cache DNS / hosts' -Status 'NA' -Severity 0 -Summary "Cache DNS et fichier hosts illisibles" -Details $details)
    }
    if ($hits.Count -gt 0) {
        foreach($h in $hits){ $details.Add("  HIT: $h") }
        # Resoudre un domaine (cache) ou une ligne hosts n'est ni l'achat ni l'usage -> WARN, jamais FLAG.
        return (New-ProbeResult -Id 'DNS' -Name 'Cache DNS / hosts' -Status 'WARN' -Severity 1 -Summary "Domaine(s) de cheat dans le cache DNS / hosts : $($hits.Count) - a verifier (resolution != usage)" -Details $details)
    }
    # Cache ephemere (vide au reboot / TTL) -> INFO hors-verdict, pas un OK qui surpromettrait.
    return (New-ProbeResult -Id 'DNS' -Name 'Cache DNS / hosts' -Status 'INFO' -Severity 0 -Summary "Aucun domaine cheat dans le cache DNS / hosts (cache ephemere)" -Details $details)
}

function Probe-RecycleBin {
    $details = New-Object System.Collections.Generic.List[string]
    $rb = "$script:SysDrive\`$Recycle.Bin"
    if (-not (Test-Path $rb)) {
        return (New-ProbeResult -Id 'RECYCLE' -Name 'Corbeille' -Status 'NA' -Severity 0 -Summary "Corbeille introuvable" -Details $details)
    }
    try {
        $items = @(Get-ChildItem $rb -Recurse -Force -File -ErrorAction SilentlyContinue)
        $details.Add("Elements en corbeille : $($items.Count)")
        if ($items.Count -gt 0) {
            $last = ($items | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
            $details.Add("Plus recent : $last")
        }
        New-ProbeResult -Id 'RECYCLE' -Name 'Corbeille' -Status 'OK' -Severity 0 -Summary "$($items.Count) element(s)" -Details $details
    } catch {
        New-ProbeResult -Id 'RECYCLE' -Name 'Corbeille' -Status 'NA' -Severity 0 -Summary "Lecture corbeille impossible" -Details @($_.Exception.Message)
    }
}

function Get-RigAssessment {
    # Logique PURE et testable : a partir de la PRESENCE de chaque signal hardware, rend
    # statut/severite/resume. Isolee de l'enumeration PnP (I/O) pour etre testable a sec.
    # Priorite : DMA connue (FLAG) > combo capture+pad (WARN) > pont USB3 FTDI (WARN) >
    # capture seule (INFO = streamer) > rien (OK).
    param([bool]$HasDma, [bool]$HasCapture, [bool]$HasVpad, [bool]$HasUsbHint)
    if ($HasDma)                   { return @{ Status='FLAG'; Severity=2; Summary='Carte DMA connue (lecture RAM = wallhack/radar possible)' } }
    if ($HasCapture -and $HasVpad) { return @{ Status='WARN'; Severity=1; Summary='Combo capture + manette virtuelle (boite a cheat CV/console possible) -- a verifier' } }
    if ($HasUsbHint)               { return @{ Status='WARN'; Severity=1; Summary='Pont USB3 FTDI (lien type carte DMA, aussi dev board FPGA) -- a verifier' } }
    if ($HasCapture)               { return @{ Status='INFO'; Severity=0; Summary='Carte de capture presente (normal pour un streamer) -- informatif' } }
    return @{ Status='OK'; Severity=0; Summary='Aucun device DMA/capture/rig connu' }
}

function Probe-Hardware {
    $details     = New-Object System.Collections.Generic.List[string]
    $dmaHits     = New-Object System.Collections.Generic.List[string]
    $usbHits     = New-Object System.Collections.Generic.List[string]
    $captureHits = New-Object System.Collections.Generic.List[string]
    $vpadHits    = New-Object System.Collections.Generic.List[string]
    try {
        $dev = @(Get-PnpDevice -ErrorAction SilentlyContinue)
        $details.Add("Peripheriques enumeres (presents + historiques) : $($dev.Count)")
        foreach($d in $dev){
            $fn = [string]$d.FriendlyName
            if ([string]::IsNullOrWhiteSpace($fn)) { continue }
            if     (Test-AnyWord $fn $script:DmaPatterns)  { $dmaHits.Add("DMA connue : $fn  [$($d.Status)]") }
            elseif (Test-AnyWord $fn $script:DmaUsbHints)  { $usbHits.Add("Pont USB3 FTDI : $fn  [$($d.Status)]") }
            if (Test-AnyWord $fn $script:CaptureCards)      { $captureHits.Add("Capture : $fn  [$($d.Status)]") }
            if (Test-AnyWord $fn $script:VirtualPadDrivers) { $vpadHits.Add("Manette virtuelle : $fn  [$($d.Status)]") }
        }
    } catch {
        return (New-ProbeResult -Id 'HARDWARE' -Name 'Hardware / DMA / capture' -Status 'NA' -Severity 0 -Summary "Enumeration PnP indisponible" -Details @($_.Exception.Message))
    }
    $a = Get-RigAssessment -HasDma ($dmaHits.Count -gt 0) -HasCapture ($captureHits.Count -gt 0) -HasVpad ($vpadHits.Count -gt 0) -HasUsbHint ($usbHits.Count -gt 0)
    # DMA et pont USB3 sont toujours listes (toujours significatifs). Capture/manette
    # virtuelle ne sont listees que si elles CONTRIBUENT au verdict (combo ou capture seule) :
    # une manette virtuelle seule est benigne (deja reportee par la sonde input) -> pas de bruit.
    foreach($h in $dmaHits) { $details.Add("  $h") }
    foreach($h in $usbHits) { $details.Add("  $h") }
    if ($a.Status -in @('WARN','INFO')) {
        foreach($h in $captureHits) { $details.Add("  $h") }
        foreach($h in $vpadHits)    { $details.Add("  $h") }
    }
    if ($captureHits.Count -gt 0 -and $vpadHits.Count -gt 0 -and $dmaHits.Count -eq 0) {
        $details.Add("  Note : capture + manette virtuelle = la chaine d'une boite a cheat console (capture HDMI -> aimbot vision -> injection manette). Legitime pour un streamer => verifier le setup visuellement.")
    }
    New-ProbeResult -Id 'HARDWARE' -Name 'Hardware / DMA / capture' -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
}

# Signatures PCIe de cartes DMA connues. VEN_10EE = Xilinx = fournisseur du firmware
# pcileech-fpga stock/public, catch par BattlEye/EAC via VID/PID depuis 2017-2018. DUAL-USE :
# des dev-boards FPGA legitimes utilisent aussi Xilinx -> WARN, JAMAIS FLAG. Un firmware custom
# bien spoofe usurpe le config space (clone le VID/PID d'un vrai SSD/NIC) -> INVISIBLE a un scan
# user-mode : cette sonde catch le DMA PARESSEUX, pas le determine. Le vrai anti-DMA = kernel +
# IOMMU cote anti-cheat (Vanguard/Ricochet 2024-2026), hors portee d'un screenshare read-only.
# Source : ecosysteme PCILeech (VID Xilinx 0x10EE, config via pcileech_cfgspace.coe), fils NTDEV
# sur les faux positifs de l'enumeration PCIe cote client.
$script:DmaPciVendors = @('VEN_10EE')

# VID grand public (Intel, AMD, NVIDIA, Realtek, Broadcom, Atheros, Mediatek). Sur une
# build recente, un device de ces vendeurs peut etre 'sans driver' (reinstall pas encore
# finie, ex : carte Wi-Fi Intel AX210 en status=Error) = ROUTINE, pas un tell DMA. On le
# liste quand meme au modo, mais en INFO (pas de faux WARN sur PC neuf). Un VID INCONNU
# sans driver, et Xilinx, restent en WARN. NOTE securite : un DMA firmware-spoofe en 8086
# passerait ce filtre -- mais la sonde le documente deja (spoof invisible => check visuel
# obligatoire), la securite reelle ne repose pas sur ce WARN mais sur l'inspection humaine.
$script:BenignPciVendors = @('VEN_8086','VEN_10DE','VEN_1002','VEN_1022','VEN_10EC','VEN_14E4','VEN_168C','VEN_14C3','VEN_1969')
# Config space PAR DEFAUT du firmware pcileech-fpga (pcileech_cfgspace.coe : VID 10EE / DID 0666) : aucun
# produit Xilinx commercial ne porte DEV_0666. Ce n'est pas un NOM renommable, c'est l'identite PCIe que
# la carte annonce -> FLAG sev2 (comme un nom 'pcileech' cote PnP). Un firmware custom change ces IDs et passe.
$script:DmaPciStockIds = @('VEN_10EE&DEV_0666')

function Get-PciProblemLevel {
    # Pur -> testable. Classe UN device PCIe : 'FLAG' = ID stock pcileech ; 'WARN' = Xilinx (dev-board
    # possible) OU device PRESENT en erreur a VID inconnu OU device PRESENT a VID grand public dont le
    # DRIVER EXISTE mais ne demarre pas (code 10/12/31/43 : une carte DMA qui clone l'ID d'une Realtek
    # 8168 obtient le vrai driver Realtek... qui echoue, car le FPGA n'est pas une NIC) ; 'INFO' = VID
    # grand public SANS driver (code 28 = reinstall pas finie, routine) ; '' = rien. Les devices
    # FANTOMES (Present=$false, code CM_PROB_PHANTOM) ne sont jamais classes : materiel debranche = normal.
    param([string]$InstanceId, [int]$ErrorCode, [bool]$Present)
    if (Test-AnyPattern $InstanceId $script:DmaPciStockIds) { return 'FLAG' }
    if (Test-AnyPattern $InstanceId $script:DmaPciVendors)  { return 'WARN' }
    if (-not $Present -or $ErrorCode -eq 0) { return '' }
    if (-not (Test-AnyPattern $InstanceId $script:BenignPciVendors)) { return 'WARN' }
    if ($ErrorCode -in @(10,12,31,43)) { return 'WARN' }
    return 'INFO'
}

function Probe-DmaPci {
    $details = New-Object System.Collections.Generic.List[string]
    $dev = @()
    # 'PCI' n'est PAS une setup-class PnP -> on enumere tout et on filtre par enumerateur (InstanceId PCI\*).
    try { $dev = @(Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -like 'PCI\*' }) } catch {
        return (New-ProbeResult -Id 'DMAPCI' -Name 'Cartes PCIe / DMA' -Status 'NA' -Severity 0 -Summary "Enumeration PCIe indisponible" -Details @($_.Exception.Message))
    }
    $flagL = New-Object System.Collections.Generic.List[string]   # ID stock pcileech
    $warnL = New-Object System.Collections.Generic.List[string]   # Xilinx / VID inconnu en erreur / driver legit qui ne demarre pas
    $infoL = New-Object System.Collections.Generic.List[string]   # VID grand public sans driver (probable reinstall)
    foreach($d in $dev){
        $iid = [string]$d.InstanceId
        $fn  = [string]$d.FriendlyName; if ([string]::IsNullOrWhiteSpace($fn)) { $fn = '(sans nom)' }
        $code = 0; $present = $true
        # CIM : propriete absente/nulle => on reste conservateur (code 0 = pas d'erreur, present).
        try { $cp = $d.PSObject.Properties['ConfigManagerErrorCode']; if ($cp -and $null -ne $cp.Value) { $code = [int]$cp.Value } } catch { }
        try { $pp = $d.PSObject.Properties['Present'];                if ($pp -and $null -ne $pp.Value) { $present = [bool]$pp.Value } } catch { }
        $line = "$fn  [$iid]  status=$($d.Status) code=$code"
        switch (Get-PciProblemLevel -InstanceId $iid -ErrorCode $code -Present $present) {
            'FLAG' { $flagL.Add("ID STOCK pcileech (10EE:0666) : $line") }
            'WARN' { if (Test-AnyPattern $iid $script:DmaPciVendors) { $warnL.Add("FPGA/DMA connu (Xilinx) : $line") }
                     elseif (Test-AnyPattern $iid $script:BenignPciVendors) { $warnL.Add("driver legitime present mais le device ne demarre pas (code $code) - un DMA qui clone cet ID echoue exactement comme ca : $line") }
                     else { $warnL.Add("PCIe en erreur, VID inconnu (sans driver ?) : $line") } }
            'INFO' { $infoL.Add("sans driver, VID grand public (probable reinstall - a confirmer visuellement, une 2e carte reste possible) : $line") }
        }
    }
    $details.Add("Devices PCIe enumeres : $($dev.Count). Verif read-only = ID stock pcileech (10EE:0666), VID Xilinx, device PCIe en erreur (sans driver / driver qui ne demarre pas). Ne voit que ce que le firmware presente : un DMA bien spoofe passe (check visuel obligatoire).")
    foreach($h in $flagL){ $details.Add("  $h") }
    foreach($h in $warnL){ $details.Add("  $h") }
    foreach($h in $infoL){ $details.Add("  $h") }
    if ($flagL.Count -gt 0) {
        return (New-ProbeResult -Id 'DMAPCI' -Name 'Cartes PCIe / DMA' -Status 'FLAG' -Severity 2 -Summary "$($flagL.Count) carte(s) PCIe a l'ID STOCK pcileech (10EE:0666) - carte DMA quasi certaine" -Details $details)
    }
    if ($warnL.Count -gt 0) {
        return (New-ProbeResult -Id 'DMAPCI' -Name 'Cartes PCIe / DMA' -Status 'WARN' -Severity 1 -Summary "$($warnL.Count) device(s) PCIe a verifier (Xilinx / en erreur) - dual-use" -Details $details)
    }
    $sumInfo = if ($infoL.Count -gt 0) { "$($dev.Count) devices PCIe ; $($infoL.Count) sans driver a VID grand public (probable reinstall), aucune carte DMA connue" } else { "$($dev.Count) devices PCIe, aucune carte DMA connue ni PCIe en erreur" }
    New-ProbeResult -Id 'DMAPCI' -Name 'Cartes PCIe / DMA' -Status 'INFO' -Severity 0 -Summary $sumInfo -Details $details
}

function Get-DmaPostureSummary {
    # Pur -> testable. INFO STRICT (jamais un signal de triche) : contextualise la sonde PCIe -
    # la machine est-elle plutot fermee ou ouverte a une carte DMA externe. Un OFF n'accuse
    # personne (VBS / protection DMA sont OFF par defaut sur beaucoup de desktops sans Thunderbolt).
    param([int]$VbsStatus, [bool]$DmaProtectionAvailable)
    if ($VbsStatus -ge 2 -and $DmaProtectionAvailable) {
        return "VBS actif + protection DMA disponible : machine plutot fermee a une carte DMA externe (contexte)"
    } elseif ($VbsStatus -ge 2) {
        return "VBS actif (protection DMA non confirmee) : partiellement durcie (contexte)"
    } else {
        return "VBS / protection DMA non active (defaut courant sur desktop) : une carte DMA serait moins genee - contexte, PAS une accusation"
    }
}

function Probe-DmaPosture {
    $details = New-Object System.Collections.Generic.List[string]
    $dg = $null
    try { $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop } catch {
        return (New-ProbeResult -Id 'DMAPOSTURE' -Name 'Posture de protection DMA (VBS/IOMMU)' -Status 'NA' -Severity 0 -Summary "Posture DMA/VBS non lisible (DeviceGuard indisponible)" -Details @($_.Exception.Message.Split([char]10)[0]))
    }
    $vbs = 0; try { $vbs = [int]$dg.VirtualizationBasedSecurityStatus } catch { }
    $avail = @(); try { $avail = @($dg.AvailableSecurityProperties) } catch { }
    $dmaAvail = ($avail -contains 3)   # 3 = DMA Protection (mapping AvailableSecurityProperties)
    $details.Add("VBS status=$vbs (0=off,1=configure,2=running) ; proprietes securite dispo=$($avail -join ',') (3=protection DMA).")
    $details.Add("Note : l'etat exact de Kernel DMA Protection n'est pas expose proprement en user-mode ; on rapporte la posture VBS + disponibilite DMA. Toujours INFO (jamais une accusation).")
    $sum = Get-DmaPostureSummary -VbsStatus $vbs -DmaProtectionAvailable $dmaAvail
    New-ProbeResult -Id 'DMAPOSTURE' -Name 'Posture de protection DMA (VBS/IOMMU)' -Status 'INFO' -Severity 0 -Summary $sum -Details $details
}

# Horodatage de derniere ecriture d'une cle HKLM (RegQueryInfoKey). .NET ne l'expose pas. Lecture
# seule, sans admin. Sert a dater la reecriture de MachineGuid (cible n°1 des spoofers HWID).
$script:RegKeyTimeCSharp = @'
using System; using System.Runtime.InteropServices;
public static class DexRegKeyTime {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern int RegOpenKeyEx(UIntPtr hKey, string sub, int opts, int sam, out UIntPtr phk);
  [DllImport("advapi32.dll", SetLastError=true)] static extern int RegQueryInfoKey(UIntPtr hKey, IntPtr cls, IntPtr clsLen, IntPtr res, out uint subKeys, out uint maxSubLen, out uint maxClsLen, out uint values, out uint maxValNameLen, out uint maxValLen, out uint secDesc, out long lastWrite);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(UIntPtr hKey);
  public static DateTime LastWriteHKLM(string sub) {
    UIntPtr HKLM = new UIntPtr(0x80000002u); UIntPtr h;
    int rc = RegOpenKeyEx(HKLM, sub, 0, 0x20019 | 0x0100, out h);   // KEY_READ | KEY_WOW64_64KEY
    if (rc != 0) throw new System.ComponentModel.Win32Exception(rc);
    try { uint a,b,c,d,e,f,g; long ft;
      rc = RegQueryInfoKey(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out a, out b, out c, out d, out e, out f, out g, out ft);
      if (rc != 0) throw new System.ComponentModel.Win32Exception(rc);
      return DateTime.FromFileTime(ft);
    } finally { RegCloseKey(h); }
  }
}
'@

function Get-HwidAssessment {
    # PUR/testable. Un spoofer HWID (contournement de ban) reecrit ce que Windows PRESENTE : serials
    # SMBIOS (via WMI), MAC, MachineGuid. Il oublie souvent la COPIE que le systeme garde ailleurs :
    #  - HKLM\HARDWARE\DESCRIPTION\System\BIOS est rempli par le noyau AU BOOT depuis les tables SMBIOS ;
    #    si WMI dit autre chose => quelqu'un a patche l'un des deux depuis. On ne compare que les
    #    paires ou les DEUX cotes sont non vides (mesure 14/09 : sur un MSI propre, le registre a des
    #    serials VIDES alors que WMI les a -> comparer du vide accuserait un innocent).
    #  - PermanentAddress (MAC gravee dans la NIC) vs MacAddress (courante) : ecart = MAC forcee.
    #    Wi-Fi => INFO seulement (Windows propose 'adresses materielles aleatoires', legitime) ;
    #    Ethernet => WARN. Une valeur 'NetworkAddress' dans la cle du driver = forcage explicite => WARN.
    #  - MachineGuid : ecrit a l'install. Cle reecrite >1 j APRES l'InstallDate => WARN (mesure 14/09 :
    #    sur ce PC la cle est ecrite 1 min AVANT l'InstallDate, donc un PC propre passe).
    # $SmbiosPairs = @{ Name; Wmi; Reg } ; $Nics = @{ Name; Mac; Permanent; Wifi } ; $RegOverrides = 'desc=MAC'.
    param($SmbiosPairs, $Nics, [string[]]$RegOverrides, $GuidKeyTime, $InstallDate)
    $warn = New-Object System.Collections.Generic.List[string]
    $info = New-Object System.Collections.Generic.List[string]
    $norm = { param($s) if ($null -eq $s) { '' } else { ([string]$s -replace '[\x00\s\-:]', '').ToUpperInvariant() } }
    # PAS de @() autour des parametres : @(List[object]) leve 'Les types des arguments ne correspondent pas'
    # sous StrictMode (mesure 14/09) ; foreach sur $null itere zero fois, c'est suffisant.
    foreach ($p in $SmbiosPairs) {
        if ($null -eq $p) { continue }
        $w = & $norm $p.Wmi; $r = & $norm $p.Reg
        if ($w.Length -eq 0 -or $r.Length -eq 0) { continue }
        if ($w -ne $r) { $warn.Add(("SMBIOS {0} : WMI='{1}' vs registre (lu au boot)='{2}' - identite patchee apres le boot ?" -f $p.Name, $p.Wmi, $p.Reg)) }
    }
    foreach ($n in $Nics) {
        if ($null -eq $n) { continue }
        $m = & $norm $n.Mac; $pm = & $norm $n.Permanent
        if ($m.Length -eq 0 -or $pm.Length -eq 0 -or $m -eq $pm) { continue }
        $line = ("MAC {0} : courante {1} != gravee {2}" -f $n.Name, $n.Mac, $n.Permanent)
        if ($n.Wifi) { $info.Add($line + " (Wi-Fi : 'adresse aleatoire' Windows possible - informatif)") } else { $warn.Add($line + " (Ethernet : MAC forcee)") }
    }
    foreach ($o in $RegOverrides) { if (-not [string]::IsNullOrWhiteSpace($o)) { $warn.Add("MAC forcee dans le registre (NetworkAddress) : $o") } }
    if ($null -ne $GuidKeyTime -and $null -ne $InstallDate) {
        $gt = [datetime]$GuidKeyTime; $it = [datetime]$InstallDate
        if ($gt -gt $it.AddDays(1)) { $warn.Add(("MachineGuid : cle reecrite le {0}, soit {1} j APRES l'installation de Windows ({2}) - cible classique d'un spoofer" -f $gt, [int]($gt - $it).TotalDays, $it)) }
    }
    if ($warn.Count -gt 0) { return @{ Status='WARN'; Severity=1; Summary="$($warn.Count) ecart(s) d'identite materielle (spoof HWID possible) - a faire expliquer"; Lines=@($warn + $info) } }
    if ($info.Count -gt 0) { return @{ Status='INFO'; Severity=0; Summary="Identite materielle coherente ; $($info.Count) ecart(s) Wi-Fi explicable(s) (adresse aleatoire)"; Lines=@($info) } }
    return @{ Status='OK'; Severity=0; Summary='Identite materielle coherente (SMBIOS, MAC, MachineGuid)'; Lines=@() }
}

function Probe-Hwid {
    $details = New-Object System.Collections.Generic.List[string]
    $pairs = New-Object System.Collections.Generic.List[object]
    $nics  = New-Object System.Collections.Generic.List[object]
    $ovr   = New-Object System.Collections.Generic.List[string]
    $readSomething = $false
    try {
        $bios = Get-CimInstance Win32_BIOS -ErrorAction Stop
        $bb   = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
        $cs   = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $reg  = Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS' -ErrorAction Stop
        $rv = { param($n) $p = $reg.PSObject.Properties[$n]; if ($p) { [string]$p.Value } else { '' } }
        $pairs.Add(@{ Name='serial systeme';       Wmi=[string]$bios.SerialNumber;      Reg=(& $rv 'SystemSerialNumber') })
        $pairs.Add(@{ Name='version BIOS';         Wmi=[string]$bios.SMBIOSBIOSVersion; Reg=(& $rv 'BIOSVersion') })
        if ($bb) { $pairs.Add(@{ Name='serial carte mere'; Wmi=[string]$bb.SerialNumber; Reg=(& $rv 'BaseBoardSerialNumber') })
                   $pairs.Add(@{ Name='modele carte mere'; Wmi=[string]$bb.Product;      Reg=(& $rv 'BaseBoardProduct') })
                   $pairs.Add(@{ Name='fabricant carte mere'; Wmi=[string]$bb.Manufacturer; Reg=(& $rv 'BaseBoardManufacturer') }) }
        if ($cs) { $pairs.Add(@{ Name='fabricant systeme'; Wmi=[string]$cs.Manufacturer; Reg=(& $rv 'SystemManufacturer') })
                   $pairs.Add(@{ Name='modele systeme';    Wmi=[string]$cs.Model;        Reg=(& $rv 'SystemProductName') }) }
        $readSomething = $true
        $details.Add("SMBIOS : $($pairs.Count) paires WMI/registre comparees (serials, modele, fabricant, version BIOS). Serial systeme WMI='$($bios.SerialNumber)'.")
    } catch { $details.Add("SMBIOS non comparable : $($_.Exception.Message.Split([char]10)[0])") }
    try {
        foreach ($a in @(Get-NetAdapter -Physical -ErrorAction Stop)) {
            $pm = ''; try { $pm = [string]$a.PermanentAddress } catch { }
            $med = ''; try { $med = [string]$a.PhysicalMediaType } catch { }
            $nics.Add(@{ Name=[string]$a.Name; Mac=[string]$a.MacAddress; Permanent=$pm; Wifi=($med -match '802\.11') })
        }
        $readSomething = $true
        $details.Add("Cartes reseau physiques : $($nics.Count) (MAC courante vs MAC gravee).")
    } catch { $details.Add("Cartes reseau non lues : $($_.Exception.Message.Split([char]10)[0])") }
    try {
        $cls = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
        foreach ($k in @(Get-ChildItem $cls -ErrorAction Stop)) {
            $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
            if ($null -eq $p) { continue }
            $na = $p.PSObject.Properties['NetworkAddress']
            if ($na -and -not [string]::IsNullOrWhiteSpace([string]$na.Value)) {
                $dd = $p.PSObject.Properties['DriverDesc']; $desc = if ($dd) { [string]$dd.Value } else { $k.PSChildName }
                $ovr.Add("$desc = $($na.Value)")
            }
        }
    } catch { }
    $guidTime = $null; $install = $null
    try {
        if (-not ('DexRegKeyTime' -as [type])) { Add-Type -TypeDefinition $script:RegKeyTimeCSharp -ErrorAction Stop }
        $guidTime = [DexRegKeyTime]::LastWriteHKLM('SOFTWARE\Microsoft\Cryptography')
        $install  = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).InstallDate
        $details.Add("MachineGuid : cle ecrite le $guidTime ; Windows installe le $install.")
    } catch { $details.Add("MachineGuid : horodatage non lu ($($_.Exception.Message.Split([char]10)[0]))") }
    if (-not $readSomething) {
        return (New-ProbeResult -Id 'HWID' -Name 'Identite materielle (HWID / spoof)' -Status 'NA' -Severity 0 -Summary "SMBIOS et cartes reseau illisibles" -Details $details)
    }
    $details.Add("Limite : un spoofer qui patche de facon coherente WMI ET le registre (ou flashe le BIOS) passe ; un ecart est un point a faire expliquer, jamais un ban.")
    $a = Get-HwidAssessment -SmbiosPairs $pairs -Nics $nics -RegOverrides $ovr -GuidKeyTime $guidTime -InstallDate $install
    foreach ($l in $a.Lines) { $details.Add("  $l") }
    New-ProbeResult -Id 'HWID' -Name 'Identite materielle (HWID / spoof)' -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
}

function Get-SystemSecurityAssessment {
    # Logique PURE testable. `testsigning ON` = drivers non signes autorises = le levier
    # classique du BYOVD et des cartes DMA : c'est un FLAG severite 3. Il se lit avec
    # bcdedit, QUI EXIGE L'ADMIN. Sans elevation la sonde ecrivait bien "non verifie" dans
    # les details -- mais son RESUME affirmait quand meme "Pas de mode test / signature
    # contournee". Le detail etait honnete, le titre mentait ; c'est le titre que lit un modo.
    param([int]$FlagCount, [bool]$BcdChecked = $true, [bool]$SecureBootKnown = $true)
    if ($FlagCount -gt 0) { return @{ Status='FLAG'; Severity=3 } }
    if (-not $BcdChecked) {
        return @{ Status='NA'; Severity=0; Summary="testsigning / nointegritychecks NON verifies (bcdedit exige l'admin) : le contournement de signature n'a pas ete controle" }
    }
    if (-not $SecureBootKnown) {
        return @{ Status='OK'; Severity=0; Summary="Pas de mode test / signature contournee (Secure Boot non lisible : BIOS legacy ou non applicable)" }
    }
    @{ Status='OK'; Severity=0; Summary="Pas de mode test / signature contournee (bcdedit et Secure Boot lus)" }
}

function Probe-SystemSecurity {
    $details = New-Object System.Collections.Generic.List[string]
    $status='OK'; $sev=0; $flags = New-Object System.Collections.Generic.List[string]
    $bcdChecked = $false; $sbKnown = $false
    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        $details.Add("Secure Boot : $sb")
        $sbKnown = $true
        if (-not $sb) { $details.Add("  (desactive - a noter)") }
    } catch { $details.Add("Secure Boot : non applicable (BIOS legacy ou non lisible)") }
    # bcdedit testsigning / nointegritychecks
    if (Test-Admin) {
        try {
            $bcd = & cmd /c "bcdedit /enum {current} 2>&1" | Out-String
            # on FLAG seulement sur une valeur AFFIRMATIVE connue (multi-locale), jamais sur
            # l'inconnu -> evite un faux ROUGE sur Windows de/nl/es/it ou le mot "Non" differe.
            if ($bcd -match '(?im)^\s*testsigning\s+(yes|oui|ja|si|sim|on)\b') { $flags.Add("testsigning ON (drivers non signes autorises)") }
            if ($bcd -match '(?im)^\s*nointegritychecks\s+(yes|oui|ja|si|sim|on)\b') { $flags.Add("nointegritychecks ON") }
            $details.Add("bcdedit testsigning/nointegritychecks inspectes.")
            $bcdChecked = $true
        } catch { $details.Add("bcdedit illisible.") }
    } else {
        $details.Add("bcdedit : admin requis (non verifie).")
    }
    # TPM
    try {
        $tpm = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        if ($null -ne $tpm) { $details.Add("TPM present : IsEnabled=$($tpm.IsEnabled_InitialValue)") } else { $details.Add("TPM : non detecte") }
    } catch { }
    $a = Get-SystemSecurityAssessment -FlagCount $flags.Count -BcdChecked $bcdChecked -SecureBootKnown $sbKnown
    if ($flags.Count -gt 0) {
        foreach($f in $flags){ $details.Add("  FLAG: $f") }
        New-ProbeResult -Id 'SECBOOT' -Name 'Securite systeme' -Status $a.Status -Severity $a.Severity -Summary ($flags -join ' ; ') -Details $details
    } else {
        New-ProbeResult -Id 'SECBOOT' -Name 'Securite systeme' -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
    }
}

function Test-LocalAddress {
    # vrai si l'IP est loopback / LAN / lien-local / multicast (= pas une connexion Internet sortante).
    # Pur -> testable. Couvre IPv4 prive (RFC1918) + IPv6 fe80::/ff.. + 0.0.0.0/::.
    param([string]$ip)
    if ([string]::IsNullOrWhiteSpace($ip)) { return $true }
    $ip = $ip.Trim([char[]]@('[',']'))
    if ($ip -in @('127.0.0.1','::1','0.0.0.0','::')) { return $true }
    if ($ip -like '127.*' -or $ip -like '10.*' -or $ip -like '192.168.*' -or $ip -like '169.254.*') { return $true }
    if ($ip -like 'fe80:*' -or $ip -like 'ff*') { return $true }   # IPv6 lien-local / multicast
    if ($ip -match '^172\.(\d{1,3})\.') { $o=[int]$Matches[1]; if ($o -ge 16 -and $o -le 31) { return $true } }
    return $false
}

function Get-ActiveConnections {
    # Connexions TCP etablies vers l'exterieur + process proprietaire (nom+chemin).
    # Get-NetTCPConnection (Win8+) ; repli netstat -ano. Dedupe sur remote+pid.
    $conns = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $add = {
        param($ra,$rp,$procId)
        if (Test-LocalAddress $ra) { return }
        $key = "$ra`:$rp/$procId"
        if ($seen.ContainsKey($key)) { return }
        $seen[$key] = $true
        $pname=''; $ppath=''
        try { $p = Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue; if ($p) { $pname=$p.Name; try { $ppath=$p.Path } catch { } } } catch { }
        $conns.Add([pscustomobject]@{ Remote=$ra; Port=$rp; Pid=$procId; PName=$pname; PPath=$ppath })
    }
    try {
        foreach($c in @(Get-NetTCPConnection -State Established -ErrorAction Stop)){
            & $add "$($c.RemoteAddress)" $c.RemotePort $c.OwningProcess
        }
        return $conns
    } catch { }
    try {
        foreach($ln in (& netstat -ano 2>$null)){
            if ($ln -notmatch 'ESTABLISHED') { continue }
            $parts = @($ln -split '\s+' | Where-Object { $_ -ne '' })
            if ($parts.Count -lt 5 -or $parts[0] -notmatch '^TCP') { continue }
            $remote = $parts[2]
            $ra = ($remote -replace ':\d+$','') -replace '[\[\]]',''
            $rp = if ($remote -match ':(\d+)$') { $Matches[1] } else { '' }
            & $add $ra $rp $parts[4]
        }
    } catch { }
    return $conns
}

function Probe-Network {
    # Snapshot des connexions sortantes actives + process qui parle. Additif vs 'Cheats connus'
    # (qui ne regarde que les noms de process a froid) : ici on capte le process CONNECTE maintenant,
    # via nom ET chemin, contre la meme table de providers.
    # Pas de reverse-DNS ni de resolution domaine-cheat->IP (lent + faux positifs CDN/Cloudflare).
    # Upgrade possible : PTR borne + skip des plages CDN connues.
    $details = New-Object System.Collections.Generic.List[string]
    $conns = Get-ActiveConnections
    if ($conns.Count -eq 0) {
        return New-ProbeResult -Id 'NET' -Name 'Connexions reseau live' -Status 'INFO' -Severity 0 -Summary "Aucune connexion sortante etablie (ou enumeration indispo)" -Details @("Get-NetTCPConnection / netstat n'ont retourne aucune connexion externe.")
    }
    $hits = New-Object System.Collections.Generic.List[string]
    foreach($cn in $conns){
        $hay = "$($cn.PName) $($cn.PPath)"
        foreach($c in $script:CheatSoftware){
            if (Test-AnyPattern $hay $c.Patterns) { $hits.Add("$($c.Name) : process '$($cn.PName)' (PID $($cn.Pid)) -> $($cn.Remote):$($cn.Port)"); break }
        }
    }
    $details.Add("Connexions sortantes etablies (hors LAN/loopback) : $($conns.Count). Verif = nom+chemin du process contre $($script:CheatSoftware.Count) providers connus.")
    foreach($cn in @($conns | Select-Object -First 40)){
        $details.Add(("  {0}:{1}  <-  {2} (PID {3})" -f $cn.Remote, $cn.Port, $(if($cn.PName){$cn.PName}else{'?'}), $cn.Pid))
    }
    if ($conns.Count -gt 40) { $details.Add("  ... (+$($conns.Count - 40) autres, tronque)") }
    if ($hits.Count -gt 0) {
        foreach($h in $hits){ $details.Add("  HIT: $h") }
        return New-ProbeResult -Id 'NET' -Name 'Connexions reseau live' -Status 'FLAG' -Severity 3 -Summary "Process cheat connu connecte en direct : $($hits.Count)" -Details $details
    }
    New-ProbeResult -Id 'NET' -Name 'Connexions reseau live' -Status 'INFO' -Severity 0 -Summary "$($conns.Count) connexion(s) sortante(s), 0 process cheat connu" -Details $details
}

function Select-UserProfileDirs {
    # PUR/testable. Dossiers de profil a lire : le compte courant D'ABORD, puis les autres comptes
    # Windows. Mesure 17/09 : 3 profils sur le PC d'Alex. Sans ca, un joueur qui triche depuis un
    # 2e compte passait sous les sondes fichier en silence. Profils speciaux (services) et profils
    # systeme (hors \Users\) ecartes ; doublons ignores sans tenir compte de la casse.
    param($Profiles, [string]$Current)
    $out = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($Current)) { $out.Add($Current.TrimEnd('\')) }
    foreach ($p in @($Profiles)) {
        if ($null -eq $p) { continue }
        if ($p.Special) { continue }
        $lp = [string]$p.LocalPath
        if ([string]::IsNullOrWhiteSpace($lp)) { continue }
        if ($lp -notmatch '(?i)^[a-z]:\\users\\[^\\]+\\?$') { continue }
        $lp = $lp.TrimEnd('\')
        if (-not ($out | Where-Object { $_ -ieq $lp })) { $out.Add($lp) }
    }
    return @($out)
}

function Select-UserHiveRoots {
    # PUR/testable. Ruches de registre UTILISATEUR a lire : HKCU d'abord, puis la ruche de chaque AUTRE
    # compte CONNECTE (HKEY_USERS\<SID> et <SID>_Classes, deja chargees par Windows : rien a charger).
    # Un compte deconnecte n'a pas sa ruche chargee : la lire exigerait `reg load` (une ecriture), que le
    # check ne fait jamais. Ces comptes sont rendus dans Unread pour que le rapport le DISE.
    param([string[]]$LoadedSids, [string]$CurrentSid, $Profiles)
    $roots = New-Object System.Collections.Generic.List[object]
    $roots.Add([pscustomobject]@{ Sid=$CurrentSid; User='HKCU:'; Classes='HKCU:\Software\Classes' })
    $loaded = @{}
    foreach ($s in @($LoadedSids)) {
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        if ($s -notmatch '^S-1-5-21-[\d-]+$') { continue }   # comptes locaux/domaine ; ecarte _Classes, SYSTEM, services
        $loaded[$s] = $true
        if ($s -eq $CurrentSid) { continue }
        $roots.Add([pscustomobject]@{ Sid=$s; User="Registry::HKEY_USERS\$s"; Classes="Registry::HKEY_USERS\${s}_Classes" })
    }
    $unread = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($Profiles)) {
        if ($null -eq $p -or $p.Special) { continue }
        $sid = [string]$p.Sid; $lp = [string]$p.LocalPath
        if ($sid -eq $CurrentSid -or $loaded.ContainsKey($sid)) { continue }
        if ($lp -notmatch '(?i)^[a-z]:\\users\\[^\\]+\\?$') { continue }
        $unread.Add($lp.TrimEnd('\'))
    }
    # ToArray() : sous PowerShell 5.1, @(<List generique>) dans un litteral d'objet leve « types des arguments ».
    return [pscustomobject]@{ Roots = $roots.ToArray(); Unread = $unread.ToArray() }
}

function Get-UserHiveRoots {
    $cur = ''
    try { $cur = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }
    $loaded = @()
    try { $loaded = @(Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop | ForEach-Object { $_.PSChildName }) } catch { }
    $profiles = @()
    try { $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Sid=$_.SID; LocalPath=$_.LocalPath; Special=[bool]$_.Special } }) } catch { }
    return (Select-UserHiveRoots -LoadedSids $loaded -CurrentSid $cur -Profiles $profiles)
}

function Get-UserProfileDirs {
    # Les profils qui existent sur le disque. Les autres comptes ne sont lisibles qu'en admin ; sans
    # admin, leurs fichiers sont simplement absents des resultats (chaque sonde le dit).
    $profiles = @()
    try { $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ LocalPath = $_.LocalPath; Special = [bool]$_.Special } }) } catch { }
    return @(Select-UserProfileDirs -Profiles $profiles -Current $env:USERPROFILE | Where-Object { Test-Path -LiteralPath $_ })
}

function Get-UserFolderRoots {
    # Bureau / Documents / Telechargements de l'utilisateur : chemins historiques ET emplacements
    # REELS. Avec OneDrive (sauvegarde des dossiers), le vrai Bureau est OneDrive\Bureau et
    # %USERPROFILE%\Desktop reste un dossier residuel : mesure 17/09, 8 fichiers lus contre 33 reels.
    # Parametres injectables pour les tests ; par defaut, on interroge Windows.
    param(
        [string]$ProfileDir = $env:USERPROFILE,
        [string]$Desktop    = [Environment]::GetFolderPath('Desktop'),
        [string]$Documents  = [Environment]::GetFolderPath('MyDocuments'),
        [string]$Downloads  = $(try { [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}') } catch { '' })
    )
    $out = New-Object System.Collections.Generic.List[string]
    $cands = @()
    if ($ProfileDir) { $cands += (Join-Path $ProfileDir 'Downloads'), (Join-Path $ProfileDir 'Desktop'), (Join-Path $ProfileDir 'Documents') }
    $cands += $Downloads, $Desktop, $Documents
    foreach ($c in $cands) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $n = $c.TrimEnd('\')
        if (-not ($out | Where-Object { $_ -ieq $n })) { $out.Add($n) }
    }
    # Tableau deroule (pas ,$out) : les appelants font @(Get-UserFolderRoots) et iterent les chemins.
    return $out.ToArray()
}

function Probe-KnownCheats {
    $details = New-Object System.Collections.Generic.List[string]
    $hits = New-Object System.Collections.Generic.List[string]
    $names = Get-UninstallEntries
    $procNames = @()
    try { $procNames = (Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) } catch { }
    # dossiers/installeurs sur quelques racines, profondeur bornee
    $roots = @(@($env:USERPROFILE) + @(Get-UserFolderRoots) + @($env:LOCALAPPDATA, $env:ProgramData))
    # Les autres comptes Windows : racine du profil, Bureau / Documents / Telechargements, AppData\Local.
    foreach ($pd in @(Get-UserProfileDirs)) {
        $roots += $pd
        $roots += @(Get-UserFolderRoots -ProfileDir $pd -Desktop '' -Documents '' -Downloads '')
        $roots += (Join-Path $pd 'AppData\Local')
    }
    $roots = @($roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object { $_.ToLowerInvariant() } -Unique)
    $folderNames = New-Object System.Collections.Generic.List[string]
    foreach($r in $roots){
        try { Get-ChildItem $r -Directory -ErrorAction SilentlyContinue | Select-Object -First 400 | ForEach-Object { $folderNames.Add($_.Name) } } catch { }
    }
    foreach($c in $script:CheatSoftware){
        $found = $false
        # nom (sauf generic) sur process + dossiers
        if (-not $c.GenericName) {
            foreach($pn in $procNames){ if (Test-AnyPattern $pn $c.Patterns) { $hits.Add("$($c.Name) : process '$pn'"); $found=$true; break } }
            if (-not $found){ foreach($fn in $folderNames){ if (Test-AnyPattern $fn $c.Patterns) { $hits.Add("$($c.Name) : dossier '$fn'"); $found=$true; break } } }
        }
        # installe (DisplayName)
        if (-not $found){ foreach($n in $names){ if (Test-AnyPattern $n $c.Patterns) { $hits.Add("$($c.Name) : installe '$n'"); $found=$true; break } } }
    }
    $details.Add("Providers verifies : $($script:CheatSoftware.Count) (process/dossiers/installes ; domaines = sonde Navigateurs).")
    if ($hits.Count -gt 0) {
        foreach($h in $hits){ $details.Add("  HIT: $h") }
        New-ProbeResult -Id 'CHEATS' -Name 'Cheats logiciels connus' -Status 'FLAG' -Severity 3 -Summary "Cheat connu detecte : $($hits.Count)" -Details $details
    } else {
        New-ProbeResult -Id 'CHEATS' -Name 'Cheats logiciels connus' -Status 'OK' -Severity 0 -Summary "Aucun provider connu (hors historique nav.)" -Details $details
    }
}

function Probe-InputManipulation {
    $details = New-Object System.Collections.Generic.List[string]
    $hits = New-Object System.Collections.Generic.List[object]
    $names = Get-UninstallEntries
    $devs = @()
    try { $devs = @(Get-PnpDevice -ErrorAction SilentlyContinue | Select-Object FriendlyName, InstanceId) } catch { }
    $drivers = @()
    try { $drivers = (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) } catch { }
    foreach($t in $script:InputTools){
        $reason = $null; $sev = $t.Severity
        foreach($n in $names){ if (Test-AnyPattern $n $t.App) { $reason="app '$n'"; break } }
        if (-not $reason -and $t.Usb.Count -gt 0){ foreach($dv in $devs){ $hay = ('{0} {1}' -f $dv.FriendlyName, $dv.InstanceId); if (Test-AnyWord $hay $t.Usb) { $reason="device '$($dv.FriendlyName)'"; break } } }
        if (-not $reason -and $t.Driver.Count -gt 0){ foreach($dr in $drivers){ if (Test-AnyPattern $dr $t.Driver) { $reason="driver '$dr'"; break } } }
        if ($reason){ $hits.Add([pscustomobject]@{ Name=$t.Name; Reason=$reason; Sev=$sev }) }
    }
    $details.Add("Outils d'input verifies : $($script:InputTools.Count) (app/driver/USB). Dual-use : presence = a verifier, escalade si hardware/anti-recoil.")
    $details.Add("Detection USB par description (FriendlyName + InstanceId). VID/PID specifiques non codes en dur (non confirmes par source fiable au build) : le match par nom couvre Cronus/XIM/Titan.")
    if ($hits.Count -gt 0) {
        $maxSev = ($hits | Measure-Object -Property Sev -Maximum).Maximum
        $status = if ($maxSev -ge 2) { 'FLAG' } elseif ($maxSev -ge 1) { 'WARN' } else { 'OK' }
        foreach($h in $hits){ $details.Add("  $($h.Name) : $($h.Reason)  [sev $($h.Sev)]") }
        $sum = if ($maxSev -ge 1) { "$($hits.Count) outil(s) d'input a verifier" } else { "$($hits.Count) suite(s) gaming courante(s) (info)" }
        New-ProbeResult -Id 'INPUT' -Name 'Manipulation input / anti-recoil' -Status $status -Severity $maxSev -Summary $sum -Details $details
    } else {
        New-ProbeResult -Id 'INPUT' -Name 'Manipulation input / anti-recoil' -Status 'OK' -Severity 0 -Summary "Aucun outil d'input/anti-recoil connu" -Details $details
    }
}

function Get-UsbHistoryHits {
    # Pur -> testable. Recoit les descriptions de devices USB DEJA branches (historique registre,
    # meme debranches) et rend les hits contre les tokens USB de $script:InputTools (word-boundary,
    # meme semantique que la sonde INPUT live). Un descripteur USB vient du FIRMWARE du device, pas
    # d'un nom de fichier renommable : c'est la trace materielle d'un branchement physique passe.
    # Complete INPUT qui ne voit que ce qui est branche a l'instant T (un Cronus debranche 5 min
    # avant le check passait au travers).
    param([string[]]$Descs, $Tools)
    $hits = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Descs) { return ,$hits }
    foreach ($t in $Tools) {
        if ($t.Usb.Count -eq 0) { continue }
        foreach ($d in $Descs) {
            if (Test-AnyWord ([string]$d) $t.Usb) {
                $hits.Add([pscustomobject]@{ Name=$t.Name; Desc=[string]$d; Sev=$t.Severity }); break
            }
        }
    }
    return ,$hits
}

function Probe-UsbHistory {
    $details = New-Object System.Collections.Generic.List[string]
    $descs = New-Object System.Collections.Generic.List[string]
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
    $read = $false
    try {
        foreach ($vid in (Get-ChildItem $root -ErrorAction Stop)) {
            foreach ($inst in (Get-ChildItem $vid.PSPath -ErrorAction SilentlyContinue)) {
                $read = $true
                $p = Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue
                # DeviceDesc/FriendlyName = descripteur firmware (nom produit en clair, ex "Cronus").
                # Acces via PSObject.Properties[] : sous StrictMode, un .Prop absent (ou $p $null)
                # jetterait et ferait tomber TOUTE la sonde en NA - beaucoup de cles USB n'ont pas FriendlyName.
                $fn = ''; $dd = ''
                if ($p) {
                    $fnp = $p.PSObject.Properties['FriendlyName']; if ($fnp) { $fn = [string]$fnp.Value }
                    $ddp = $p.PSObject.Properties['DeviceDesc'];   if ($ddp) { $dd = [string]$ddp.Value }
                }
                $hay = (('{0} {1}' -f $fn, $dd)).Trim()
                if ($hay) { $descs.Add($hay) }
            }
        }
    } catch {
        return (New-ProbeResult -Id 'USBHIST' -Name 'Historique USB (devices debranches)' -Status 'NA' -Severity 0 -Summary "Enum USB non lisible ($($_.Exception.Message.Split([char]10)[0]))" -Details $details)
    }
    if (-not $read) {
        return (New-ProbeResult -Id 'USBHIST' -Name 'Historique USB (devices debranches)' -Status 'NA' -Severity 0 -Summary "Aucune entree USB historique lisible" -Details $details)
    }
    # ponytail: date de branchement (LastArrivalDate, sous-cle Properties/GUID) non lue - marginale
    # (le modo fait de toute facon expliquer le device) ; a ajouter si un jour on veut trier par fraicheur.
    $details.Add("$($descs.Count) device(s) USB deja branche(s) sur cette machine (historique registre, y compris debranches).")
    $hits = Get-UsbHistoryHits -Descs $descs -Tools $script:InputTools
    if ($hits.Count -gt 0) {
        $maxSev = ($hits | Measure-Object -Property Sev -Maximum).Maximum
        $status = if ($maxSev -ge 2) { 'FLAG' } else { 'WARN' }
        foreach ($h in $hits) { $details.Add("  $($h.Name) : '$($h.Desc)'  [sev $($h.Sev)]") }
        $sum = "$($hits.Count) device(s) d'input/anti-recoil dans l'historique USB (a pu etre debranche avant le check)"
        New-ProbeResult -Id 'USBHIST' -Name 'Historique USB (devices debranches)' -Status $status -Severity $maxSev -Summary $sum -Details $details
    } else {
        New-ProbeResult -Id 'USBHIST' -Name 'Historique USB (devices debranches)' -Status 'OK' -Severity 0 -Summary "Aucun boitier Cronus/XIM/kmbox dans l'historique USB" -Details $details
    }
}

function Test-IsGpcScript {
    # Pur -> testable. Vrai si le CONTENU ressemble a un script GPC (langage des boitiers Cronus
    # Zen/Max, ou s'ecrivent les macros anti-recoil). On sniffe les mots-cles du langage, PAS juste
    # l'extension .gpc : une collision d'extension ne doit pas FLAG (loi "prouver pas nommer").
    # event_press/event_release sont quasi exclusifs a GPC ; sinon on exige >=2 marqueurs.
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    $exclusive = @('event_press','event_release','get_ptime','set_rumble')
    foreach ($m in $exclusive) { if ($Text.IndexOf($m,[System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true } }
    $markers = @('set_val','get_val','combo','remap','get_lval','block')
    $n = 0
    foreach ($m in $markers) { if ($Text.IndexOf($m,[System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $n++ } }
    return ($n -ge 2)
}

function Probe-GpcScripts {
    $details = New-Object System.Collections.Generic.List[string]
    $confirmed = New-Object System.Collections.Generic.List[string]
    $extOnly = New-Object System.Collections.Generic.List[string]
    # Zones utilisateur usuelles seulement (pas tout le disque : couteux + le .gpc arrive par download).
    $roots = @(@(Get-UserFolderRoots) + @($env:TEMP)) | Select-Object -Unique
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        try {
            foreach ($f in (Get-ChildItem -LiteralPath $r -Recurse -File -Filter *.gpc -Force -ErrorAction SilentlyContinue)) {
                $txt = ''
                try { $txt = (Get-Content -LiteralPath $f.FullName -TotalCount 500 -ErrorAction SilentlyContinue) -join "`n" } catch { }
                if (Test-IsGpcScript $txt) { $confirmed.Add($f.FullName) } else { $extOnly.Add($f.FullName) }
            }
        } catch { }
    }
    $details.Add("Recherche de scripts GPC (macros Cronus) dans Downloads/Desktop/Documents/Temp - contenu sniffe, pas juste l'extension.")
    if ($confirmed.Count -gt 0) {
        foreach ($x in $confirmed) { $details.Add("SCRIPT GPC CONFIRME (contenu) : $x") }
        New-ProbeResult -Id 'GPC' -Name 'Scripts anti-recoil Cronus (.gpc)' -Status 'FLAG' -Severity 2 -Summary "$($confirmed.Count) script(s) GPC (macro anti-recoil Cronus) confirme(s) par le contenu" -Details $details
    } elseif ($extOnly.Count -gt 0) {
        foreach ($x in $extOnly) { $details.Add("Fichier .gpc SANS contenu GPC reconnu (collision d'extension possible) : $x") }
        New-ProbeResult -Id 'GPC' -Name 'Scripts anti-recoil Cronus (.gpc)' -Status 'WARN' -Severity 1 -Summary "$($extOnly.Count) fichier(s) .gpc sans contenu GPC confirme - a verifier" -Details $details
    } else {
        New-ProbeResult -Id 'GPC' -Name 'Scripts anti-recoil Cronus (.gpc)' -Status 'OK' -Severity 0 -Summary "Aucun script GPC (Cronus) dans les zones utilisateur" -Details $details
    }
}

function Get-WerCrashHits {
    # Pur -> testable. Recoit des noms d'app issus des rapports d'erreur Windows (WER). Le nom du
    # binaire est ecrit AU MOMENT DU CRASH => il survit a la suppression du binaire (source
    # d'execution anti-wipe de plus). Meme classement 2 niveaux que les autres sondes : nom
    # distinctif => FLAG, mot de categorie/generique => WARN.
    param([string[]]$Names, [string[]]$FlagPatterns, [string[]]$WarnPatterns)
    $flag = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Names) { return @{ Flag=$flag; Warn=$warn } }
    foreach ($n in $Names) {
        $s = [string]$n
        if ([string]::IsNullOrEmpty($s)) { continue }
        if (Test-AnyWord $s $FlagPatterns) { $flag.Add($s) }
        elseif (Test-AnyWord $s $WarnPatterns) { $warn.Add($s) }
    }
    return @{ Flag=$flag; Warn=$warn }
}

function Get-WerAssessment {
    # Logique PURE testable. WER est une preuve ANTI-WIPE : le nom du binaire qui a plante
    # survit a la suppression du binaire. Deux facons de mentir sans planter :
    #  - 0 rapport lu (dossier absent ou acces refuse) et on annonce "aucun nom suspect" ;
    #  - plafond de scan atteint : on n'a vu qu'une partie et on conclut sur le tout.
    param(
        [int]$FlagCount, [int]$WarnCount, [int]$Scanned,
        [bool]$Capped = $false, [int]$Denied = 0
    )
    if ($FlagCount -gt 0) { return @{ Status='FLAG'; Severity=2; Summary="$FlagCount cheat(s) au nom distinctif ont plante sur cette machine (WER)" } }
    if ($WarnCount -gt 0) { return @{ Status='WARN'; Severity=1; Summary="$WarnCount nom(s) generique(s) dans les crashs WER - a verifier" } }
    if ($Scanned -eq 0) {
        $why = 'dossiers WER absents'
        if ($Denied -gt 0) { $why = "$Denied dossier(s) WER refuse(s) a la lecture" }
        return @{ Status='NA'; Severity=0; Summary="Aucun rapport WER n'a pu etre lu ($why) : cette preuve anti-wipe n'a PAS ete examinee" }
    }
    if ($Denied -gt 0) {
        # Cas REEL mesure sur la machine d'Alex sans admin : l'archive machine
        # (ProgramData\...\WER\ReportArchive + ReportQueue) est refusee, seuls les 2
        # rapports du profil utilisateur sont lus. Conclure "aucun nom suspect" couvrirait
        # une zone jamais ouverte -- justement celle qui garde l'historique le plus long.
        return @{ Status='NA'; Severity=0; Summary="Lecture PARTIELLE : $Scanned rapport(s) lu(s) mais $Denied dossier(s) WER refuse(s) (admin requis) - rien de suspect PARMI CEUX LUS, la zone refusee reste inconnue" }
    }
    if ($Capped) {
        return @{ Status='OK'; Severity=0; Summary="$Scanned crashs WER analyses (PLAFOND ATTEINT : le scan est TRONQUE, d'autres rapports n'ont pas ete lus), aucun nom suspect parmi eux" }
    }
    @{ Status='OK'; Severity=0; Summary="$Scanned crashs WER analyses (dossiers lus en entier), aucun nom suspect" }
}

function Probe-WerCrashes {
    $details = New-Object System.Collections.Generic.List[string]
    $names = New-Object System.Collections.Generic.List[string]
    $roots = @("$env:ProgramData\Microsoft\Windows\WER","$env:LOCALAPPDATA\Microsoft\Windows\WER")
    foreach ($pd in @(Get-UserProfileDirs)) { $roots += (Join-Path $pd 'AppData\Local\Microsoft\Windows\WER') }   # tous les comptes
    $roots = @($roots | Where-Object { $_ } | Sort-Object { $_.ToLowerInvariant() } -Unique)
    $scanned = 0; $cap = 3000; $capped = $false; $denied = 0
    foreach ($r in $roots) {
        foreach ($sub in @('ReportArchive','ReportQueue')) {
            $d = Join-Path $r $sub
            if (-not (Test-Path $d)) { continue }
            try {
                foreach ($rep in (Get-ChildItem -LiteralPath $d -Directory -ErrorAction Stop)) {
                    if ($scanned -ge $cap) { $capped = $true; break }
                    $scanned++
                    $names.Add($rep.Name)   # dossier "AppCrash_<exe>_<hash>_..." => porte le nom du binaire
                    $wer = Join-Path $rep.FullName 'Report.wer'
                    if (Test-Path $wer) {
                        try {
                            foreach ($ln in (Get-Content -LiteralPath $wer -TotalCount 40 -ErrorAction SilentlyContinue)) {
                                if ($ln -match '^(?:AppPath|Sig\[0\]\.Value|TargetAppId)=(.+)$') { $names.Add($Matches[1].Trim()) }
                            }
                        } catch { }
                    }
                }
            } catch { $denied++; $details.Add("Dossier WER non lisible : $d ($($_.Exception.Message.Split([char]10)[0]))") }
        }
    }
    $details.Add("$scanned rapport(s) d'erreur Windows (WER) analyse(s) - le nom du binaire qui a plante survit a sa suppression.")
    if ($capped) { $details.Add("PLAFOND DE SCAN ATTEINT ($cap) : tous les rapports n'ont PAS ete lus. Un 'rien trouve' ne porte que sur ceux-la.") }
    $a = Get-WerCrashHits -Names $names -FlagPatterns (Get-CheatFlagPatterns) -WarnPatterns $script:CheatWarnWords
    $uFlag = @($a.Flag | Select-Object -Unique)
    $uWarn = @($a.Warn | Select-Object -Unique)
    foreach ($x in $uFlag) { $details.Add("CHEAT DISTINCTIF qui a plante (WER) : $x") }
    foreach ($x in $uWarn) { $details.Add("Nom generique/categorie dans un crash (dual-use) : $x") }
    $v = Get-WerAssessment -FlagCount $uFlag.Count -WarnCount $uWarn.Count -Scanned $scanned -Capped $capped -Denied $denied
    New-ProbeResult -Id 'WER' -Name "Rapports d'erreur (WER, anti-wipe)" -Status $v.Status -Severity $v.Severity -Summary $v.Summary -Details $details
}

function ConvertFrom-RecentDocValue {
    # Pur -> testable. La valeur binaire d'une entree RecentDocs commence par le NOM DE FICHIER en
    # UTF-16LE, termine par un double octet nul, suivi d'un PIDL binaire. On extrait juste le nom.
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 2) { return '' }
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i + 1 -lt $Bytes.Length; $i += 2) {
        $code = [int]$Bytes[$i] -bor ([int]$Bytes[$i+1] -shl 8)
        if ($code -eq 0) { break }
        [void]$sb.Append([char]$code)
    }
    return $sb.ToString()
}

function ConvertFrom-MuiCacheName {
    # Pur -> testable. Nom de valeur MuiCache = '<chemin exe>.FriendlyAppName' / '.ApplicationCompany' ;
    # rend le chemin de l'exe, '' pour les valeurs de service (LangID...) ou sans suffixe connu.
    param([string]$ValueName)
    if ([string]::IsNullOrWhiteSpace($ValueName)) { return '' }
    $m = [regex]::Match($ValueName, '(?i)^(.+?)\.(FriendlyAppName|ApplicationCompany)$')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Probe-RecentActivity {
    $details = New-Object System.Collections.Generic.List[string]
    $names = New-Object System.Collections.Generic.List[string]
    $hives = Get-UserHiveRoots
    $muiCount = 0
    # Chaque compte Windows connecte (HKCU puis HKEY_USERS\<SID>), pas seulement celui qui lance le check.
    foreach ($hive in @($hives.Roots)) {
    # RecentDocs = fichiers ouverts recemment (valeurs binaires, nom en tete UTF-16).
    $rdRoot = "$($hive.User)\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    try {
        $keys = @($rdRoot)
        $keys += @(Get-ChildItem $rdRoot -ErrorAction SilentlyContinue | ForEach-Object { $_.PSPath })
        foreach ($k in $keys) {
            $item = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue
            if ($null -eq $item) { continue }
            foreach ($vn in $item.GetValueNames()) {
                if ($vn -eq 'MRUListEx') { continue }
                $data = $item.GetValue($vn)
                if ($data -is [byte[]]) { $nm = ConvertFrom-RecentDocValue $data; if ($nm) { $names.Add($nm) } }
            }
        }
    } catch { }
    # RunMRU = commandes tapees dans la boite Executer (valeurs texte "cmd\1").
    $rmRoot = "$($hive.User)\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    try {
        $item = Get-Item -LiteralPath $rmRoot -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            foreach ($vn in $item.GetValueNames()) {
                if ($vn -eq 'MRUList') { continue }
                $v = [string]$item.GetValue($vn)
                if ($v) { $names.Add(($v -replace '\\1$','')) }
            }
        }
    } catch { }
    # MuiCache = chemin de chaque exe LANCE (Explorateur/ShellExecute) avec son nom d'application, ecrit au
    # lancement, JAMAIS purge par Windows, oublie par la plupart des 'cleaners' -> source anti-wipe de plus.
    $muiRoot = "$($hive.Classes)\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    try {
        $item = Get-Item -LiteralPath $muiRoot -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            foreach ($vn in $item.GetValueNames()) {
                $p = ConvertFrom-MuiCacheName $vn
                if ($p) { $names.Add($p); $muiCount++ }
            }
        }
    } catch { }
    }
    $details.Add("$($names.Count) entree(s) RecentDocs/RunMRU/MuiCache analysee(s) sur $(@($hives.Roots).Count) compte(s) connecte(s) (fichiers ouverts recemment + commandes Executer + $muiCount exe lances).")
    if (@($hives.Unread).Count -gt 0) { $details.Add("NOTE : non lu pour $(@($hives.Unread).Count) compte(s) Windows non connecte(s) (ruche non chargee ; la charger serait une ecriture) : $(@($hives.Unread) -join ', ').") }
    $a = Get-WerCrashHits -Names $names -FlagPatterns (Get-CheatFlagPatterns) -WarnPatterns $script:CheatWarnWords
    if ($a.Flag.Count -gt 0) {
        foreach ($x in ($a.Flag | Select-Object -Unique)) { $details.Add("Nom de cheat DISTINCTIF ouvert/tape recemment : $x") }
        New-ProbeResult -Id 'MRU' -Name 'Fichiers recents / Executer (RecentDocs, RunMRU)' -Status 'FLAG' -Severity 2 -Summary "$(@($a.Flag | Select-Object -Unique).Count) nom(s) de cheat distinctif(s) dans les fichiers recents / Executer" -Details $details
    } elseif ($a.Warn.Count -gt 0) {
        foreach ($x in ($a.Warn | Select-Object -Unique)) { $details.Add("Nom generique/categorie ouvert recemment (dual-use) : $x") }
        New-ProbeResult -Id 'MRU' -Name 'Fichiers recents / Executer (RecentDocs, RunMRU)' -Status 'WARN' -Severity 1 -Summary "$(@($a.Warn | Select-Object -Unique).Count) nom(s) generique(s) dans les fichiers recents - a verifier" -Details $details
    } else {
        New-ProbeResult -Id 'MRU' -Name 'Fichiers recents / Executer (RecentDocs, RunMRU)' -Status 'OK' -Severity 0 -Summary "Rien de suspect dans les fichiers recents / Executer" -Details $details
    }
}

function Get-MotwCheatHits {
    # Pur -> testable. Recoit des couples fichier/URL-de-provenance (Mark-of-the-Web, flux NTFS
    # Zone.Identifier). L'URL de telechargement est collee au fichier par Windows et SURVIT a
    # l'effacement de l'historique du navigateur : un joueur qui wipe Chrome la laisse derriere lui.
    # Un fichier telecharge DEPUIS un domaine de cheat connu = provenance distinctive + le binaire
    # est present. Domaine de cheat OU token distinctif dans l'URL/le nom => FLAG.
    param($Entries, [string[]]$Domains, [string[]]$FlagPatterns)
    $hits = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Entries) { return ,$hits }
    foreach ($e in $Entries) {
        if ($null -eq $e) { continue }
        $url = [string]$e.Url; $file = [string]$e.File
        if ([string]::IsNullOrEmpty($url)) { continue }
        $why = $null
        if (Test-AnyPattern $url $Domains) { $why = "telecharge depuis un domaine de cheat" }
        elseif (Test-AnyWord ($url + ' ' + $file) $FlagPatterns) { $why = "provenance/nom de cheat distinctif" }
        if ($why) { $hits.Add([pscustomobject]@{ File=$file; Url=$url; Why=$why }) }
    }
    return ,$hits
}

function Probe-DownloadProvenance {
    $details = New-Object System.Collections.Generic.List[string]
    $domains = @(); foreach ($c in $script:CheatSoftware) { if ($c.Domains) { $domains += $c.Domains } }
    $entries = New-Object System.Collections.Generic.List[object]
    $roots = @(@(Get-UserFolderRoots) + @($env:TEMP)) | Where-Object { $_ } | Select-Object -Unique
    $exts = @('.exe','.dll','.scr','.zip','.rar','.7z','.ps1','.bat','.msi')
    # Cap PAR RACINE (pas global) pour qu'aucune zone ne soit affamee par une autre + on lit les
    # ADS des fichiers les PLUS RECENTS d'abord (un cheat telecharge pour la session est recent).
    # Lire le flux Zone.Identifier de chaque fichier coute ~2 ms => on borne pour rester rapide.
    $perRootCap = 1200; $scanned = 0; $dropped = 0
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        try {
            # -Depth 2 (pas -Recurse total) : un fichier telecharge est a la racine ou 1-2 niveaux
            # sous Downloads, jamais enterre profond. Evite l'enumeration lente d'arbres OneDrive/Temp
            # (mesure : -Recurse = 20-50 s, -Depth 2 = ~0 s).
            $cands = @(Get-ChildItem -LiteralPath $r -Depth 2 -File -Force -ErrorAction SilentlyContinue | Where-Object { $exts -contains $_.Extension.ToLower() })
            if ($cands.Count -gt $perRootCap) { $dropped += ($cands.Count - $perRootCap) }
            $cands = @($cands | Sort-Object LastWriteTime -Descending | Select-Object -First $perRootCap)
            foreach ($f in $cands) {
                $scanned++
                $zi = ''
                try { $zi = (Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue) -join "`n" } catch { }
                if (-not $zi) { continue }
                $url = ''
                foreach ($ln in ($zi -split "`n")) {
                    if ($ln -match '^(?:HostUrl|ReferrerUrl)=(.+)$') { $url = $Matches[1].Trim(); if ($ln -match '^HostUrl=') { break } }
                }
                if ($url) { $entries.Add([pscustomobject]@{ File=$f.FullName; Url=$url }) }
            }
        } catch { }
    }
    $details.Add("$($entries.Count) fichier(s) telecharge(s) avec une URL de provenance (Mark-of-the-Web) sur $scanned scanne(s) - l'URL survit a l'effacement de l'historique du navigateur.")
    if ($dropped -gt 0) { $details.Add("$dropped fichier(s) plus anciens non scannes (limite $perRootCap/zone, les plus recents d'abord) - non couverts, a garder en tete.") }
    $hits = Get-MotwCheatHits -Entries $entries -Domains $domains -FlagPatterns (Get-CheatFlagPatterns)
    if ($hits.Count -gt 0) {
        foreach ($h in $hits) { $details.Add("PROVENANCE CHEAT ($($h.Why)) : $($h.File)  <=  $($h.Url)") }
        New-ProbeResult -Id 'MOTW' -Name 'Provenance des telechargements (Mark-of-the-Web)' -Status 'FLAG' -Severity 2 -Summary "$($hits.Count) fichier(s) telecharge(s) depuis un domaine/provider de cheat (provenance survit au wipe navigateur)" -Details $details
    } else {
        New-ProbeResult -Id 'MOTW' -Name 'Provenance des telechargements (Mark-of-the-Web)' -Status 'OK' -Severity 0 -Summary "Aucun fichier telecharge depuis un domaine de cheat connu" -Details $details
    }
}

function Get-VmAssessment {
    # Logique PURE testable : la machine du check doit etre la VRAIE machine de jeu.
    # Tourner le check dans une VM clean pendant qu'on joue sur l'hote = evasion screenshare.
    param([bool]$VendorMatch, [bool]$HypervisorPresent)
    if ($VendorMatch)       { return @{ Status='WARN'; Severity=1; Summary='Machine VIRTUELLE detectee (vendor VM) - le check doit tourner sur la vraie machine de jeu, pas une VM' } }
    if ($HypervisorPresent) { return @{ Status='INFO'; Severity=0; Summary='Hyperviseur present - peut etre Hyper-V/VBS/WSL sur une machine reelle (Win11) OU une VM ; a confirmer visuellement' } }
    return @{ Status='OK'; Severity=0; Summary='Aucun signe de machine virtuelle' }
}

function Probe-Virtualization {
    $details = New-Object System.Collections.Generic.List[string]
    $vmVendors = @('vmware','virtualbox','innotek','qemu','kvm','xen','parallels','bochs','virtual machine','msft virtual','hyper-v','red hat','bhyve','utm','citrix')
    $vendorMatch = $false; $hyp = $false; $read = $false
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($null -ne $cs) {
            $read = $true
            try { $hyp = [bool]$cs.HypervisorPresent } catch { }
            $hay = ('{0} {1}' -f $cs.Manufacturer, $cs.Model)
            $details.Add("ComputerSystem : $hay")
            if (Test-AnyWord $hay $vmVendors) { $vendorMatch = $true }
        }
    } catch { }
    try {
        $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
        if ($null -ne $bios) {
            $read = $true
            # PAS le numero de serie (alphanum arbitraire => un 'xen'/'kvm'/'utm' fortuit ferait un faux WARN)
            $bhay = ('{0} {1}' -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion)
            if (Test-AnyWord $bhay $vmVendors) { $vendorMatch = $true; $details.Add("BIOS : $($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)") }
        }
    } catch { }
    if (-not $read) {
        return (New-ProbeResult -Id 'VM' -Name 'Virtualisation (VM / hyperviseur)' -Status 'NA' -Severity 0 -Summary "Virtualisation non lisible (WMI indisponible)" -Details $details)
    }
    $details.Add("HypervisorPresent = $hyp")
    $a = Get-VmAssessment -VendorMatch $vendorMatch -HypervisorPresent $hyp
    New-ProbeResult -Id 'VM' -Name 'Virtualisation (VM / hyperviseur)' -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
}

# Resume unique de « protection coupee » : Get-EvasionProfile s'en sert pour distinguer ce signal
# FORT d'une simple exclusion en zone user (signal prep). Une seule source, pas deux chaines.
$script:DefenderRealtimeOffSummary = 'Protection temps reel Defender DESACTIVEE (antivirus coupe avant le check ?)'

function Get-DefenderAssessment {
    # Logique PURE testable. Une exclusion Defender au nom de cheat = whitelist d'un dossier
    # de cheat (tell classique). Protection coupee / exclusion en zone temp = a verifier.
    param([bool]$RealtimeDisabled, [bool]$CheatExclusion, [int]$RiskyExclusionCount, [int]$TotalExclusionCount)
    if ($CheatExclusion)        { return @{ Status='FLAG'; Severity=2; Summary='Exclusion Defender au nom de cheat (dossier/process whiteliste pour echapper a l antivirus)' } }
    if ($RealtimeDisabled)      { return @{ Status='WARN'; Severity=1; Summary=$script:DefenderRealtimeOffSummary } }
    if ($RiskyExclusionCount -gt 0) { return @{ Status='WARN'; Severity=1; Summary="$RiskyExclusionCount exclusion(s) Defender en zone user/temp/downloads - a verifier" } }
    if ($TotalExclusionCount -gt 0) { return @{ Status='INFO'; Severity=0; Summary="$TotalExclusionCount exclusion(s) Defender (souvent legit : jeux/dev) - listees" } }
    return @{ Status='OK'; Severity=0; Summary='Aucune exclusion Defender, protection temps reel active' }
}

function Probe-DefenderExclusions {
    $details = New-Object System.Collections.Generic.List[string]
    $pref = $null
    try { $pref = Get-MpPreference -ErrorAction Stop } catch {
        return (New-ProbeResult -Id 'DEFENDER' -Name 'Exclusions Windows Defender' -Status 'NA' -Severity 0 -Summary "Get-MpPreference indisponible (Defender absent ou AV tiers)" -Details @($_.Exception.Message))
    }
    $paths = @(); $procs = @(); $exts = @()
    try { $paths = @($pref.ExclusionPath  | Where-Object { $_ }) } catch { }
    try { $procs = @($pref.ExclusionProcess | Where-Object { $_ }) } catch { }
    try { $exts  = @($pref.ExclusionExtension | Where-Object { $_ }) } catch { }
    $all = @($paths + $procs + $exts)
    $rtDisabled = $false
    try { $rtDisabled = [bool]$pref.DisableRealtimeMonitoring } catch { }
    # FLAG seulement sur un nom de cheat DISTINCTIF ; un mot generique (loader/cheat) ou une
    # zone temp = WARN (un mod-loader peut etre legitimement exclu).
    $flagPat = Get-CheatFlagPatterns
    $cheatHit = $false
    foreach ($x in $all) { if (Test-AnyWord ([string]$x) $flagPat) { $cheatHit = $true; $details.Add("EXCLUSION AU NOM DE CHEAT DISTINCTIF : $x") } }
    $genericHits = @($all | Where-Object { (Test-AnyWord ([string]$_) $script:CheatWarnWords) -and -not (Test-AnyWord ([string]$_) $flagPat) })
    foreach ($x in $genericHits) { $details.Add("Exclusion au nom generique (dual-use) : $x") }
    $riskyZones = @('\temp\','\downloads\','\appdata\local\temp\','\users\public\','\desktop\')
    $risky = @($paths | Where-Object { Test-AnyPattern ([string]$_) $riskyZones })
    if ($all.Count -gt 0) {
        $details.Add("Exclusions Defender ($($all.Count)) :")
        foreach ($x in $all) { $details.Add("  $x") }
    }
    if ($rtDisabled) { $details.Add("Protection temps reel : DESACTIVEE") }
    $riskyTotal = $risky.Count + @($genericHits).Count
    $a = Get-DefenderAssessment -RealtimeDisabled $rtDisabled -CheatExclusion $cheatHit -RiskyExclusionCount $riskyTotal -TotalExclusionCount $all.Count
    New-ProbeResult -Id 'DEFENDER' -Name 'Exclusions Windows Defender' -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
}

function Get-DefenderThreatAssessment {
    # Pur -> testable. Recoit les menaces DEJA detectees par Defender (nom Microsoft + chemin) et
    # les classe. Le verdict est SIGNE MICROSOFT, pas par nous : c'est sa force. Survit a la
    # suppression du binaire (l'historique Defender reste). Chaque menace = @{ Name; Path }.
    # Loi "prouver pas nommer" : FLAG seulement si un token de cheat DISTINCTIF (notre liste)
    # apparait dans le nom/chemin Microsoft = les deux sources concordent. Categorie HackTool/
    # GameHack generique (Cheat Engine, trainer de jeu SOLO) = WARN, jamais FLAG (piege FP de Fable).
    param($Threats, [string[]]$FlagPatterns)
    $flag = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $info = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Threats) { return @{ Status='OK'; Severity=0; Flag=$flag; Warn=$warn; Info=$info } }
    $strongCat = @('hacktool','gamehack','game hack')
    foreach ($th in $Threats) {
        if ($null -eq $th) { continue }
        $name = [string]$th.Name; $path = [string]$th.Path
        $hay = ($name + ' ' + $path).Trim()
        if ([string]::IsNullOrEmpty($hay)) { continue }
        if (Test-AnyWord $hay $FlagPatterns) {
            $flag.Add($hay)                       # cheat NOMME connu detecte par Microsoft => FLAG
        } elseif (Test-AnyPattern $name $strongCat) {
            $warn.Add($hay)                       # Microsoft dit "outil de triche" mais generique => WARN (modo juge)
        } else {
            $info.Add($hay)                       # Defender a chope qqch (PUA/malware) - pas forcement un cheat de jeu
        }
    }
    $status = if ($flag.Count -gt 0) { 'FLAG' } elseif ($warn.Count -gt 0) { 'WARN' } elseif ($info.Count -gt 0) { 'INFO' } else { 'OK' }
    $sev    = if ($flag.Count -gt 0) { 2 } elseif ($warn.Count -gt 0) { 1 } else { 0 }
    @{ Status=$status; Severity=$sev; Flag=$flag; Warn=$warn; Info=$info }
}

function Probe-DefenderThreats {
    $details = New-Object System.Collections.Generic.List[string]
    $threats = @()
    try {
        $raw = @(Get-MpThreat -ErrorAction Stop)
        foreach ($t in $raw) {
            $nm = ''; $res = @()
            $nmp = $t.PSObject.Properties['ThreatName']; if ($nmp) { $nm = [string]$nmp.Value }
            $rp  = $t.PSObject.Properties['Resources'];  if ($rp -and $rp.Value) { $res = @($rp.Value) }
            $exec = $false
            $ep = $t.PSObject.Properties['DidThreatExecute']; if ($ep) { try { $exec = [bool]$ep.Value } catch { } }
            $path = ($res -join ' ') -replace '(?i)(file|containerfile|regkey|amsi):_?', ''
            $threats += @{ Name=$nm; Path=$path; Executed=$exec }
        }
    } catch {
        return (New-ProbeResult -Id 'DEFTHREAT' -Name 'Historique menaces Defender' -Status 'NA' -Severity 0 -Summary "Historique Defender non lisible ($($_.Exception.Message.Split([char]10)[0]))" -Details $details)
    }
    if ($threats.Count -eq 0) {
        $details.Add("L'historique Defender se purge tout seul (~30 j sur certains items) : un historique vide n'est PAS une preuve de PC propre.")
        return (New-ProbeResult -Id 'DEFTHREAT' -Name 'Historique menaces Defender' -Status 'OK' -Severity 0 -Summary "Aucune menace dans l'historique Defender (ne prouve pas l'absence de cheat : l'historique se purge)" -Details $details)
    }
    $a = Get-DefenderThreatAssessment -Threats $threats -FlagPatterns (Get-CheatFlagPatterns)
    foreach ($x in $a.Flag) { $details.Add("[cheat NOMME detecte par Defender] $x") }
    foreach ($x in $a.Warn) { $details.Add("[outil de triche (categorie Microsoft), generique] $x") }
    foreach ($x in $a.Info) { $details.Add("[menace detectee (pas forcement un cheat de jeu)] $x") }
    foreach ($th in $threats) { if ($th.Executed) { $details.Add("  -> Microsoft indique que cette menace a EXECUTE : $($th.Name)") } }
    $sum = switch ($a.Status) {
        'FLAG' { "$($a.Flag.Count) cheat(s) connu(s) deja detecte(s) par Defender sur cette machine" }
        'WARN' { "$($a.Warn.Count) outil(s) de triche detecte(s) par Defender (categorie generique - a verifier)" }
        'INFO' { "$($a.Info.Count) menace(s) dans l'historique Defender (pas forcement liee(s) au jeu)" }
        default { "Historique Defender lu, rien de suspect" }
    }
    New-ProbeResult -Id 'DEFTHREAT' -Name 'Historique menaces Defender' -Status $a.Status -Severity $a.Severity -Summary $sum -Details $details
}

function Get-DriverAssessment {
    # Logique PURE testable. Driver kernel non signe charge = fort signal BYOVD. Driver connu
    # abusable = a verifier (souvent dual-use : Afterburner/HWiNFO). On reste en WARN (le
    # moderateur tranche) pour ne pas crier SUSPECT sur un outil de monitoring legitime.
    param([int]$UnsignedCount, [int]$VulnerableCount, [int]$UserZoneCount = 0)
    if ($UnsignedCount -gt 0 -or $VulnerableCount -gt 0 -or $UserZoneCount -gt 0) {
        return @{ Status='WARN'; Severity=1; Summary="$UnsignedCount driver(s) kernel non signe(s) + $VulnerableCount driver(s) connu(s) abusable(s) (BYOVD) + $UserZoneCount enregistre(s) depuis un dossier utilisateur - a verifier" }
    }
    return @{ Status='OK'; Severity=0; Summary='Aucun driver kernel non signe, abusable connu, ou enregistre depuis un dossier utilisateur' }
}

function Test-UserZoneDriverPath {
    # PUR/testable. Vrai si un chemin de driver kernel pointe sous \Users\ (Temp, Downloads, Desktop...).
    # C'est la signature d'un MAPPER : kdmapper enregistre un service SCM vers
    # \??\C:\Users\x\AppData\Local\Temp\iqvw64e.sys, charge, puis supprime le service - sauf si ca plante.
    # \ProgramData N'EST PAS une zone user : les anti-triche y vivent (Battle.net randgrid.sys, mesure 14/09).
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return [regex]::IsMatch($Path, '(?i)(^|[\\/])users[\\/]')
}

function Probe-KernelDrivers {
    # Vecteur DMA / cheat kernel : un driver .sys non signe charge, ou un driver connu
    # abusable (BYOVD), permet de lire/ecrire la memoire kernel et de contourner l'anti-cheat.
    # Les services de driver NON charges sont aussi lus (residu d'un mapper : service qui pointe sous \Users\).
    $details = New-Object System.Collections.Generic.List[string]
    $all = @(); $drivers = @()
    try { $all = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop); $drivers = @($all | Where-Object { $_.State -eq 'Running' }) } catch {
        return (New-ProbeResult -Id 'KDRV' -Name 'Drivers kernel (BYOVD)' -Status 'NA' -Severity 0 -Summary "Enumeration des drivers indisponible" -Details @($_.Exception.Message))
    }
    $unsigned = New-Object System.Collections.Generic.List[string]
    $vuln     = New-Object System.Collections.Generic.List[string]
    $userZone = New-Object System.Collections.Generic.List[string]
    foreach ($d in $all) {
        if (Test-UserZoneDriverPath ([string]$d.PathName)) { $userZone.Add("$($d.Name) [$($d.State)]  ($($d.PathName))") }
    }
    foreach ($d in $drivers) {
        $nm = [string]$d.Name
        $path = [string]$d.PathName
        if ($path) {
            $path = $path.Trim('"').Trim()
            if ($path -match '^\\\?\?\\') { $path = $path -replace '^\\\?\?\\', '' }
            if ($path -match '^\\SystemRoot\\') { $path = $env:SystemRoot + '\' + ($path -replace '^\\SystemRoot\\', '') }
        }
        $file = ''
        try { if ($path) { $file = [System.IO.Path]::GetFileName($path) } } catch { }
        if ((Test-AnyPattern $nm $script:VulnerableDrivers) -or (Test-AnyPattern $file $script:VulnerableDrivers)) {
            $vuln.Add("$nm  ($file)")
        }
        if ($path -and (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                if ($null -ne $sig -and $sig.Status -ne 'Valid') { $unsigned.Add("$nm [$($sig.Status)]  ($path)") }
            } catch { }
        }
    }
    $details.Add("Drivers kernel enregistres : $($all.Count) dont $($drivers.Count) en cours d'execution. Verif = signature Authenticode (non signe = fort signal BYOVD) + liste curee de drivers connus abusables + service qui pointe sous \Users\ (residu de mapper).")
    if (-not (Test-Admin)) { $details.Add("NOTE : sans admin, la lecture de certains chemins/signatures peut etre partielle.") }
    if ($vuln.Count -gt 0) {
        $details.Add("DRIVERS CONNUS ABUSABLES (BYOVD - souvent dual-use Afterburner/HWiNFO/monitoring, a confirmer) :")
        foreach ($v in $vuln) { $details.Add("  $v") }
    }
    if ($unsigned.Count -gt 0) {
        $details.Add("DRIVERS KERNEL NON SIGNES / SIGNATURE INVALIDE (rare et notable sur Windows x64) :")
        foreach ($u in $unsigned) { $details.Add("  $u") }
    }
    if ($userZone.Count -gt 0) {
        $details.Add("SERVICES DE DRIVER ENREGISTRES DEPUIS UN DOSSIER UTILISATEUR (Temp/Downloads = pattern kdmapper/BYOVD, rarement legitime) :")
        foreach ($u in $userZone) { $details.Add("  $u") }
    }
    $a = Get-DriverAssessment -UnsignedCount $unsigned.Count -VulnerableCount $vuln.Count -UserZoneCount $userZone.Count
    New-ProbeResult -Id 'KDRV' -Name 'Drivers kernel (BYOVD)' -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
}

function Get-DriverInstallHits {
    # PUR/testable. Classe des installs de service/driver (event 7045) : FLAG si le nom/chemin porte
    # un nom de PROVIDER de cheat DISTINCTIF (jamais un mot de categorie -> pas de faux "aimbot-remover"),
    # WARN si un driver BYOVD dual-use (rtcore64=Afterburner, winring0=HWiNFO...) -- la DATE d'install
    # est le vrai apport (KDRV ne voit que les drivers CHARGES ; 7045 attrape un install-puis-suppression).
    # installs = liste de @{ Name; Path; Time }. Rend une List (consommer sans @()).
    param($installs, [string[]]$flagPatterns, [string[]]$byovdPatterns)
    $hits = New-Object System.Collections.Generic.List[object]
    if ($null -eq $installs) { return ,$hits }
    foreach ($i in $installs) {
        $hay = ('{0} {1}' -f $i.Name, $i.Path)
        if (Test-AnyWord $hay $flagPatterns) {
            $hits.Add([pscustomobject]@{ Name=$i.Name; Path=$i.Path; Time=$i.Time; Level='FLAG' })
        } elseif (Test-AnyWord $hay $byovdPatterns) {
            $hits.Add([pscustomobject]@{ Name=$i.Name; Path=$i.Path; Time=$i.Time; Level='WARN' })
        }
    }
    return ,$hits
}

function Probe-DriverInstalls {
    $details = New-Object System.Collections.Generic.List[string]
    # Event 7045 (System log, Service Control Manager) = "un service/driver a ete installe", avec sa
    # DATE. Lisible sans admin. Properties : [0]=nom, [1]=chemin image, [4]=compte.
    $events = $null
    try { $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 500 -ErrorAction Stop) }
    catch {
        return (New-ProbeResult -Id 'DRVINST' -Name 'Installs de driver/service (7045)' -Status 'NA' -Severity 0 -Summary "Aucun event 7045 lisible (log vide/tourne ou inaccessible)" -Details @($_.Exception.Message))
    }
    $installs = New-Object System.Collections.Generic.List[object]
    foreach ($e in $events) {
        $nm = ''; $pth = ''
        try { $nm  = [string]$e.Properties[0].Value } catch { }
        try { $pth = [string]$e.Properties[1].Value } catch { }
        $installs.Add([pscustomobject]@{ Name=$nm; Path=$pth; Time=$e.TimeCreated })
    }
    $details.Add("Installs de service/driver analyses (event 7045) : $($installs.Count).")
    $hits = Get-DriverInstallHits $installs (Get-PsHistoryFlagTargets) $script:VulnerableDrivers
    $flagHits = @($hits | Where-Object { $_.Level -eq 'FLAG' })
    $warnHits = @($hits | Where-Object { $_.Level -eq 'WARN' })
    if ($flagHits.Count -gt 0) {
        foreach ($h in $flagHits) { $details.Add(("  FLAG install au nom de cheat distinctif : {0}  ({1})  installe le {2}" -f $h.Name, $h.Path, $h.Time)) }
        foreach ($h in $warnHits) { $details.Add(("  (BYOVD dual-use : {0} installe le {1})" -f $h.Name, $h.Time)) }
        return (New-ProbeResult -Id 'DRVINST' -Name 'Installs de driver/service (7045)' -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) install de service au nom de cheat distinctif" -Details $details)
    } elseif ($warnHits.Count -gt 0) {
        foreach ($h in $warnHits) { $details.Add(("  driver abusable (BYOVD) installe : {0}  ({1})  le {2}" -f $h.Name, $h.Path, $h.Time)) }
        return (New-ProbeResult -Id 'DRVINST' -Name 'Installs de driver/service (7045)' -Status 'WARN' -Severity 1 -Summary "$($warnHits.Count) install(s) de driver abusable (BYOVD) date(s) - a verifier (dual-use : Afterburner/HWiNFO)" -Details $details)
    }
    New-ProbeResult -Id 'DRVINST' -Name 'Installs de driver/service (7045)' -Status 'OK' -Severity 0 -Summary "$($installs.Count) install(s) analyse(s), aucun driver abusable/cheat" -Details $details
}

function Get-CiLogHits {
    # PUR/testable. Journal Microsoft-Windows-CodeIntegrity/Operational : Windows y ecrit LUI-MEME chaque
    # image qu'il a refuse de charger (3033/3077 = niveau de signature insuffisant / bloquee par la
    # politique, 3004/3001 = integrite non verifiable, 3076 = audit). Un driver mappe (kdmapper + driver
    # vulnerable), un driver non signe, un driver de spoofer : ils passent par la et laissent une ligne
    # DATEE qui survit a la suppression du .sys. Les messages sont LOCALISES (FR/EN...) : on n'analyse que
    # les CHEMINS (\Device\HarddiskVolumeN\... ou C:\...), independants de la langue.
    # Bruit mesure 14/09 : 3033 tire aussi sur des DLL legitimes (Bonjour mdnsNSP.dll dans svchost) ->
    # on ne garde que les .sys (drivers = le vecteur kernel), sauf nom de cheat distinctif (toute image).
    # Rend une List de @{ Id; Time; Path; Level } (FLAG = nom de cheat ; WARN = .sys refuse).
    param($Events, [string[]]$FlagPatterns)
    $hits = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Events) { return ,$hits }
    $rx = [regex]'(?i)(\\Device\\HarddiskVolume\d+\\[^\s"''<>|]+|\\\?\?\\[^\s"''<>|]+|[A-Z]:\\[^\s"''<>|]+)'
    foreach ($e in $Events) {
        if ($null -eq $e) { continue }
        $msg = [string]$e.Message
        if ([string]::IsNullOrWhiteSpace($msg)) { continue }
        $seen = @{}
        foreach ($m in $rx.Matches($msg)) {
            $p = $m.Value.TrimEnd('.', ',', ';', ')')
            if ($seen.ContainsKey($p)) { continue }; $seen[$p] = $true
            $file = ''; try { $file = [System.IO.Path]::GetFileName($p) } catch { $file = $p }
            if (Test-AnyWord $p $FlagPatterns) { $hits.Add([pscustomobject]@{ Id=$e.Id; Time=$e.Time; Path=$p; Level='FLAG' }) }
            elseif ($file -match '(?i)\.sys$')  { $hits.Add([pscustomobject]@{ Id=$e.Id; Time=$e.Time; Path=$p; Level='WARN' }) }
        }
    }
    return ,$hits
}

function Probe-CodeIntegrity {
    $details = New-Object System.Collections.Generic.List[string]
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=@(3001,3004,3033,3076,3077) } -MaxEvents 3000 -ErrorAction Stop)
    } catch {
        # "aucun evenement" est un vrai resultat (log lu, rien dedans) ; tout autre echec = non lu.
        if ($_.Exception.Message -match '(?i)no events|aucun .*ev|NoMatchingEvents') { $events = @() }
        else { return (New-ProbeResult -Id 'CILOG' -Name 'Journal Code Integrity (drivers refuses)' -Status 'NA' -Severity 0 -Summary "Journal CodeIntegrity non lisible" -Details @($_.Exception.Message.Split([char]10)[0])) }
    }
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in $events) { $list.Add(@{ Id=$e.Id; Time=$e.TimeCreated; Message=[string]$e.Message }) }
    $hits = Get-CiLogHits -Events $list -FlagPatterns (Get-CheatFlagPatterns)
    $flagHits = @($hits | Where-Object { $_.Level -eq 'FLAG' })
    $warnHits = @($hits | Where-Object { $_.Level -eq 'WARN' } | Sort-Object Path -Unique)
    $details.Add("Evenements Code Integrity lus : $($events.Count) (refus de chargement 3001/3004/3033/3076/3077). Seuls les drivers .sys (et tout nom de cheat distinctif) sont retenus ; les DLL refusees (frequent, legitime) sont ignorees.")
    foreach ($h in $flagHits) { $details.Add(("  FLAG nom de cheat distinctif refuse au chargement : {0}  (event {1}, {2})" -f $h.Path, $h.Id, $h.Time)) }
    foreach ($h in $warnHits) {
        $why = if (Test-UserZoneDriverPath $h.Path) { 'depuis un dossier UTILISATEUR = pattern mapper' } elseif (Test-AnyPattern $h.Path $script:VulnerableDrivers) { 'driver connu abusable (BYOVD, dual-use)' } else { 'driver refuse (vieux driver legitime possible)' }
        $details.Add(("  driver .sys refuse : {0}  [{1}]  (event {2}, {3})" -f $h.Path, $why, $h.Id, $h.Time))
    }
    if ($flagHits.Count -gt 0) {
        return (New-ProbeResult -Id 'CILOG' -Name 'Journal Code Integrity (drivers refuses)' -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) image(s) au nom de cheat distinctif refusee(s) au chargement (journal Windows, date)" -Details $details)
    }
    if ($warnHits.Count -gt 0) {
        return (New-ProbeResult -Id 'CILOG' -Name 'Journal Code Integrity (drivers refuses)' -Status 'WARN' -Severity 1 -Summary "$($warnHits.Count) driver(s) .sys refuse(s) par Code Integrity - a verifier (BYOVD / mapper ? ou vieux driver)" -Details $details)
    }
    New-ProbeResult -Id 'CILOG' -Name 'Journal Code Integrity (drivers refuses)' -Status 'OK' -Severity 0 -Summary "$($events.Count) evenement(s) lu(s), aucun driver .sys refuse ni nom de cheat" -Details $details
}

function Probe-Injection {
    # Vecteurs d'INJECTION / hijack au demarrage des process (un overlay/cheat qui se charge
    # DANS le jeu) : AppInit_DLLs (DLL chargee dans tout process usant user32.dll), AppCertDLLs,
    # et IFEO Debugger (detourne le lancement d'un exe). Ces cles sont VIDES sur une machine
    # saine -> une valeur non vide = point d'injection a verifier (WARN) ; nom de cheat = FLAG.
    # Acces registre via PSObject.Properties[] (renvoie $null si absent) = safe sous StrictMode.
    $details = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $flag = New-Object System.Collections.Generic.List[string]
    $flagPat = Get-CheatFlagPatterns
    # AppInit_DLLs (64 + 32 bits)
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        try {
            if (-not (Test-Path $k)) { continue }
            $pp = Get-ItemProperty $k -ErrorAction SilentlyContinue
            if ($null -eq $pp) { continue }
            $aiProp = $pp.PSObject.Properties['AppInit_DLLs']
            if ($null -eq $aiProp) { continue }
            $ai = [string]$aiProp.Value
            if ([string]::IsNullOrWhiteSpace($ai)) { continue }
            $enProp = $pp.PSObject.Properties['LoadAppInit_DLLs']
            $en = if ($null -ne $enProp) { [int]$enProp.Value } else { 0 }
            $line = "AppInit_DLLs = $ai (LoadAppInit_DLLs=$en)"
            if (Test-AnyWord $ai $flagPat) { $flag.Add($line) } else { $warn.Add($line) }
        } catch { }
    }
    # AppCertDLLs
    try {
        $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
        if (Test-Path $k) {
            $pp = Get-ItemProperty $k -ErrorAction SilentlyContinue
            if ($null -ne $pp) {
                foreach ($p in $pp.PSObject.Properties) {
                    if ($p.Name -like 'PS*') { continue }
                    $v = [string]$p.Value
                    if ([string]::IsNullOrWhiteSpace($v)) { continue }
                    $line = "AppCertDLL $($p.Name) = $v"
                    if (Test-AnyWord $v $flagPat) { $flag.Add($line) } else { $warn.Add($line) }
                }
            }
        }
    } catch { }
    # IFEO Debugger (detournement de lancement)
    try {
        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        if (Test-Path $ifeo) {
            foreach ($sub in (Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
                try {
                    $dp = Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue
                    if ($null -eq $dp) { continue }
                    $dbgProp = $dp.PSObject.Properties['Debugger']
                    if ($null -eq $dbgProp) { continue }
                    $dbg = [string]$dbgProp.Value
                    if ([string]::IsNullOrWhiteSpace($dbg)) { continue }
                    $line = "IFEO Debugger sur $($sub.PSChildName) -> $dbg"
                    if (Test-AnyWord $dbg $flagPat) { $flag.Add($line) } else { $warn.Add($line) }
                } catch { }
            }
        }
    } catch { }
    $details.Add("Vecteurs verifies : AppInit_DLLs (64/32), AppCertDLLs, IFEO Debugger. Vides sur une machine saine ; une valeur = point d'injection/hijack a verifier (certains outils legitimes en posent aussi -> revue humaine).")
    foreach ($f in $flag) { $details.Add("  FLAG: $f") }
    foreach ($w in $warn) { $details.Add("  WARN: $w") }
    if ($flag.Count -gt 0) {
        return (New-ProbeResult -Id 'INJECT' -Name 'Injection / hijack (AppInit/IFEO)' -Status 'FLAG' -Severity 2 -Summary "$($flag.Count) vecteur(s) d'injection au nom de cheat" -Details $details)
    }
    if ($warn.Count -gt 0) {
        return (New-ProbeResult -Id 'INJECT' -Name 'Injection / hijack (AppInit/IFEO)' -Status 'WARN' -Severity 1 -Summary "$($warn.Count) vecteur(s) d'injection/hijack a verifier (souvent vide sur PC sain)" -Details $details)
    }
    New-ProbeResult -Id 'INJECT' -Name 'Injection / hijack (AppInit/IFEO)' -Status 'OK' -Severity 0 -Summary "Aucun AppInit/AppCert/IFEO Debugger positionne" -Details $details
}

# ============================================================================
# COUCHE 4 - REPORTING
# ============================================================================

function ConvertTo-HtmlText {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return '' }
    return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function Get-Native64PowerShell {
    # PUR. Dans un PowerShell 32 bits sur Windows 64 bits, HKLM:\SOFTWARE (Run, IFEO) et
    # System32\drivers sont rediriges vers WOW6432Node / SysWOW64 : plusieurs sondes lisaient les
    # mauvais emplacements et concluaient « rien trouve ». Rend le PowerShell natif a relancer.
    param([bool]$Is64BitOS, [bool]$Is64BitProcess, [string]$WinDir)
    if ($Is64BitOS -and -not $Is64BitProcess -and $WinDir) {
        return (Join-Path $WinDir 'sysnative\WindowsPowerShell\v1.0\powershell.exe')
    }
    return $null
}

function ConvertTo-ArgList {
    # PUR. Parametres lies -> arguments de ligne de commande pour la relance 64 bits.
    param($Bound)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($k in $Bound.Keys) {
        $v = $Bound[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $out.Add("-$k") }
        } elseif ($null -ne $v) {
            $out.Add("-$k"); $out.Add([string]$v)
        }
    }
    return $out.ToArray()
}

function Resolve-DefaultReportDir {
    # Le resultat se lit dans la fenetre. Les fichiers (txt/html/csv) restent une trace technique :
    # dans TEMP, jamais sur le Bureau du joueur.
    Join-Path $env:TEMP 'DexCheck'
}

function Get-FindingScreenLines {
    # PUR/testable. Le DETAIL de chaque WARN/FLAG (quel fichier, quelle commande), pour l'ecran de fin.
    # Lu par un moderateur au moment de decider : FLAG d'abord, le sens de l'alerte (montre /
    # ne prouve pas), puis les PREUVES (lignes indentees = fichiers, commandes, dates) avant
    # les notes techniques, 6 lignes max par alerte.
    param($results)
    $out = New-Object System.Collections.Generic.List[string]
    $ordered = @(@($results | Where-Object { $_.Status -eq 'FLAG' }) + @($results | Where-Object { $_.Status -eq 'WARN' }))
    foreach ($r in $ordered) {
        $out.Add(("[{0}] {1} : {2}" -f $r.Status, $r.Name, $r.Summary))
        foreach ($ml in @(Get-MeaningLines $r)) { $out.Add(("    {0}" -f $ml)) }
        $details = @($r.Details | ForEach-Object { [string]$_ })
        $evidence = @($details | Where-Object { $_ -match '^\s{2,}\S' })
        # @( ) : une seule ligne de preuve serait deballee en scalaire et .Count leverait (StrictMode).
        $pick = @(if ($evidence.Count -gt 0) { $evidence } else { $details })
        # Les sondes ajoutent leurs lignes SUSPECTES en dernier (apres volumes, notes, activite
        # recente) : les 6 dernieres. Mesure 17/09 : les 6 premieres montraient des .tmp de
        # compilation et cachaient la vraie ligne suspecte.
        foreach ($d in @($pick | Select-Object -Last 6)) { $out.Add(("    {0}" -f $d.Trim())) }
        if ($pick.Count -gt 6) { $out.Add(("    (+ {0} autre(s) dans la trace %TEMP%\DexCheck)" -f ($pick.Count - 6))) }
    }
    return ,$out
}

function Test-DirWritable {
    # vrai si on peut REELLEMENT ecrire dans $dir (pas juste Test-Path) : ecrit puis
    # supprime un fichier temoin. Couvre OneDrive read-only / verrou AV / droits manquants.
    param([string]$dir)
    try {
        if ([string]::IsNullOrWhiteSpace($dir)) { return $false }
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $dir (".wzc_{0}.tmp" -f ([guid]::NewGuid().ToString('N')))
        [System.IO.File]::WriteAllText($probe, 'x')
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}

function Get-EvasionProfile {
    # PURE testable. Correle les signaux d'EVASION (nettoyage/masquage) entre sondes et decide
    # si le verdict doit monter d'un cran (A VERIFIER -> SUSPECT). GARDE-FOU anti-faux-SUSPECT :
    # les signaux explicables par une OPTIMISATION gaming (USN off, prefetch vide, reinstall
    # recente, cleaner type ccleaner) sont classes "prep" et NE suffisent JAMAIS seuls a escalader
    # (un PC de joueur debloate les cumule souvent). Escalade UNIQUEMENT si un signal "fort" non
    # explicable par l'optimisation (horloge reculee, Defender coupe, outil de wipe reel, journal
    # efface) co-occure avec AU MOINS un autre signal d'evasion.
    param($results)
    $strong = New-Object System.Collections.Generic.List[string]
    $weak   = New-Object System.Collections.Generic.List[string]
    foreach ($r in $results) {
        switch ([string]$r.Id) {
            'IDENT'    { if ($r.Status -eq 'WARN') { $strong.Add('Horloge systeme possiblement reculee') } }
            # FORT seulement si l'antivirus est COUPE ou une exclusion porte un nom de cheat (FLAG).
            # Une exclusion en Downloads/Temp est un conseil courant pour un mod bloque par Defender :
            # signal prep, sinon exclusion + USN off (debloat) donnait SUSPECT sans nom de cheat.
            'DEFENDER' {
                if ($r.Status -eq 'FLAG' -or ($r.Status -eq 'WARN' -and [string]$r.Summary -eq $script:DefenderRealtimeOffSummary)) { $strong.Add('Windows Defender coupe ou exclusion au nom de cheat') }
                elseif ($r.Status -eq 'WARN') { $weak.Add('Exclusion Defender en zone user/temp (dual-use)') }
            }
            'ANTIFOR'  { if ($r.Status -eq 'FLAG') { $strong.Add('Outil d effacement securise (wipe)') } elseif ($r.Status -eq 'WARN') { $weak.Add('Nettoyeur installe (dual-use)') } }
            'EVTLOG'   { if ($r.Status -eq 'FLAG') { $strong.Add('Journaux d evenements effaces') } elseif ($r.Status -eq 'WARN') { $weak.Add('Journal d evenements court/tronque') } }
            'USN'      { if ($r.Status -eq 'WARN') { $weak.Add('Journal USN desactive (historique des suppressions)') } }
            'PREFETCH' { if ($r.Status -eq 'WARN') { $weak.Add('Prefetch vide/desactive') } }
            'WINAGE'   { if ($r.Status -eq 'WARN') { $weak.Add('Windows reinstalle recemment') } }
        }
    }
    $escalate = ($strong.Count -ge 1 -and ($strong.Count + $weak.Count) -ge 2)
    return [pscustomobject]@{ Strong = $strong; Weak = $weak; Total = ($strong.Count + $weak.Count); Escalate = $escalate }
}

# Canaux de preuve DECISIFS : si l'un d'eux n'a pas pu etre lu (NA), un "CLEAN" affirmerait
# l'absence de traces dans un endroit qu'on n'a jamais ouvert. Les sondes -Deep (DEEPFREE,
# DEEPUSN) sont volontairement EXCLUES : elles sont NA sur tout run rapide, meme en admin,
# et les inclure ferait basculer chaque check normal en "A VERIFIER" pour rien.
$script:CoreEvidenceIds = @('PREFETCH','SHIMCACHE','DELFILES','USN','EXEC','PCA','ANTIFOR','WER','EVTLOG','SECBOOT')

# Artefacts d'EXECUTION anti-wipe INDEPENDANTS : deux d'entre eux en FLAG (nom distinctif) = execution
# corroboree -> ROUGE. CILOG ajoute le 14/09 : un refus de chargement de driver au nom de cheat est ecrit
# par le noyau dans son propre journal, independamment du systeme de fichiers (prefetch/USN) et de la
# ruche (shimcache/PCA) : c'est une source de corroboration de plus, pas un doublon.
$script:AntiWipeIds = @('DELFILES','EXEC','SHIMCACHE','PCA','PREFETCH','CILOG')

function Get-Verdict {
    param($results)
    $crit = @($results | Where-Object { $_.Severity -ge 3 })
    $flag = @($results | Where-Object { $_.Status -eq 'FLAG' })
    $warn = @($results | Where-Object { $_.Status -eq 'WARN' })
    if ($crit.Count -gt 0) { return 'ROUGE' }
    # Execution d'un cheat CONFIRMEE (les FLAG anti-wipe sont distinctifs-only depuis la reclassif des
    # mots de categorie) :
    #  - vue sur >=2 artefacts anti-wipe INDEPENDANTS (prefetch/execution/shimcache/PCA/USN-supprime) =
    #    concordance = execution reelle, pas un residu isole -> ROUGE.
    #  - OU vue sur >=1 artefact + un nettoyage COORDONNE (wipe/logs effaces/Defender coupe + corrob.) =
    #    "il a tourne puis efface ses traces" -> ROUGE.
    # Un FLAG anti-wipe SEUL, ou un device (Cronus) seul, reste SUSPECT : un signal isole ne condamne pas.
    $antiWipe = @($flag | Where-Object { $script:AntiWipeIds -contains [string]$_.Id })
    if ($antiWipe.Count -ge 2) { return 'ROUGE' }
    if ($antiWipe.Count -ge 1 -and (Get-EvasionProfile $results).Escalate) { return 'ROUGE' }
    if ($flag.Count -gt 0) { return 'SUSPECT' }
    if ($warn.Count -gt 0) {
        # Un profil d'evasion COORDONNE (signal fort + corroboration) monte A VERIFIER -> SUSPECT.
        if ((Get-EvasionProfile $results).Escalate) { return 'SUSPECT' }
        return 'A VERIFIER'
    }
    # Rien n'a bouge -- mais a-t-on seulement pu REGARDER ? Un canal decisif en NA (typiquement
    # un run sans admin : prefetch, shimcache, USN, journaux, WER...) veut dire "non examine",
    # pas "rien trouve". Rendre CLEAN la reviendrait a certifier une zone jamais ouverte, et
    # l'outil annonce deja "certaines sondes seront N/A". On ne cree PAS de 5e verdict :
    # "A VERIFIER" veut deja dire "un humain doit regarder", ce qui est exactement le cas.
    $blind = @($results | Where-Object { $_.Status -eq 'NA' -and $script:CoreEvidenceIds -contains [string]$_.Id })
    if ($blind.Count -gt 0) { return 'A VERIFIER' }
    return 'CLEAN'
}

$script:Limites = @(
    "Limites (a garder en tete) :",
    "- SSD + TRIM : pas de recuperation fiable du CONTENU des fichiers supprimes. La force",
    "  de l'outil est la TIMELINE (USN/MFT gardent des preuves de suppression : noms + dates).",
    "- Catch le cheater negligent et le wipe juste avant le check. Un cheater determine",
    "  (2e SSD, cheat DMA hardware, OS fraiche bootee pour l'occasion) peut passer.",
    "- Wallhack = lecture de la memoire du jeu : soit un cheat LOGICIEL (PC), soit une carte",
    "  DMA -> radar/ESP affiche sur une 2e machine (Mac/PC). Une carte DMA usurpe ses IDs et",
    "  peut passer ce scan : le check VISUEL du setup (2e PC, carte FPGA, cable USB3 entre les",
    "  machines, radar sur un 2e ecran/tel) reste indispensable. Sur console (PS5) le vrai",
    "  wallhack est quasi impossible (memoire verrouillee) ; le risque console = aimbot/recoil.",
    "- Un PC trop propre / trop neuf est lui-meme suspect.",
    "- Les outils d'input (reWASD, DS4Windows, G HUB...) sont dual-use : presence = a verifier,",
    "  pas un ban automatique. L'admin garde le jugement final."
)

function Get-StatusTally {
    # Ligne de bilan chiffree (pur -> testable). ASCII pur (pas d'unicode : fiable sur tout conhost).
    param($results)
    $ok=0; $info=0; $warn=0; $flag=0; $na=0; $total=0
    foreach($r in $results){ $total++; switch ([string]$r.Status) { 'OK' {$ok++} 'INFO' {$info++} 'WARN' {$warn++} 'FLAG' {$flag++} 'NA' {$na++} } }
    "$ok OK | $info INFO | $warn WARN | $flag FLAG | $na NA   ($total sondes)"
}

function Get-VerdictReasoning {
    # Paragraphe de synthese "ce qui est trouve / ce que ca prouve / ce que ca ne prouve pas".
    # Pur -> testable. Reutilise Get-EvasionProfile (deja teste) + les compteurs de statuts.
    param($results)
    $flags = @($results | Where-Object { $_.Status -eq 'FLAG' })
    $warns = @($results | Where-Object { $_.Status -eq 'WARN' })
    $prof  = Get-EvasionProfile $results
    $out = New-Object System.Collections.Generic.List[string]
    $blind = @($results | Where-Object { $_.Status -eq 'NA' -and $script:CoreEvidenceIds -contains [string]$_.Id })
    if ($flags.Count -eq 0 -and $warns.Count -eq 0) {
        if ($blind.Count -gt 0) {
            $out.Add("Aucune sonde n'a leve de drapeau PARMI CELLES QUI ONT PU LIRE. Mais $($blind.Count) canal(aux) de preuve decisif(s) n'ont PAS ete examines : $(($blind | ForEach-Object { $_.Id }) -join ', ') -- typiquement un check lance sans droits admin. 'Rien trouve' ne porte donc PAS sur ces zones.")
        } else {
            $out.Add("Aucune sonde n'a leve de drapeau : rien de suspect dans ce qu'un check logiciel peut voir.")
        }
    } else {
        if ($blind.Count -gt 0) {
            $out.Add("$($blind.Count) canal(aux) de preuve decisif(s) n'ont PAS pu etre lus : $(($blind | ForEach-Object { $_.Id }) -join ', ') -- le tableau est incomplet.")
        }
        $out.Add("Ont bouge : $($flags.Count) drapeau(x) rouge(s), $($warns.Count) point(s) a verifier.")
        # Corroboration : plusieurs artefacts anti-wipe INDEPENDANTS qui pointent un exe de triche
        # au nom distinctif = execution confirmee, pas un simple soupcon (une trace isolee peut etre
        # un residu ; plusieurs qui concordent, non).
        $corr = @($flags | Where-Object { $script:AntiWipeIds -contains [string]$_.Id })
        if ($corr.Count -ge 2) {
            $out.Add("$($corr.Count) artefacts anti-wipe INDEPENDANTS (prefetch / execution / shimcache / PCA...) pointent un executable de triche au nom distinctif : concordance = execution CONFIRMEE malgre l'effacement du binaire, pas un simple soupcon.")
        }
        if ($prof.Total -ge 2) {
            if ($prof.Escalate) {
                $out.Add("Un signal FORT non explicable par une optimisation + une corroboration co-occurrent : compatible avec un nettoyage COORDONNE juste avant le check (le verdict a ete monte).")
            } else {
                $out.Add("Les signaux sont surtout du type debloat/optimisation gaming (USN off, prefetch vide, reinstall) : explicables sans triche -> pas d'escalade automatique, a recouper visuellement.")
            }
        }
    }
    $out.Add("Portee : ce check ne peut PAS voir un cheat DMA (2e PC + carte), un radar dans un onglet navigateur, ni un OS fraichement reimage. Un verdict propre ne PROUVE pas l'absence de triche - le check visuel du setup reste obligatoire.")
    return $out
}

function Get-VerdictAction {
    # PUR/testable. L'ACTION que le modo doit prendre pour ce verdict -- c'est LE point du headline :
    # l'echec type est de tirer une MAUVAISE ACTION d'un label (accuser sur un SUSPECT). Purement
    # presentation : ne recalcule RIEN, lit le verdict deja calcule par Get-Verdict.
    param([string]$verdict)
    switch ($verdict) {
        'ROUGE'      { return "MONTRER a l'arbitre : artefacts distinctifs corroborants (voir ce qui a ete trouve), faire une capture de cet ecran. Ne pas bannir sur ce seul rapport sans arbitrage." }
        'SUSPECT'    { return "NE PAS accuser : un seul artefact distinctif = a verifier, pas une preuve. Poursuivre le check visuel du setup + croiser la VOD." }
        'A VERIFIER' { return "NE PAS accuser : des points dual-use a recouper. Poursuivre le check visuel du setup." }
        'CLEAN'      { return "Rien de suspect cote logiciel. Poursuivre le check visuel (DMA / 2e PC / OS reimage non couverts) : un verdict propre ne prouve pas l'absence de triche." }
        default      { return "Poursuivre le check visuel du setup." }
    }
}

function Write-Reports {
    param($results, [string]$dir, [datetime]$start, [bool]$degraded, [bool]$deep)
    $verdict = Get-Verdict $results
    $stamp = $start.ToString('yyyyMMdd-HHmmss')
    $base = "DexCheck_${env:COMPUTERNAME}_$stamp"
    $txt = Join-Path $dir "$base.txt"
    $html = Join-Path $dir "$base.html"

    $flags = @($results | Where-Object { $_.Status -eq 'FLAG' })
    $warns = @($results | Where-Object { $_.Status -eq 'WARN' })

    # --- TXT ---
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("==================================================================")
    [void]$sb.AppendLine(" DEXCHECK - PC CHECK FORENSIC   v$script:Version   -   by DrDexter")
    [void]$sb.AppendLine("==================================================================")
    [void]$sb.AppendLine(" Machine    : $env:COMPUTERNAME  /  Utilisateur : $env:USERNAME")
    # ISO 8601 : un rapport forensic est lu par des gens dont on ne connait pas la
    # locale, et `"$start"` rendait le format US (08/15/2026) sur un rapport francais.
    # 2026-08-15 ne peut etre confondu avec rien.
    [void]$sb.AppendLine(" Date       : " + $start.ToString('yyyy-MM-dd HH:mm:ss'))
    if (-not [string]::IsNullOrWhiteSpace($script:Nonce)) { [void]$sb.AppendLine(" Nonce      : $script:Nonce   (dicte par le modo => ce rapport a ete genere LIVE pour cette session)") }
    # Empreinte du SCRIPT qui a produit ce rapport. Sans elle, le rapport annonce sa
    # version ("v1.0.0") sans la PROUVER : un script modifie imprime la meme ligne. Avec
    # elle, le modo compare a l'empreinte officielle et sait s'il lit la sortie du vrai
    # DexCheck. C'est la moitie manquante de la chaine de confiance -- l'autre moitie
    # (le hash du rapport lui-meme) existait deja.
    # LIMITE ASSUMEE : un script hostile peut imprimer l'empreinte officielle au lieu de
    # la sienne. Ca n'arrete pas un faussaire determine ; ca rend une modification naive
    # visible et ca permet de VERIFIER un run honnete. La confiance de fond reste
    # "le modo fournit le script".
    [void]$sb.AppendLine(" Script     : " + $script:SelfHash)
    [void]$sb.AppendLine(" Mode       : " + $(if($deep){'APPROFONDI (-Deep)'}else{'rapide'}) + $(if($degraded){'  [DEGRADE - sans admin]'}else{''}))
    [void]$sb.AppendLine(" VERDICT    : $verdict")
    [void]$sb.AppendLine(" ACTION     : $(Get-VerdictAction $verdict)")
    [void]$sb.AppendLine(" BILAN      : $(Get-StatusTally $results)")
    [void]$sb.AppendLine("------------------------------------------------------------------")
    [void]$sb.AppendLine(" RAISONNEMENT (ce qui est trouve / ce que ca prouve / ce que ca ne prouve pas) :")
    foreach($rl in (Get-VerdictReasoning $results)){ [void]$sb.AppendLine("   $rl") }
    [void]$sb.AppendLine("------------------------------------------------------------------")
    if ($flags.Count -gt 0) {
        [void]$sb.AppendLine(" DRAPEAUX ROUGES :")
        foreach($f in $flags){ [void]$sb.AppendLine("   [FLAG] $($f.Name) : $($f.Summary)") }
        [void]$sb.AppendLine("")
    }
    if ($warns.Count -gt 0) {
        [void]$sb.AppendLine(" A VERIFIER :")
        foreach($w in $warns){ [void]$sb.AppendLine("   [WARN] $($w.Name) : $($w.Summary)") }
        [void]$sb.AppendLine("")
    }
    $prof = Get-EvasionProfile $results
    if ($prof.Total -ge 2) {
        [void]$sb.AppendLine(" PROFIL D'EVASION (signaux de nettoyage/masquage qui co-occurrent) :")
        foreach($s in $prof.Strong){ [void]$sb.AppendLine("   [fort] $s") }
        foreach($s in $prof.Weak){   [void]$sb.AppendLine("   [prep] $s") }
        if ($prof.Escalate) {
            [void]$sb.AppendLine("   => Un signal FORT (non explicable par une optimisation) + corroboration : compatible")
            [void]$sb.AppendLine("      avec un nettoyage COORDONNE avant le check. Verdict monte a SUSPECT.")
        } else {
            [void]$sb.AppendLine("   => Signaux souvent explicables par une optimisation gaming (debloat) : PAS d'escalade")
            [void]$sb.AppendLine("      automatique, mais a recouper visuellement (l'admin garde le jugement final).")
        }
        [void]$sb.AppendLine("")
    }
    [void]$sb.AppendLine("------------------------------------------------------------------")
    [void]$sb.AppendLine(" DETAIL PAR SONDE :")
    foreach($r in $results){
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine(" [$($r.Status)] $($r.Name) -- $($r.Summary)")
        foreach($ml in (Get-MeaningLines $r)){ [void]$sb.AppendLine("      $ml") }
        foreach($d in $r.Details){ [void]$sb.AppendLine("      $d") }
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("------------------------------------------------------------------")
    foreach($l in $script:Limites){ [void]$sb.AppendLine(" $l") }
    [System.IO.File]::WriteAllText($txt, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    # --- HTML : verdict + action, puis les FLAG/WARN DEPLIES (avec Montre / Ne prouve pas), le reste
    #     (OK/INFO/NA) REPLIE dans un <details> : le modo lit d'abord ce qui compte. ---
    $colorMap = @{ OK='#1f9d55'; INFO='#0ea5e9'; WARN='#d97706'; FLAG='#dc2626'; NA='#6b7280'; ERROR='#9333ea' }
    $rowOf = {
        param($r, [bool]$open)
        $c = $colorMap[$r.Status]; if (-not $c) { $c = '#6b7280' }
        $det = ($r.Details | ForEach-Object { ConvertTo-HtmlText $_ }) -join '<br>'
        $meaning = (Get-MeaningLines $r | ForEach-Object { ConvertTo-HtmlText $_ }) -join '<br>'
        if ($meaning) { $det = "<span style='color:#cbd5e1'>$meaning</span><br>$det" }
        $o = if ($open) { ' open' } else { '' }
        "<details$o><summary><span class='st' style='color:$c'>$($r.Status)</span> <b>$(ConvertTo-HtmlText $r.Name)</b> &mdash; $(ConvertTo-HtmlText $r.Summary)</summary><div class='det'>$det</div></details>"
    }
    $hot  = @($results | Where-Object { $_.Status -in @('FLAG','WARN','ERROR') })
    $rest = @($results | Where-Object { $_.Status -notin @('FLAG','WARN','ERROR') })
    $hotHtml  = ($hot  | ForEach-Object { & $rowOf $_ $true })  -join "`n"
    $restHtml = ($rest | ForEach-Object { & $rowOf $_ $false }) -join "`n"
    $vColor = switch ($verdict) { 'CLEAN' {'#1f9d55'} 'A VERIFIER' {'#d97706'} 'SUSPECT' {'#dc2626'} 'ROUGE' {'#991b1b'} default {'#6b7280'} }
    $limHtml = ($script:Limites | ForEach-Object { ConvertTo-HtmlText $_ }) -join '<br>'
    $hotTitle = if ($hot.Count -gt 0) { "$($hot.Count) point(s) a regarder (FLAG / WARN)" } else { "Aucun FLAG ni WARN" }
    $htmlDoc = @"
<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'><title>DexCheck $env:COMPUTERNAME</title>
<style>body{background:#0f1115;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif;margin:24px;max-width:1100px}
h1{font-size:20px}h2{font-size:15px;margin:22px 0 8px;color:#cbd5e1}.v{display:inline-block;padding:4px 12px;border-radius:6px;color:#fff;background:$vColor;font-weight:bold}
.act{background:#171a21;border-left:4px solid $vColor;padding:8px 12px;margin:10px 0;font-size:14px}
details{border-bottom:1px solid #1f2430;padding:6px 0}summary{cursor:pointer;font-size:14px}.st{font-weight:bold;display:inline-block;min-width:44px}
.det{color:#9ca3af;font-size:12px;padding:6px 0 4px 52px;white-space:pre-wrap}
.meta{color:#9ca3af;font-size:12px}.lim{margin-top:20px;color:#9ca3af;font-size:12px;border-top:1px solid #1f2430;padding-top:12px}</style></head><body>
<h1>DEXCHECK - PC Check forensic <span style='color:#6b7280;font-size:13px'>v$script:Version &middot; by DrDexter</span></h1>
<p>Machine <b>$env:COMPUTERNAME</b> / $env:USERNAME &middot; $($start.ToString('yyyy-MM-dd HH:mm:ss'))$(if(-not [string]::IsNullOrWhiteSpace($script:Nonce)){" &middot; nonce <b>$(ConvertTo-HtmlText $script:Nonce)</b>"}) &middot; Verdict : <span class='v'>$verdict</span></p>
<div class='act'><b>ACTION :</b> $(ConvertTo-HtmlText (Get-VerdictAction $verdict))</div>
<p class='meta'>Bilan : $(ConvertTo-HtmlText (Get-StatusTally $results)) &middot; Mode $(if($deep){'approfondi (-Deep)'}else{'rapide'})$(if($degraded){' &middot; <b>DEGRADE (sans admin)</b>'}) &middot; Empreinte du script : <code>$(ConvertTo-HtmlText $script:SelfHash)</code></p>
<p style='color:#cbd5e1;font-size:13px'>$((Get-VerdictReasoning $results | ForEach-Object { ConvertTo-HtmlText $_ }) -join '<br>')</p>
<h2>$hotTitle</h2>
$hotHtml
<h2>Autres sondes ($($rest.Count) : OK / INFO / NA) &mdash; cliquer pour deplier</h2>
$restHtml
<div class='lim'>$limHtml</div></body></html>
"@
    [System.IO.File]::WriteAllText($html, $htmlDoc, (New-Object System.Text.UTF8Encoding($true)))

    return [pscustomobject]@{ Txt=$txt; Html=$html; Verdict=$verdict }
}

function Get-FreshnessWall {
    # Pur -> testable. Le "mur de fraicheur" : sur un Windows VIEUX, si plusieurs sources a BASELINE
    # LONGUE demarrent TOUTES bien apres l'install ET de facon SYNCHRONISEE, c'est le pattern d'un
    # nettoyage synchronise (tout commence il y a 3 jours sur un Windows de 2 ans). PRESENTATION
    # SEULE : ne touche jamais le verdict (la sonde TIMELINE n'emet que OK/INFO, Id absent de
    # Get-EvasionProfile). Garde-fous anti-faux-SUSPECT : Windows recent -> pas de mur (reinstall =
    # tout jeune, normal) ; <2 sources utilisables -> pas de mur (un point n'est pas un mur) ; une
    # source qui remonte pres de l'install -> pas de mur (vieille histoire presente). Les sources en
    # FENETRE GLISSANTE (USN, Prefetch sature, Shimcache...) sont exclues par l'appelant (Usable=$false).
    param([datetime]$InstallDate, [datetime]$Now, $Sources)
    # $Sources = liste de @{ Name; Oldest([datetime] ou $null); Usable([bool]) }
    $installAgeDays = ($Now - $InstallDate).TotalDays
    $res = [ordered]@{ Wall=$false; Reason=''; InstallAgeDays=[int]$installAgeDays; WindowStart=$null; WindowEnd=$null; Used=@() }
    if ($installAgeDays -lt 180) { $res.Reason = "Windows recent (<180j) : timeline non significative (une reinstall rend tout jeune, c'est normal)"; return [pscustomobject]$res }
    $usable = @($Sources | Where-Object { $_ -and $_.Usable -and $_.Oldest })
    if ($usable.Count -lt 2) { $res.Reason = "moins de 2 sources a baseline longue utilisables : pas de mur (un point n'est pas un mur)"; return [pscustomobject]$res }
    # TOUTES les sources utilisables doivent demarrer >30j apres l'install ; si une seule remonte
    # pres de l'install, il y a une vraie vieille histoire -> pas un mur.
    $late = @($usable | Where-Object { ((($_.Oldest) - $InstallDate)).TotalDays -gt 30 })
    if ($late.Count -ne $usable.Count) { $res.Reason = "au moins une source remonte pres de l'install (vieille histoire presente) : pas de mur"; return [pscustomobject]$res }
    $dates = @($usable | ForEach-Object { $_.Oldest } | Sort-Object)
    $span = ($dates[-1] - $dates[0]).TotalDays
    $res.Used = @($usable | ForEach-Object { $_.Name })
    if ($span -le 14) {
        $res.Wall = $true; $res.WindowStart = $dates[0]; $res.WindowEnd = $dates[-1]
        $res.Reason = "pattern compatible avec un nettoyage SYNCHRONISE : les traces de $($usable.Count) sources demarrent dans une fenetre de $([int]$span)j, bien apres un Windows de $([int]$installAgeDays)j - a recouper, NE CONDAMNE PAS seul"
    } else {
        $res.Reason = "les sources demarrent tard mais DESYNCHRONISEES (etalees sur $([int]$span)j) : pas un mur (accidents independants, pas un wipe unique)"
    }
    return [pscustomobject]$res
}

function Probe-Timeline {
    $details = New-Object System.Collections.Generic.List[string]
    $now = Get-Date
    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {
        return (New-ProbeResult -Id 'TIMELINE' -Name 'Mur de fraicheur (timeline)' -Status 'NA' -Severity 0 -Summary "Date d'installation Windows non lisible" -Details $details)
    }
    $install = $os.InstallDate
    $sources = New-Object System.Collections.Generic.List[object]
    # Source 1 : journal System (plus vieil event). Utilisable dans le CALCUL seulement si pas plein
    # (fill<50%) : un log plein = rollover naturel = "recent" ne prouve rien.
    try {
        $oldestEvt = Get-WinEvent -LogName System -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($null -ne $oldestEvt) {
            $fill = $null
            try { $li = Get-WinEvent -ListLog System -ErrorAction SilentlyContinue; if ($null -ne $li -and $li.MaximumSizeInBytes -gt 0) { $fill = $li.FileSize / [double]$li.MaximumSizeInBytes } } catch { }
            $evtUsable = ($null -ne $fill -and $fill -lt 0.5)
            $note = if ($evtUsable) { 'baseline longue' } elseif ($null -ne $fill) { 'log plein (rollover) - hors calcul' } else { 'remplissage inconnu - hors calcul' }
            $sources.Add([pscustomobject]@{ Name='Journal System'; Oldest=$oldestEvt.TimeCreated; Usable=$evtUsable; Note=$note })
        }
    } catch { }
    # Source 2 : Prefetch (plus vieux .pf). Utilisable seulement si la fenetre n'est pas saturee
    # (<900 fichiers) : a 1024 la rotation efface les vieux = "recent" normal.
    try {
        $pf = @(Get-ChildItem "$script:SysDrive\Windows\Prefetch" -Filter *.pf -File -ErrorAction SilentlyContinue)
        if ($pf.Count -gt 0) {
            $oldestPf = ($pf | Sort-Object CreationTime | Select-Object -First 1).CreationTime
            $pfUsable = ($pf.Count -lt 900)
            $note = if ($pfUsable) { 'baseline longue' } else { 'fenetre saturee (>=900 .pf) - hors calcul' }
            $sources.Add([pscustomobject]@{ Name='Prefetch'; Oldest=$oldestPf; Usable=$pfUsable; Note=$note })
        }
    } catch { }
    $details.Add("Date d'installation Windows : $install (reference).")
    foreach ($s in $sources) { $details.Add(("  {0} : plus vieil artefact {1} ({2})" -f $s.Name, $s.Oldest, $s.Note)) }
    $details.Add("Sources en FENETRE GLISSANTE (USN/Shimcache/PCA/navigateur/DNS) exclues du calcul : leur plus vieil artefact est recent par nature, ca ne prouve aucun nettoyage.")
    $wall = Get-FreshnessWall -InstallDate $install -Now $now -Sources $sources
    if ($wall.Wall) {
        $details.Add("Fenetre de nettoyage estimee : $($wall.WindowStart) -> $($wall.WindowEnd).")
        New-ProbeResult -Id 'TIMELINE' -Name 'Mur de fraicheur (timeline)' -Status 'INFO' -Severity 0 -Summary ("MUR DE FRAICHEUR : " + $wall.Reason) -Details $details
    } else {
        New-ProbeResult -Id 'TIMELINE' -Name 'Mur de fraicheur (timeline)' -Status 'INFO' -Severity 0 -Summary ("Pas de mur de fraicheur - " + $wall.Reason) -Details $details
    }
}

# ============================================================================
# MAIN
# ============================================================================

function Invoke-DexCheck {
    $start = Get-Date
    $script:IsAdmin = Test-Admin
    $degraded = -not $script:IsAdmin
    # nonce : nettoye ("/backtick -> arg casse a l'elevation), stocke pour affichage + rapport + hash
    $script:Nonce = if ($Nonce) { ($Nonce -replace '["`]', '').Trim() } else { '' }

    # Elevation (ignoree si pas de chemin de script -> dot-source/iex : on reste en degrade)
    if (-not $script:IsAdmin -and -not $NoElevate -and -not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        try {
            $argList = @('-NoProfile','-ExecutionPolicy','Bypass','-File', ('"{0}"' -f $PSCommandPath))
            if ($Deep)    { $argList += '-Deep' }
            if ($NoPause) { $argList += '-NoPause' }
            if (-not [string]::IsNullOrWhiteSpace($script:Nonce)) { $argList += @('-Nonce', ('"{0}"' -f $script:Nonce)) }
            if ($Deep -and $FreeSpaceCapMB -ne 1024) { $argList += @('-FreeSpaceCapMB', "$FreeSpaceCapMB") }
            # chemin explicite vers Windows PowerShell 5.1 (PSHOME pointe pwsh si lance sous PS7)
            $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if (-not (Test-Path $psExe)) { $psExe = 'powershell.exe' }
            Start-Process -FilePath $psExe -Verb RunAs -ArgumentList $argList -ErrorAction Stop
            return  # l'instance elevee prend le relais
        } catch {
            $degraded = $true
            Write-Host "`n  UAC refuse -> mode DEGRADE (sans admin), couverture partielle.`n" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "  ==================================================================" -ForegroundColor Cyan
    Write-Host "   DEXCHECK - PC CHECK FORENSIC   v$script:Version   -   by DrDexter" -ForegroundColor Cyan
    Write-Host "  ==================================================================" -ForegroundColor Cyan
    Write-Host ("   Machine $env:COMPUTERNAME / $env:USERNAME  -  admin: {0}{1}" -f $script:IsAdmin, $(if($Deep){' - mode -Deep'}else{''})) -ForegroundColor DarkCyan
    if (-not [string]::IsNullOrWhiteSpace($script:Nonce)) { Write-Host ("   Nonce (anti-rejeu, dicte par le modo) : {0}" -f $script:Nonce) -ForegroundColor Magenta }
    if ($degraded) { Write-Host "   [MODE DEGRADE : sans droits admin, certaines sondes seront N/A]" -ForegroundColor Yellow }
    Write-Host ""

    $probes = @(
        @{ Name='Identite & horloge';            Fn=${function:Probe-Identity} }
        @{ Name='Virtualisation (VM / hyperviseur)'; Fn=${function:Probe-Virtualization} }
        @{ Name='Age de Windows';                Fn=${function:Probe-WindowsAge} }
        @{ Name='USN Journal (etat)';            Fn=${function:Probe-Usn} }
        @{ Name='Fichiers supprimes (USN)';      Fn=${function:Probe-DeletedFiles} }
        @{ Name='Prefetch';                      Fn=${function:Probe-Prefetch} }
        @{ Name="Traces d'execution (anti-wipe)"; Fn=${function:Probe-ExecEvidence} }
        @{ Name='Shimcache (AppCompatCache)';     Fn=${function:Probe-Shimcache} }
        @{ Name='PCA lancements (Win11, anti-wipe)'; Fn=${function:Probe-Pca} }
        @{ Name='Processus & injections';        Fn=${function:Probe-Processes} }
        @{ Name='Connexions reseau live';        Fn=${function:Probe-Network} }
        @{ Name='Persistence';                   Fn=${function:Probe-Persistence} }
        @{ Name="Journaux d'evenements";         Fn=${function:Probe-EventLogs} }
        @{ Name='Outils anti-forensic/wipe';     Fn=${function:Probe-AntiForensic} }
        @{ Name='Navigateurs (sites cheats)';    Fn=${function:Probe-Browsers} }
        @{ Name='Historique PowerShell';         Fn=${function:Probe-PsHistory} }
        @{ Name='Installs de driver/service (7045)'; Fn=${function:Probe-DriverInstalls} }
        @{ Name='Cache DNS / hosts';             Fn=${function:Probe-DnsCache} }
        @{ Name='Corbeille';                     Fn=${function:Probe-RecycleBin} }
        @{ Name='Hardware / DMA / capture';      Fn=${function:Probe-Hardware} }
        @{ Name='Cartes PCIe / DMA';             Fn=${function:Probe-DmaPci} }
        @{ Name='Posture de protection DMA (VBS/IOMMU)'; Fn=${function:Probe-DmaPosture} }
        @{ Name='Identite materielle (HWID / spoof)'; Fn=${function:Probe-Hwid} }
        @{ Name='Journal Code Integrity (drivers refuses)'; Fn=${function:Probe-CodeIntegrity} }
        @{ Name='Mur de fraicheur (timeline)';    Fn=${function:Probe-Timeline} }
        @{ Name='Points de restauration (Shadow Copies)'; Fn=${function:Probe-ShadowCopies} }
        @{ Name='Securite systeme';              Fn=${function:Probe-SystemSecurity} }
        @{ Name='Exclusions Windows Defender';   Fn=${function:Probe-DefenderExclusions} }
        @{ Name='Drivers kernel (BYOVD)';        Fn=${function:Probe-KernelDrivers} }
        @{ Name='Injection / hijack (AppInit/IFEO)'; Fn=${function:Probe-Injection} }
        @{ Name='Cheats logiciels connus';       Fn=${function:Probe-KnownCheats} }
        @{ Name='Manipulation input / anti-recoil'; Fn=${function:Probe-InputManipulation} }
        @{ Name='Historique USB (devices debranches)'; Fn=${function:Probe-UsbHistory} }
        @{ Name='Historique menaces Defender';    Fn=${function:Probe-DefenderThreats} }
        @{ Name='Scripts anti-recoil Cronus (.gpc)'; Fn=${function:Probe-GpcScripts} }
        @{ Name="Rapports d'erreur (WER, anti-wipe)"; Fn=${function:Probe-WerCrashes} }
        @{ Name='Fichiers recents / Executer (RecentDocs, RunMRU)'; Fn=${function:Probe-RecentActivity} }
        @{ Name='Provenance des telechargements (Mark-of-the-Web)'; Fn=${function:Probe-DownloadProvenance} }
    )
    if ($Deep) {
        $probes += @{ Name='[-Deep] Dump USN suppressions (CSV)'; Fn=${function:Probe-DeepUsnDump} }
        $probes += @{ Name='[-Deep] Scan signatures espace libre'; Fn=${function:Probe-DeepFreeSpaceScan} }
    }

    $script:RunStamp = $start.ToString('yyyyMMdd-HHmmss')
    $preferredDir = if (-not [string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir } else { Resolve-DefaultReportDir }
    if (-not (Test-Path -LiteralPath $preferredDir)) { try { New-Item -ItemType Directory -Force -Path $preferredDir | Out-Null } catch { } }
    $script:ReportDir = if (Test-DirWritable $preferredDir) { $preferredDir } else { $env:TEMP }

    $results = New-Object System.Collections.Generic.List[object]
    $idx = 0
    Write-Host ("   {0} sondes, lecture seule. Chaque ligne = une sonde terminee." -f $probes.Count) -ForegroundColor DarkGray
    foreach($p in $probes){
        $idx++
        # ligne de progression ecrasee par le resultat : le joueur/modo voit ce qui tourne, jamais un ecran fige
        Write-Host ("  [{0,2}/{1}] {2} ..." -f $idx, $probes.Count, $p.Name) -ForegroundColor DarkGray -NoNewline
        $r = $null
        try {
            $r = & $p.Fn
        } catch {
            $r = New-ProbeResult -Id 'ERR' -Name $p.Name -Status 'ERROR' -Severity 1 -Summary ("Exception: " + $_.Exception.Message)
        }
        if ($null -eq $r) { $r = New-ProbeResult -Id 'ERR' -Name $p.Name -Status 'ERROR' -Severity 1 -Summary 'Aucun resultat retourne' }
        Write-Host ("`r" + (' ' * 78) + "`r") -NoNewline
        Write-ProbeLine $r -Index $idx -Total $probes.Count
        $results.Add($r)
    }

    # rapport (filet : si l'ecriture echoue, repli sur TEMP, puis abandon propre)
    $rep = $null
    try { $rep = Write-Reports -results $results -dir $script:ReportDir -start $start -degraded $degraded -deep ([bool]$Deep) }
    catch {
        $script:ReportDir = $env:TEMP
        try { $rep = Write-Reports -results $results -dir $script:ReportDir -start $start -degraded $degraded -deep ([bool]$Deep) } catch { }
    }
    if ($null -eq $rep) {
        Write-Host "`n  [ERREUR] Impossible d'ecrire le rapport (TEMP inaccessible)." -ForegroundColor Red
        if (-not $NoPause) { try { Read-Host "  Entree pour fermer" | Out-Null } catch { } }
        return
    }

    Write-Host ""
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor Cyan
    $vcol = switch ($rep.Verdict) { 'CLEAN' {'Green'} 'A VERIFIER' {'Yellow'} 'SUSPECT' {'Red'} 'ROUGE' {'Red'} default {'Gray'} }
    $tcol = if (@($results | Where-Object { $_.Status -eq 'FLAG' }).Count -gt 0) { 'Red' } elseif (@($results | Where-Object { $_.Status -eq 'WARN' }).Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("   BILAN   : {0}" -f (Get-StatusTally $results)) -ForegroundColor $tcol
    Write-Host "  ==================================================================" -ForegroundColor $vcol
    Write-Host ("   VERDICT : {0}" -f $rep.Verdict) -ForegroundColor $vcol
    Write-Host "  ==================================================================" -ForegroundColor $vcol
    Write-Host ("   ACTION  : {0}" -f (Get-VerdictAction $rep.Verdict)) -ForegroundColor $vcol
    foreach($rl in (Get-VerdictReasoning $results)){ Write-Host ("   $rl") -ForegroundColor DarkGray }
    $finding = Get-FindingScreenLines $results
    if ($finding.Count -gt 0) {
        Write-Host ""
        Write-Host "   CE QUI A ETE TROUVE :" -ForegroundColor $vcol
        foreach ($fl in $finding) { Write-Host ("   $fl") -ForegroundColor Gray }
    }
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    if (-not $NoPause) {
        try { Read-Host "  Appuie sur Entree pour fermer" | Out-Null } catch { }
    }
    return $rep
}

if (-not $NoRun) {
    $native = Get-Native64PowerShell -Is64BitOS ([Environment]::Is64BitOperatingSystem) `
        -Is64BitProcess ([Environment]::Is64BitProcess) -WinDir $env:WINDIR
    if ($native -and $PSCommandPath -and (Test-Path -LiteralPath $native)) {
        Write-Host "  PowerShell 32 bits detecte : relance en 64 bits (sinon registre et pilotes seraient mal lus)." -ForegroundColor Yellow
        & $native -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @(ConvertTo-ArgList $PSBoundParameters)
        exit $LASTEXITCODE
    }
    Invoke-DexCheck | Out-Null
}
