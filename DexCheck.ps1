<#
    DexCheck.ps1 - PC check forensic anti-triche (CoD/Warzone)
    Auteur : Alexandre Blanchard (DrDexter). Deploye pour la communaute Warzup.
    Usage joueur : clic-droit > Executer avec PowerShell, ou via LANCER-LE-CHECK.txt.
    Le script s'auto-eleve en admin (UAC). En screenshare, le rapport defile en direct :
    c'est CA la preuve. Le hash SHA256 affiche a la fin rend le rapport SAUVEGARDE
    infalsifiable (toute edition ulterieure du fichier change le hash) ; il ne prouve PAS
    un run honnete. Confiance = le MODO fournit le script (ou en verifie le hash) et
    regarde le direct, le joueur ne se check pas avec un script qu'il a apporte.

    Switches :
      -Deep       analyse approfondie (plus lent, pour un joueur deja suspect)
      -Nonce      mot dicte par le modo au moment du check : imprime a l'ecran + dans le
                  rapport, donc plie dans le hash SHA256. Prouve que le rapport a ete
                  genere LIVE pour CETTE session (anti-rapport-prefabrique / anti-rejeu).
      -NoElevate  ne pas tenter l'elevation UAC (tests)
      -NoPause    ne pas attendre une touche a la fin (tests / automation)
      -OutputDir  dossier de sortie du rapport (defaut : Bureau)

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

$script:Version  = '1.0.0'
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
    @{ Name='Strike Pack (Collective Minds)'; App=@('strike pack','collective minds'); Driver=@(); Usb=@('strike pack','collective minds'); Severity=1 }
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
$script:CheatFlagWords = @(
    'engineowning','enginowning','phantomoverlay','lavicheats','interwebz','memesense',
    'fecurity','disconnect.gg','coldware','coldvision','hypervision','hypercheats',
    'ring-1','susano','abstrakt','klarcheats','cobraaim','aimbot','wallhack','triggerbot',
    'unlockall','unlock_all','spoofer','hwidspoofer','cronus','xim',
    'bleachbit','privazer','injector','skript.gg'
)
# reWASD = outil de remap LEGITIME (dual-use) -> WARN, jamais FLAG (decision Alex 03/07 : un mec
# clean ne doit pas ressortir SUSPECT ; seul un VRAI cheat FLAG). Cronus/XIM restent FLAG (hardware
# d'anti-recoil = vraie triche, sev2 dans InputTools).
$script:CheatWarnWords = @('cheat','loader','skript','hwid','cleaner','unlocker','rewasd')
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
                        res.Total++;
                        if (ts > 0) {
                            if (res.OldestTicks == 0 || ts < res.OldestTicks) res.OldestTicks = ts;
                            if (ts > res.NewestTicks) res.NewestTicks = ts;
                        }
                        res.Recent.Add(new Rec { Name = nm, Time = dt, Reason = reason, Attributes = attrs });
                        if (res.Recent.Count > maxRecent) res.Recent.RemoveAt(0);
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
    DNS       = @{ Shows="un domaine de cheat a ete resolu (cache DNS, par n'importe quel process) ou est fige dans le fichier hosts"; ProvesNot="resoudre/pinger un domaine n'est ni l'avoir achete ni l'avoir utilise en match ; le cache DNS se vide au reboot / a l'expiration du TTL" }
    HARDWARE  = @{ Shows="un device type DMA / capture / rig est present"; ProvesNot="une carte de capture = streamer normal ; une carte DMA bien configuree usurpe ses IDs et peut passer -> check visuel obligatoire" }
    DMAPCI    = @{ Shows="une carte PCIe FPGA (Xilinx/pcileech) ou un device PCIe sans driver = support materiel possible d'un wallhack/radar DMA sur 2e machine"; ProvesNot="dev-boards FPGA et devices sans driver legitimes declenchent aussi ; une carte DMA bien firmware-spoofee usurpe ses IDs et reste INVISIBLE a ce scan read-only -> check visuel obligatoire" }
    SECBOOT   = @{ Shows="le PC autorise des drivers non signes (testsigning/nointegritychecks) = porte pour un cheat kernel"; ProvesNot="certains outils/dev legitimes l'activent aussi - c'est une porte ouverte, pas une preuve" }
    NET       = @{ Shows="un process parle a Internet pendant la session"; ProvesNot="quasi tout process legitime a des connexions ; seul un nom de cheat connu compte ici" }
    CHEATS    = @{ Shows="un provider de cheat connu est installe / present"; ProvesNot="presence du fichier n'est pas un usage prouve en match - a confirmer visuellement" }
    INPUT     = @{ Shows="un outil de remap/anti-recoil ou un device (Cronus/XIM) est present"; ProvesNot="manette et remap = dual-use legitime ; seul le hardware anti-recoil est un signal fort" }
    VM        = @{ Shows="le check tourne peut-etre dans une VM pendant qu'on joue sur l'hote (evasion screenshare)"; ProvesNot="Hyper-V/VBS/WSL sont presents sur des machines reelles Win11 - a confirmer visuellement" }
    DEFENDER  = @{ Shows="une exclusion ou une protection coupee peut cacher un cheat de l'antivirus"; ProvesNot="beaucoup d'exclusions sont legitimes (jeux, dev) - le contexte compte" }
    KDRV      = @{ Shows="un driver kernel non signe ou connu abusable (BYOVD) = acces kernel possible pour un cheat"; ProvesNot="ces drivers sont souvent dual-use (Afterburner/HWiNFO/monitoring) - a confirmer" }
    INJECT    = @{ Shows="un point d'injection DLL (AppInit/AppCert/IFEO) est positionne = un overlay/cheat peut se charger dans le jeu"; ProvesNot="quelques outils legitimes en posent - valeur non vide = a verifier, pas a bannir" }
}

function Get-MeaningLines {
    # Rend les 2 lignes "Montre / Ne prouve pas" pour un WARN/FLAG ; vide sinon. Pur -> testable.
    param($r)
    if ($r.Status -notin @('WARN','FLAG')) { return @() }
    $m = $script:ProbeMeaning[$r.Id]
    if ($null -eq $m) { return @() }
    # Sur un FLAG (= nom de cheat DISTINCTIF par construction, jamais generique), on affiche une
    # formulation FERME quand elle existe : pas de hedge "dual-use" qui ne s'applique pas ici.
    $shows = if ($r.Status -eq 'FLAG' -and $m.ShowsFlag)     { $m.ShowsFlag }     else { $m.Shows }
    $pnot  = if ($r.Status -eq 'FLAG' -and $m.ProvesNotFlag) { $m.ProvesNotFlag } else { $m.ProvesNot }
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
    param($r)
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
    Write-Host ("  {0} {1,-30}" -f $tag, $r.Name) -ForegroundColor $color -NoNewline
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
    foreach ($drive in $drives) {
        $scan = $null
        try { $scan = Get-UsnScan -Volume $drive -FlagPatterns $flagPat -WarnPatterns $script:CheatWarnWords } catch { $details.Add("  $drive : USN illisible/inactif (ignore)"); continue }
        $readAny = $true
        $t = [int64]$scan.Total
        $grandTotal += $t
        if ($scan.OldestTicks -gt 0 -and $scan.NewestTicks -gt 0) {
            try {
                $o = [DateTime]::FromFileTime($scan.OldestTicks); $n = [DateTime]::FromFileTime($scan.NewestTicks); $sp = $n - $o
                $details.Add(("  {0} : {1} suppression(s), fenetre {2:yyyy-MM-dd HH:mm} -> {3:yyyy-MM-dd HH:mm} (~{4} j)" -f $drive, $t, $o, $n, [int]$sp.TotalDays))
            } catch { $details.Add("  $drive : $t suppression(s)") }
        } else { $details.Add("  $drive : $t suppression(s)") }
        foreach ($s in $scan.FlagSuspects) { $flagAll.Add([pscustomobject]@{ Time = $s.Time; Name = ("[$drive] " + [string]$s.Name) }) }
        foreach ($s in $scan.WarnSuspects) { $warnAll.Add([pscustomobject]@{ Time = $s.Time; Name = ("[$drive] " + [string]$s.Name) }) }
        foreach ($r in $scan.Recent) { $recentAll.Add([pscustomobject]@{ Time = $r.Time; Name = ("[$drive] " + [string]$r.Name) }) }
    }
    if (-not $readAny) {
        return (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'NA' -Severity 0 -Summary "Aucun journal USN lisible (inactif sur tous les volumes ?)" -Details $details)
    }
    $details.Add("Total suppressions (tous volumes) : $grandTotal. Chaque journal est scanne EN ENTIER ; le match suspect couvre 100%, pas un echantillon biaise vers les vieilles entrees.")
    $details.Add("NOTE fenetre : le journal USN 'tourne' (wrap) a sa taille max = une fenetre courte est NORMALE sur machine active ; tres courte sur PC ancien et peu actif = a creuser (purge/recreation).")
    $recent = @($recentAll | Sort-Object Time -Descending | Select-Object -First 10)
    if ($recent.Count -gt 0) {
        $details.Add("Plus recentes (tous volumes) :")
        foreach ($d in $recent) { $details.Add(("  {0:yyyy-MM-dd HH:mm}  {1}" -f $d.Time, $d.Name)) }
    }
    $flagHits = @($flagAll | Sort-Object Time -Descending)
    $warnHits = @($warnAll | Sort-Object Time -Descending)
    if ($flagHits.Count -gt 0) {
        $details.Add("SUPPRESSIONS AU NOM DE CHEAT (distinctif, tous volumes) :")
        foreach ($h in ($flagHits | Select-Object -First 25)) { $details.Add(("  {0:yyyy-MM-dd HH:mm}  {1}" -f $h.Time, $h.Name)) }
        if ($warnHits.Count -gt 0) { $details.Add("(+ $($warnHits.Count) suppression(s) au nom generique loader/cheat - listees a part)") }
        return (New-ProbeResult -Id 'DELFILES' -Name 'Fichiers supprimes (USN)' -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) suppression(s) au nom de cheat distinctif" -Details $details)
    }
    if ($warnHits.Count -gt 0) {
        $details.Add("SUPPRESSIONS AU NOM GENERIQUE (loader/cheat/skript... = dual-use, a verifier, PAS un ban) :")
        foreach ($h in ($warnHits | Select-Object -First 25)) { $details.Add(("  {0:yyyy-MM-dd HH:mm}  {1}" -f $h.Time, $h.Name)) }
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

    $uaRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
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

    $flagPat = Get-CheatFlagPatterns
    $warnPat = @($script:CheatWarnWords)

    $total = $execs.Count
    $details.Add("Traces d'execution lues : $total (BAM/DAM = derniere exec + chemin ; UserAssist = lancements GUI). Ces artefacts survivent a la suppression du binaire.")
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

function Probe-Processes {
    $details = New-Object System.Collections.Generic.List[string]
    $procs = Get-CimInstance Win32_Process -ErrorAction Stop
    $cheatPat = @(); foreach($c in $script:CheatSoftware){ if(-not $c.GenericName){ $cheatPat += $c.Patterns } }
    $suspect = New-Object System.Collections.Generic.List[string]
    $userDirs = @('\temp\','\downloads\','\appdata\local\temp\','\users\public\')
    foreach ($p in $procs) {
        $name = $p.Name; $path = $p.ExecutablePath
        if ((Test-AnyPattern $name $cheatPat) -or (Test-AnyPattern $path $cheatPat)) {
            $suspect.Add("CHEAT? $name  ($path)")
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
    $details.Add("Processus actifs : $($procs.Count) (detection par nom connu + executables non signes en zone temp ; pas d'inspection d'injection DLL en memoire).")
    if ($suspect.Count -gt 0) {
        foreach($s in $suspect){ $details.Add("  $s") }
        $status = if ($suspect | Where-Object { $_ -like 'CHEAT?*' }) { 'FLAG' } else { 'WARN' }
        $sev = if ($status -eq 'FLAG') { 2 } else { 1 }
        New-ProbeResult -Id 'PROC' -Name 'Processus & injections' -Status $status -Severity $sev -Summary "$($suspect.Count) processus a verifier" -Details $details
    } else {
        New-ProbeResult -Id 'PROC' -Name 'Processus & injections' -Status 'OK' -Severity 0 -Summary "$($procs.Count) processus, rien de connu" -Details $details
    }
}

function Probe-Persistence {
    $details = New-Object System.Collections.Generic.List[string]
    $suspect = New-Object System.Collections.Generic.List[string]
    $pat = @(); foreach($c in $script:CheatSoftware){ $pat += $c.Patterns }
    foreach($t in $script:InputTools){ $pat += $t.App }
    # Run keys
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach($rk in $runKeys){
        try {
            if (-not (Test-Path $rk)) { continue }
            $props = Get-ItemProperty $rk -ErrorAction SilentlyContinue
            foreach($p in $props.PSObject.Properties){
                if ($p.Name -like 'PS*') { continue }
                $val = [string]$p.Value
                if ((Test-AnyPattern $val $pat) -or (Test-AnyPattern $p.Name $pat)) { $suspect.Add("Run: $($p.Name) = $val") }
                elseif (Test-AnyPattern $val @('\temp\','\downloads\','\appdata\local\temp\')) { $suspect.Add("Run en zone temp: $($p.Name) = $val") }
            }
        } catch { }
    }
    # Scheduled tasks
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach($tk in $tasks){
            $acts = $tk.Actions
            foreach($a in $acts){
                $ex = ''
                try { $ex = [string]$a.Execute } catch { }
                if ((Test-AnyPattern $ex $pat) -or (Test-AnyPattern $tk.TaskName $pat)) { $suspect.Add("Tache: $($tk.TaskName) -> $ex") }
            }
        }
    } catch { }
    $details.Add("Cles Run + taches planifiees inspectees.")
    if ($suspect.Count -gt 0) {
        foreach($s in $suspect){ $details.Add("  $s") }
        New-ProbeResult -Id 'PERSIST' -Name 'Persistence' -Status 'WARN' -Severity 1 -Summary "$($suspect.Count) point(s) de persistence a verifier" -Details $details
    } else {
        New-ProbeResult -Id 'PERSIST' -Name 'Persistence' -Status 'OK' -Severity 0 -Summary "Aucune persistence suspecte" -Details $details
    }
}

function Probe-EventLogs {
    $details = New-Object System.Collections.Generic.List[string]
    $status='OK'; $sev=0; $summary='Journaux coherents'
    $cleared = New-Object System.Collections.Generic.List[string]
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
    New-ProbeResult -Id 'EVTLOG' -Name "Journaux d'evenements" -Status $status -Severity $sev -Summary $summary -Details $details
}

function Probe-AntiForensic {
    $details = New-Object System.Collections.Generic.List[string]
    $flagHits = New-Object System.Collections.Generic.List[string]  # outils de wipe -> FLAG
    $warnHits = New-Object System.Collections.Generic.List[string]  # nettoyeurs courants -> WARN
    $names = Get-UninstallEntries
    $pf = @()
    try { $pf = @(Get-ChildItem "$script:SysDrive\Windows\Prefetch" -Filter *.pf -File -ErrorAction SilentlyContinue) } catch { }
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
    if ($flagHits.Count -gt 0) {
        New-ProbeResult -Id 'ANTIFOR' -Name 'Outils anti-forensic/wipe' -Status 'FLAG' -Severity 2 -Summary "$($flagHits.Count) outil(s) d'effacement securise QUI A TOURNE (wipe avant le check ?)" -Details $details
    } elseif ($warnHits.Count -gt 0) {
        New-ProbeResult -Id 'ANTIFOR' -Name 'Outils anti-forensic/wipe' -Status 'WARN' -Severity 1 -Summary "$($warnHits.Count) nettoyeur(s) courant(s) (dual-use, a verifier)" -Details $details
    } else {
        New-ProbeResult -Id 'ANTIFOR' -Name 'Outils anti-forensic/wipe' -Status 'OK' -Severity 0 -Summary "Aucun outil de wipe connu" -Details $details
    }
}

function Probe-Browsers {
    $details = New-Object System.Collections.Generic.List[string]
    $hits = New-Object System.Collections.Generic.List[string]
    $domains = New-Object System.Collections.Generic.List[string]
    foreach($c in $script:CheatSoftware){ foreach($d in $c.Domains){ $domains.Add($d) } }
    $local = $env:LOCALAPPDATA; $roaming = $env:APPDATA
    $dbs = @(
        "$local\Google\Chrome\User Data\*\History",
        "$local\Microsoft\Edge\User Data\*\History",
        "$local\BraveSoftware\Brave-Browser\User Data\*\History",
        "$roaming\Mozilla\Firefox\Profiles\*\places.sqlite",
        "$roaming\Opera Software\Opera Stable\History"
    )
    $checked = 0
    foreach($pattern in $dbs){
        $files = @(Get-ChildItem $pattern -File -ErrorAction SilentlyContinue)
        foreach($f in $files){
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

function Probe-DmaPci {
    $details = New-Object System.Collections.Generic.List[string]
    $dev = @()
    # 'PCI' n'est PAS une setup-class PnP -> on enumere tout et on filtre par enumerateur (InstanceId PCI\*).
    try { $dev = @(Get-PnpDevice -ErrorAction Stop | Where-Object { $_.InstanceId -like 'PCI\*' }) } catch {
        return (New-ProbeResult -Id 'DMAPCI' -Name 'Cartes PCIe / DMA' -Status 'NA' -Severity 0 -Summary "Enumeration PCIe indisponible" -Details @($_.Exception.Message))
    }
    $xil = New-Object System.Collections.Generic.List[string]
    $nodrv = New-Object System.Collections.Generic.List[string]        # VID inconnu sans driver -> WARN
    $nodrvBenign = New-Object System.Collections.Generic.List[string]  # VID grand public sans driver -> INFO (probable reinstall)
    foreach($d in $dev){
        $iid = [string]$d.InstanceId
        $fn  = [string]$d.FriendlyName; if ([string]::IsNullOrWhiteSpace($fn)) { $fn = '(sans nom)' }
        if (Test-AnyPattern $iid $script:DmaPciVendors) { $xil.Add("$fn  [$iid]  status=$($d.Status)") }
        # device PCIe en erreur (typiquement sans driver = ConfigManagerErrorCode 28) : tell classique
        # d'une carte DMA... mais aussi de plein de hardware benin. VID grand public => INFO (reinstall),
        # VID inconnu => WARN. Xilinx (teste avant) reste WARN quoi qu'il arrive.
        elseif ([string]$d.Status -eq 'Error') {
            if (Test-AnyPattern $iid $script:BenignPciVendors) { $nodrvBenign.Add("$fn  [$iid]  status=Error (VID grand public : driver non installe ?)") }
            else { $nodrv.Add("$fn  [$iid]  status=Error (sans driver ?)") }
        }
    }
    $details.Add("Devices PCIe enumeres : $($dev.Count). Verif read-only = VID de carte DMA connue (Xilinx pcileech) + device PCIe sans driver. Ne voit que ce que le firmware presente : un DMA bien spoofe passe (check visuel obligatoire).")
    foreach($h in $nodrvBenign){ $details.Add("  sans driver, VID grand public (probable reinstall - a confirmer visuellement, un 2e carte reste possible) : $h") }
    if ($xil.Count -gt 0 -or $nodrv.Count -gt 0) {
        foreach($h in $xil){ $details.Add("  FPGA/DMA connu (Xilinx) : $h") }
        foreach($h in $nodrv){ $details.Add("  PCIe sans driver (VID inconnu) : $h") }
        $sum = @()
        if ($xil.Count -gt 0){ $sum += "$($xil.Count) carte(s) FPGA Xilinx (pcileech ?)" }
        if ($nodrv.Count -gt 0){ $sum += "$($nodrv.Count) device(s) PCIe sans driver (VID inconnu)" }
        return (New-ProbeResult -Id 'DMAPCI' -Name 'Cartes PCIe / DMA' -Status 'WARN' -Severity 1 -Summary (($sum -join ' ; ') + " - a verifier (dual-use)") -Details $details)
    }
    $sumInfo = if ($nodrvBenign.Count -gt 0) { "$($dev.Count) devices PCIe ; $($nodrvBenign.Count) sans driver a VID grand public (probable reinstall), aucune carte DMA connue" } else { "$($dev.Count) devices PCIe, aucune carte DMA connue ni PCIe sans driver" }
    New-ProbeResult -Id 'DMAPCI' -Name 'Cartes PCIe / DMA' -Status 'INFO' -Severity 0 -Summary $sumInfo -Details $details
}

function Probe-SystemSecurity {
    $details = New-Object System.Collections.Generic.List[string]
    $status='OK'; $sev=0; $flags = New-Object System.Collections.Generic.List[string]
    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction Stop
        $details.Add("Secure Boot : $sb")
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
        } catch { $details.Add("bcdedit illisible.") }
    } else {
        $details.Add("bcdedit : admin requis (non verifie).")
    }
    # TPM
    try {
        $tpm = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        if ($null -ne $tpm) { $details.Add("TPM present : IsEnabled=$($tpm.IsEnabled_InitialValue)") } else { $details.Add("TPM : non detecte") }
    } catch { }
    if ($flags.Count -gt 0) {
        foreach($f in $flags){ $details.Add("  FLAG: $f") }
        $status='FLAG'; $sev=3
        New-ProbeResult -Id 'SECBOOT' -Name 'Securite systeme' -Status $status -Severity $sev -Summary ($flags -join ' ; ') -Details $details
    } else {
        New-ProbeResult -Id 'SECBOOT' -Name 'Securite systeme' -Status 'OK' -Severity 0 -Summary "Pas de mode test / signature contournee" -Details $details
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

function Probe-KnownCheats {
    $details = New-Object System.Collections.Generic.List[string]
    $hits = New-Object System.Collections.Generic.List[string]
    $names = Get-UninstallEntries
    $procNames = @()
    try { $procNames = (Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) } catch { }
    # dossiers/installeurs sur quelques racines, profondeur bornee
    $roots = @($env:USERPROFILE, "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", $env:LOCALAPPDATA, $env:ProgramData) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique
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
        if (-not $reason -and $t.Usb.Count -gt 0){ foreach($dv in $devs){ $hay = ('{0} {1}' -f $dv.FriendlyName, $dv.InstanceId); if (Test-AnyWord $hay $t.Usb) { $reason="device '$($dv.FriendlyName)'"; $sev=2; break } } }
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

function Get-DefenderAssessment {
    # Logique PURE testable. Une exclusion Defender au nom de cheat = whitelist d'un dossier
    # de cheat (tell classique). Protection coupee / exclusion en zone temp = a verifier.
    param([bool]$RealtimeDisabled, [bool]$CheatExclusion, [int]$RiskyExclusionCount, [int]$TotalExclusionCount)
    if ($CheatExclusion)        { return @{ Status='FLAG'; Severity=2; Summary='Exclusion Defender au nom de cheat (dossier/process whiteliste pour echapper a l antivirus)' } }
    if ($RealtimeDisabled)      { return @{ Status='WARN'; Severity=1; Summary='Protection temps reel Defender DESACTIVEE (antivirus coupe avant le check ?)' } }
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

function Get-DriverAssessment {
    # Logique PURE testable. Driver kernel non signe charge = fort signal BYOVD. Driver connu
    # abusable = a verifier (souvent dual-use : Afterburner/HWiNFO). On reste en WARN (le
    # moderateur tranche) pour ne pas crier SUSPECT sur un outil de monitoring legitime.
    param([int]$UnsignedCount, [int]$VulnerableCount)
    if ($UnsignedCount -gt 0 -or $VulnerableCount -gt 0) {
        return @{ Status='WARN'; Severity=1; Summary="$UnsignedCount driver(s) kernel non signe(s) + $VulnerableCount driver(s) connu(s) abusable(s) (BYOVD) - a verifier" }
    }
    return @{ Status='OK'; Severity=0; Summary='Aucun driver kernel non signe ou abusable connu' }
}

function Probe-KernelDrivers {
    # Vecteur DMA / cheat kernel : un driver .sys non signe charge, ou un driver connu
    # abusable (BYOVD), permet de lire/ecrire la memoire kernel et de contourner l'anti-cheat.
    $details = New-Object System.Collections.Generic.List[string]
    $drivers = @()
    try { $drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' }) } catch {
        return (New-ProbeResult -Id 'KDRV' -Name 'Drivers kernel (BYOVD)' -Status 'NA' -Severity 0 -Summary "Enumeration des drivers indisponible" -Details @($_.Exception.Message))
    }
    $unsigned = New-Object System.Collections.Generic.List[string]
    $vuln     = New-Object System.Collections.Generic.List[string]
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
    $details.Add("Drivers kernel en cours d'execution : $($drivers.Count). Verif = signature Authenticode (non signe = fort signal BYOVD) + liste curee de drivers connus abusables.")
    if (-not (Test-Admin)) { $details.Add("NOTE : sans admin, la lecture de certains chemins/signatures peut etre partielle.") }
    if ($vuln.Count -gt 0) {
        $details.Add("DRIVERS CONNUS ABUSABLES (BYOVD - souvent dual-use Afterburner/HWiNFO/monitoring, a confirmer) :")
        foreach ($v in $vuln) { $details.Add("  $v") }
    }
    if ($unsigned.Count -gt 0) {
        $details.Add("DRIVERS KERNEL NON SIGNES / SIGNATURE INVALIDE (rare et notable sur Windows x64) :")
        foreach ($u in $unsigned) { $details.Add("  $u") }
    }
    $a = Get-DriverAssessment -UnsignedCount $unsigned.Count -VulnerableCount $vuln.Count
    New-ProbeResult -Id 'KDRV' -Name 'Drivers kernel (BYOVD)' -Status $a.Status -Severity $a.Severity -Summary $a.Summary -Details $details
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

function Resolve-Desktop {
    try {
        $d = [Environment]::GetFolderPath('Desktop')
        if (-not [string]::IsNullOrWhiteSpace($d) -and (Test-Path $d)) { return $d }
    } catch { }
    return $env:USERPROFILE
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
            'DEFENDER' { if ($r.Status -eq 'WARN' -or $r.Status -eq 'FLAG') { $strong.Add('Windows Defender affaibli/contourne') } }
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

function Get-Verdict {
    param($results)
    $crit = @($results | Where-Object { $_.Severity -ge 3 })
    $flag = @($results | Where-Object { $_.Status -eq 'FLAG' })
    $warn = @($results | Where-Object { $_.Status -eq 'WARN' })
    if ($crit.Count -gt 0) { return 'ROUGE' }
    if ($flag.Count -gt 0) { return 'SUSPECT' }
    if ($warn.Count -gt 0) {
        # Un profil d'evasion COORDONNE (signal fort + corroboration) monte A VERIFIER -> SUSPECT.
        if ((Get-EvasionProfile $results).Escalate) { return 'SUSPECT' }
        return 'A VERIFIER'
    }
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
    if ($flags.Count -eq 0 -and $warns.Count -eq 0) {
        $out.Add("Aucune sonde n'a leve de drapeau : rien de suspect dans ce qu'un check logiciel peut voir.")
    } else {
        $out.Add("Ont bouge : $($flags.Count) drapeau(x) rouge(s), $($warns.Count) point(s) a verifier.")
        # Corroboration : plusieurs artefacts anti-wipe INDEPENDANTS qui pointent un exe de triche
        # au nom distinctif = execution confirmee, pas un simple soupcon (une trace isolee peut etre
        # un residu ; plusieurs qui concordent, non).
        $corr = @($flags | Where-Object { @('DELFILES','EXEC','SHIMCACHE','PCA','PREFETCH') -contains [string]$_.Id })
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
    [void]$sb.AppendLine(" Date       : $start")
    if (-not [string]::IsNullOrWhiteSpace($script:Nonce)) { [void]$sb.AppendLine(" Nonce      : $script:Nonce   (dicte par le modo => ce rapport a ete genere LIVE pour cette session)") }
    [void]$sb.AppendLine(" Mode       : " + $(if($deep){'APPROFONDI (-Deep)'}else{'rapide'}) + $(if($degraded){'  [DEGRADE - sans admin]'}else{''}))
    [void]$sb.AppendLine(" VERDICT    : $verdict")
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

    # --- HTML ---
    $rows = New-Object System.Text.StringBuilder
    $colorMap = @{ OK='#1f9d55'; INFO='#0ea5e9'; WARN='#d97706'; FLAG='#dc2626'; NA='#6b7280'; ERROR='#9333ea' }
    foreach($r in $results){
        $c = $colorMap[$r.Status]; if (-not $c) { $c = '#6b7280' }
        $det = ($r.Details | ForEach-Object { ConvertTo-HtmlText $_ }) -join '<br>'
        $meaning = (Get-MeaningLines $r | ForEach-Object { ConvertTo-HtmlText $_ }) -join '<br>'
        if ($meaning) { $det = "<span style='color:#cbd5e1'>$meaning</span><br>$det" }
        [void]$rows.AppendLine("<tr><td style='color:$c;font-weight:bold'>$($r.Status)</td><td>$(ConvertTo-HtmlText $r.Name)</td><td>$(ConvertTo-HtmlText $r.Summary)</td></tr><tr><td></td><td colspan='2' style='color:#9ca3af;font-size:12px'>$det</td></tr>")
    }
    $vColor = switch ($verdict) { 'CLEAN' {'#1f9d55'} 'A VERIFIER' {'#d97706'} 'SUSPECT' {'#dc2626'} 'ROUGE' {'#991b1b'} default {'#6b7280'} }
    $limHtml = ($script:Limites | ForEach-Object { ConvertTo-HtmlText $_ }) -join '<br>'
    $htmlDoc = @"
<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'><title>DexCheck $env:COMPUTERNAME</title>
<style>body{background:#0f1115;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif;margin:24px}
h1{font-size:20px}.v{display:inline-block;padding:4px 12px;border-radius:6px;color:#fff;background:$vColor;font-weight:bold}
table{border-collapse:collapse;width:100%;margin-top:16px}td{border-bottom:1px solid #1f2430;padding:6px 8px;vertical-align:top}
.lim{margin-top:20px;color:#9ca3af;font-size:12px;border-top:1px solid #1f2430;padding-top:12px}</style></head><body>
<h1>DEXCHECK - PC Check forensic <span style='color:#6b7280;font-size:13px'>v$script:Version &middot; by DrDexter</span></h1>
<p>Machine <b>$env:COMPUTERNAME</b> / $env:USERNAME &middot; $start$(if(-not [string]::IsNullOrWhiteSpace($script:Nonce)){" &middot; nonce <b>$(ConvertTo-HtmlText $script:Nonce)</b>"}) &middot; Verdict : <span class='v'>$verdict</span></p>
<p style='color:#cbd5e1;font-size:13px;max-width:900px'>$((Get-VerdictReasoning $results | ForEach-Object { ConvertTo-HtmlText $_ }) -join '<br>')</p>
<table>$($rows.ToString())</table>
<div class='lim'>$limHtml</div></body></html>
"@
    [System.IO.File]::WriteAllText($html, $htmlDoc, (New-Object System.Text.UTF8Encoding($true)))

    return [pscustomobject]@{ Txt=$txt; Html=$html; Verdict=$verdict }
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
        @{ Name='Cache DNS / hosts';             Fn=${function:Probe-DnsCache} }
        @{ Name='Corbeille';                     Fn=${function:Probe-RecycleBin} }
        @{ Name='Hardware / DMA / capture';      Fn=${function:Probe-Hardware} }
        @{ Name='Cartes PCIe / DMA';             Fn=${function:Probe-DmaPci} }
        @{ Name='Securite systeme';              Fn=${function:Probe-SystemSecurity} }
        @{ Name='Exclusions Windows Defender';   Fn=${function:Probe-DefenderExclusions} }
        @{ Name='Drivers kernel (BYOVD)';        Fn=${function:Probe-KernelDrivers} }
        @{ Name='Injection / hijack (AppInit/IFEO)'; Fn=${function:Probe-Injection} }
        @{ Name='Cheats logiciels connus';       Fn=${function:Probe-KnownCheats} }
        @{ Name='Manipulation input / anti-recoil'; Fn=${function:Probe-InputManipulation} }
    )
    if ($Deep) {
        $probes += @{ Name='[-Deep] Dump USN suppressions (CSV)'; Fn=${function:Probe-DeepUsnDump} }
        $probes += @{ Name='[-Deep] Scan signatures espace libre'; Fn=${function:Probe-DeepFreeSpaceScan} }
    }

    $script:RunStamp = $start.ToString('yyyyMMdd-HHmmss')
    $preferredDir = if (-not [string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir } else { Resolve-Desktop }
    $script:ReportDir = if (Test-DirWritable $preferredDir) { $preferredDir } else { $env:TEMP }

    $results = New-Object System.Collections.Generic.List[object]
    foreach($p in $probes){
        $r = $null
        try {
            $r = & $p.Fn
        } catch {
            $r = New-ProbeResult -Id 'ERR' -Name $p.Name -Status 'ERROR' -Severity 1 -Summary ("Exception: " + $_.Exception.Message)
        }
        if ($null -eq $r) { $r = New-ProbeResult -Id 'ERR' -Name $p.Name -Status 'ERROR' -Severity 1 -Summary 'Aucun resultat retourne' }
        Write-ProbeLine $r
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
        Write-Host "`n  [ERREUR] Impossible d'ecrire le rapport (Bureau et TEMP inaccessibles)." -ForegroundColor Red
        if (-not $NoPause) { try { Read-Host "  Entree pour fermer" | Out-Null } catch { } }
        return
    }

    $hash = try { (Get-FileHash -Path $rep.Txt -Algorithm SHA256 -ErrorAction Stop).Hash } catch { 'n/a' }
    Write-Host ""
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor Cyan
    $vcol = switch ($rep.Verdict) { 'CLEAN' {'Green'} 'A VERIFIER' {'Yellow'} 'SUSPECT' {'Red'} 'ROUGE' {'Red'} default {'Gray'} }
    $tcol = if (@($results | Where-Object { $_.Status -eq 'FLAG' }).Count -gt 0) { 'Red' } elseif (@($results | Where-Object { $_.Status -eq 'WARN' }).Count -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host ("   BILAN   : {0}" -f (Get-StatusTally $results)) -ForegroundColor $tcol
    Write-Host "  ==================================================================" -ForegroundColor $vcol
    Write-Host ("   VERDICT : {0}" -f $rep.Verdict) -ForegroundColor $vcol
    Write-Host "  ==================================================================" -ForegroundColor $vcol
    foreach($rl in (Get-VerdictReasoning $results)){ Write-Host ("   $rl") -ForegroundColor DarkGray }
    Write-Host ("   Rapport : {0}" -f $rep.Txt) -ForegroundColor Gray
    Write-Host ("   HTML    : {0}" -f $rep.Html) -ForegroundColor Gray
    Write-Host ("   SHA256  : {0}" -f $hash) -ForegroundColor Cyan
    Write-Host "  ------------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""

    if (-not $NoPause) {
        try { Read-Host "  Appuie sur Entree pour fermer" | Out-Null } catch { }
    }
    return $rep
}

if (-not $NoRun) { Invoke-DexCheck | Out-Null }
