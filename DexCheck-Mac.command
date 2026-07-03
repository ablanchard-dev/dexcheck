#!/bin/bash
# =============================================================================
# DexCheck-Mac.command - PC check forensic anti-triche macOS (CoD/Warzone).
# Auteur : Alexandre Blanchard (DrDexter). Deploye pour la communaute Warzup.
# Pendant macOS du DexCheck.ps1 Windows, pour le cas "cheat sur Mac
# branche au setup" : le Mac sert de machine RADAR/ESP (wallhack via carte DMA
# dans le PC de jeu) ou d'aimbot par VISION (capture HDMI -> CV -> injection).
#
# A faire en partage d'ecran avec un responsable. Le check LIT seulement, il ne
# modifie rien, et ecrit un rapport + un SHA256 (empreinte infalsifiable).
#
#   bash DexCheck-Mac.command               # mode leger (zero permission)
#   sudo bash DexCheck-Mac.command --deep   # approfondi (Full Disk Access + sudo)
#   bash DexCheck-Mac.command --self-test   # auto-test de la logique pure (CI)
#
# 100% natif macOS (system_profiler, ioreg, sqlite3, csrutil, spctl, log...).
# Compatible bash 3.2 (macOS) : pas de tableaux associatifs.
# =============================================================================

VERSION="1.0.0"
DEEP=0; NOCOLOR=0; SELFTEST=0; OUTDIR=""

for arg in "$@"; do
  case "$arg" in
    --deep)      DEEP=1 ;;
    --no-color)  NOCOLOR=1 ;;
    --self-test) SELFTEST=1 ;;
    --out=*)     OUTDIR="${arg#--out=}" ;;
    -h|--help)
      echo "Usage: bash DexCheck-Mac.command [--deep] [--no-color] [--out=DIR] [--self-test]"
      exit 0 ;;
  esac
done

# --- Couleurs ---------------------------------------------------------------
if [ "$NOCOLOR" = "1" ] || [ ! -t 1 ]; then
  C_OK=""; C_WARN=""; C_FLAG=""; C_INFO=""; C_RST=""; C_HEAD=""
else
  C_OK="$(printf '\033[32m')"; C_WARN="$(printf '\033[33m')"; C_FLAG="$(printf '\033[31m')"
  C_INFO="$(printf '\033[36m')"; C_RST="$(printf '\033[0m')"; C_HEAD="$(printf '\033[36m')"
fi

# =============================================================================
# LOGIQUE PURE (testable a sec via --self-test, tourne sur n'importe quel bash)
# =============================================================================
# Les tables de signatures sont des alternations ERE delimitees par '|'. Elles servent
# A LA FOIS aux sondes reelles (grep -iE "$SIG_X") ET au self-test (matches_any) : une
# seule source de verite, donc le test couvre le vrai chemin de detection.
# Tokens DISTINCTIFS uniquement (>=5 car en general), multi-mots colles ('cam link') pour
# eviter les faux positifs (ex: 'cam' seul matcherait 'webcam').
SIG_CAPTURE="elgato|avermedia|magewell|blackmagic|cam link|live gamer|game capture|ezcap"
SIG_DMA="pcileech|leetdma|captaindma|screamer|enigma x1|raptordma|ft601|ft60x|ft600"
SIG_REMOTE="anydesk|teamviewer|parsec|moonlight|sunshine|rustdesk|splashtop|nomachine|jump desktop|chrome remote desktop|deskreen|realvnc|apple remote desktop"
SIG_CHEAT="aimbot|wallhack|triggerbot|colorbot|dma radar|unknowncheats|engineowning|phantomoverlay|radarflow|dmaradar"
SIG_CHEATDOM="engineowning|phantomoverlay|lavicheats|unknowncheats|fecurity|interwebz|memesense|skript.gg|coldvision|hypervision|hypercheats|ring-1|susano.gg|abstrakt.cc|klarcheats|cobracheats|disconnect.gg"

# matches_any HAYSTACK PIPE_PATTERNS -> 0 si une pattern est sous-chaine (insensible casse).
matches_any() {
  local hay; hay=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  local pats="$2" p lp oldifs="$IFS"
  IFS='|'
  for p in $pats; do
    IFS="$oldifs"
    lp=$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')
    if [ -n "$lp" ]; then
      case "$hay" in *"$lp"*) return 0 ;; esac
    fi
    IFS='|'
  done
  IFS="$oldifs"
  return 1
}

# sev_to_verdict MAXSEV -> chaine de verdict (meme echelle que le Windows)
sev_to_verdict() {
  case "$1" in
    3) echo "ROUGE" ;;
    2) echo "SUSPECT" ;;
    1) echo "A VERIFIER" ;;
    *) echo "CLEAN" ;;
  esac
}

# =============================================================================
# AUTO-TEST (gate "dev lead" pour la logique pure + les tables reellement utilisees)
# =============================================================================
run_self_test() {
  local fails=0
  _eq() { if [ "$2" = "$3" ]; then echo "  [PASS] $1"; else echo "  [FAIL] $1 (got='$2' want='$3')"; fails=$((fails+1)); fi; }
  _true()  { if "$@"; then echo "  [PASS] $T"; else echo "  [FAIL] $T"; fails=$((fails+1)); fi; }
  _false() { if "$@"; then echo "  [FAIL] $T"; fails=$((fails+1)); else echo "  [PASS] $T"; fi; }

  echo "== AUTO-TEST DexCheck-Mac v$VERSION =="
  _eq "verdict 0 => CLEAN"      "$(sev_to_verdict 0)" "CLEAN"
  _eq "verdict 1 => A VERIFIER" "$(sev_to_verdict 1)" "A VERIFIER"
  _eq "verdict 2 => SUSPECT"    "$(sev_to_verdict 2)" "SUSPECT"
  _eq "verdict 3 => ROUGE"      "$(sev_to_verdict 3)" "ROUGE"

  T="capture: Elgato detecte"                ; _true  matches_any "Elgato Game Capture HD60 X" "$SIG_CAPTURE"
  T="capture: webcam Logitech = PAS FP"      ; _false matches_any "Logitech BRIO 4K Webcam"    "$SIG_CAPTURE"
  T="capture: iSight/FaceTime = PAS FP"      ; _false matches_any "FaceTime HD Camera"         "$SIG_CAPTURE"
  T="dma: FT601 = pont DMA"                  ; _true  matches_any "FTDI FT601 SuperSpeed"       "$SIG_DMA"
  T="dma: cle USB normale = PAS FP"          ; _false matches_any "SanDisk Ultra USB 3.0"       "$SIG_DMA"
  T="remote: AnyDesk detecte"                ; _true  matches_any "AnyDesk.app"                 "$SIG_REMOTE"
  T="remote: Parsec detecte"                 ; _true  matches_any "Parsec"                      "$SIG_REMOTE"
  T="remote: Safari = PAS FP"                ; _false matches_any "Safari.app"                  "$SIG_REMOTE"
  T="remote: Jump Desktop detecte"           ; _true  matches_any "Jump Desktop.app"           "$SIG_REMOTE"
  T="remote: Chrome Remote Desktop detecte"  ; _true  matches_any "Chrome Remote Desktop Host"  "$SIG_REMOTE"
  T="remote: Messages = PAS FP"              ; _false matches_any "Messages.app"                "$SIG_REMOTE"
  T="cheat: aimbot detecte"                  ; _true  matches_any "cod-aimbot-loader"           "$SIG_CHEAT"
  T="cheat: dma radar detecte"               ; _true  matches_any "warzone dma radar"           "$SIG_CHEAT"
  T="cheat: radarflow detecte"               ; _true  matches_any "RadarFlow"                   "$SIG_CHEAT"
  T="cheat: app legitime = PAS FP"           ; _false matches_any "Discord"                     "$SIG_CHEAT"
  T="cheatdom: skript.gg detecte"            ; _true  matches_any "skript.gg/download"          "$SIG_CHEATDOM"
  T="cheatdom: hypervision detecte"          ; _true  matches_any "hypervision.io"              "$SIG_CHEATDOM"
  T="cheatdom: apple.com = PAS FP"           ; _false matches_any "https://apple.com"           "$SIG_CHEATDOM"
  T="match: chaine vide = pas de match"      ; _false matches_any "Finder"                      ""

  echo ""
  echo "BILAN self-test : ${fails} FAIL"
  return "$fails"
}

if [ "$SELFTEST" = "1" ]; then
  run_self_test
  exit $?
fi

# =============================================================================
# A PARTIR D'ICI : sondes macOS reelles (necessitent un vrai Mac)
# =============================================================================
MAXSEV=0; REPORT=""
HOSTN=$(hostname 2>/dev/null || echo inconnu)
WHO=$(id -un 2>/dev/null || echo inconnu)
IS_ROOT=0; [ "$(id -u 2>/dev/null)" = "0" ] && IS_ROOT=1

# Detection Full Disk Access : on tente de lire la TCC.db utilisateur. Refus -> pas de FDA.
HAS_FDA=0
TCC_USER="$HOME/Library/Application Support/com.apple.TCC/TCC.db"
if [ -r "$TCC_USER" ] && sqlite3 "$TCC_USER" "select count(*) from access" >/dev/null 2>&1; then
  HAS_FDA=1
fi

rep_add() { REPORT="${REPORT}$1
"; }
probe() {  # STATUS SEV NAME SUMMARY
  local st="$1" sev="$2" name="$3" sum="$4" col=""
  case "$st" in
    OK)         col="$C_OK" ;;
    INFO)       col="$C_INFO" ;;
    WARN)       col="$C_WARN"; [ "$sev" -gt "$MAXSEV" ] && MAXSEV=$sev ;;
    FLAG|ROUGE) col="$C_FLAG"; [ "$sev" -gt "$MAXSEV" ] && MAXSEV=$sev ;;
  esac
  printf "  ${col}[%-4s]${C_RST} %-34s %s\n" "$st" "$name" "$sum"
  rep_add "[$st] $name -- $sum"
}
detail() { printf "        %s\n" "$1"; rep_add "      $1"; }

# --- En-tete ----------------------------------------------------------------
MODE="leger"; [ "$DEEP" = "1" ] && MODE="-deep"
echo ""
echo "  ${C_HEAD}==================================================================${C_RST}"
echo "  ${C_HEAD} DEXCHECK - PC CHECK FORENSIC (MAC)   v$VERSION   by DrDexter${C_RST}"
echo "  ${C_HEAD}==================================================================${C_RST}"
echo "   Machine $HOSTN / $WHO  -  root: $IS_ROOT  FDA: $HAS_FDA  mode: $MODE"
echo ""
rep_add "DEXCHECK - PC CHECK FORENSIC (MAC) v$VERSION  -  by DrDexter"
rep_add "Machine $HOSTN / $WHO  root=$IS_ROOT FDA=$HAS_FDA mode=$MODE"
rep_add ""
if [ "$DEEP" = "1" ] && [ "$HAS_FDA" = "0" ]; then
  echo "  ${C_WARN}[!] Mode -deep demande mais Full Disk Access absent : les sondes profondes${C_RST}"
  echo "  ${C_WARN}    (enregistrement d'ecran, historiques) seront en N/A. Donner au Terminal :${C_RST}"
  echo "  ${C_WARN}    Reglages Systeme > Confidentialite > Acces complet au disque > Terminal,${C_RST}"
  echo "  ${C_WARN}    puis relancer avec sudo. Un refus est lui-meme un signal pour le responsable.${C_RST}"
  echo ""
fi

# --- 1. Identite & horloge --------------------------------------------------
OSV=$(sw_vers -productVersion 2>/dev/null)
TZN=$(systemsetup -gettimezone 2>/dev/null | sed 's/^.*: //'); [ -z "$TZN" ] && TZN=$(date +%Z 2>/dev/null)
probe OK 0 "Identite & horloge" "$HOSTN / $WHO, macOS $OSV"
detail "Date systeme : $(date 2>/dev/null)  (TZ $TZN)"
detail "Uptime : $(uptime 2>/dev/null | sed 's/^ *//')"

# --- 2. Age de l'install macOS ----------------------------------------------
INST=""
[ -e /var/db/.AppleSetupDone ] && INST=$(stat -f '%SB' -t '%Y-%m-%d' /var/db/.AppleSetupDone 2>/dev/null)
[ -z "$INST" ] && INST=$(stat -f '%SB' -t '%Y-%m-%d' /var/db 2>/dev/null)
if [ -n "$INST" ]; then
  IE=$(date -j -f '%Y-%m-%d' "$INST" +%s 2>/dev/null); NE=$(date +%s 2>/dev/null)
  if [ -n "$IE" ]; then
    DAYS=$(( (NE - IE) / 86400 ))
    if [ "$DAYS" -lt 3 ]; then probe WARN 1 "Age de macOS" "Installe il y a $DAYS j -- OS tres recent (reinstall ?)"
    else probe OK 0 "Age de macOS" "Installe il y a $DAYS j (~$INST)"; fi
  else probe OK 0 "Age de macOS" "Date d'install : $INST"; fi
else probe NA 0 "Age de macOS" "Date d'install indeterminee"; fi

# --- 3. Cartes de capture (USB) ---------------------------------------------
USB=$(system_profiler SPUSBDataType 2>/dev/null)
CAP=$(printf '%s\n' "$USB" | grep -iE "$SIG_CAPTURE" | sed 's/^ *//;s/:$//' | sort -u)
if [ -n "$CAP" ]; then
  probe INFO 0 "Carte de capture (USB)" "Capture HDMI detectee (normal streamer, suspect si console+CV)"
  printf '%s\n' "$CAP" | while IFS= read -r l; do [ -n "$l" ] && detail "Capture : $l"; done
else
  probe OK 0 "Carte de capture (USB)" "Aucune carte de capture connue"
fi

# --- 4. Pont USB FTDI / carte DMA -------------------------------------------
DMA=$(printf '%s\n' "$USB" | grep -iE "$SIG_DMA" | sed 's/^ *//;s/:$//' | sort -u)
if [ -n "$DMA" ]; then
  probe WARN 1 "Pont USB3 FTDI / DMA" "Lien type carte DMA detecte (aussi dev board) -- a verifier"
  printf '%s\n' "$DMA" | while IFS= read -r l; do [ -n "$l" ] && detail "FTDI/DMA : $l"; done
else
  probe OK 0 "Pont USB3 FTDI / DMA" "Aucun pont FTDI/DMA connu"
fi

# --- 5. Outils de remote / streaming ----------------------------------------
HAYSTACK=$( { ps -axo comm 2>/dev/null; ls /Applications 2>/dev/null; ls "$HOME/Applications" 2>/dev/null; } )
REM=$(printf '%s\n' "$HAYSTACK" | grep -iE "$SIG_REMOTE" | sed 's#.*/##' | sort -u)
VNC_ON=$(launchctl list 2>/dev/null | grep -i 'screensharing')
if [ -n "$REM" ] || [ -n "$VNC_ON" ]; then
  probe WARN 1 "Remote / streaming" "Outil(s) de controle/stream a distance -- a verifier"
  printf '%s\n' "$REM" | while IFS= read -r l; do [ -n "$l" ] && detail "Remote : $l"; done
  [ -n "$VNC_ON" ] && detail "Partage d'ecran macOS (VNC) actif"
else
  probe OK 0 "Remote / streaming" "Aucun outil de remote connu"
fi

# --- 6. Apps / process radar-ESP-aimbot -------------------------------------
CHE=$(printf '%s\n' "$HAYSTACK" | grep -iE "$SIG_CHEAT" | sed 's#.*/##' | sort -u)
if [ -n "$CHE" ]; then
  probe FLAG 2 "Cheats / radar / ESP" "Nom(s) de cheat connu(s) detecte(s)"
  printf '%s\n' "$CHE" | while IFS= read -r l; do [ -n "$l" ] && detail "Cheat : $l"; done
else
  probe OK 0 "Cheats / radar / ESP" "Aucun nom de cheat/radar connu (apps + process)"
fi

# --- 7. Persistance (LaunchAgents / Daemons / login items) ------------------
PERSIST=$( { ls "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null; \
             osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | tr ',' '\n'; } )
PSUS=$(printf '%s\n' "$PERSIST" | grep -iE "$SIG_CHEAT|$SIG_REMOTE" | sed 's/^ *//' | sort -u)
PCNT=$(printf '%s\n' "$PERSIST" | grep -c .)
if [ -n "$PSUS" ]; then
  probe WARN 1 "Persistance" "Element(s) de demarrage suspect(s) -- a verifier"
  printf '%s\n' "$PSUS" | while IFS= read -r l; do [ -n "$l" ] && detail "Demarrage : $l"; done
else
  probe OK 0 "Persistance" "$PCNT element(s) de demarrage, rien de connu"
fi

# --- 8. SIP / Gatekeeper ----------------------------------------------------
SIP=$(csrutil status 2>/dev/null); GK=$(spctl --status 2>/dev/null)
if printf '%s' "$SIP" | grep -iq 'disabled'; then
  probe WARN 1 "SIP (protection systeme)" "SIP DESACTIVE -- permet de charger des drivers non signes"; detail "$SIP"
elif printf '%s' "$GK" | grep -iq 'disabled'; then
  probe WARN 1 "Gatekeeper" "Gatekeeper DESACTIVE -- apps non signees autorisees"; detail "$GK"
else
  probe OK 0 "SIP / Gatekeeper" "SIP actif, Gatekeeper actif"
fi

# --- 9. Extensions / kexts tiers --------------------------------------------
KEXTS=$( { kextstat 2>/dev/null | grep -viE 'com\.apple' | awk '{print $6}'; \
           systemextensionsctl list 2>/dev/null | grep -iE 'enabled|activated'; } | grep -v '^$' | sort -u)
if [ -n "$KEXTS" ]; then
  probe INFO 0 "Extensions / kexts tiers" "Extension(s) non-Apple presente(s) (a inspecter si suspect)"
  printf '%s\n' "$KEXTS" | head -n 15 | while IFS= read -r l; do [ -n "$l" ] && detail "ext : $l"; done
else
  probe OK 0 "Extensions / kexts tiers" "Aucune extension non-Apple chargee"
fi

# --- 10. Corbeille ----------------------------------------------------------
probe OK 0 "Corbeille" "$(ls -A "$HOME/.Trash" 2>/dev/null | grep -c .) element(s)"

# =============================================================================
# SONDES -DEEP (Full Disk Access + sudo)
# =============================================================================
if [ "$DEEP" = "1" ]; then
  if [ "$HAS_FDA" = "1" ]; then
    # 11. Permission "Enregistrement de l'ecran" = LE signal aimbot vision
    SC=""
    for db in "$TCC_USER" "/Library/Application Support/com.apple.TCC/TCC.db"; do
      [ -r "$db" ] || continue
      SC="$SC
$(sqlite3 "$db" "select client from access where service='kTCCServiceScreenCapture' and auth_value>0" 2>/dev/null)"
    done
    SCN=$(printf '%s\n' "$SC" | grep -viE 'com\.apple|^$' | sort -u)
    if [ -n "$SCN" ]; then
      probe WARN 1 "[-deep] Enregistrement d'ecran" "App(s) non-Apple peuvent capturer l'ecran -- verifier (aimbot vision)"
      printf '%s\n' "$SCN" | while IFS= read -r l; do [ -n "$l" ] && detail "ScreenCapture : $l"; done
    else
      probe OK 0 "[-deep] Enregistrement d'ecran" "Aucune app non-Apple avec capture d'ecran"
    fi

    # 12. Permission Accessibilite = injection d'inputs
    AX=$(sqlite3 "$TCC_USER" "select client from access where service='kTCCServiceAccessibility' and auth_value>0" 2>/dev/null | grep -viE 'com\.apple|^$' | sort -u)
    if [ -n "$AX" ]; then
      probe INFO 0 "[-deep] Accessibilite (injection)" "App(s) non-Apple avec controle clavier/souris (a verifier)"
      printf '%s\n' "$AX" | while IFS= read -r l; do [ -n "$l" ] && detail "Accessibilite : $l"; done
    else
      probe OK 0 "[-deep] Accessibilite (injection)" "Aucune app non-Apple en Accessibilite"
    fi

    # 13. Historiques navigateurs : domaines de cheat
    BR=""
    SAFARI="$HOME/Library/Safari/History.db"
    [ -r "$SAFARI" ] && BR="$BR
$(sqlite3 "$SAFARI" "select url from history_items" 2>/dev/null | grep -iE "$SIG_CHEATDOM")"
    for ch in "$HOME/Library/Application Support/Google/Chrome/Default/History" \
              "$HOME/Library/Application Support/BraveSoftware/Brave-Browser/Default/History" \
              "$HOME/Library/Application Support/Microsoft Edge/Default/History"; do
      [ -r "$ch" ] || continue
      if cp "$ch" "/tmp/wzc_hist_$$" 2>/dev/null; then
        BR="$BR
$(sqlite3 "/tmp/wzc_hist_$$" "select url from urls" 2>/dev/null | grep -iE "$SIG_CHEATDOM")"
        rm -f "/tmp/wzc_hist_$$" 2>/dev/null
      fi
    done
    BRH=$(printf '%s\n' "$BR" | grep -v '^$' | sort -u)
    if [ -n "$BRH" ]; then
      probe FLAG 2 "[-deep] Navigateurs (sites cheats)" "Domaine(s) de cheat dans l'historique"
      printf '%s\n' "$BRH" | head -n 10 | while IFS= read -r l; do [ -n "$l" ] && detail "$l"; done
    else
      probe OK 0 "[-deep] Navigateurs (sites cheats)" "Aucun domaine cheat connu dans l'historique"
    fi

    # 14. Quarantine (telechargements)
    QDB="$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    if [ -r "$QDB" ]; then
      Q=$(sqlite3 "$QDB" "select LSQuarantineDataURLString from LSQuarantineEvent" 2>/dev/null | grep -iE "$SIG_CHEAT|$SIG_CHEATDOM" | sort -u)
      if [ -n "$Q" ]; then
        probe FLAG 2 "[-deep] Telechargements (quarantine)" "Telechargement(s) au nom suspect"
        printf '%s\n' "$Q" | head -n 10 | while IFS= read -r l; do [ -n "$l" ] && detail "$l"; done
      else
        probe OK 0 "[-deep] Telechargements (quarantine)" "Aucun telechargement au nom de cheat connu"
      fi
    else
      probe NA 0 "[-deep] Telechargements (quarantine)" "Base quarantine illisible"
    fi
  else
    probe NA 0 "[-deep] Sondes profondes" "Full Disk Access absent -> non executees (voir avertissement en-tete)"
  fi
fi

# =============================================================================
# VERDICT + RAPPORT
# =============================================================================
VERDICT=$(sev_to_verdict "$MAXSEV")
rep_add ""
rep_add "VERDICT : $VERDICT"
rep_add ""
rep_add "RAISONNEMENT (ce qui est trouve / ce que ca prouve / ce que ca ne prouve pas) :"
if [ "$VERDICT" = "CLEAN" ]; then
  rep_add "- Aucune sonde n'a leve de drapeau : rien de suspect dans ce qu'un scan local read-only voit sur ce Mac."
else
  rep_add "- Des signaux ont ete leves (voir le detail par sonde) : a recouper visuellement, le responsable garde le jugement final."
fi
rep_add "- Portee : ce Mac peut afficher un radar DMA (2e machine) OU un radar dans un simple onglet navigateur,"
rep_add "  tous deux invisibles a ce scan. Un verdict propre ne PROUVE pas l'absence de triche - le check VISUEL du setup reste obligatoire."
rep_add ""
rep_add "Limites (a garder en tete) :"
rep_add "- Wallhack = lecture memoire : cheat logiciel OU carte DMA dans le PC de jeu -> radar/ESP"
rep_add "  affiche sur ce Mac. Le radar peut tourner dans un simple onglet navigateur = invisible"
rep_add "  a ce scan. Une carte DMA usurpe ses IDs. Le check VISUEL du setup reste indispensable."
rep_add "- Sur console (PS5) le vrai wallhack est quasi impossible ; risque console = aimbot/recoil."
rep_add "- Sans Full Disk Access (--deep), le meilleur signal (permission d'enregistrement d'ecran)"
rep_add "  est indisponible. Un refus de FDA est lui-meme un signal pour le responsable."

if [ -z "$OUTDIR" ]; then
  if [ -d "$HOME/Desktop" ] && [ -w "$HOME/Desktop" ]; then OUTDIR="$HOME/Desktop"; else OUTDIR="${TMPDIR:-/tmp}"; fi
fi
STAMP=$(date +%Y%m%d-%H%M%S 2>/dev/null)
BASE="DexCheck-Mac_${HOSTN}_${STAMP}"
TXT="$OUTDIR/$BASE.txt"; HTML="$OUTDIR/$BASE.html"

printf '%s\n' "$REPORT" > "$TXT" 2>/dev/null
{
  echo "<!doctype html><html><head><meta charset=utf-8><title>$BASE</title>"
  echo "<style>body{background:#111;color:#ddd;font-family:Menlo,monospace;padding:20px}pre{white-space:pre-wrap}h1{color:#3cf}</style></head><body>"
  echo "<h1>DexCheck-Mac &mdash; $HOSTN</h1><pre>"
  printf '%s\n' "$REPORT" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'
  echo "</pre></body></html>"
} > "$HTML" 2>/dev/null

SHA=$(shasum -a 256 "$TXT" 2>/dev/null | awk '{print $1}'); [ -z "$SHA" ] && SHA="n/a"
VC="$C_OK"; case "$VERDICT" in "A VERIFIER") VC="$C_WARN" ;; SUSPECT|ROUGE) VC="$C_FLAG" ;; esac
echo ""
echo "  ${C_HEAD}------------------------------------------------------------------${C_RST}"
echo "   VERDICT : ${VC}${VERDICT}${C_RST}"
if [ "$VERDICT" = "CLEAN" ]; then
  echo "   ${C_INFO}Aucun signal ; mais un radar DMA/onglet navigateur est invisible a ce scan - verdict propre != absence de triche.${C_RST}"
else
  echo "   ${C_INFO}Signaux leves (voir rapport) ; a recouper visuellement, jugement final au responsable.${C_RST}"
fi
echo "   Rapport : $TXT"
echo "   HTML    : $HTML"
echo "   SHA256  : ${C_INFO}${SHA}${C_RST}"
echo "  ${C_HEAD}------------------------------------------------------------------${C_RST}"
echo ""
exit 0
