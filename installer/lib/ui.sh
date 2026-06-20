# shellcheck shell=bash
#
# secure-base Helper: Ausgabe und Live-Statusliste
#
# Bietet:
#   ui_init            — interne Zustandsvariablen initialisieren
#   ui_banner          — Startbanner ausgeben
#   ui_list_draw       — vollstaendige Statusliste zeichnen (einmalig oder live)
#   ui_list_update     — Zustand eines Moduls aendern und Liste neu zeichnen
#   ui_message         — WARN/ERROR-Meldung oberhalb der Liste ausgeben
#   ui_summary         — Abschlussmeldung ausgeben
#   ui_status_start    — Ticker-Worker fuer ein Modul starten
#   ui_status_stop     — Ticker-Worker stoppen (idempotent)
#   ui_status_pause    — Ticker anhalten und Statuszeile entfernen
#   ui_status_resume   — Ticker nach Pause weiterfuehren
#
# Ausgabe-Konzept:
#   Am TTY: fixe Live-Statusliste, die bei jedem Statuswechsel neu gezeichnet
#   wird (tput-Cursor-Neupositionierung). Meldungen (WARN/ERROR) erscheinen
#   oberhalb der Liste. Unterhalb der Liste: Trennlinie + Statuszeile mit
#   aktuellem Modul, juengster Aktion und im Sekundentakt mitlaufender Laufzeit.
#   Non-TTY (Pipe, Umleitung): einfache Einzelzeilen ohne Cursor-Steuerung.
#
# Symbole und Farben:
#   ✓ gruen  (ok)     ▶ blau   (laeuft)
#   · grau   (wartet) ⚠ gelb   (Warnung)
#   ✗ rot    (Fehler)
#
# Globals (von ui_init gesetzt):
#   _UI_TTY             — 1 wenn stdout ein TTY ist, sonst 0
#   _UI_OUT             — Dateideskriptor fuer TTY-Ausgabe (FD 3 nach open_log,
#                         FD 1 davor); nie durch den Log-Filter geleitet
#   _UI_MODULES         — Array der Modulnamen (Reihenfolge = Darstellungsreihenfolge)
#   _UI_STATE           — assoziatives Array: Modulname -> Zustand
#   _UI_LABEL           — assoziatives Array: Modulname -> Anzeigebezeichnung
#   _UI_LIST_LINES      — Anzahl der zuletzt gezeichneten Listenzeilen (fuer tput)
#   _UI_TOTAL_LINES     — Gesamtzahl gezeichneter Live-Zeilen (Liste + ggf.
#                         Trennlinie + Statuszeile); Bezugspunkt fuer tput cuu
#   _UI_LOG_PATH        — Logdatei-Pfad fuer Anzeige in Banner und Summary
#   _UI_START_TS        — Zeitstempel des Starts (Sekunden seit Epoch)
#
# Globals (Ticker-Status):
#   _UI_STATUS_ACTIVE   — 1 wenn Ticker aktiv, 0 sonst
#   _UI_STATUS_PID      — PID des laufenden Ticker-Workers (leer wenn kein Worker)
#   _UI_STATUS_LOCK     — Pfad zur Lock-Datei (mktemp, 0600)
#   _UI_STATUS_LOCK_FD  — Dateideskriptor der offenen Lock-Datei
#   _UI_STATUS_MODUL    — Name des Moduls, fuer das der Ticker laeuft
#   _UI_STATUS_LABEL    — Anzeige-Bezeichnung des Moduls (als Argument uebergeben)
#   _UI_STATUS_START_TS — Startzeit des aktuellen Modul-Laufs (Sekunden seit Epoch)
#   _UI_STATUS_PAUSED   — 1 wenn Ticker via ui_status_pause angehalten, 0 sonst

# ANSI-Farb- und Reset-Codes als Konstanten
readonly _SB_C_RESET='\033[0m'
readonly _SB_C_GREEN='\033[32m'
readonly _SB_C_BLUE='\033[34m'
readonly _SB_C_GREY='\033[90m'
readonly _SB_C_YELLOW='\033[33m'
readonly _SB_C_RED='\033[31m'
readonly _SB_C_BOLD='\033[1m'

# Zustaende
readonly _SB_ST_WAIT="wait"
readonly _SB_ST_RUN="run"
readonly _SB_ST_OK="ok"
readonly _SB_ST_WARN="warn"
readonly _SB_ST_ERROR="error"

_UI_TTY=0
_UI_OUT=1   # FD fuer TTY-Ausgabe; wird in ui_init auf SB_UI_TTY_FD gesetzt
_UI_LIST_LINES=0
_UI_TOTAL_LINES=0
_UI_LOG_PATH=""
_UI_START_TS=0

declare -a _UI_MODULES=()
declare -A _UI_STATE=()
declare -A _UI_LABEL=()

# Ticker-Zustand
_UI_STATUS_ACTIVE=0
_UI_STATUS_PID=""
_UI_STATUS_LOCK=""
_UI_STATUS_LOCK_FD=""
_UI_STATUS_MODUL=""
_UI_STATUS_LABEL=""
_UI_STATUS_START_TS=0
_UI_STATUS_PAUSED=0

#######################################
# Initialisiert die UI-Zustandsvariablen.
# Legt _UI_OUT fest: wird SB_UI_TTY_FD nach open_log gesetzt, wird dieser
# FD fuer alle TTY-Ausgaben genutzt (umgeht den Log-Filter); sonst FD 1.
# Richtet das flock-Lock fuer die Ticker-Synchronisation ein, falls flock
# verfuegbar ist und ein TTY vorliegt.
# Globals:   _UI_TTY, _UI_OUT, _UI_MODULES, _UI_STATE, _UI_LABEL,
#             _UI_LIST_LINES, _UI_TOTAL_LINES, _UI_LOG_PATH, _UI_START_TS,
#             _UI_STATUS_LOCK, _UI_STATUS_LOCK_FD, SB_UI_TTY_FD
# Arguments:
#   $1        — Logdatei-Pfad (fuer Anzeige)
#   $2 ..     — Modulnamen
#######################################
ui_init() {
    local logpath=$1
    shift
    # TTY-Modus bestimmen. Nach open_log ist FD 1 auf den Log-Filter
    # umgeleitet — daher NICHT ueber [ -t 1 ] erkennen. SB_UI_TTY_FD haelt
    # den echten Terminal-FD, falls stdout beim Start ein TTY war.
    if [ -n "${SB_UI_TTY_FD:-}" ]; then
        _UI_TTY=1
        _UI_OUT=${SB_UI_TTY_FD}
    elif [ -t 1 ]; then
        _UI_TTY=1
        _UI_OUT=1
    else
        _UI_TTY=0
        _UI_OUT=1
    fi
    _UI_LOG_PATH=$logpath
    _UI_START_TS=$(date +%s)
    _UI_MODULES=("$@")
    _UI_STATE=()
    _UI_LABEL=()
    local m
    for m in "${_UI_MODULES[@]}"; do
        _UI_STATE["$m"]=$_SB_ST_WAIT
        _UI_LABEL["$m"]=${SB_MODUL_LABEL[$m]:-$m}
    done
    _UI_LIST_LINES=0
    _UI_TOTAL_LINES=0

    # Lock-Datei fuer Ticker-Synchronisation einrichten (nur am TTY,
    # nur wenn flock verfuegbar — konv-scripting-bash.md 5.7).
    _UI_STATUS_LOCK=""
    _UI_STATUS_LOCK_FD=""
    if [ "$_UI_TTY" -eq 1 ] && [ "${SB_QUIET:-0}" -eq 0 ] \
        && command -v flock >/dev/null 2>&1; then
        _UI_STATUS_LOCK=$(mktemp)
        # mktemp legt umask-abhaengig an; Modus unabhaengig davon auf 0600.
        chmod 600 "$_UI_STATUS_LOCK"
        # FD einmal oeffnen; Worker erbt ihn (kein Reopen des Pfads).
        exec {_UI_STATUS_LOCK_FD}<>"$_UI_STATUS_LOCK"
    fi
}

#######################################
# Gibt das Symbol fuer einen Zustand zurueck.
# Arguments: $1 — Zustand
# Outputs:   stdout — Symbol-String (ggf. mit Farbe am TTY)
#######################################
_ui_symbol() {
    local st=$1 tty=${2:-0}
    if [ "$tty" -eq 1 ]; then
        case "$st" in
            "$_SB_ST_OK") printf '%b%s%b' "$_SB_C_GREEN" '✓' "$_SB_C_RESET" ;;
            "$_SB_ST_RUN") printf '%b%s%b' "$_SB_C_BLUE" '▶' "$_SB_C_RESET" ;;
            "$_SB_ST_WAIT") printf '%b%s%b' "$_SB_C_GREY" '·' "$_SB_C_RESET" ;;
            "$_SB_ST_WARN") printf '%b%s%b' "$_SB_C_YELLOW" '⚠' "$_SB_C_RESET" ;;
            "$_SB_ST_ERROR") printf '%b%s%b' "$_SB_C_RED" '✗' "$_SB_C_RESET" ;;
            *) printf '?' ;;
        esac
    else
        case "$st" in
            "$_SB_ST_OK") printf '[ok]' ;;
            "$_SB_ST_RUN") printf '[>>]' ;;
            "$_SB_ST_WAIT") printf '[ .]' ;;
            "$_SB_ST_WARN") printf '[!!]' ;;
            "$_SB_ST_ERROR") printf '[EE]' ;;
            *) printf '[?]' ;;
        esac
    fi
}

#######################################
# Gibt die Trennlinie passend zur Terminalbreite aus.
# Arguments: $1 — optionaler Beschriftungstext
# Outputs:   FD _UI_OUT
#######################################
_ui_rule() {
    local label=${1:-}
    local cols
    cols=$(tput cols 2>/dev/null || printf '60')
    if [ -n "$label" ]; then
        local prefix="━━━ $label "
        local rest=$(( cols - ${#prefix} ))
        printf '%s' "$prefix" >&"$_UI_OUT"
        if [ "$rest" -gt 0 ]; then
            printf '━%.0s' $(seq 1 "$rest") >&"$_UI_OUT"
        fi
    else
        printf '━%.0s' $(seq 1 "$cols") >&"$_UI_OUT"
    fi
    printf '\n' >&"$_UI_OUT"
}

#######################################
# Zeichnet die Statusliste einmalig (kein Cursor-Zurueck).
# Non-TTY-Ausgabe: eine Zeile pro Modul.
# Globals:   _UI_MODULES, _UI_STATE, _UI_LABEL, _UI_TTY, _UI_LIST_LINES,
#             _UI_OUT
# Outputs:   stdout (Non-TTY) oder FD _UI_OUT (TTY)
#######################################
ui_list_draw() {
    [ "${SB_QUIET:-0}" -eq 1 ] && return
    # Die Live-Statusliste ist reine Anzeige und gehoert nicht ins Logfile;
    # nur am TTY zeichnen.
    [ "$_UI_TTY" -eq 1 ] || return 0
    # TTY: jede Zeile vor dem Schreiben loeschen (tput el / \033[K), damit
    # Reste laengerer Vorgaenger-Zeilen nicht stehen bleiben.
    local m count=0
    for m in "${_UI_MODULES[@]}"; do
        local sym
        sym=$(_ui_symbol "${_UI_STATE[$m]}" 1)
        printf '    %s  %-12s  %s\033[K\n' "$sym" "$m" "${_UI_LABEL[$m]}" >&"$_UI_OUT"
        count=$((count + 1))
    done
    _UI_LIST_LINES=$count
}

#######################################
# Zeichnet den gesamten Live-Block (Liste + ggf. Statuszeile) neu.
# Positioniert den Cursor zuerst mit tput cuu auf _UI_TOTAL_LINES.
# Interner Helfer — muss unter Lock aufgerufen werden.
# Globals:   _UI_TOTAL_LINES, _UI_STATUS_ACTIVE, _UI_STATUS_MODUL,
#             _UI_STATUS_LABEL, _UI_STATUS_START_TS, _UI_OUT, SB_CURRENT_LOG,
#             SB_SUB
#######################################
_ui_draw_block() {
    # Cursor an den Blockanfang.
    if [ "${_UI_TOTAL_LINES:-0}" -gt 0 ]; then
        local cuu_seq
        cuu_seq=$(tput cuu "$_UI_TOTAL_LINES" 2>/dev/null) || true
        [ -n "$cuu_seq" ] && printf '%s' "$cuu_seq" >&"$_UI_OUT"
    fi
    # Liste (aktualisiert _UI_LIST_LINES).
    ui_list_draw
    # Statuszeile nur wenn aktiv.
    if [ "${_UI_STATUS_ACTIVE:-0}" -eq 1 ]; then
        _ui_status_render_lines
        _UI_TOTAL_LINES=$(( _UI_LIST_LINES + 2 ))
    else
        _UI_TOTAL_LINES=$_UI_LIST_LINES
    fi
}

#######################################
# Schreibt Trennlinie und Statuszeile (ohne Cursor-Positionierung).
# Interner Helfer — muss unter Lock aufgerufen werden.
# Globals:   _UI_STATUS_MODUL, _UI_STATUS_LABEL, _UI_STATUS_START_TS,
#             _UI_OUT, SB_CURRENT_LOG, SB_SUB
#######################################
_ui_status_render_lines() {
    local cols
    cols=$(tput cols 2>/dev/null || printf '60')
    # Trennlinie (schmal, grau).
    local sep_len=$(( cols < 4 ? cols : cols / 2 ))
    printf '%b' "$_SB_C_GREY" >&"$_UI_OUT"
    printf '─%.0s' $(seq 1 "$sep_len") >&"$_UI_OUT"
    printf '%b\033[K\n' "$_SB_C_RESET" >&"$_UI_OUT"

    # Aktion aus dem Logfile lesen (letzte INFO-Zeile ab Modul-Start-Marker).
    local aktion=""
    aktion=$(_ui_letzter_info_text "${_UI_STATUS_MODUL:-}" "${SB_SUB:-}" \
        "${_UI_STATUS_LABEL:-}")

    # Laufzeit berechnen.
    local now elapsed min sec dauer
    now=$(date +%s)
    elapsed=$(( now - _UI_STATUS_START_TS ))
    min=$(( elapsed / 60 ))
    sec=$(( elapsed % 60 ))
    printf -v dauer '%dm%02ds' "$min" "$sec"

    # Aktion auf sichere Laenge kuerzen (Terminalbreite abzgl. fester Teile).
    # Fester Overhead: "  <modul> · " + "  (<dauer>)" + Sicherheitsabstand.
    local overhead=$(( ${#_UI_STATUS_MODUL} + ${#dauer} + 16 ))
    local maxlen=$(( cols - overhead ))
    [ "$maxlen" -lt 10 ] && maxlen=10
    if [ "${#aktion}" -gt "$maxlen" ]; then
        aktion="${aktion:0:$maxlen}…"
    fi

    printf '  %s · %s  (%s)\033[K\n' \
        "${_UI_STATUS_MODUL:-}" "$aktion" "$dauer" >&"$_UI_OUT"
}

#######################################
# Liest die letzte INFO-Zeile des aktuellen Modul-Laufs aus dem Logfile.
# Gibt den Anzeige-Bezeichner zurueck, falls keine INFO-Zeile vorhanden.
# Steuerzeichen werden entfernt (konv-scripting-bash.md 4.3/4.8).
# Globals:   SB_CURRENT_LOG
# Arguments: $1 — Modulname, $2 — Subkommando, $3 — Fallback-Bezeichnung
# Outputs:   stdout — Aktionstext
#######################################
_ui_letzter_info_text() {
    local modul=$1 sub=$2 fallback=$3
    [ -f "${SB_CURRENT_LOG:-}" ] || { printf '%s' "$fallback"; return; }
    local startzeile
    startzeile=$(grep -nF -- "--- Modul ${modul} (${sub}) ---" \
        "${SB_CURRENT_LOG}" 2>/dev/null | tail -1 | cut -d: -f1)
    if [ -z "$startzeile" ]; then
        printf '%s' "$fallback"
        return
    fi
    local text
    text=$(tail -n "+${startzeile}" "${SB_CURRENT_LOG}" 2>/dev/null \
        | grep ' INFO ' | tail -1 \
        | sed -E 's/^[^ ]+ +INFO +//')
    # Steuerzeichen entfernen.
    text=$(printf '%s' "$text" | tr -d '[:cntrl:]')
    if [ -z "$text" ]; then
        printf '%s' "$fallback"
    else
        printf '%s' "$text"
    fi
}

#######################################
# Aktualisiert den Zustand eines Moduls und zeichnet die Liste neu (TTY).
# Non-TTY: gibt nur die geaenderte Zeile aus.
# Haelt das Lock, damit kein Ticker dazwischenschreibt.
# Globals:   _UI_STATE, _UI_TTY, _UI_LIST_LINES, _UI_TOTAL_LINES,
#             _UI_STATUS_LOCK_FD, _UI_OUT
# Arguments: $1 — Modulname, $2 — neuer Zustand, $3 — optionale Bezeichnung
#######################################
ui_list_update() {
    local modul=$1 zustand=$2 label=${3:-}
    _UI_STATE["$modul"]=$zustand
    if [ -n "$label" ]; then
        _UI_LABEL["$modul"]=$label
    fi
    [ "${SB_QUIET:-0}" -eq 1 ] && return
    # Zustand wurde aktualisiert; gezeichnet wird nur am TTY.
    [ "$_UI_TTY" -eq 1 ] || return 0
    # Blockierendes Lock: der Vordergrund muss in jedem Fall zeichnen.
    if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
        flock "$_UI_STATUS_LOCK_FD"
    fi
    _ui_draw_block
    if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
        flock -u "$_UI_STATUS_LOCK_FD"
    fi
}

#######################################
# Gibt eine WARN- oder ERROR-Meldung oberhalb der Liste aus.
# Non-TTY: einfache Zeile nach stderr.
# Haelt das Lock; pausiert den Ticker waehrend der Ausgabe.
# Globals:   _UI_TTY, _UI_LIST_LINES, _UI_TOTAL_LINES, _UI_STATUS_LOCK_FD,
#             _UI_OUT
# Arguments: $1 — Stufe (WARN|ERROR), $2 — Modulname, $3+ — Text
#######################################
ui_message() {
    local stufe=$1 modul=$2
    shift 2
    local text="$*"
    # Reine Anzeige; im Datei-/Pipe-Modus steht die Meldung bereits als
    # WARN/ERROR-Zeile im Logfile.
    [ "$_UI_TTY" -eq 1 ] || return 0

    # Ticker pausieren, damit er nicht dazwischenschreibt.
    local ticker_war_aktiv=0
    if [ "${_UI_STATUS_ACTIVE:-0}" -eq 1 ]; then
        ticker_war_aktiv=1
        ui_status_pause
    fi

    # Blockierendes Lock holen.
    if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
        flock "$_UI_STATUS_LOCK_FD"
    fi

    # Cursor vor die Liste setzen (Gesamtblock).
    if [ "${_UI_TOTAL_LINES:-0}" -gt 0 ]; then
        local cuu_seq
        cuu_seq=$(tput cuu "$_UI_TOTAL_LINES" 2>/dev/null) || true
        [ -n "$cuu_seq" ] && printf '%s' "$cuu_seq" >&"$_UI_OUT"
    fi

    # Meldung ausgeben.
    case "$stufe" in
        WARN) printf '%b  ⚠  %-12s  %s%b\033[K\n' \
                  "$_SB_C_YELLOW" "$modul" "$text" "$_SB_C_RESET" >&"$_UI_OUT" ;;
        ERROR) printf '%b  ✗  %-12s  %s%b\033[K\n' \
                   "$_SB_C_RED" "$modul" "$text" "$_SB_C_RESET" >&"$_UI_OUT" ;;
        *) printf '     %-12s  %s\033[K\n' "$modul" "$text" >&"$_UI_OUT" ;;
    esac

    # _UI_TOTAL_LINES voruebergehend zuruecksetzen, da ui_list_draw
    # _UI_LIST_LINES neu setzt und _ui_draw_block _UI_TOTAL_LINES berechnet.
    _UI_TOTAL_LINES=0
    _UI_LIST_LINES=0
    ui_list_draw
    _UI_TOTAL_LINES=$_UI_LIST_LINES

    if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
        flock -u "$_UI_STATUS_LOCK_FD"
    fi

    # Ticker wieder starten wenn er vorher aktiv war.
    if [ "$ticker_war_aktiv" -eq 1 ]; then
        ui_status_resume
    fi
}

#######################################
# Gibt das Startbanner aus.
# Globals:   _UI_TTY, _UI_LOG_PATH, _UI_OUT
# Arguments: $1 — Modus (install|uninstall|check|test)
#            $2 — Dry-Run (1 oder 0)
#######################################
ui_banner() {
    [ "${SB_QUIET:-0}" -eq 1 ] && return
    # Banner ist reine Bildschirm-Anzeige; nicht ins Logfile.
    [ "$_UI_TTY" -eq 1 ] || return 0
    local modus=$1 dryrun=${2:-0}
    printf '\n' >&"$_UI_OUT"
    _ui_rule "Linux Secure Base · Installer 1.0"
    printf '\n' >&"$_UI_OUT"
    if [ "$dryrun" -eq 1 ]; then
        printf '%b  Modus %-10s  [TROCKENLAUF — keine Aenderungen]%b\n' \
            "$_SB_C_YELLOW" "$modus" "$_SB_C_RESET" >&"$_UI_OUT"
    else
        printf '  Modus %-10s\n' "$modus" >&"$_UI_OUT"
    fi
    printf '  Log   %s\n' "${_UI_LOG_PATH:-—}" >&"$_UI_OUT"
    printf '\n' >&"$_UI_OUT"
}

#######################################
# Gibt die Abschluss-Summary aus.
# Globals:   _UI_TTY, _UI_MODULES, _UI_STATE, _UI_LOG_PATH, _UI_START_TS,
#             _UI_OUT
# Arguments: keine
#######################################
ui_summary() {
    # Reine Anzeige; im Datei-/Pipe-Modus genuegt die Sammelbilanz-Logzeile.
    [ "$_UI_TTY" -eq 1 ] || return 0
    local total=0 ok=0 warn=0 err=0
    local m
    for m in "${_UI_MODULES[@]}"; do
        # Pseudo-Eintrag der Abschluss-Doku nicht als Modul zaehlen (Plan 2.8).
        [ "$m" = "${SB_REPORT_UI_NAME:-}" ] && continue
        total=$((total + 1))
        case "${_UI_STATE[$m]}" in
            "$_SB_ST_OK") ok=$((ok + 1)) ;;
            "$_SB_ST_WARN") warn=$((warn + 1)) ;;
            "$_SB_ST_ERROR") err=$((err + 1)) ;;
        esac
    done
    local elapsed=$(( $(date +%s) - _UI_START_TS ))
    local min=$(( elapsed / 60 ))
    local sec=$(( elapsed % 60 ))
    local dauer
    printf -v dauer '%dm%02ds' "$min" "$sec"

    # Bei Fehler das abgebrochene Modul ermitteln (erstes mit Fehlerzustand).
    local fail_modul=""
    if [ "$err" -gt 0 ]; then
        for m in "${_UI_MODULES[@]}"; do
            if [ "${_UI_STATE[$m]}" = "$_SB_ST_ERROR" ]; then
                fail_modul=$m
                break
            fi
        done
    fi

    printf '\n' >&"$_UI_OUT"
    if [ "$err" -gt 0 ]; then
        _ui_rule "Abgebrochen"
        printf '\n' >&"$_UI_OUT"
        printf '%b  ✗  Abbruch bei %s — %s%b\033[K\n' \
            "$_SB_C_RED" "$fail_modul" "${SB_FAIL_TEXT:-Ursache im Logfile}" "$_SB_C_RESET" >&"$_UI_OUT"
        printf '%b  %d/%d Module · %d Fehler · %d Warnungen · %s%b\033[K\n' \
            "$_SB_C_RED" "$ok" "$total" "$err" "$warn" "$dauer" "$_SB_C_RESET" >&"$_UI_OUT"
    elif [ "$warn" -gt 0 ]; then
        _ui_rule "Fertig"
        printf '\n' >&"$_UI_OUT"
        printf '%b  %d/%d Module · 0 Fehler · %d Warnungen · %s%b\n' \
            "$_SB_C_YELLOW" "$ok" "$total" "$warn" "$dauer" "$_SB_C_RESET" >&"$_UI_OUT"
    else
        _ui_rule "Fertig"
        printf '\n' >&"$_UI_OUT"
        printf '%b  %d/%d Module · 0 Fehler · 0 Warnungen · %s%b\n' \
            "$_SB_C_GREEN" "$ok" "$total" "$dauer" "$_SB_C_RESET" >&"$_UI_OUT"
    fi
    printf '  Log: %s\n\n' "${_UI_LOG_PATH:-—}" >&"$_UI_OUT"
}

# -------------------------------------------------------------------------
# Live-Statuszeile: Ticker-Worker und Steuerungsfunktionen
# -------------------------------------------------------------------------

#######################################
# Hintergrund-Worker: rendert die Statuszeile einmal pro Sekunde.
# Laeuft als Kindprozess; erbt _UI_OUT, _UI_STATUS_LOCK_FD, _UI_LIST_LINES,
# _UI_TOTAL_LINES sowie alle Variablen aus der Shell-Umgebung zum Startzeitpunkt.
# Das Listenbild ist eine eingefrorene Kopie — der Worker stoppt bevor
# der Hauptprozess einen Zustandswechsel vornimmt (2.5 des Plans).
# Stop: SIGTERM an diese PID; der Trap bricht die Schleife ab.
# Globals:   _UI_STATUS_LOCK_FD, _UI_STATUS_ACTIVE, _UI_OUT,
#             _UI_STATUS_MODUL, _UI_STATUS_LABEL, _UI_STATUS_START_TS
# Arguments: keine (Werte ueber geerbte Variablen)
#######################################
_ui_status_ticker() {
    local _ticker_stop=0
    trap '_ticker_stop=1' TERM

    while [ "$_ticker_stop" -eq 0 ]; do
        # Erst schlafen, dann rendern — erster Render nach 1s (Hauptprozess
        # zeichnet die initiale Statuszeile beim Start).
        sleep 1 &
        wait $! 2>/dev/null || true
        [ "$_ticker_stop" -eq 1 ] && break

        # Nicht-blockierendes Lock: Tick ueberspringen wenn Vordergrund schreibt.
        if flock -n "$_UI_STATUS_LOCK_FD" 2>/dev/null; then
            _ui_draw_block
            flock -u "$_UI_STATUS_LOCK_FD"
        fi
    done
}

#######################################
# Startet den Ticker-Worker fuer ein Modul.
# No-op bei non-TTY, SB_QUIET=1 oder fehlendem flock.
# Globals:   _UI_STATUS_ACTIVE, _UI_STATUS_PID, _UI_STATUS_MODUL,
#             _UI_STATUS_LABEL, _UI_STATUS_START_TS, _UI_STATUS_PAUSED,
#             _UI_TOTAL_LINES, _UI_LIST_LINES, _UI_STATUS_LOCK_FD
# Arguments: $1 — Modulname
#######################################
ui_status_start() {
    local modul=$1
    # Vorbedingungen: TTY, kein Quiet-Modus, Lock eingerichtet.
    [ "$_UI_TTY" -eq 1 ] || return 0
    [ "${SB_QUIET:-0}" -eq 0 ] || return 0
    [ -n "${_UI_STATUS_LOCK_FD:-}" ] || return 0

    _UI_STATUS_MODUL=$modul
    _UI_STATUS_LABEL=${_UI_LABEL[$modul]:-$modul}
    _UI_STATUS_START_TS=$(date +%s)
    _UI_STATUS_ACTIVE=1
    _UI_STATUS_PAUSED=0

    # Initiale Statuszeile zeichnen (unter Lock).
    flock "$_UI_STATUS_LOCK_FD"
    _UI_TOTAL_LINES=$(( _UI_LIST_LINES + 2 ))
    _ui_status_render_lines
    flock -u "$_UI_STATUS_LOCK_FD"

    # Worker starten; erbt alle aktuellen Shell-Variablen und den Lock-FD.
    _ui_status_ticker &
    _UI_STATUS_PID=$!
}

#######################################
# Stoppt den Ticker-Worker (idempotent).
# Entfernt Trennlinie und Statuszeile aus dem Bild.
# Globals:   _UI_STATUS_ACTIVE, _UI_STATUS_PID, _UI_STATUS_PAUSED,
#             _UI_TOTAL_LINES, _UI_LIST_LINES, _UI_STATUS_LOCK_FD, _UI_OUT
#######################################
ui_status_stop() {
    # Idempotent: kein aktiver Ticker -> no-op.
    [ "${_UI_STATUS_ACTIVE:-0}" -eq 1 ] || return 0

    # Worker beenden und einsammeln.
    if [ -n "${_UI_STATUS_PID:-}" ]; then
        kill "$_UI_STATUS_PID" 2>/dev/null || true
        wait "$_UI_STATUS_PID" 2>/dev/null || true
        _UI_STATUS_PID=""
    fi

    _UI_STATUS_ACTIVE=0
    _UI_STATUS_PAUSED=0

    # Statuszeile und Trennlinie aus dem Bild entfernen: Block ohne
    # Statuszeile neu zeichnen.
    if [ "$_UI_TTY" -eq 1 ] && [ "${SB_QUIET:-0}" -eq 0 ]; then
        if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
            flock "$_UI_STATUS_LOCK_FD"
        fi
        if [ "${_UI_TOTAL_LINES:-0}" -gt 0 ]; then
            local cuu_seq
            cuu_seq=$(tput cuu "$_UI_TOTAL_LINES" 2>/dev/null) || true
            [ -n "$cuu_seq" ] && printf '%s' "$cuu_seq" >&"$_UI_OUT"
        fi
        ui_list_draw
        # Reste der Statuszeilen loeschen.
        printf '\033[K\n\033[K' >&"$_UI_OUT"
        # Cursor eine Zeile hoch (zurueck auf die Zeile nach der Liste).
        local cuu1
        cuu1=$(tput cuu 1 2>/dev/null) || true
        [ -n "$cuu1" ] && printf '%s' "$cuu1" >&"$_UI_OUT"
        _UI_TOTAL_LINES=$_UI_LIST_LINES
        if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
            flock -u "$_UI_STATUS_LOCK_FD"
        fi
    fi
}

#######################################
# Haelt den Ticker an und entfernt die Statuszeile (fuer interaktive Schritte
# oder WARN/ERROR-Ausgaben). Merkt sich, dass nach der Pause wieder gestartet
# werden soll.
# Globals:   _UI_STATUS_ACTIVE, _UI_STATUS_PAUSED
#######################################
ui_status_pause() {
    # Nur pausieren wenn aktiv und noch nicht pausiert.
    [ "${_UI_STATUS_ACTIVE:-0}" -eq 1 ] || return 0
    [ "${_UI_STATUS_PAUSED:-0}" -eq 0 ] || return 0
    _UI_STATUS_PAUSED=1
    # Worker stoppen ohne _UI_STATUS_ACTIVE zu loeschen (Resume-Erkennung).
    if [ -n "${_UI_STATUS_PID:-}" ]; then
        kill "$_UI_STATUS_PID" 2>/dev/null || true
        wait "$_UI_STATUS_PID" 2>/dev/null || true
        _UI_STATUS_PID=""
    fi
    # Statuszeile aus dem Bild entfernen.
    if [ "$_UI_TTY" -eq 1 ] && [ "${SB_QUIET:-0}" -eq 0 ]; then
        if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
            flock "$_UI_STATUS_LOCK_FD"
        fi
        if [ "${_UI_TOTAL_LINES:-0}" -gt 0 ]; then
            local cuu_seq
            cuu_seq=$(tput cuu "$_UI_TOTAL_LINES" 2>/dev/null) || true
            [ -n "$cuu_seq" ] && printf '%s' "$cuu_seq" >&"$_UI_OUT"
        fi
        ui_list_draw
        printf '\033[K\n\033[K' >&"$_UI_OUT"
        local cuu1
        cuu1=$(tput cuu 1 2>/dev/null) || true
        [ -n "$cuu1" ] && printf '%s' "$cuu1" >&"$_UI_OUT"
        _UI_TOTAL_LINES=$_UI_LIST_LINES
        if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
            flock -u "$_UI_STATUS_LOCK_FD"
        fi
    fi
}

#######################################
# Startet den Ticker nach ui_status_pause neu. Die Modul-Startzeit bleibt
# erhalten, damit die Laufzeit weiterzaehlt.
# Globals:   _UI_STATUS_ACTIVE, _UI_STATUS_PAUSED, _UI_STATUS_MODUL,
#             _UI_STATUS_PID, _UI_STATUS_START_TS
#######################################
ui_status_resume() {
    # Nur wenn in Pause (Ticker war aktiv, aber gestoppt).
    [ "${_UI_STATUS_ACTIVE:-0}" -eq 1 ] || return 0
    [ "${_UI_STATUS_PAUSED:-0}" -eq 1 ] || return 0
    [ -n "${_UI_STATUS_LOCK_FD:-}" ] || return 0

    _UI_STATUS_PAUSED=0

    # Statuszeile erneut zeichnen.
    flock "$_UI_STATUS_LOCK_FD"
    _UI_TOTAL_LINES=$(( _UI_LIST_LINES + 2 ))
    _ui_status_render_lines
    flock -u "$_UI_STATUS_LOCK_FD"

    # Worker neu starten (Startzeit bleibt aus der urspruenglichen).
    _ui_status_ticker &
    _UI_STATUS_PID=$!
}

#######################################
# Raumt Lock-FD und Lock-Datei auf. Als Teil der EXIT-Trap aufrufen.
# Globals:   _UI_STATUS_LOCK_FD, _UI_STATUS_LOCK
#######################################
_ui_status_cleanup() {
    if [ -n "${_UI_STATUS_LOCK_FD:-}" ]; then
        exec {_UI_STATUS_LOCK_FD}>&- 2>/dev/null || true
        _UI_STATUS_LOCK_FD=""
    fi
    if [ -n "${_UI_STATUS_LOCK:-}" ]; then
        rm -f "$_UI_STATUS_LOCK"
        _UI_STATUS_LOCK=""
    fi
}
