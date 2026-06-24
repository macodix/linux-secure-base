# shellcheck shell=bash
#
# secure-base Helper: Ausgabe und Live-Statusliste
#
# Bietet:
#   ui_init        — interne Zustandsvariablen initialisieren
#   ui_banner      — Startbanner ausgeben
#   ui_list_draw   — vollstaendige Statusliste zeichnen (einmalig oder live)
#   ui_list_update — Zustand eines Moduls aendern und Liste neu zeichnen
#   ui_message     — WARN/ERROR-Meldung oberhalb der Liste ausgeben
#   ui_summary     — Abschlussmeldung ausgeben
#
# Ausgabe-Konzept:
#   Am TTY: fixe Live-Statusliste, die bei jedem Statuswechsel neu gezeichnet
#   wird (tput-Cursor-Neupositionierung). Meldungen (WARN/ERROR) erscheinen
#   oberhalb der Liste.
#   Non-TTY (Pipe, Umleitung): einfache Einzelzeilen ohne Cursor-Steuerung.
#
# Symbole und Farben:
#   ✓ gruen  (ok)     ▶ blau   (laeuft)
#   · grau   (wartet) ⚠ gelb   (Warnung)
#   ✗ rot    (Fehler)
#
# Globals (von ui_init gesetzt):
#   _UI_TTY         — 1 wenn stdout ein TTY ist, sonst 0
#   _UI_OUT         — Dateideskriptor fuer TTY-Ausgabe (FD 3 nach open_log,
#                     FD 1 davor); nie durch den Log-Filter geleitet
#   _UI_MODULES     — Array der Modulnamen (Reihenfolge = Darstellungsreihenfolge)
#   _UI_STATE       — assoziatives Array: Modulname -> Zustand
#   _UI_LABEL       — assoziatives Array: Modulname -> Anzeigebezeichnung
#   _UI_LIST_LINES  — Anzahl der zuletzt gezeichneten Listenzeilen (fuer tput)
#   _UI_LOG_PATH    — Logdatei-Pfad fuer Anzeige in Banner und Summary
#   _UI_START_TS    — Zeitstempel des Starts (Sekunden seit Epoch)

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
_UI_LOG_PATH=""
_UI_START_TS=0
# PID des Lebenszeichen-Pollers (ui_heartbeat_start), leer wenn keiner laeuft.
_UI_HB_PID=""

declare -a _UI_MODULES=()
declare -A _UI_STATE=()
declare -A _UI_LABEL=()

#######################################
# Initialisiert die UI-Zustandsvariablen.
# Legt _UI_OUT fest: wird SB_UI_TTY_FD nach open_log gesetzt, wird dieser
# FD fuer alle TTY-Ausgaben genutzt (umgeht den Log-Filter); sonst FD 1.
# Globals:   _UI_TTY, _UI_OUT, _UI_MODULES, _UI_STATE, _UI_LABEL,
#             _UI_LOG_PATH, _UI_START_TS, SB_UI_TTY_FD
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
# Aktualisiert den Zustand eines Moduls und zeichnet die Liste neu (TTY).
# Non-TTY: gibt nur die geaenderte Zeile aus.
# Globals:   _UI_STATE, _UI_TTY, _UI_LIST_LINES, _UI_OUT
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
    # Cursor um _UI_LIST_LINES Zeilen hoch, dann Liste neu zeichnen.
    # tput-Sequenz direkt ans echte Terminal (FD _UI_OUT), nicht als Text
    # in den Log-Filter. tput-Fehler ignorieren (kein Terminal vorhanden).
    if [ "$_UI_LIST_LINES" -gt 0 ]; then
        local cuu_seq
        cuu_seq=$(tput cuu "$_UI_LIST_LINES" 2>/dev/null) || true
        [ -n "$cuu_seq" ] && printf '%s' "$cuu_seq" >&"$_UI_OUT"
    fi
    ui_list_draw
}

#######################################
# Gibt eine WARN- oder ERROR-Meldung oberhalb der Liste aus.
# Non-TTY: einfache Zeile nach stderr.
# Globals:   _UI_TTY, _UI_LIST_LINES, _UI_OUT
# Arguments: $1 — Stufe (WARN|ERROR), $2 — Modulname, $3+ — Text
#######################################
ui_message() {
    local stufe=$1 modul=$2
    shift 2
    local text="$*"
    # Reine Anzeige; im Datei-/Pipe-Modus steht die Meldung bereits als
    # WARN/ERROR-Zeile im Logfile.
    [ "$_UI_TTY" -eq 1 ] || return 0
    # Cursor vor die Liste setzen, Meldung mit Clear-to-EOL schreiben,
    # dann Liste neu zeichnen. Alle Ausgaben direkt ans echte Terminal (FD _UI_OUT).
    if [ "$_UI_LIST_LINES" -gt 0 ]; then
        local cuu_seq
        cuu_seq=$(tput cuu "$_UI_LIST_LINES" 2>/dev/null) || true
        [ -n "$cuu_seq" ] && printf '%s' "$cuu_seq" >&"$_UI_OUT"
    fi
    case "$stufe" in
        WARN) printf '%b  ⚠  %-12s  %s%b\033[K\n' \
                  "$_SB_C_YELLOW" "$modul" "$text" "$_SB_C_RESET" >&"$_UI_OUT" ;;
        ERROR) printf '%b  ✗  %-12s  %s%b\033[K\n' \
                   "$_SB_C_RED" "$modul" "$text" "$_SB_C_RESET" >&"$_UI_OUT" ;;
        *) printf '     %-12s  %s\033[K\n' "$modul" "$text" >&"$_UI_OUT" ;;
    esac
    _UI_LIST_LINES=$((_UI_LIST_LINES + 1))
    ui_list_draw
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
        # Pseudo-Eintrag der Abschluss-Doku zaehlt nicht als Modul.
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

    # Bei Fehler: bei install/uninstall das abgebrochene Modul ermitteln.
    local fail_modul=""
    if [ "$err" -gt 0 ]; then
        for m in "${_UI_MODULES[@]}"; do
            if [ "${_UI_STATE[$m]}" = "$_SB_ST_ERROR" ]; then
                fail_modul=$m
                break
            fi
        done
    fi

    # check/test laufen durch alle Module; "Abgebrochen" waere irreführend.
    local sub="${SB_SUB:-}"
    local is_diagnose=0
    if [ "$sub" = "check" ] || [ "$sub" = "test" ]; then
        is_diagnose=1
    fi

    printf '\n' >&"$_UI_OUT"
    if [ "$err" -gt 0 ] && [ "$is_diagnose" -eq 1 ]; then
        _ui_rule "Fertig"
        printf '\n' >&"$_UI_OUT"
        printf '%b  %d/%d Module geprüft · %d mit Mängeln · %d Warnungen · %s%b\033[K\n' \
            "$_SB_C_RED" "$total" "$total" "$err" "$warn" "$dauer" "$_SB_C_RESET" >&"$_UI_OUT"
    elif [ "$err" -gt 0 ]; then
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

#######################################
# Startet das Lebenszeichen unter der Statusliste.
# Zeichnet unter der Liste einen Trennblock (Leerzeile, Linie, Leerzeile) und
# darunter die "Aktuell:"-Zeile mit der juengsten Logzeile (Timestamp
# abgeschnitten). Ein Poller aktualisiert NUR diese unterste Zeile rein
# HORIZONTAL (\r + Clear-to-EOL, kein vertikales Cursor-Movement im Takt).
# ui_heartbeat_stop raeumt den Block ab und stellt die Cursor-Basis wieder her,
# daher bleiben ui_list_update/ui_list_draw unangetastet.
# No-op bei non-TTY, SB_QUIET=1 oder fehlendem Logfile.
# Globals:   _UI_TTY, _UI_OUT, _UI_HB_PID, SB_CURRENT_LOG, SB_QUIET
# Arguments: $1 — Anzeige-Label des aktiven Moduls (Fallback-Text)
#######################################
ui_heartbeat_start() {
    local label=$1
    [ "$_UI_TTY" -eq 1 ] || return 0
    [ "${SB_QUIET:-0}" -eq 0 ] || return 0
    [ -n "${SB_CURRENT_LOG:-}" ] || return 0
    local cols linie
    cols=$(tput cols 2>/dev/null || echo 60)
    linie=$(printf '─%.0s' $(seq 1 "$cols"))
    # Block unter der Liste: Leerzeile, Trennlinie, Leerzeile, Aktuell-Zeile.
    # Die ersten drei Zeilen sind statisch; nur die unterste (Aktuell-)Zeile
    # aktualisiert der Poller horizontal. ui_heartbeat_stop raeumt alle vier
    # Zeilen wieder ab und stellt die Cursor-Basis fuer ui_list_update her.
    printf '\033[K\n%s\033[K\n\033[K\n    Aktuell: %s\033[K' "$linie" "$label" >&"$_UI_OUT"
    (
        while :; do
            sleep 1
            letzte=$(tail -n1 "$SB_CURRENT_LOG" 2>/dev/null | cut -d' ' -f2-)
            zeile="    Aktuell: ${letzte:-$label}"
            printf '\r%s\033[K' "${zeile:0:cols}" >&"$_UI_OUT"
        done
    ) &
    _UI_HB_PID=$!
}

#######################################
# Stoppt das Lebenszeichen und loescht seine Zeile.
# Idempotent. Nach dem Aufruf steht der Cursor am Anfang der (geleerten)
# Zeile unter der Liste — die Ausgangslage, die ui_list_update erwartet.
# Globals:   _UI_HB_PID, _UI_TTY, _UI_OUT
#######################################
ui_heartbeat_stop() {
    [ -n "${_UI_HB_PID:-}" ] || return 0
    kill "$_UI_HB_PID" 2>/dev/null || true
    wait "$_UI_HB_PID" 2>/dev/null || true
    _UI_HB_PID=""
    # Aktuell-Zeile und die drei statischen Zeilen (Leer/Linie/Leer) entfernen,
    # Cursor zurueck auf die Zeile direkt unter der Liste (ui_list_update-Basis).
    [ "$_UI_TTY" -eq 1 ] \
        && printf '\r\033[K\033[1A\033[K\033[1A\033[K\033[1A\033[K' >&"$_UI_OUT"
    return 0
}
