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
_UI_LIST_LINES=0
_UI_LOG_PATH=""
_UI_START_TS=0

declare -a _UI_MODULES=()
declare -A _UI_STATE=()
declare -A _UI_LABEL=()

#######################################
# Initialisiert die UI-Zustandsvariablen.
# Globals:   _UI_TTY, _UI_MODULES, _UI_STATE, _UI_LABEL,
#             _UI_LOG_PATH, _UI_START_TS
# Arguments:
#   $1        — Logdatei-Pfad (fuer Anzeige)
#   $2 ..     — Modulnamen
#######################################
ui_init() {
    local logpath=$1
    shift
    [ -t 1 ] && _UI_TTY=1 || _UI_TTY=0
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
# Outputs:   stdout
#######################################
_ui_rule() {
    local label=${1:-}
    local cols
    cols=$(tput cols 2>/dev/null || printf '60')
    if [ -n "$label" ]; then
        local prefix="━━━ $label "
        local rest=$(( cols - ${#prefix} ))
        printf '%s' "$prefix"
        if [ "$rest" -gt 0 ]; then
            printf '━%.0s' $(seq 1 "$rest")
        fi
    else
        printf '━%.0s' $(seq 1 "$cols")
    fi
    printf '\n'
}

#######################################
# Zeichnet die Statusliste einmalig (kein Cursor-Zurueck).
# Non-TTY-Ausgabe: eine Zeile pro Modul.
# Globals:   _UI_MODULES, _UI_STATE, _UI_LABEL, _UI_TTY, _UI_LIST_LINES
# Outputs:   stdout
#######################################
ui_list_draw() {
    [ "${SB_QUIET:-0}" -eq 1 ] && return
    if [ "$_UI_TTY" -eq 0 ]; then
        local m
        for m in "${_UI_MODULES[@]}"; do
            local sym
            sym=$(_ui_symbol "${_UI_STATE[$m]}" 0)
            printf '  %s  %-12s  %s\n' "$sym" "$m" "${_UI_LABEL[$m]}"
        done
        return
    fi
    # TTY: Liste direkt ausgeben und Zeilenanzahl zaehlen
    local m count=0
    for m in "${_UI_MODULES[@]}"; do
        local sym
        sym=$(_ui_symbol "${_UI_STATE[$m]}" 1)
        printf '    %s  %-12s  %s\n' "$sym" "$m" "${_UI_LABEL[$m]}"
        count=$((count + 1))
    done
    _UI_LIST_LINES=$count
}

#######################################
# Aktualisiert den Zustand eines Moduls und zeichnet die Liste neu (TTY).
# Non-TTY: gibt nur die geaenderte Zeile aus.
# Globals:   _UI_STATE, _UI_TTY, _UI_LIST_LINES
# Arguments: $1 — Modulname, $2 — neuer Zustand, $3 — optionale Bezeichnung
#######################################
ui_list_update() {
    local modul=$1 zustand=$2 label=${3:-}
    _UI_STATE["$modul"]=$zustand
    if [ -n "$label" ]; then
        _UI_LABEL["$modul"]=$label
    fi
    [ "${SB_QUIET:-0}" -eq 1 ] && return
    if [ "$_UI_TTY" -eq 0 ]; then
        local sym
        sym=$(_ui_symbol "$zustand" 0)
        printf '  %s  %-12s  %s\n' "$sym" "$modul" "${_UI_LABEL[$modul]}"
        return
    fi
    # Cursor um _UI_LIST_LINES Zeilen hoch, dann Liste neu zeichnen
    if [ "$_UI_LIST_LINES" -gt 0 ]; then
        tput cuu "$_UI_LIST_LINES" 2>/dev/null || true
    fi
    ui_list_draw
}

#######################################
# Gibt eine WARN- oder ERROR-Meldung oberhalb der Liste aus.
# Non-TTY: einfache Zeile nach stderr.
# Globals:   _UI_TTY, _UI_LIST_LINES
# Arguments: $1 — Stufe (WARN|ERROR), $2 — Modulname, $3+ — Text
#######################################
ui_message() {
    local stufe=$1 modul=$2
    shift 2
    local text="$*"
    if [ "$_UI_TTY" -eq 0 ]; then
        printf '  %s  %s  %s\n' "$stufe" "$modul" "$text" >&2
        return
    fi
    # Cursor vor die Liste setzen, eine leere Zeile einfuegen, Meldung schreiben,
    # dann Liste neu zeichnen
    if [ "$_UI_LIST_LINES" -gt 0 ]; then
        tput cuu "$_UI_LIST_LINES" 2>/dev/null || true
    fi
    case "$stufe" in
        WARN) printf '%b  ⚠  %-12s  %s%b\n' "$_SB_C_YELLOW" "$modul" "$text" "$_SB_C_RESET" ;;
        ERROR) printf '%b  ✗  %-12s  %s%b\n' "$_SB_C_RED" "$modul" "$text" "$_SB_C_RESET" ;;
        *) printf '     %-12s  %s\n' "$modul" "$text" ;;
    esac
    _UI_LIST_LINES=$((_UI_LIST_LINES + 1))
    ui_list_draw
}

#######################################
# Gibt das Startbanner aus.
# Globals:   _UI_TTY, _UI_LOG_PATH
# Arguments: $1 — Modus (install|uninstall|check|test)
#            $2 — Dry-Run (1 oder 0)
#######################################
ui_banner() {
    [ "${SB_QUIET:-0}" -eq 1 ] && return
    local modus=$1 dryrun=${2:-0}
    if [ "$_UI_TTY" -eq 1 ]; then
        printf '\n'
        _ui_rule "Linux Secure Base · Installer 1.0"
        printf '\n'
        if [ "$dryrun" -eq 1 ]; then
            printf '%b  Modus %-10s  [TROCKENLAUF — keine Aenderungen]%b\n' \
                "$_SB_C_YELLOW" "$modus" "$_SB_C_RESET"
        else
            printf '  Modus %-10s\n' "$modus"
        fi
        printf '  Log   %s\n' "${_UI_LOG_PATH:-—}"
        printf '\n'
    else
        printf '=== Linux Secure Base · Installer 1.0 · Modus: %s' "$modus"
        [ "$dryrun" -eq 1 ] && printf ' [TROCKENLAUF]'
        printf ' ===\n'
        printf 'Log: %s\n' "${_UI_LOG_PATH:-—}"
    fi
}

#######################################
# Gibt die Abschluss-Summary aus.
# Globals:   _UI_TTY, _UI_MODULES, _UI_STATE, _UI_LOG_PATH, _UI_START_TS
# Arguments: keine
#######################################
ui_summary() {
    local total=0 ok=0 warn=0 err=0
    local m
    for m in "${_UI_MODULES[@]}"; do
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

    if [ "$_UI_TTY" -eq 1 ]; then
        printf '\n'
        _ui_rule "Fertig"
        printf '\n'
        if [ "$err" -gt 0 ]; then
            printf '%b  %d/%d Module · %d Fehler · %d Warnungen · %s%b\n' \
                "$_SB_C_RED" "$ok" "$total" "$err" "$warn" "$dauer" "$_SB_C_RESET"
        elif [ "$warn" -gt 0 ]; then
            printf '%b  %d/%d Module · 0 Fehler · %d Warnungen · %s%b\n' \
                "$_SB_C_YELLOW" "$ok" "$total" "$warn" "$dauer" "$_SB_C_RESET"
        else
            printf '%b  %d/%d Module · 0 Fehler · 0 Warnungen · %s%b\n' \
                "$_SB_C_GREEN" "$ok" "$total" "$dauer" "$_SB_C_RESET"
        fi
        printf '  Log: %s\n\n' "${_UI_LOG_PATH:-—}"
    else
        printf '=== Fertig: %d/%d ok · %d Fehler · %d Warnungen · %s · Log: %s ===\n' \
            "$ok" "$total" "$err" "$warn" "$dauer" "${_UI_LOG_PATH:-—}"
    fi
}
