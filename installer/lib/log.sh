# shellcheck shell=bash
#
# secure-base Helper: Logging und Ausgabe
#
# Bietet:
#   log          — strukturierte Ausgabe (INFO/WARN/ERROR)
#   die          — Fehler loggen und Skript beenden
#   ensure_log_dir — /var/log/secure-base/ idempotent anlegen
#   open_log     — Logdatei öffnen, stdout/stderr umleiten
#   _sb_close_log — Filtersubprozesse am Exit abwarten
#
# Globals (gesetzt von open_log, gelesen von _sb_close_log):
#   SB_LOG_DIR, SB_FILTER_OUT_PID, SB_FILTER_ERR_PID
#   SB_WARN_COUNT, SB_ERROR_COUNT, SB_CURRENT_LOG, SB_UI_TTY_FD

# Log-Verzeichnis: als root nach /var/log, sonst (check/test/Trockenlauf ohne
# root) in ein temporaeres Verzeichnis.
if [ "$(id -u)" -eq 0 ]; then
    SB_LOG_DIR="/var/log/secure-base"
else
    SB_LOG_DIR="${TMPDIR:-/tmp}/secure-base"
fi
readonly SB_LOG_DIR

SB_FILTER_OUT_PID=""
SB_FILTER_ERR_PID=""
# Pfad der zuletzt geoeffneten Logdatei (von open_log gesetzt).
SB_CURRENT_LOG=""
# FD des echten Terminals, gesetzt von open_log wenn stdout ein TTY ist.
# Leere Zeichenkette = kein TTY-UI-Modus.
SB_UI_TTY_FD=""

# Zaehler fuer WARN/ERROR-Meldungen im laufenden Prozess.
# Subshells zaehlen nicht (Module loggen Mehrzeiler ueber Prozesssubstitution).
SB_WARN_COUNT=0
SB_ERROR_COUNT=0

#######################################
# Schreibt eine Log-Zeile.
# WARN und ERROR gehen nach stderr, INFO nach stdout.
# WARN/ERROR erhoehen die globalen Zaehler.
# Globals:   SB_WARN_COUNT, SB_ERROR_COUNT
# Arguments: $1 — Stufe (INFO|WARN|ERROR), $2+ — Text
# Outputs:   stdout (INFO) oder stderr (WARN/ERROR)
#######################################
log() {
    local stufe=$1
    shift
    case "$stufe" in
        INFO) ;;
        WARN) SB_WARN_COUNT=$((SB_WARN_COUNT + 1)) ;;
        ERROR) SB_ERROR_COUNT=$((SB_ERROR_COUNT + 1)) ;;
        *)
            printf 'ERROR unbekannte Log-Stufe: %s\n' "$stufe" >&2
            return 2
            ;;
    esac
    local zeile
    zeile=$(printf '%-5s %s' "$stufe" "$*")
    case "$stufe" in
        INFO) printf '%s\n' "$zeile" ;;
        WARN | ERROR) printf '%s\n' "$zeile" >&2 ;;
    esac
}

#######################################
# Loggt eine Fehlermeldung und beendet das Skript mit Exit-Code 1.
# Arguments: $* — Fehlermeldung
#######################################
die() {
    log ERROR "$*"
    exit 1
}

#######################################
# Legt /var/log/secure-base/ idempotent an (root:adm, 0750).
#######################################
ensure_log_dir() {
    if [ -d "$SB_LOG_DIR" ]; then
        return
    fi
    if [ "$(id -u)" -eq 0 ]; then
        install -d -o root -g adm -m 0750 "$SB_LOG_DIR"
    else
        mkdir -p "$SB_LOG_DIR"
    fi
}

#######################################
# Liest Zeilen aus stdin und schreibt sie zeitgestempelt ins Logfile.
# Am Terminal erscheinen Zeilen nur im Verbose-Modus (SB_SHOW_INFO=1),
# und nur wenn kein TTY-UI aktiv ist (SB_UI_TTY_FD gesetzt). WARN/ERROR
# am Terminal verantwortet ui_message, nicht dieser Filter.
# Globals:   SB_SHOW_INFO, SB_UI_TTY_FD
# Arguments: $1 — Pfad zur Logdatei
# Outputs:   Logfile (immer); stdout nur im Non-TTY-Verbose-Modus
#######################################
_sb_log_filter() {
    local lf=$1 line ts
    while IFS= read -r line; do
        printf -v ts '%(%Y-%m-%dT%H:%M:%S%z)T' -1
        printf '%s %s\n' "$ts" "$line" >>"$lf"
        # Im TTY-UI-Modus erscheinen Log-Zeilen nie am Terminal —
        # die UI zeichnet den Zustand; WARN/ERROR ruft ui_message auf.
        [ -n "${SB_UI_TTY_FD:-}" ] && continue
        # Non-TTY: Verbose-Filter
        case "$line" in
            INFO*) [ "${SB_SHOW_INFO:-0}" -eq 1 ] || continue ;;
        esac
        printf '%s\n' "$line"
    done
}

#######################################
# Oeffnet die Logdatei und leitet stdout/stderr ueber _sb_log_filter.
# Ist stdout beim Aufruf ein TTY, wird der echte Terminal-FD in
# SB_UI_TTY_FD festgehalten, damit ui.sh direkt ans Terminal schreiben
# kann — vorbei am Filter. Der Filter gibt dann keine Zeilen ans Terminal
# aus (TTY-UI-Modus, s. _sb_log_filter).
# Logfile: /var/log/secure-base/<modul>-<sub>-<ts>.log, Mode 0640.
# Globals:   SB_FILTER_OUT_PID, SB_FILTER_ERR_PID, SB_UI_TTY_FD
# Arguments: $1 — Modulname, $2 — Subkommando
#######################################
open_log() {
    local modul=$1
    local subkommando=$2
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    ensure_log_dir
    local logfile="${SB_LOG_DIR}/${modul}-${subkommando}-${ts}.log"
    SB_CURRENT_LOG=$logfile
    export SB_CURRENT_LOG
    # Terminal-FD vor der Umleitung sichern (nur wenn stdout ein TTY ist).
    if [ -t 1 ]; then
        exec 3>&1
        SB_UI_TTY_FD=3
        export SB_UI_TTY_FD
    fi
    exec > >(umask 0027; _sb_log_filter "$logfile")
    SB_FILTER_OUT_PID=$!
    exec 2> >(umask 0027; _sb_log_filter "$logfile" >&2)
    SB_FILTER_ERR_PID=$!
    trap '_sb_close_log' EXIT
}

#######################################
# Wartet am Skript-Exit auf die Filtersubprozesse aus open_log.
# Ohne vorherigen open_log-Aufruf keine Wirkung.
# Globals:   SB_FILTER_OUT_PID, SB_FILTER_ERR_PID
#######################################
_sb_close_log() {
    # FDs schliessen, damit die Filtersubprozesse EOF auf der Pipe sehen.
    # Ohne diesen Schritt wuerden sie nie enden und wait blockierte.
    exec 1>&- 2>&-
    if [ -n "${SB_FILTER_OUT_PID:-}" ]; then
        wait "$SB_FILTER_OUT_PID" 2>/dev/null || true
        SB_FILTER_OUT_PID=""
    fi
    if [ -n "${SB_FILTER_ERR_PID:-}" ]; then
        wait "$SB_FILTER_ERR_PID" 2>/dev/null || true
        SB_FILTER_ERR_PID=""
    fi
}
