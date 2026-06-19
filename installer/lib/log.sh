# shellcheck shell=bash
#
# secure-base Helper: Logging und Ausgabe
#
# Bietet:
#   log             — strukturierte Ausgabe (INFO/WARN/ERROR)
#   die             — Fehler loggen und Skript beenden
#   ensure_log_dir  — Log-Verzeichnis idempotent anlegen
#   open_log        — zentrales Logfile oeffnen, stdout/stderr umleiten
#   _sb_close_log   — Filtersubprozesse am Exit abwarten
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

# Fester Name des zentralen Logfiles (Append-Modus, alle Laeufe).
# Installation der logrotate-Konfiguration (installer/logrotate.d/secure-base)
# nach /etc/logrotate.d/secure-base erfolgt durch das logging-Modul/Deployment.
readonly SB_LOG_FILE="${SB_LOG_DIR}/secure-base.log"

SB_FILTER_OUT_PID=""
SB_FILTER_ERR_PID=""
# Pfad der zuletzt geoeffneten Logdatei (von open_log gesetzt).
# Nicht ueberschreiben, wenn bereits durch den Installer-Prozess exportiert
# (Modul laeuft als Kindprozess und soll denselben Logpfad erben).
: "${SB_CURRENT_LOG:=}"
# FD des echten Terminals, gesetzt von open_log wenn stdout ein TTY ist.
# Leere Zeichenkette = kein TTY-UI-Modus. Ebenfalls nicht ueberschreiben
# wenn durch den Installer-Prozess exportiert.
: "${SB_UI_TTY_FD:=}"

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
# Legt das Log-Verzeichnis idempotent an (root:adm, 0750).
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
#            $2 — "err" wenn dieser Filter fuer stderr-Eingabe benutzt
#                 wird; dann geht die Terminal-Ausgabe auf stderr statt
#                 stdout, um Doppel-Eintrag im Logfile zu vermeiden.
# Outputs:   Logfile (immer); FD 1 (stdout-Filter) bzw. FD 2 (stderr-Filter)
#            im Non-TTY-Verbose-Modus
#######################################
_sb_log_filter() {
    local lf=$1 is_err=${2:-} line ts
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
        if [ "$is_err" = "err" ]; then
            printf '%s\n' "$line" >&2
        else
            printf '%s\n' "$line"
        fi
    done
}

#######################################
# Oeffnet das zentrale Logfile und leitet stdout/stderr ueber _sb_log_filter.
#
# Wird aufgerufen vom Installer (secure-base-installer) und von Modulen
# (via dispatch), die ohne Installer direkt gestartet werden.
#
# Laeuft das Modul als Kindprozess des Installers, ist SB_CURRENT_LOG
# bereits exportiert. In diesem Fall werden keine neuen Filter geoeffnet —
# stdout/stderr fliessen bereits ueber die geerbten FDs in den
# Installer-Filter. Nur _sb_close_log wird als Trap eingetragen.
#
# Ist stdout beim Aufruf ein TTY, wird der echte Terminal-FD in
# SB_UI_TTY_FD festgehalten, damit ui.sh direkt ans Terminal schreiben
# kann — vorbei am Filter.
#
# Logfile: ${SB_LOG_DIR}/secure-base.log (Append-Modus, kein Zeitstempel
# im Namen). Der Installer schreibt je Lauf eine Trennzeile.
# Globals:   SB_FILTER_OUT_PID, SB_FILTER_ERR_PID, SB_UI_TTY_FD,
#            SB_CURRENT_LOG
# Arguments: keine
#######################################
open_log() {
    ensure_log_dir
    # Wenn SB_CURRENT_LOG bereits gesetzt ist, laeuft dieses Skript als
    # Kindprozess des Installers. stdout/stderr sind bereits in den
    # Installer-Filter umgeleitet — keine neuen Filter oeffnen.
    if [ -n "${SB_CURRENT_LOG:-}" ]; then
        trap '_sb_close_log' EXIT
        return
    fi
    local logfile="$SB_LOG_FILE"
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
    # Der stderr-Filter erbt FD 1 = stdout-Filter-Schreib-Ende (da exec > >(...)
    # bereits gesetzt ist). Mit dem "err"-Parameter schreibt _sb_log_filter
    # seine Terminal-Ausgabe auf FD 2 statt FD 1, sodass kein Zeilenduplikat
    # ueber den stdout-Filter ins Logfile gelangt.
    exec 2> >(umask 0027; _sb_log_filter "$logfile" err)
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
