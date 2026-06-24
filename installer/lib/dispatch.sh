# shellcheck shell=bash
#
# secure-base Helper: Subkommando-Dispatch fuer Module
#
# Bietet dispatch — validiert Subkommando, oeffnet das Log und ruft
# do_install/do_uninstall/do_check/do_test/do_doc.
#
# Das aufrufende Modul muss diese fuenf Funktionen definieren.
# Im Regelfall ueber den Installer secure-base-installer aufrufen.

# Modul und Subkommando des laufenden Dispatch — von dispatch gesetzt,
# vom EXIT-Trap _sb_finish gelesen. Global, weil der Trap auf dem
# Erfolgspfad erst nach Rueckkehr aus dispatch feuert.
SB_MODUL=""
SB_SUB=""

#######################################
# Abschlussbilanz eines Modul-Laufs.
# Wird als EXIT-Trap gesetzt; feuert bei jedem Ende des Modul-Prozesses.
# Globals:   SB_MODUL, SB_SUB, SB_ERROR_COUNT, SB_WARN_COUNT
#######################################
_sb_finish() {
    local rc=$?
    # Im doc-Lauf keine Abschlussbilanz und kein Leerzeilen-Trenner ausgeben:
    # doc_build faengt stdout des Kindprozesses ab; INFO geht auf stdout und
    # wuerde den Markdown verunreinigen (Plan 2.9).
    if [ "$SB_SUB" != "doc" ]; then
        local status
        if [ "$rc" -eq 0 ] && [ "$SB_ERROR_COUNT" -eq 0 ]; then
            status=ERFOLG
        else
            status=FEHLER
        fi
        log INFO "=== ${SB_MODUL} ${SB_SUB}: ${status} (${SB_WARN_COUNT} Warnungen, ${SB_ERROR_COUNT} Fehler) ==="
        printf '\n'
    fi
    _sb_close_log
}

#######################################
# Gibt die Usage eines Moduls im Unix-Stil aus.
# Arguments: $1 — Modulname
# Outputs:   stderr
#######################################
_dispatch_usage() {
    local modul=$1
    cat >&2 <<EOF
SYNOPSIS
    $modul [-c <pfad>] <KOMMANDO>

KOMMANDOS
    install    Modul installieren und konfigurieren
    uninstall  Modul-Konfiguration zuruecknehmen
    check      Soll-Ist-Vergleich ohne Aenderungen
    test       Funktionstest ohne Aenderungen

OPTIONEN
    -c <pfad>  Alternative Konfigdatei (Default: conf/secure-base.conf)

EXIT STATUS
    0  Erfolg
    1  Fehler
    2  Aufruffehler

HINWEIS
    Einzelmodul der Linux Secure Base. Im Regelfall ueber den Installer
    secure-base-installer aufrufen, nicht direkt.
EOF
}

#######################################
# Standard-Implementierung fuer do_doc: laedt die conf und gibt module_doc
# nach stdout. Kann vom Modul ueberschrieben werden, wenn noetig.
# Globals:   SB_CONF (lesend)
#######################################
do_doc() {
    load_conf "$SB_CONF"
    module_doc
}

#######################################
# Validiert das Subkommando, oeffnet das Log und delegiert an do_*.
# Arguments: $1 — Modulname, $2 — Subkommando (install|uninstall|check|test)
# Globals:   SB_MODUL, SB_SUB
#######################################
dispatch() {
    local modul=$1
    shift
    # Optionales -c <pfad> vor dem Subkommando (setzt die zentrale SB_CONF).
    local OPTIND=1 opt
    while getopts ':c:h' opt; do
        case "$opt" in
            c) export SB_CONF="$OPTARG" ;;
            h) _dispatch_usage "$modul"; exit 0 ;;
            :) printf 'Option -%s erwartet ein Argument\n' "$OPTARG" >&2
               _dispatch_usage "$modul"; exit 2 ;;
            \?) printf 'Unbekannte Option: -%s\n' "$OPTARG" >&2
                _dispatch_usage "$modul"; exit 2 ;;
        esac
    done
    shift $((OPTIND - 1))

    local sub=${1:-}
    case "$sub" in
        --help) _dispatch_usage "$modul"; exit 0 ;;
        "")
            _dispatch_usage "$modul"
            exit 2
            ;;
        install | uninstall | check | test | doc) ;;
        *)
            printf 'unbekanntes Subkommando: %s\n\n' "$sub" >&2
            _dispatch_usage "$modul"
            exit 2
            ;;
    esac
    shift

    # root nur fuer aendernde Laeufe; check/test kommen ohne root aus
    # (konsistent zum Installer secure-base-installer).
    # doc ist rein lesend und benoetigt ebenfalls kein root (Plan 2.9).
    case "$sub" in
        install | uninstall) require_root ;;
    esac
    open_log
    # _sb_finish ersetzt den _sb_close_log-Trap aus open_log und ruft
    # _sb_close_log selbst. Modul/Sub global, da der Trap erst nach
    # Rueckkehr aus dispatch feuert.
    SB_MODUL=$modul
    SB_SUB=$sub
    trap '_sb_finish' EXIT

    # Start-Marker ins zentrale Logfile: grenzt Modul-Laeufe lesbar ab und
    # dient dem Installer als Anker fuer die Fehlersuche dieses Laufs.
    # Im doc-Lauf unterdrueckt: doc_build faengt stdout ab; INFO geht auf
    # stdout und wuerde den Markdown verunreinigen (Plan 2.9).
    [ "$sub" = "doc" ] || log INFO "--- Modul ${modul} (${sub}) ---"

    case "$sub" in
        install) do_install "$@" ;;
        uninstall) do_uninstall "$@" ;;
        check) do_check "$@" ;;
        test) do_test "$@" ;;
        doc) do_doc "$@" ;;
    esac
}
