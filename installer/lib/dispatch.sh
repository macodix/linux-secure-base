# shellcheck shell=bash
#
# secure-base Helper: Subkommando-Dispatch fuer Module
#
# Bietet dispatch — validiert Subkommando, oeffnet das Log und ruft
# do_install/do_uninstall/do_check/do_test.
#
# Das aufrufende Modul muss diese vier Funktionen definieren.

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
    local status
    if [ "$rc" -eq 0 ] && [ "$SB_ERROR_COUNT" -eq 0 ]; then
        status=ERFOLG
    else
        status=FEHLER
    fi
    log INFO "=== ${SB_MODUL} ${SB_SUB}: ${status} (${SB_WARN_COUNT} Warnungen, ${SB_ERROR_COUNT} Fehler) ==="
    printf '\n'
    _sb_close_log
}

#######################################
# Validiert das Subkommando, oeffnet das Log und delegiert an do_*.
# Arguments: $1 — Modulname, $2 — Subkommando (install|uninstall|check|test)
# Globals:   SB_MODUL, SB_SUB
#######################################
dispatch() {
    local modul=$1
    shift
    local sub=${1:-}
    if [ -z "$sub" ]; then
        printf 'Aufruf: %s {install|uninstall|check|test}\n' "$modul" >&2
        exit 2
    fi
    shift

    case "$sub" in
        install | uninstall | check | test) ;;
        *)
            printf 'unbekanntes Subkommando: %s\n' "$sub" >&2
            printf 'Erwartet: install | uninstall | check | test\n' >&2
            exit 2
            ;;
    esac

    require_root
    open_log "$modul" "$sub"
    # _sb_finish ersetzt den _sb_close_log-Trap aus open_log und ruft
    # _sb_close_log selbst. Modul/Sub global, da der Trap erst nach
    # Rueckkehr aus dispatch feuert.
    SB_MODUL=$modul
    SB_SUB=$sub
    trap '_sb_finish' EXIT

    case "$sub" in
        install) do_install "$@" ;;
        uninstall) do_uninstall "$@" ;;
        check) do_check "$@" ;;
        test) do_test "$@" ;;
    esac
}
