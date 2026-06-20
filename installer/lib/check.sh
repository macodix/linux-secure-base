# shellcheck shell=bash
#
# secure-base Helper: check-Hilfsfunktionen
#
# Bietet Helfer fuer do_check-Routinen in Modulen. Alle Funktionen
# geben 0 bei OK und 1 bei Abweichung zurueck; das Modul aggregiert
# den Rueckgabewert in einer lokalen exit_code-Variablen.
#
# Bietet:
#   check_packages     — Paket-Installation pruefen
#   check_svc_enabled  — Service active + enabled pruefen
#   check_file_mode    — Dateipfad, Mode und Owner pruefen

#######################################
# Prueft, ob jedes angegebene Paket installiert ist.
# Arguments: $@ — eine oder mehrere Paketnamen
# Returns:   0 alle installiert, 1 mindestens eines fehlt
#######################################
check_packages() {
    local rc=0 pkg
    for pkg in "$@"; do
        if pkg_installed "$pkg"; then
            log INFO "Paket installiert: $pkg"
        else
            log ERROR "Paket fehlt: $pkg"
            rc=1
        fi
    done
    return "$rc"
}

#######################################
# Prueft, ob ein Service aktiv und beim Boot aktiviert ist.
# Arguments: $1 — Service-Name
# Returns:   0 active+enabled, 1 Abweichung
#######################################
check_svc_enabled() {
    local name=$1 rc=0
    if svc_active "$name"; then
        log INFO "check: ${name}.service aktiv"
    else
        log ERROR "check: ${name}.service nicht aktiv"
        rc=1
    fi
    local state
    state=$(systemctl is-enabled "$name" 2>/dev/null || true)
    if [ "$state" = "enabled" ]; then
        log INFO "check: ${name}.service enabled (boot-persistent)"
    else
        log ERROR "check: ${name}.service nicht enabled (ist: ${state:-unbekannt})"
        rc=1
    fi
    return "$rc"
}

#######################################
# Prueft Existenz, Mode und Owner einer Datei oder eines Verzeichnisses.
# Arguments:
#   $1 — Pfad
#   $2 — erwarteter Mode (oktal, z. B. 600)
#   $3 — erwarteter Owner (user:group, z. B. root:root)
# Returns:   0 OK, 1 Abweichung
#######################################
check_file_mode() {
    local path=$1 mode_soll=$2 owner_soll=$3
    if [ ! -e "$path" ]; then
        log ERROR "check: $path fehlt"
        return 1
    fi
    local rc=0 mode owner
    mode=$(stat -c '%a' "$path")
    owner=$(stat -c '%U:%G' "$path")
    if [ "$mode" != "$mode_soll" ]; then
        log ERROR "check: $path Mode $mode, erwartet $mode_soll"
        rc=1
    fi
    if [ "$owner" != "$owner_soll" ]; then
        log ERROR "check: $path Owner $owner, erwartet $owner_soll"
        rc=1
    fi
    if [ "$rc" -eq 0 ]; then
        log INFO "check: $path OK (${mode_soll} ${owner_soll})"
    fi
    return "$rc"
}
