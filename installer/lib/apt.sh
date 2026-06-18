# shellcheck shell=bash
#
# secure-base Helper: apt/dpkg
# Bietet pkg_installed, pkg_install, pkg_remove, pkg_upgrade.

# Alle apt-get-Aufrufe gehen durch diesen internen Wrapper.
# NEEDRESTART_SUSPEND=1 verhindert den interaktiven Daemon-Restart-Prompt
# (Ubuntu 22.04+ hat needrestart per Default installiert).
_sb_apt() {
    NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive apt-get "$@"
}

#######################################
# Prueft, ob ein Paket installiert ist.
# Arguments: $1 — Paketname
# Returns:   0 installiert, 1 nicht installiert
#######################################
pkg_installed() {
    local paket=$1
    dpkg-query -W -f='${Status}' "$paket" 2>/dev/null \
        | grep -q "install ok installed"
}

#######################################
# Idempotente Installation: nur fehlende Pakete werden installiert.
# Arguments: $1 .. — Paketnamen
#######################################
pkg_install() {
    local fehlend=()
    local paket
    for paket in "$@"; do
        if ! pkg_installed "$paket"; then
            fehlend+=("$paket")
        fi
    done
    if [ "${#fehlend[@]}" -eq 0 ]; then
        log INFO "Pakete bereits installiert: $*"
        return 0
    fi
    log INFO "Installiere Pakete: ${fehlend[*]}"
    _sb_apt install -y "${fehlend[@]}"
}

#######################################
# Idempotente Entfernung (ohne --purge): nur vorhandene Pakete werden entfernt.
# Arguments: $1 .. — Paketnamen
#######################################
pkg_remove() {
    local vorhanden=()
    local paket
    for paket in "$@"; do
        if pkg_installed "$paket"; then
            vorhanden+=("$paket")
        fi
    done
    if [ "${#vorhanden[@]}" -eq 0 ]; then
        log INFO "Pakete bereits entfernt: $*"
        return 0
    fi
    log INFO "Entferne Pakete: ${vorhanden[*]}"
    _sb_apt remove -y "${vorhanden[@]}"
}

#######################################
# Aktualisiert den Paketindex und installiert vorhandene Updates.
# Kein Kernel-Sprung (upgrade, nicht dist-upgrade).
#######################################
pkg_upgrade() {
    log INFO "apt-get update"
    _sb_apt update
    log INFO "apt-get upgrade (non-interactive)"
    _sb_apt -y upgrade
}
