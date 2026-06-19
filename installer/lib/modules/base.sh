#!/bin/bash
#
# Linux Secure Base — Modul base
# Hostname, Zeitzone und Paketquellen aktualisieren.
# Aufruf: base.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="base"
readonly CONF_COMMON="$SCRIPT_DIR/conf/common.conf"
# base hat keine modulspezifische .conf — alle Werte aus common.conf.

#######################################
# Prueft, dass die fuer base noetigen Keys in common.conf gesetzt sind.
# Globals:   FQDN, TIMEZONE
#######################################
require_base_keys() {
    [ -n "${FQDN:-}" ] || die "FQDN nicht gesetzt in $CONF_COMMON"
    [ -n "${TIMEZONE:-}" ] || die "TIMEZONE nicht gesetzt in $CONF_COMMON"
}

do_install() {
    require_root
    require_cmd hostnamectl
    require_cmd timedatectl
    require_cmd apt-get
    load_conf "$CONF_COMMON"
    require_base_keys

    local current_host current_tz
    current_host=$(hostname)
    if [ "$current_host" != "$FQDN" ]; then
        log INFO "Hostname setzen: $current_host -> $FQDN"
        hostnamectl set-hostname "$FQDN"
    else
        log INFO "Hostname bereits $FQDN — uebersprungen"
    fi

    current_tz=$(timedatectl show --property=Timezone --value)
    if [ "$current_tz" != "$TIMEZONE" ]; then
        log INFO "Zeitzone setzen: $current_tz -> $TIMEZONE"
        timedatectl set-timezone "$TIMEZONE"
    else
        log INFO "Zeitzone bereits $TIMEZONE — uebersprungen"
    fi

    pkg_upgrade

    if [ -e /var/run/reboot-required ]; then
        log WARN "NEUSTART ERFORDERLICH: apt-upgrade hat Reboot-pflichtige Pakete aktualisiert."
        if [ -r /var/run/reboot-required.pkgs ]; then
            local pkg
            while IFS= read -r pkg; do
                log INFO "  - $pkg"
            done </var/run/reboot-required.pkgs
        fi
        die "Server neu starten und secure-base erneut aufrufen, bevor weitere Module installiert werden."
    fi
}

do_uninstall() {
    require_root
    require_cmd timedatectl
    log WARN "base uninstall: Hostname, Zeitzone und apt-Stand werden NICHT zurueckgesetzt — manuell setzen, falls gewuenscht."
    local current_host current_tz
    current_host=$(hostname)
    current_tz=$(timedatectl show --property=Timezone --value)
    log INFO "Aktueller Hostname: $current_host"
    log INFO "Aktuelle Zeitzone:  $current_tz"
}

do_check() {
    require_root
    require_cmd timedatectl
    load_conf "$CONF_COMMON"
    require_base_keys

    local current_host current_tz exit_code=0
    current_host=$(hostname)
    current_tz=$(timedatectl show --property=Timezone --value)

    if [ "$current_host" = "$FQDN" ]; then
        log INFO "Hostname OK: $FQDN"
    else
        log ERROR "Hostname-Mismatch: ist $current_host, soll $FQDN"
        exit_code=1
    fi

    if [ "$current_tz" = "$TIMEZONE" ]; then
        log INFO "Zeitzone OK: $TIMEZONE"
    else
        log ERROR "Zeitzone-Mismatch: ist $current_tz, soll $TIMEZONE"
        exit_code=1
    fi

    exit "$exit_code"
}

do_test() {
    log WARN "Kein sinnvoller Funktionstest fuer base definiert (Hostname/Zeitzone/apt sind statische Konfigurationswerte; check deckt den Soll-Ist-Abgleich ab)."
}

dispatch "$MODULE" "$@"
