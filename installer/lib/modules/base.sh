#!/bin/bash
#
# Linux Secure Base — Modul base
# Hostname, Zeitzone, NTP-Zeitsynchronisation und Paketquellen aktualisieren.
# Aufruf: base.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="base"
# base hat keine modulspezifische .conf — alle Werte aus secure-base.conf.

#######################################
# Prueft, dass die fuer base noetigen Keys in secure-base.conf gesetzt sind.
# Globals:   FQDN, TIMEZONE
#######################################
require_base_keys() {
    [ -n "${FQDN:-}" ] || die "FQDN nicht gesetzt in $SB_CONF"
    [ -n "${TIMEZONE:-}" ] || die "TIMEZONE nicht gesetzt in $SB_CONF"
}

do_install() {
    require_root
    require_cmd hostnamectl
    require_cmd timedatectl
    require_cmd apt-get
    load_conf "$SB_CONF"
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

    # NTP-Zeitsynchronisation sicherstellen (konv-system.md 3.5 b).
    log INFO "base install: NTP-Zeitsynchronisation aktivieren (timedatectl set-ntp true)"
    timedatectl set-ntp true

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
    load_conf "$SB_CONF"
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

    # NTP-Zeitsynchronisation (konv-system.md 3.5 b).
    local ntp_sync
    ntp_sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
    if [ "$ntp_sync" = "yes" ]; then
        log INFO "NTPSynchronized: yes"
    else
        log ERROR "NTPSynchronized: $ntp_sync (soll: yes)"
        exit_code=1
    fi

    exit "$exit_code"
}

do_test() {
    log WARN "Kein sinnvoller Funktionstest fuer base definiert (Hostname/Zeitzone/apt sind statische Konfigurationswerte; check deckt den Soll-Ist-Abgleich ab)."
}

#######################################
# Liefert den Markdown-Abschnitt dieses Moduls fuer die Abschluss-Doku.
# Nur lesend; nimmt keine Systemaenderung vor. Gibt ausschliesslich
# Markdown nach stdout aus. Nimmt conf-Werte ueber die von do_doc per
# load_conf geladene Umgebung ab.
# Globals:   FQDN, TIMEZONE (lesend, ueber doc_val)
# Outputs:   stdout — Markdown-Abschnitt (beginnt mit "## <Label>")
#######################################
module_doc() {
    doc_section "Grundkonfiguration"
    # shellcheck disable=SC2016  # Backtick ist Markdown-Syntax, keine Shell-Expansion
    printf '**Hostname:** `%s`\n\n' "$(doc_val FQDN)"
    # shellcheck disable=SC2016
    printf '**Zeitzone:** `%s`\n\n' "$(doc_val TIMEZONE)"
    doc_note "Keine Pakete installiert; apt-upgrade laeuft ohne Versionspin. NTP-Zeitsynchronisation via systemd-timesyncd aktiviert (timedatectl set-ntp true, konv-system.md 3.5 b)."
}

#######################################
# Subkommando "doc": laedt die conf und gibt module_doc nach stdout.
# Nur lesend, kein require_root.
# Globals:   SB_CONF (lesend)
# Outputs:   stdout — Markdown-Abschnitt dieses Moduls
#######################################
do_doc() {
    load_conf "$SB_CONF"
    module_doc
}

dispatch "$MODULE" "$@"
