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

readonly SYSCTL_CONF="/etc/sysctl.d/60-secure-base.conf"

# Soll-Parameter gemaess konv-system.md 3.9 a/b/c.
# Format: "schluessel=wert" (kein Leerzeichen um =).
readonly -a SYSCTL_PARAMS=(
    "kernel.randomize_va_space=2"
    "kernel.kptr_restrict=2"
    "kernel.dmesg_restrict=1"
    "kernel.yama.ptrace_scope=1"
)

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

    # sysctl-Haertung (konv-system.md 3.9).
    log INFO "base install: sysctl-Konfig nach $SYSCTL_CONF schreiben"
    {
        printf '# Von secure-base/base angelegt — nicht von Hand bearbeiten.\n'
        printf '# Kernel-Haertung gemaess konv-system.md 3.9\n'
        local p
        for p in "${SYSCTL_PARAMS[@]}"; do
            printf '%s\n' "${p/=/ = }"
        done
    } > "$SYSCTL_CONF"
    chmod 644 "$SYSCTL_CONF"
    log INFO "base install: sysctl --system anwenden"
    sysctl --system

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

    if [ -f "$SYSCTL_CONF" ]; then
        log INFO "base uninstall: $SYSCTL_CONF entfernen"
        rm -f "$SYSCTL_CONF"
        log INFO "base uninstall: sysctl --system anwenden (Datei entfernt)"
        sysctl --system
    else
        log INFO "base uninstall: $SYSCTL_CONF nicht vorhanden — uebersprungen"
    fi
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

    # sysctl-Parameter (konv-system.md 3.9 a/b/c).
    local p key soll ist
    for p in "${SYSCTL_PARAMS[@]}"; do
        key="${p%%=*}"
        soll="${p#*=}"
        ist=$(sysctl -n "$key" 2>/dev/null || true)
        if [ "$ist" = "$soll" ]; then
            log INFO "sysctl $key = $ist OK"
        else
            log ERROR "sysctl $key = $ist, soll $soll"
            exit_code=1
        fi
    done

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
    doc_files_begin
    doc_file "$SYSCTL_CONF" \
        "kernel.randomize_va_space = 2" \
        "kernel.kptr_restrict = 2" \
        "kernel.dmesg_restrict = 1" \
        "kernel.yama.ptrace_scope = 1"
    doc_note "Keine Pakete installiert; apt-upgrade laeuft ohne Versionspin. NTP-Zeitsynchronisation via systemd-timesyncd aktiviert (timedatectl set-ntp true, konv-system.md 3.5 b). sysctl-Haertung gemaess konv-system.md 3.9."
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
