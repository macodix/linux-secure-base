#!/bin/bash
#
# Linux Secure Base — Modul base
# Hostname, Zeitzone, NTP-Zeitsynchronisation, Paketquellen,
# Kernel-Modul-Blacklist, autofs-Deaktivierung und AppArmor-Aktivierung.
# Aufruf: base.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="base"
# base hat keine modulspezifische .conf — alle Werte aus secure-base.conf.

readonly SYSCTL_CONF="/etc/sysctl.d/60-secure-base.conf"

# Modprobe-Blacklist fuer Wechseldatentraeger-Kernel-Module (konv-system.md 3.1 c).
# Auf virtuellen Servern ohne physische USB-Schnittstellen ohne praktische Wirkung,
# aber gemaess Regelwerk trotzdem gesetzt.
readonly MODPROBE_CONF="/etc/modprobe.d/secure-base-blacklist.conf"

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

    # Integritaets-/Cruft-Pruefung (konv-system.md 3.7 a):
    # debsums: veraenderte Paket-Dateien erkennen (OPS.1.1.3.A10 (S), ergaenzend).
    # cruft-ng: paketfremde Dateien in System-Pfaden aufspueren (Cruft-Pruefung).
    pkg_install debsums cruft-ng

    # Kernel-Modul-Blacklist (konv-system.md 3.1 c).
    log INFO "base install: Kernel-Modul-Blacklist nach $MODPROBE_CONF schreiben"
    {
        printf '# Von secure-base/base angelegt — nicht von Hand bearbeiten.\n'
        printf '# USB-Storage-Blacklist gemaess konv-system.md 3.1 c.\n'
        printf '# Auf VMs ohne USB-Schnittstellen ohne praktische Wirkung,\n'
        printf '# aber gemaess Regelwerk gesetzt.\n'
        printf 'install usb-storage /bin/true\n'
        printf 'blacklist usb-storage\n'
    } > "$MODPROBE_CONF"
    chmod 644 "$MODPROBE_CONF"

    # autofs deaktivieren (konv-system.md 3.1 d).
    # systemctl mask ist robust: schlaegt nicht fehl, wenn das Paket fehlt.
    log INFO "base install: autofs maskieren (systemctl mask autofs)"
    systemctl mask autofs 2>/dev/null || true

    # AppArmor sicherstellen (konv-system.md 3.10 b).
    # apparmor-utils liefert aa-status. AppArmor ist Ubuntu-Basis-
    # Infrastruktur und wird beim uninstall NICHT entfernt (analog openssh-server).
    # Kein eigenes sshd-Profil: sshd hat kein Ubuntu-Standard-AppArmor-Profil;
    # seine Eindaemmung erfolgt ueber den restriktiven Paketfilter (ufw) und die
    # SSH-Haertung. Ein eigenes Profil wuerde Aussperr-Risiko erzeugen und wird
    # bewusst nicht erstellt (Soll-Teilerfuellung mit Begruendung,
    # qm-richtlinien.md Kap. 5).
    pkg_install apparmor apparmor-utils
    if ! svc_active apparmor; then
        svc_enable_now apparmor
    else
        log INFO "base install: apparmor bereits aktiv — uebersprungen"
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

    if [ -f "$SYSCTL_CONF" ]; then
        log INFO "base uninstall: $SYSCTL_CONF entfernen"
        rm -f "$SYSCTL_CONF"
        log INFO "base uninstall: sysctl --system anwenden (Datei entfernt)"
        sysctl --system
    else
        log INFO "base uninstall: $SYSCTL_CONF nicht vorhanden — uebersprungen"
    fi

    # Pruefwerkzeuge entfernen (konv-system.md 3.7 a).
    pkg_remove debsums cruft-ng

    # Modul-Blacklist entfernen (konv-system.md 3.1 c).
    if [ -f "$MODPROBE_CONF" ]; then
        log INFO "base uninstall: $MODPROBE_CONF entfernen"
        rm -f "$MODPROBE_CONF"
    else
        log INFO "base uninstall: $MODPROBE_CONF nicht vorhanden — uebersprungen"
    fi

    # autofs-Maske aufheben (konv-system.md 3.1 d).
    # Nur entmaskieren, wenn zuvor von uns maskiert (tatsaechlicher Zustand: masked).
    local autofs_state
    autofs_state=$(systemctl is-enabled autofs 2>/dev/null || true)
    if [ "$autofs_state" = "masked" ]; then
        log INFO "base uninstall: autofs-Maske aufheben (systemctl unmask autofs)"
        systemctl unmask autofs 2>/dev/null || true
    else
        log INFO "base uninstall: autofs nicht maskiert (ist: ${autofs_state:-unbekannt}) — uebersprungen"
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

    # Aktive/enabled Dienste und lauschende Ports (konv-system.md 3.1 a/b).
    # Nicht-eingreifend: Das Regelwerk fordert den Abgleich gegen eine
    # Betriebsdokumentation (welche Dienste erlaubt sind). Da diese
    # systemspezifisch ist, gibt dieser Check nur den Ist-Stand aus und
    # meldet ihn als WARN, damit der Operator selbst entscheidet.
    log WARN "check 3.1a: enabled Dienste (Soll-Ist-Abgleich mit Betriebsdokumentation erforderlich):"
    local enabled_units
    enabled_units=$(systemctl list-unit-files --state=enabled --type=service --no-legend 2>/dev/null \
        | awk '{print $1}' || true)
    if [ -n "$enabled_units" ]; then
        local u
        while IFS= read -r u; do
            log WARN "  enabled: $u"
        done <<< "$enabled_units"
    else
        log INFO "check 3.1a: keine enabled Services gefunden"
    fi
    log WARN "check 3.1b: lauschende Ports (Soll-Ist-Abgleich mit Betriebsdokumentation erforderlich):"
    if command -v ss >/dev/null 2>&1; then
        local ports
        ports=$(ss -H -tulpen 2>/dev/null || true)
        if [ -n "$ports" ]; then
            local line
            while IFS= read -r line; do
                log WARN "  port: $line"
            done <<< "$ports"
        else
            log INFO "check 3.1b: keine lauschenden Ports gefunden"
        fi
    else
        log WARN "check 3.1b: ss nicht verfuegbar — Ports nicht pruefbar"
    fi

    # Kernel-Modul-Blacklist (konv-system.md 3.1 c).
    if [ -f "$MODPROBE_CONF" ]; then
        log INFO "check: $MODPROBE_CONF vorhanden"
        if grep -q "^install usb-storage /bin/true" "$MODPROBE_CONF" \
            && grep -q "^blacklist usb-storage" "$MODPROBE_CONF"; then
            log INFO "check: usb-storage-Eintraege OK"
        else
            log ERROR "check: $MODPROBE_CONF fehlt Eintraege fuer usb-storage (install /bin/true und/oder blacklist)"
            exit_code=1
        fi
    else
        log ERROR "check: $MODPROBE_CONF fehlt"
        exit_code=1
    fi
    # Hinweis: modprobe -n -v usb-storage (Soll: install /bin/true) und
    # lsmod | grep usb_storage sind nur am echten System mit root verifizierbar.

    # autofs-Status (konv-system.md 3.1 d).
    local autofs_state
    autofs_state=$(systemctl is-enabled autofs 2>/dev/null || true)
    if [ "$autofs_state" = "masked" ]; then
        log INFO "check: autofs maskiert OK"
    elif [ -z "$autofs_state" ]; then
        log INFO "check: autofs-Paket nicht installiert — Anforderung erfuellt"
    else
        log ERROR "check: autofs ist-Zustand '$autofs_state', soll 'masked' oder nicht installiert"
        exit_code=1
    fi

    # --- konv-system.md 3.10 b: AppArmor aktiv, Profile im Enforce-Modus ---
    # Soll-Grenze: sshd hat kein Ubuntu-Standard-AppArmor-Profil; seine
    # Eindaemmung erfolgt ueber ufw und SSH-Haertung. Ein eigenes sshd-Profil
    # wird bewusst nicht erstellt (Aussperr-Risiko; Soll-Teilerfuellung mit
    # Begruendung, qm-richtlinien.md Kap. 5). Pruefbar nur am echten System
    # mit root und funktionsfaehigem apparmor-Dienst.
    if command -v aa-status >/dev/null 2>&1; then
        # aa-status gibt Exit 0 wenn AppArmor aktiv, sonst ungleich 0.
        if aa-status --enabled 2>/dev/null; then
            log INFO "check 3.10b: AppArmor enabled/aktiv — OK"
        else
            log ERROR "check 3.10b: AppArmor nicht aktiv (aa-status --enabled fehlgeschlagen)"
            exit_code=1
        fi
        # Anzahl Profile im Enforce-Modus aus aa-status-Ausgabe ermitteln.
        local enforce_count
        enforce_count=$(aa-status 2>/dev/null \
            | awk '/profiles are in enforce mode/{print $1}' || true)
        if [[ "$enforce_count" =~ ^[0-9]+$ ]] && [ "$enforce_count" -gt 0 ]; then
            log INFO "check 3.10b: $enforce_count Profile im Enforce-Modus — OK"
        else
            log ERROR "check 3.10b: keine Profile im Enforce-Modus (Ist: ${enforce_count:-unbekannt})"
            exit_code=1
        fi
        # Profile im Complain-Modus: WARN, kein ERROR (Distro-abhaengig).
        local complain_count
        complain_count=$(aa-status 2>/dev/null \
            | awk '/profiles are in complain mode/{print $1}' || true)
        if [[ "$complain_count" =~ ^[0-9]+$ ]] && [ "$complain_count" -gt 0 ]; then
            log WARN "check 3.10b: $complain_count Profile im Complain-Modus (Soll-Ist-Abgleich mit Betriebsdokumentation empfohlen)"
        fi
    else
        log ERROR "check 3.10b: aa-status nicht verfuegbar — AppArmor-Pruefung nicht moeglich (base install behebt das)"
        exit_code=1
    fi

    # --- konv-system.md 3.7 a (1): Signaturprüfung der Paketverwaltung nicht umgangen ---
    # ERROR bei: [trusted=yes] in apt-Quellen oder --allow-unauthenticated.
    # Nicht-eingreifend: nur Befunde ausgeben.
    log INFO "check 3.7(1): apt-Quellen auf umgangene Signaturpruefung pruefen"
    local trusted_hits unauth_hits
    trusted_hits=$(grep -rn '\[trusted=yes\]' \
        /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true)
    unauth_hits=$(grep -rn '\-\-allow-unauthenticated' \
        /etc/apt/sources.list /etc/apt/sources.list.d/ \
        /etc/apt/apt.conf /etc/apt/apt.conf.d/ 2>/dev/null || true)
    if [ -z "$trusted_hits" ] && [ -z "$unauth_hits" ]; then
        log INFO "check 3.7(1): Signaturpruefung der Paketverwaltung nicht umgangen — OK"
    else
        [ -n "$trusted_hits" ] && log ERROR "check 3.7(1): [trusted=yes] gefunden: $trusted_hits"
        [ -n "$unauth_hits" ] && log ERROR "check 3.7(1): --allow-unauthenticated gefunden: $unauth_hits"
        exit_code=1
    fi

    # --- konv-system.md 3.7 a (2): Cruft-Pruefung paketfremder Dateien ---
    # cruft-ng listet Dateien in System-Pfaden ohne Paketzugehoerigkeit.
    # Nicht-eingreifend: nur Befunde ausgeben, kein Loeschen/Aendern.
    if command -v cruft >/dev/null 2>&1; then
        log INFO "check 3.7(2): cruft (Paket cruft-ng) — paketfremde Dateien in System-Pfaden suchen"
        local cruft_out
        # cruft schreibt Befunde nach stdout; Laufzeit kann hoch sein.
        cruft_out=$(cruft 2>/dev/null || true)
        if [ -z "$cruft_out" ]; then
            log INFO "check 3.7(2): cruft — keine paketfremden Dateien gefunden"
        else
            local cf
            while IFS= read -r cf; do
                log WARN "check 3.7(2): cruft — paketfremde Datei: $cf"
            done <<< "$cruft_out"
            # WARN, kein ERROR: Einzelbefunde erfordern manuelle Bewertung
            # (Konfigurationen, temporaere Dateien u.ae. koennen legitim sein).
            log WARN "check 3.7(2): cruft-Befunde manuell bewerten; ggf. paketfremde Installationen pruefen"
        fi
    else
        log ERROR "check 3.7(2): cruft (Paket cruft-ng) nicht installiert — Cruft-Pruefung nicht moeglich (base install behebt das)"
        exit_code=1
    fi

    # --- OPS.1.1.3.A10 (S) Ergaenzung: Integritaet vorhandener Paket-Dateien ---
    # debsums -c: vergleicht Checksummen installierter Dateien gegen Paket-DB.
    # Ergaenzend zu (2), prueft andere Dimension (veraendert, nicht: paketfremd).
    if command -v debsums >/dev/null 2>&1; then
        log INFO "check 3.7 erg.: debsums — Integritaets-Pruefung veraenderter Paket-Dateien"
        local debsums_out
        debsums_out=$(debsums -c 2>/dev/null || true)
        if [ -z "$debsums_out" ]; then
            log INFO "check 3.7 erg.: debsums — keine veraenderten Paket-Dateien gefunden"
        else
            local df
            while IFS= read -r df; do
                log ERROR "check 3.7 erg.: debsums — veraenderte Datei: $df"
            done <<< "$debsums_out"
            exit_code=1
        fi
    else
        log WARN "check 3.7 erg.: debsums nicht installiert — Integritaetspruefung nicht moeglich (base install behebt das)"
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
    doc_packages apparmor apparmor-utils debsums cruft-ng
    doc_files_begin
    doc_file "$SYSCTL_CONF" \
        "kernel.randomize_va_space = 2" \
        "kernel.kptr_restrict = 2" \
        "kernel.dmesg_restrict = 1" \
        "kernel.yama.ptrace_scope = 1"
    doc_file "$MODPROBE_CONF" \
        "install usb-storage /bin/true" \
        "blacklist usb-storage"
    doc_note "NTP-Zeitsynchronisation via systemd-timesyncd aktiviert (timedatectl set-ntp true, konv-system.md 3.5 b). sysctl-Haertung gemaess konv-system.md 3.9. USB-Storage-Blacklist gemaess konv-system.md 3.1 c. autofs maskiert (systemctl mask autofs, konv-system.md 3.1 d). AppArmor-Dienst aktiv (konv-system.md 3.10 b): apparmor + apparmor-utils installiert, Dienst enabled. Soll-Teilerfuellung mit Begruendung (qm-richtlinien.md Kap. 5): sshd hat kein Ubuntu-Standard-AppArmor-Profil; seine Eindaemmung erfolgt ueber den restriktiven Paketfilter (ufw) und die SSH-Haertung. Ein eigenes sshd-Profil wird bewusst nicht erstellt (Aussperr-Risiko). Integritaets-/Cruft-Pruefung gemaess konv-system.md 3.7 a: (1) apt-Quellen auf umgangene Signaturpruefung (grep), (2) paketfremde Dateien (cruft-ng), ergaenzend: veraenderte Paket-Dateien (debsums, OPS.1.1.3.A10 (S))."
}

dispatch "$MODULE" "$@"
