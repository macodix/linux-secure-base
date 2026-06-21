#!/bin/bash
#
# Linux Secure Base — Modul unattended
# Automatisierte Sicherheitsupdates via unattended-upgrades:
# Allowed-Origins (base/security/updates), automatischer Reboot im
# Nachtfenster, periodische Ausfuehrung (APT::Periodic) und zwei
# systemd-Timer-Overrides (apt-daily / apt-daily-upgrade), damit der
# Upgrade-Lauf vor dem Reboot greift. Mail-Report nur im Fehlerfall an
# ADMIN_MAIL ueber das postfix-Relay. Nicht sitzungs-kritisch.
# Aufruf: unattended.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="unattended"

readonly UU_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
readonly PERIODIC_CONF="/etc/apt/apt.conf.d/20auto-upgrades"
readonly DAILY_DROPIN="/etc/systemd/system/apt-daily.timer.d/secure-base.conf"
readonly UPGRADE_DROPIN="/etc/systemd/system/apt-daily-upgrade.timer.d/secure-base.conf"

# Aktiver Allowed-Origins-Block. Single-Quotes: ${distro_id}/${distro_codename}
# sind hier woertlicher apt.conf-Text, KEINE Shell-Variablen.
# shellcheck disable=SC2016
readonly ALLOWED_ORIGINS='Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}:${distro_codename}-updates";
};'

# --- Hilfsfunktionen -------------------------------------------------

# Grobe Plausibilitaet einer HH:MM-Uhrzeit (24h, anchored). Leer wird vom
# Aufrufer vorher gedefaultet, hier also immer mit konkretem Wert gerufen.
valid_hhmm() {
    [[ "$1" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]
}

# Maskiert ERE-Metazeichen, damit ein Wert woertlich ins grep -E-Muster
# (file_has_line) eingesetzt werden kann.
ere_escape() {
    printf '%s' "$1" | sed 's/[^a-zA-Z0-9_@-]/\\&/g'
}

# Prueft Mail-Empfaenger, Reboot-Schalter und die drei Uhrzeiten, bevor
# sie verwendet werden. Bricht sonst mit die ab.
require_unattended_conf() {
    # ADMIN_MAIL gegen einen anchored Zeichensatz pruefen, BEVOR der Wert
    # woertlich in die Mail-Direktive von 50unattended-upgrades geschrieben
    # wird. Schliesst Anfuehrungszeichen, Semikolon, Leerzeichen und
    # insbesondere Zeilenumbruch aus.
    if ! [[ "${ADMIN_MAIL:-}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]; then
        die "ADMIN_MAIL ('${ADMIN_MAIL:-}') ist leer oder keine gueltige Mail-Adresse (erwartet z. B. admin@example.com). In secure-base.conf korrigieren."
    fi
    local reboot=${AUTO_REBOOT:-true}
    if [ "$reboot" != "true" ] && [ "$reboot" != "false" ]; then
        die "AUTO_REBOOT ('$reboot') muss 'true' oder 'false' sein. In secure-base.conf korrigieren."
    fi
    local rt=${AUTO_REBOOT_TIME:-23:45}
    local dt=${APT_DAILY_TIME:-23:15}
    local ut=${APT_DAILY_UPGRADE_TIME:-23:30}
    local name val
    for name in AUTO_REBOOT_TIME:"$rt" APT_DAILY_TIME:"$dt" APT_DAILY_UPGRADE_TIME:"$ut"; do
        val=${name#*:}
        if ! valid_hhmm "$val"; then
            die "${name%%:*} ('$val') ist keine gueltige Uhrzeit im Format HH:MM. In secure-base.conf korrigieren."
        fi
    done
    # Reihenfolge ist nur eine Empfehlung — kein Abbruch, nur Hinweis.
    if ! { [[ "$dt" < "$ut" ]] && [[ "$ut" < "$rt" ]]; }; then
        log WARN "unattended: Uhrzeiten nicht in Reihenfolge APT_DAILY_TIME ($dt) < APT_DAILY_UPGRADE_TIME ($ut) < AUTO_REBOOT_TIME ($rt) — Updates koennten nach dem Reboot laufen."
    fi
}

# Schreibt einen systemd-Timer-Drop-in mit gepinnter OnCalendar-Zeit.
# Leeres OnCalendar= leert die additive Distro-Default-Liste,
# RandomizedDelaySec=0 verhindert die 12h-Streuung des Distro-Defaults.
write_timer_override() {
    local timer=$1 hhmm=$2
    local dir="/etc/systemd/system/${timer}.d"
    local file="$dir/secure-base.conf"
    mkdir -p "$dir"
    cat > "$file" <<EOF
# Von secure-base/unattended angelegt - nicht von Hand editieren.
# Override der OnCalendar-Zeit; leeres OnCalendar= leert die additive
# Liste des Distro-Defaults, RandomizedDelaySec=0 pinnt die Uhrzeit.
[Timer]
OnCalendar=
OnCalendar=*-*-* ${hhmm}:00
RandomizedDelaySec=0
EOF
    chmod 644 "$file"
    log INFO "unattended install: Timer-Override $file (OnCalendar $hhmm)"
}

# --- Subkommandos ----------------------------------------------------

do_install() {
    require_root
    load_conf "$SB_CONF"
    require_unattended_conf

    local reboot reboot_time daily upgrade
    reboot=${AUTO_REBOOT:-true}
    reboot_time=${AUTO_REBOOT_TIME:-23:45}
    daily=${APT_DAILY_TIME:-23:15}
    upgrade=${APT_DAILY_UPGRADE_TIME:-23:30}

    # (1) Paket installieren.
    log INFO "unattended install: Paket unattended-upgrades installieren"
    pkg_install unattended-upgrades

    # (2) 50unattended-upgrades haerten: Allowed-Origins-Block + vier
    #     Einzelzeilen-Direktiven (apt.conf-Stil, cp='//').
    log INFO "unattended install: $UU_CONF haerten (Allowed-Origins, Reboot=$reboot @ $reboot_time, Mail=$ADMIN_MAIL only-on-error)"
    ensure_block "$UU_CONF" allowed-origins "$ALLOWED_ORIGINS" \
        '^Unattended-Upgrade::Allowed-Origins' '^}' '//'
    ensure_setting "$UU_CONF" "Unattended-Upgrade::Automatic-Reboot"      "\"$reboot\";"       " " "//"
    ensure_setting "$UU_CONF" "Unattended-Upgrade::Automatic-Reboot-Time" "\"$reboot_time\";"  " " "//"
    ensure_setting "$UU_CONF" "Unattended-Upgrade::Mail"                  "\"$ADMIN_MAIL\";"   " " "//"
    ensure_setting "$UU_CONF" "Unattended-Upgrade::MailReport"            "\"only-on-error\";" " " "//"

    # (3) 20auto-upgrades sicherstellen (kann je nach Image fehlen) und
    #     die periodische Ausfuehrung aktivieren.
    if [ ! -f "$PERIODIC_CONF" ]; then
        log INFO "unattended install: $PERIODIC_CONF fehlt — leere Datei anlegen (0644)"
        : > "$PERIODIC_CONF"
        chmod 644 "$PERIODIC_CONF"
    fi
    log INFO "unattended install: $PERIODIC_CONF setzen (periodische Ausfuehrung aktivieren)"
    ensure_setting "$PERIODIC_CONF" "APT::Periodic::Update-Package-Lists" '"1";' " " "//"
    ensure_setting "$PERIODIC_CONF" "APT::Periodic::Unattended-Upgrade"   '"1";' " " "//"
    ensure_setting "$PERIODIC_CONF" "APT::Periodic::AutocleanInterval"    '"7";' " " "//"

    # (4) Timer-Overrides schreiben und uebernehmen.
    write_timer_override apt-daily.timer         "$daily"
    write_timer_override apt-daily-upgrade.timer "$upgrade"
    log INFO "unattended install: systemctl daemon-reload + Timer neu starten"
    systemctl daemon-reload
    systemctl restart apt-daily.timer apt-daily-upgrade.timer
}

do_uninstall() {
    require_root
    # secure-base.conf wird hier bewusst NICHT geladen/validiert: der
    # Rueckbau ist konfig-unabhaengig und muss auch bei fehlender/defekter
    # Conf durchlaufen (fail-safe).

    # (1) apt-Timer-Sonderfall: apt-daily.timer und apt-daily-upgrade.timer
    #     gehoeren zum Distro-Default und werden NICHT deaktiviert. Nur die
    #     eigenen Drop-in-Overrides entfernen, dann systemd neu laden und die
    #     Timer neu starten -> Distro-Default-Zeiten greifen wieder.
    local t reloaded=0 file dir
    for t in apt-daily.timer apt-daily-upgrade.timer; do
        dir="/etc/systemd/system/${t}.d"
        file="$dir/secure-base.conf"
        if [ -f "$file" ]; then
            log INFO "unattended uninstall: Timer-Override $file entfernen"
            rm -f "$file"
            rmdir "$dir" 2>/dev/null || true   # nur wenn jetzt leer
            reloaded=1
        fi
    done
    if [ "$reloaded" -eq 1 ]; then
        log INFO "unattended uninstall: systemctl daemon-reload + Timer neu starten (Distro-Default-Zeiten)"
        systemctl daemon-reload
        systemctl restart apt-daily.timer apt-daily-upgrade.timer || true
    fi

    # (2) apt.conf-Eingriffe zuruecknehmen (Marker-Mechanik, cp='//').
    if [ -f "$UU_CONF" ]; then
        log INFO "unattended uninstall: Eingriffe in $UU_CONF zuruecknehmen"
        remove_block   "$UU_CONF" allowed-origins                              "//"
        remove_setting "$UU_CONF" "Unattended-Upgrade::Automatic-Reboot"       "//"
        remove_setting "$UU_CONF" "Unattended-Upgrade::Automatic-Reboot-Time"  "//"
        remove_setting "$UU_CONF" "Unattended-Upgrade::Mail"                   "//"
        remove_setting "$UU_CONF" "Unattended-Upgrade::MailReport"             "//"
    fi
    if [ -f "$PERIODIC_CONF" ]; then
        log INFO "unattended uninstall: Eingriffe in $PERIODIC_CONF zuruecknehmen"
        remove_setting "$PERIODIC_CONF" "APT::Periodic::Update-Package-Lists" "//"
        remove_setting "$PERIODIC_CONF" "APT::Periodic::Unattended-Upgrade"   "//"
        remove_setting "$PERIODIC_CONF" "APT::Periodic::AutocleanInterval"    "//"
    fi

    # (3) Paket entfernen (ohne --purge).
    if pkg_installed unattended-upgrades; then
        log INFO "unattended uninstall: Paket unattended-upgrades entfernen (ohne --purge)"
        pkg_remove unattended-upgrades
    else
        log INFO "unattended uninstall: Paket unattended-upgrades nicht installiert — nichts zu entfernen"
    fi
}

do_check() {
    require_root
    load_conf "$SB_CONF"
    require_unattended_conf

    local rc=0
    local reboot reboot_time daily upgrade
    reboot=${AUTO_REBOOT:-true}
    reboot_time=${AUTO_REBOOT_TIME:-23:45}
    daily=${APT_DAILY_TIME:-23:15}
    upgrade=${APT_DAILY_UPGRADE_TIME:-23:30}

    # (1) Paket installiert.
    check_packages unattended-upgrades || exit 1

    # (2) Allowed-Origins-Block aktiv (drei Origins). Anchored mit
    #     fuehrendem Whitespace -> auskommentierte //-Zeilen matchen nicht.
    # ${distro_id}/${distro_codename} sind hier woertlicher Datei-Text,
    # keine Shell-Variablen — die Single-Quotes sind beabsichtigt (SC2016).
    local o_base o_sec o_upd
    # shellcheck disable=SC2016
    o_base=$(ere_escape '"${distro_id}:${distro_codename}";')
    # shellcheck disable=SC2016
    o_sec=$(ere_escape '"${distro_id}:${distro_codename}-security";')
    # shellcheck disable=SC2016
    o_upd=$(ere_escape '"${distro_id}:${distro_codename}-updates";')
    if file_has_line "$UU_CONF" "^[[:space:]]+${o_base}$" \
        && file_has_line "$UU_CONF" "^[[:space:]]+${o_sec}$" \
        && file_has_line "$UU_CONF" "^[[:space:]]+${o_upd}$"; then
        log INFO "check: Allowed-Origins aktiv (base, -security, -updates)"
    else
        log ERROR "check: Allowed-Origins nicht vollstaendig aktiv (base/-security/-updates)"
        rc=1
    fi

    # (3) Vier Direktiven aktiv in 50unattended-upgrades (Mail ERE-maskiert).
    local mail_re
    mail_re=$(ere_escape "${ADMIN_MAIL:-}")
    if file_has_line "$UU_CONF" "^Unattended-Upgrade::Automatic-Reboot \"${reboot}\";$"; then
        log INFO "check: Automatic-Reboot \"$reboot\" gesetzt"
    else
        log ERROR "check: Automatic-Reboot nicht aktiv auf \"$reboot\""
        rc=1
    fi
    if file_has_line "$UU_CONF" "^Unattended-Upgrade::Automatic-Reboot-Time \"${reboot_time}\";$"; then
        log INFO "check: Automatic-Reboot-Time \"$reboot_time\" gesetzt"
    else
        log ERROR "check: Automatic-Reboot-Time nicht aktiv auf \"$reboot_time\""
        rc=1
    fi
    if file_has_line "$UU_CONF" "^Unattended-Upgrade::Mail \"${mail_re}\";$"; then
        log INFO "check: Mail \"$ADMIN_MAIL\" gesetzt"
    else
        log ERROR "check: Mail nicht aktiv auf \"$ADMIN_MAIL\""
        rc=1
    fi
    if file_has_line "$UU_CONF" '^Unattended-Upgrade::MailReport "only-on-error";$'; then
        log INFO "check: MailReport \"only-on-error\" gesetzt"
    else
        log ERROR "check: MailReport nicht aktiv auf \"only-on-error\""
        rc=1
    fi

    # (4) Drei Periodic-Direktiven aktiv in 20auto-upgrades.
    if file_has_line "$PERIODIC_CONF" '^APT::Periodic::Update-Package-Lists "1";$'; then
        log INFO "check: Periodic Update-Package-Lists \"1\" gesetzt"
    else
        log ERROR "check: Periodic Update-Package-Lists nicht aktiv auf \"1\""
        rc=1
    fi
    if file_has_line "$PERIODIC_CONF" '^APT::Periodic::Unattended-Upgrade "1";$'; then
        log INFO "check: Periodic Unattended-Upgrade \"1\" gesetzt"
    else
        log ERROR "check: Periodic Unattended-Upgrade nicht aktiv auf \"1\""
        rc=1
    fi
    if file_has_line "$PERIODIC_CONF" '^APT::Periodic::AutocleanInterval "7";$'; then
        log INFO "check: Periodic AutocleanInterval \"7\" gesetzt"
    else
        log ERROR "check: Periodic AutocleanInterval nicht aktiv auf \"7\""
        rc=1
    fi

    # (5) Timer-Overrides vorhanden mit erwarteter OnCalendar-Zeile
    #     (* sind ERE-Metazeichen, daher escaped).
    if file_has_line "$DAILY_DROPIN" "^OnCalendar=\\*-\\*-\\* ${daily}:00$"; then
        log INFO "check: apt-daily.timer Override OnCalendar $daily gesetzt"
    else
        log ERROR "check: apt-daily.timer Override fehlt oder OnCalendar != $daily ($DAILY_DROPIN)"
        rc=1
    fi
    if file_has_line "$UPGRADE_DROPIN" "^OnCalendar=\\*-\\*-\\* ${upgrade}:00$"; then
        log INFO "check: apt-daily-upgrade.timer Override OnCalendar $upgrade gesetzt"
    else
        log ERROR "check: apt-daily-upgrade.timer Override fehlt oder OnCalendar != $upgrade ($UPGRADE_DROPIN)"
        rc=1
    fi

    exit "$rc"
}

do_test() {
    require_root
    load_conf "$SB_CONF"
    require_unattended_conf

    local rc=0

    # (1) Non-destruktiver Trockenlauf. Simuliert nur — keine
    #     Installation, kein Reboot. Beweist, dass unattended-upgrade die
    #     geschriebene Konfiguration ohne Syntax-/Logikfehler einliest.
    if ! pkg_installed unattended-upgrades; then
        log ERROR "test: Paket unattended-upgrades nicht installiert — kein Funktionstest moeglich"
        exit 1
    fi
    log INFO "test: unattended-upgrade --dry-run --debug (simuliert, installiert nichts, rebootet nicht)"
    local out uurc=0
    out=$(unattended-upgrade --dry-run --debug 2>&1) || uurc=$?
    if [ -n "$out" ]; then
        local line
        while IFS= read -r line; do log INFO "unattended-upgrade: $line"; done <<<"$out"
    fi
    if [ "$uurc" -ne 0 ]; then
        log ERROR "test: unattended-upgrade --dry-run fehlgeschlagen (Exit $uurc)"
        rc=1
    else
        log INFO "test: Trockenlauf erfolgreich — Konfiguration wird von unattended-upgrade akzeptiert"
    fi

    # (2) Naechste geplante Timer-Ausloesungen zur Kontrolle ins Log.
    log INFO "test: naechste geplante Timer-Ausloesungen:"
    local tout
    tout=$(systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --no-pager 2>&1) || true
    if [ -n "$tout" ]; then
        local tline
        while IFS= read -r tline; do log INFO "list-timers: $tline"; done <<<"$tout"
    fi

    exit "$rc"
}

#######################################
# Liefert den Markdown-Abschnitt dieses Moduls fuer die Abschluss-Doku.
# Nur lesend; nimmt keine Systemaenderung vor. Gibt ausschliesslich
# Markdown nach stdout aus. Nimmt conf-Werte ueber die von do_doc per
# load_conf geladene Umgebung ab.
# Globals:   UU_CONF, PERIODIC_CONF, DAILY_DROPIN, UPGRADE_DROPIN (lesend, via doc_val)
# Outputs:   stdout — Markdown-Abschnitt (beginnt mit "## <Label>")
#######################################
module_doc() {
    doc_section "Automatische Sicherheitsupdates"
    doc_packages unattended-upgrades
    doc_files_begin
    doc_file "$UU_CONF" \
        "Automatic-Reboot = $(doc_val AUTO_REBOOT)" \
        "Automatic-Reboot-Time = $(doc_val AUTO_REBOOT_TIME)" \
        "Mail = $(doc_val ADMIN_MAIL) (only-on-error)"
    doc_file "$PERIODIC_CONF" \
        "APT::Periodic::Update-Package-Lists = 1" \
        "APT::Periodic::Unattended-Upgrade = 1"
    doc_file "$DAILY_DROPIN" \
        "OnCalendar = $(doc_val APT_DAILY_TIME)"
    doc_file "$UPGRADE_DROPIN" \
        "OnCalendar = $(doc_val APT_DAILY_UPGRADE_TIME)"
    doc_timer_cron "apt-daily.timer und apt-daily-upgrade.timer (systemd) mit konfigurierten Uhrzeiten"
}

dispatch "$MODULE" "$@"
