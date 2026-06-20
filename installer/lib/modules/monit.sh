#!/bin/bash
#
# Linux Secure Base — Modul monit
# Monitoring: Paket installieren, globale Einstellungen in /etc/monit/monitrc
# ueber die Marker-Mechanik setzen (set daemon/log/mailserver/alert sowie die
# Bloecke mail-format/httpd), die ausgewaehlten Checks unter
# /etc/monit/conf.d/ als eigene Dateien anlegen, Konfig per 'monit -t' pruefen,
# Dienst aktivieren und starten. Alarm-Mail laeuft ueber das lokale Postfix
# (Modul postfix). Nicht sitzungs-kritisch; check/test lesend.
# Aufruf: monit.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="monit"
readonly CONF_COMMON="$SCRIPT_DIR/conf/common.conf"

readonly MONITRC="/etc/monit/monitrc"
readonly CONFD="/etc/monit/conf.d"

# --- Konstanten der monitrc-Globals ----------------------------------

# Vier Einzelzeilen-Direktiven (Marker-Mechanik, ensure_setting). Der
# Schluessel ist eine Mehrwort-Direktive.
readonly DAEMON_VALUE="60 with start delay 60"
readonly LOG_VALUE="/var/log/monit.log"
readonly MAILSERVER_VALUE="localhost"

# --- Konfig-Pruefung -------------------------------------------------

# Feste Liste aller je vom Modul verwalteten Checks (Teardown-/Iterations-
# Basis, unabhaengig von CHECKS_ENABLED).
known_checks() {
    printf '%s\n' system rootfs sshd postfix fail2ban ufw cron rkhunter restic
}

# Validiert alle .conf-Werte, BEVOR sie in die monitrc-Direktiven oder in
# Dateinamen unter $CONFD gehen. ADMIN_MAIL/MONIT_MAIL_FROM anchored;
# CHECKS_ENABLED als Whitelist-Set-Membership.
require_monit_conf() {
    [[ "${ADMIN_MAIL:-}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] \
        || die "ADMIN_MAIL fehlt oder ist ungueltig: '${ADMIN_MAIL:-}'"
    [[ "${MONIT_MAIL_FROM:-}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] \
        || die "MONIT_MAIL_FROM fehlt oder ist ungueltig: '${MONIT_MAIL_FROM:-}'"

    if ! declare -p CHECKS_ENABLED >/dev/null 2>&1; then
        die "CHECKS_ENABLED ist nicht gesetzt (Array erwartet)"
    fi
    if [ "${#CHECKS_ENABLED[@]}" -eq 0 ]; then
        die "CHECKS_ENABLED ist leer (mindestens ein Check erwartet)"
    fi
    local c
    for c in "${CHECKS_ENABLED[@]}"; do
        case "$c" in
            system|rootfs|sshd|postfix|fail2ban|ufw|cron|rkhunter|restic) ;;
            *) die "CHECKS_ENABLED enthaelt unbekannten Wert: '$c' (erlaubt: system rootfs sshd postfix fail2ban ufw cron rkhunter restic)" ;;
        esac
    done
}

# --- monitrc-Globals -------------------------------------------------

# Setzt die vier Einzelzeilen-Direktiven und die zwei Bloecke in
# /etc/monit/monitrc ueber die Marker-Mechanik. monit-eigene Variablen
# ($HOST/$EVENT/...) bleiben literal; nur MONIT_MAIL_FROM wird eingesetzt.
patch_monitrc_globals() {
    ensure_setting "$MONITRC" "set daemon"     "$DAEMON_VALUE"
    ensure_setting "$MONITRC" "set log"        "$LOG_VALUE"
    ensure_setting "$MONITRC" "set mailserver" "$MAILSERVER_VALUE"
    ensure_setting "$MONITRC" "set alert"      "$ADMIN_MAIL"

    local mail_format httpd_block
    mail_format=$(cat <<EOF
set mail-format {
    from:    ${MONIT_MAIL_FROM}
    subject: monit [\$HOST] \$EVENT - \$SERVICE
    message: \$EVENT - \$SERVICE auf \$HOST (\$DATE)
             \$DESCRIPTION
}
EOF
)
    ensure_block "$MONITRC" "set mail-format" "$mail_format"

    httpd_block=$(cat <<'EOF'
set httpd port 2812 and
    use address localhost
    allow localhost
EOF
)
    ensure_block "$MONITRC" "set httpd" "$httpd_block"
}

# Schreibt die conf.d-Datei fuer einen Check (eigene Datei, 0644, komplett
# ueberschrieben — idempotent). monit-Variablen literal (quotierte Heredocs).
write_check() {
    local name=$1
    local dest="$CONFD/$name" content
    case "$name" in
        system)
            content=$(cat <<'EOF'
check system $HOST
    if loadavg (1min) > 4    then alert
    if loadavg (5min) > 2    then alert
    if memory usage > 90 %   then alert
    if cpu usage (user) > 90 % for 5 cycles then alert
EOF
)
            ;;
        rootfs)
            content=$(cat <<'EOF'
check filesystem rootfs with path /
    if space usage > 85 % then alert
    if inode usage > 85 % then alert
EOF
)
            ;;
        sshd)
            content=$(cat <<'EOF'
check process sshd matching "sshd"
    start program = "/bin/systemctl start ssh"
    stop  program = "/bin/systemctl stop  ssh"
    if 5 restarts within 5 cycles then alert
EOF
)
            ;;
        postfix)
            content=$(cat <<'EOF'
check process postfix with pidfile /var/spool/postfix/pid/master.pid
    start program = "/bin/systemctl start postfix"
    stop  program = "/bin/systemctl stop  postfix"
EOF
)
            ;;
        fail2ban)
            content=$(cat <<'EOF'
check process fail2ban with pidfile /var/run/fail2ban/fail2ban.pid
    start program = "/bin/systemctl start fail2ban"
    stop  program = "/bin/systemctl stop  fail2ban"
EOF
)
            ;;
        ufw)
            content=$(cat <<'EOF'
check program ufw with path "/bin/systemctl is-active --quiet ufw"
    if status != 0 then alert
EOF
)
            ;;
        cron)
            content=$(cat <<'EOF'
check process crond with pidfile /var/run/crond.pid
    start program = "/bin/systemctl start cron"
    stop  program = "/bin/systemctl stop  cron"
    if 5 restarts within 5 cycles then alert
EOF
)
            ;;
        rkhunter)
            content=$(cat <<'EOF'
check file rkhunter with path /var/log/rkhunter.log
    if mtime > 25 hours then alert
EOF
)
            ;;
        restic)
            content=$(cat <<'EOF'
check file restic_backup with path /var/lib/secure-base/restic-last-success
    if mtime > 26 hours then alert
EOF
)
            ;;
        *)
            die "write_check: unbekannter Check '$name'"
            ;;
    esac
    printf '%s\n' "$content" >"$dest"
    chmod 644 "$dest"
    log INFO "monit install: Check $name nach $dest geschrieben (0644)"
}

# --- Subkommandos ----------------------------------------------------

do_install() {
    require_root
    load_conf "$CONF_COMMON"
    require_monit_conf

    log INFO "monit install: Paket installieren"
    pkg_install monit

    log INFO "monit install: globale Einstellungen in $MONITRC setzen"
    patch_monitrc_globals

    log INFO "monit install: Checks aus CHECKS_ENABLED anlegen (${CHECKS_ENABLED[*]})"
    local c
    for c in "${CHECKS_ENABLED[@]}"; do
        write_check "$c"
    done

    # Syntaxpruefung VOR (Neu-)Start, damit eine kaputte Konfig den Dienst
    # nicht in einen Crash-Loop bringt.
    log INFO "monit install: Konfiguration pruefen (monit -t)"
    local out trc=0
    out=$(monit -t 2>&1) || trc=$?
    local line
    while IFS= read -r line; do
        [ -n "$line" ] && log INFO "monit -t: $line"
    done <<<"$out"
    if [ "$trc" -ne 0 ]; then
        die "monit install: 'monit -t' meldet Syntaxfehler (Exit $trc) — Dienst NICHT gestartet"
    fi

    log INFO "monit install: Dienst aktivieren und starten"
    svc_enable_now monit

    # apt startet monit bei der Installation bereits mit der Default-Konfig;
    # 'systemctl enable --now' macht dann KEINEN Neustart, der Daemon laeufe
    # sonst mit veralteter Konfig. Daher die Konfig IMMER neu einlesen —
    # idempotent, auch nach Frischstart unschaedlich.
    log INFO "monit install: Konfiguration in den laufenden Daemon einlesen (monit reload)"
    monit reload
}

do_uninstall() {
    require_root
    # common.conf wird bewusst NICHT geladen: der Rueckbau ist
    # konfig-unabhaengig (feste Datei-/Marker-Namen) und muss auch bei
    # fehlender/defekter Conf durchlaufen (fail-safe).
    if ! pkg_installed monit; then
        log INFO "monit uninstall: Paket monit nicht installiert — nichts zu tun"
        return 0
    fi

    # (1) Dienst stoppen und deaktivieren — zwingend vor apt remove.
    svc_disable_now monit

    # (2) Eigene Dateien entfernen: alle je verwalteten conf.d-Checks,
    # unabhaengig von CHECKS_ENABLED.
    local name dest
    while IFS= read -r name; do
        dest="$CONFD/$name"
        if [ -e "$dest" ]; then
            log INFO "monit uninstall: Check-Datei $dest entfernen"
            rm -f "$dest"
        fi
    done < <(known_checks)

    # (3) Konfig-Eingriffe in /etc/monit/monitrc zuruecknehmen.
    log INFO "monit uninstall: globale Eingriffe in $MONITRC zuruecknehmen"
    remove_setting "$MONITRC" "set daemon"
    remove_setting "$MONITRC" "set log"
    remove_setting "$MONITRC" "set mailserver"
    remove_setting "$MONITRC" "set alert"
    remove_block "$MONITRC" "set mail-format"
    remove_block "$MONITRC" "set httpd"

    # (4) Paket entfernen (ohne --purge).
    log INFO "monit uninstall: Paket entfernen (ohne --purge)"
    pkg_remove monit
}

do_check() {
    require_root
    load_conf "$CONF_COMMON"
    require_monit_conf

    local rc=0

    if pkg_installed monit; then
        log INFO "check: Paket monit installiert"
    else
        log ERROR "check: Paket monit nicht installiert — Soll-Zustand nicht erfuellt"
        exit 1
    fi

    check_svc_enabled monit || rc=1

    # Die sechs monitrc-Eingriffe (Marker vorhanden?).
    local key
    for key in "set daemon" "set log" "set mailserver" "set alert" "set mail-format" "set httpd"; do
        if grep -qF "# secure-base:${key}:begin" "$MONITRC" 2>/dev/null; then
            log INFO "check: monitrc-Eingriff '$key' vorhanden"
        else
            log ERROR "check: monitrc-Eingriff '$key' fehlt in $MONITRC"
            rc=1
        fi
    done

    # Je CHECKS_ENABLED-Eintrag die conf.d-Datei (0644 root:root).
    local c
    for c in "${CHECKS_ENABLED[@]}"; do
        check_file_mode "$CONFD/$c" 644 root:root || rc=1
    done

    exit "$rc"
}

do_test() {
    require_root
    load_conf "$CONF_COMMON"
    require_monit_conf

    local rc=0

    if ! pkg_installed monit; then
        log ERROR "test: Paket monit nicht installiert — kein Funktionstest moeglich"
        exit 1
    fi

    # (1) Syntaxpruefung (sitzungs-neutral, kein Restart).
    local out trc=0 line
    out=$(monit -t 2>&1) || trc=$?
    while IFS= read -r line; do
        [ -n "$line" ] && log INFO "monit -t: $line"
    done <<<"$out"
    if [ "$trc" -eq 0 ]; then
        log INFO "test: 'monit -t' ok (Konfiguration syntaktisch gueltig)"
    else
        log ERROR "test: 'monit -t' meldet Fehler (Exit $trc)"
        rc=1
    fi

    # (2) Statusabruf ueber den lokalen httpd (rein lesend).
    local src=0
    out=$(monit status 2>&1) || src=$?
    while IFS= read -r line; do
        [ -n "$line" ] && log INFO "monit status: $line"
    done <<<"$out"
    if [ "$src" -eq 0 ]; then
        log INFO "test: 'monit status' abrufbar (Dienst erreichbar)"
    else
        log ERROR "test: 'monit status' nicht abrufbar (Exit $src) — Dienst/httpd nicht erreichbar"
        rc=1
    fi

    # (3) mail-Befehl fuer die Alarm-Zustellung vorhanden?
    if command -v mail >/dev/null 2>&1; then
        log INFO "test: 'mail'-Befehl vorhanden (Alarm-Zustellung moeglich)"
    else
        log WARN "test: 'mail'-Befehl fehlt — monit-Alarm-Mails wuerden nicht zugestellt (Modul postfix installiert mailutils)"
    fi

    exit "$rc"
}

dispatch "$MODULE" "$@"
