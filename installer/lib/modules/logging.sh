#!/bin/bash
#
# Linux Secure Base — Modul logging
# Protokollierung: journald persistent (Storage/SystemMaxUse/MaxRetentionSec)
# und logwatch als taeglicher Mail-Report ueber das postfix-Relay.
# Schreibt die logrotate-Konfig fuer /var/log/secure-base/secure-base.log
# nach /etc/logrotate.d/secure-base.
# journald wird nur neu gestartet, nie entfernt (Basis-Infrastruktur).
# auditd: Paket + Regeldatei + sudo-Protokollierung gemaess konv-system.md 3.4.
# Nicht sitzungs-kritisch.
# Aufruf: logging.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="logging"

readonly JOURNALD_CONF="/etc/systemd/journald.conf"
readonly LOGWATCH_CONF="/etc/logwatch/conf/logwatch.conf"
readonly JOURNAL_DIR="/var/log/journal"
readonly LOGROTATE_CONF="/etc/logrotate.d/secure-base"
readonly AUDIT_RULES_FILE="/etc/audit/rules.d/secure-base.rules"
readonly SUDOLOG_CONF="/etc/sudoers.d/secure-base-sudolog"

# Soll-Regeln gemaess konv-system.md 3.4 b (exakt).
# -e 2 (Immutable) steht als letzte Regel.
readonly AUDIT_RULES_CONTENT='-w /etc/sudoers     -p wa -k scope
-w /etc/sudoers.d   -p wa -k scope
-w /etc/passwd      -p wa -k identity
-w /etc/shadow      -p wa -k identity
-w /etc/group       -p wa -k identity
-w /var/log/lastlog -p wa -k logins
-e 2'

# --- Hilfsfunktionen -------------------------------------------------

# Effektiver Absender: root@<domain>, Domain aus FQDN abgeleitet (via mailfrom_from_fqdn).
# Leer, wenn aus FQDN keine Domain ableitbar ist (FQDN ohne Punkt).
logwatch_mailfrom() { mailfrom_from_fqdn; }

# Prueft Empfaenger (ADMIN_MAIL), FQDN-Zeichensatz und Absender-
# Ableitbarkeit. Bricht sonst mit die ab.
require_logging_mail() {
    if [ -z "${ADMIN_MAIL:-}" ]; then
        die "ADMIN_MAIL nicht gesetzt in secure-base.conf — Logwatch-Empfaenger fehlt."
    fi
    # FQDN-Zeichensatz pruefen: nur Buchstaben, Ziffern, Punkt und Bindestrich.
    if ! [[ "${FQDN:-}" =~ ^[A-Za-z0-9.-]+$ ]]; then
        die "FQDN ('${FQDN:-}') enthaelt unzulaessige Zeichen (erlaubt: Buchstaben, Ziffern, '.', '-'). FQDN in secure-base.conf korrigieren."
    fi
    if [ -z "$(logwatch_mailfrom)" ]; then
        die "Kein Logwatch-Absender ableitbar: FQDN ('${FQDN:-}') enthaelt keine Domain. FQDN in secure-base.conf als vollstaendigen Hostnamen mit Domain setzen (z. B. srv001.example.com)."
    fi
}

# Grobe Plausibilitaet der optionalen journald-Groessenwerte (leer = ok,
# Default greift).
validate_journald_sizes() {
    local use=${JOURNALD_MAX_USE:-}
    local ret=${JOURNALD_MAX_RETENTION:-}
    if [ -n "$use" ] && ! [[ "$use" =~ ^[0-9]+[KMGT]?$ ]]; then
        die "JOURNALD_MAX_USE ('$use') ist kein gueltiges systemd-Groessenmass (erwartet z. B. 500M, 1G, 2G)."
    fi
    if [ -n "$ret" ] && ! [[ "$ret" =~ ^[0-9]+(s|min|h|day|week|month|year)$ ]]; then
        die "JOURNALD_MAX_RETENTION ('$ret') ist keine gueltige systemd-Zeitangabe (erwartet z. B. 4week, 3month, 1year)."
    fi
}

# Schreibt die logrotate-Konfiguration fuer das secure-base-Logfile.
write_logrotate_conf() {
    cat > "$LOGROTATE_CONF" <<'EOF'
/var/log/secure-base/secure-base.log {
    weekly
    size 5M
    compress
    rotate 8
    missingok
    notifempty
    copytruncate
}
EOF
    chmod 644 "$LOGROTATE_CONF"
    log INFO "logging install: logrotate-Konfig nach $LOGROTATE_CONF geschrieben (0644)"
}

# --- Subkommandos ----------------------------------------------------

do_install() {
    require_root
    load_conf "$SB_CONF"
    require_logging_mail
    validate_journald_sizes

    local mailto mailfrom max_use max_ret
    mailto=${ADMIN_MAIL:-}
    mailfrom=$(logwatch_mailfrom)
    max_use=${JOURNALD_MAX_USE:-1G}
    max_ret=${JOURNALD_MAX_RETENTION:-3month}

    # journald persistent haerten.
    log INFO "logging install: $JOURNALD_CONF haerten (Storage=persistent, SystemMaxUse=$max_use, MaxRetentionSec=$max_ret)"
    ensure_setting "$JOURNALD_CONF" Storage         persistent  "="
    ensure_setting "$JOURNALD_CONF" SystemMaxUse    "$max_use"  "="
    ensure_setting "$JOURNALD_CONF" MaxRetentionSec "$max_ret"  "="

    # journald neu starten — uebernimmt den persistenten Storage und legt
    # /var/log/journal/ an. Kein svc_enable_now: systemd-journald ist
    # socket-aktiviert und immer aktiv, nur der Restart laedt die Konfig.
    log INFO "logging install: systemd-journald neu starten (uebernimmt persistenten Storage)"
    systemctl restart systemd-journald

    # logwatch installieren.
    log INFO "logging install: Paket logwatch installieren"
    pkg_install logwatch

    # /etc/logwatch/conf/logwatch.conf existiert nach apt install nicht
    # zwingend — das Paket legt oft nur das Verzeichnis an, die Defaults
    # liegen unter /usr/share/logwatch/default.conf/. ensure_setting
    # braucht aber eine vorhandene Datei: anlegen, falls sie fehlt.
    if [ ! -f "$LOGWATCH_CONF" ]; then
        log INFO "logging install: $LOGWATCH_CONF fehlt — leere Override-Datei anlegen (0644)"
        mkdir -p "$(dirname "$LOGWATCH_CONF")"
        : > "$LOGWATCH_CONF"
        chmod 644 "$LOGWATCH_CONF"
    fi

    # logwatch konfigurieren (sechs Direktiven, Separator ' = ').
    log INFO "logging install: $LOGWATCH_CONF konfigurieren (MailTo=$mailto, MailFrom=$mailfrom)"
    ensure_setting "$LOGWATCH_CONF" Output   mail        " = "
    ensure_setting "$LOGWATCH_CONF" Format   text        " = "
    ensure_setting "$LOGWATCH_CONF" Detail   Med         " = "
    ensure_setting "$LOGWATCH_CONF" Range    yesterday   " = "
    ensure_setting "$LOGWATCH_CONF" MailTo   "$mailto"   " = "
    ensure_setting "$LOGWATCH_CONF" MailFrom "$mailfrom" " = "

    # logrotate-Konfig fuer das secure-base-Logfile schreiben.
    write_logrotate_conf

    # --- auditd (konv-system.md 3.4) ---

    # sudo-Protokollierung gemaess 3.4 a.
    log INFO "logging install: sudo-Protokollierung nach $SUDOLOG_CONF einrichten"
    printf 'Defaults logfile="/var/log/sudo.log"\n' > "$SUDOLOG_CONF"
    chmod 440 "$SUDOLOG_CONF"

    # auditd-Paket installieren.
    log INFO "logging install: Paket auditd installieren"
    pkg_install auditd

    # Regeldatei schreiben (nur bei Aenderung — -e 2 macht Laufzeit-Reload
    # ohne Reboot unmoeoglich; Datei-Aenderungen greifen erst nach dem
    # naechsten Boot).
    if [ -f "$AUDIT_RULES_FILE" ] \
        && [ "$(cat "$AUDIT_RULES_FILE")" = "$AUDIT_RULES_CONTENT" ]; then
        log INFO "logging install: $AUDIT_RULES_FILE unveraendert — uebersprungen"
    else
        log INFO "logging install: Audit-Regeln nach $AUDIT_RULES_FILE schreiben"
        mkdir -p "$(dirname "$AUDIT_RULES_FILE")"
        printf '%s\n' "$AUDIT_RULES_CONTENT" > "$AUDIT_RULES_FILE"
        chmod 640 "$AUDIT_RULES_FILE"
        log WARN "logging install: -e 2 (Immutable) ist gesetzt — neue Regeln greifen erst nach einem Neustart."
    fi

    # auditd aktivieren und starten.
    log INFO "logging install: auditd aktivieren und starten"
    svc_enable_now auditd
}

do_uninstall() {
    require_root
    # secure-base.conf wird hier bewusst NICHT geladen/validiert: der Rueckbau
    # ist konfig-unabhaengig und muss auch bei fehlender/defekter Conf
    # durchlaufen (fail-safe).

    # (1) journald-Sonderfall: systemd-journald ist Basis-Infrastruktur
    #     von systemd und wird NICHT entfernt/gestoppt. Nur die eigenen
    #     Direktiven zuruecknehmen, dann neu laden.
    if [ -f "$JOURNALD_CONF" ]; then
        log INFO "logging uninstall: journald-Direktiven in $JOURNALD_CONF zuruecknehmen"
        remove_setting "$JOURNALD_CONF" Storage
        remove_setting "$JOURNALD_CONF" SystemMaxUse
        remove_setting "$JOURNALD_CONF" MaxRetentionSec
        log INFO "logging uninstall: systemd-journald neu starten (uebernimmt zurueckgesetzte Konfig)"
        systemctl restart systemd-journald
    else
        log INFO "logging uninstall: $JOURNALD_CONF nicht vorhanden — keine journald-Reverts noetig"
    fi

    # (2) logwatch: eigene Konfig-Eingriffe zuruecknehmen, dann Paket.
    #     logwatch hat keinen eigenen Daemon (Lauf via cron.daily) —
    #     kein svc_disable_now.
    if pkg_installed logwatch; then
        if [ -f "$LOGWATCH_CONF" ]; then
            log INFO "logging uninstall: logwatch-Direktiven in $LOGWATCH_CONF zuruecknehmen"
            remove_setting "$LOGWATCH_CONF" Output
            remove_setting "$LOGWATCH_CONF" Format
            remove_setting "$LOGWATCH_CONF" Detail
            remove_setting "$LOGWATCH_CONF" Range
            remove_setting "$LOGWATCH_CONF" MailTo
            remove_setting "$LOGWATCH_CONF" MailFrom
        fi
        log INFO "logging uninstall: Paket logwatch entfernen (ohne --purge)"
        pkg_remove logwatch
    else
        log INFO "logging uninstall: Paket logwatch nicht installiert — nichts zu entfernen"
    fi

    # (3) logrotate-Konfig entfernen.
    if [ -f "$LOGROTATE_CONF" ]; then
        log INFO "logging uninstall: $LOGROTATE_CONF entfernen"
        rm -f "$LOGROTATE_CONF"
    else
        log INFO "logging uninstall: $LOGROTATE_CONF nicht vorhanden — uebersprungen"
    fi

    # (4) auditd: Regeldatei + sudo-Log-Konfig entfernen, Dienst stoppen.
    if [ -f "$AUDIT_RULES_FILE" ]; then
        log INFO "logging uninstall: $AUDIT_RULES_FILE entfernen"
        rm -f "$AUDIT_RULES_FILE"
    else
        log INFO "logging uninstall: $AUDIT_RULES_FILE nicht vorhanden — uebersprungen"
    fi
    if [ -f "$SUDOLOG_CONF" ]; then
        log INFO "logging uninstall: $SUDOLOG_CONF entfernen"
        rm -f "$SUDOLOG_CONF"
    else
        log INFO "logging uninstall: $SUDOLOG_CONF nicht vorhanden — uebersprungen"
    fi
    if pkg_installed auditd; then
        log INFO "logging uninstall: auditd stoppen und deaktivieren"
        systemctl disable --now auditd 2>/dev/null || true
        log INFO "logging uninstall: Paket auditd entfernen (ohne --purge)"
        pkg_remove auditd
    else
        log INFO "logging uninstall: Paket auditd nicht installiert — nichts zu entfernen"
    fi
    log WARN "logging uninstall: /var/log/sudo.log bleibt (Audit-Datensicherung). Manuell entfernen, falls gewuenscht."
}

do_check() {
    require_root
    load_conf "$SB_CONF"
    require_logging_mail
    validate_journald_sizes

    local rc=0
    local mailto mailfrom max_use max_ret
    mailto=${ADMIN_MAIL:-}
    mailfrom=$(logwatch_mailfrom)
    max_use=${JOURNALD_MAX_USE:-1G}
    max_ret=${JOURNALD_MAX_RETENTION:-3month}

    # (1) journald-Direktiven.
    local use_re ret_re
    use_re=$(ere_escape "$max_use")
    ret_re=$(ere_escape "$max_ret")
    if file_has_line "$JOURNALD_CONF" '^Storage=persistent$'; then
        log INFO "check: journald Storage=persistent gesetzt"
    else
        log ERROR "check: journald Storage nicht aktiv auf persistent"
        rc=1
    fi
    if file_has_line "$JOURNALD_CONF" "^SystemMaxUse=${use_re}$"; then
        log INFO "check: journald SystemMaxUse=$max_use gesetzt"
    else
        log ERROR "check: journald SystemMaxUse nicht aktiv auf $max_use"
        rc=1
    fi
    if file_has_line "$JOURNALD_CONF" "^MaxRetentionSec=${ret_re}$"; then
        log INFO "check: journald MaxRetentionSec=$max_ret gesetzt"
    else
        log ERROR "check: journald MaxRetentionSec nicht aktiv auf $max_ret"
        rc=1
    fi

    # (2) Persistenz wirksam: /var/log/journal/ vorhanden.
    if [ -d "$JOURNAL_DIR" ]; then
        log INFO "check: $JOURNAL_DIR vorhanden (Persistenz aktiv)"
    else
        log ERROR "check: $JOURNAL_DIR fehlt — Persistenz nicht aktiv"
        rc=1
    fi

    # (3) logwatch installiert.
    check_packages logwatch || exit 1

    # (4) logwatch-Direktiven (MailTo/MailFrom ERE-maskiert).
    local mailto_re mailfrom_re
    mailto_re=$(ere_escape "$mailto")
    mailfrom_re=$(ere_escape "$mailfrom")
    if file_has_line "$LOGWATCH_CONF" '^Output = mail$'; then
        log INFO "check: logwatch Output = mail gesetzt"
    else
        log ERROR "check: logwatch Output nicht aktiv auf mail"
        rc=1
    fi
    if file_has_line "$LOGWATCH_CONF" '^Format = text$'; then
        log INFO "check: logwatch Format = text gesetzt"
    else
        log ERROR "check: logwatch Format nicht aktiv auf text"
        rc=1
    fi
    if file_has_line "$LOGWATCH_CONF" '^Detail = Med$'; then
        log INFO "check: logwatch Detail = Med gesetzt"
    else
        log ERROR "check: logwatch Detail nicht aktiv auf Med"
        rc=1
    fi
    if file_has_line "$LOGWATCH_CONF" '^Range = yesterday$'; then
        log INFO "check: logwatch Range = yesterday gesetzt"
    else
        log ERROR "check: logwatch Range nicht aktiv auf yesterday"
        rc=1
    fi
    if file_has_line "$LOGWATCH_CONF" "^MailTo = ${mailto_re}$"; then
        log INFO "check: logwatch MailTo = $mailto gesetzt"
    else
        log ERROR "check: logwatch MailTo nicht aktiv auf $mailto"
        rc=1
    fi
    if file_has_line "$LOGWATCH_CONF" "^MailFrom = ${mailfrom_re}$"; then
        log INFO "check: logwatch MailFrom = $mailfrom gesetzt"
    else
        log ERROR "check: logwatch MailFrom nicht aktiv auf $mailfrom"
        rc=1
    fi

    # (5) logrotate-Konfig vorhanden.
    if [ -f "$LOGROTATE_CONF" ]; then
        log INFO "check: $LOGROTATE_CONF vorhanden"
    else
        log ERROR "check: $LOGROTATE_CONF fehlt"
        rc=1
    fi

    # (6) auditd aktiv (konv-system.md 3.4 b).
    check_packages auditd || rc=1
    if [ "$(systemctl is-active auditd 2>/dev/null)" = "active" ]; then
        log INFO "check: auditd aktiv"
    else
        log ERROR "check: auditd nicht aktiv"
        rc=1
    fi

    # (7) Soll-Regeln vollstaendiger Abgleich (konv-system.md 3.4 b).
    # Bei -e 2 koennen Regeln zur Laufzeit nicht mehr geaendert werden;
    # der Abgleich erfolgt deshalb gegen die persistente Regeldatei.
    local rule
    while IFS= read -r rule; do
        # Leerzeilen und Kommentare ueberspringen.
        [[ "$rule" =~ ^[[:space:]]*$ ]] && continue
        [[ "$rule" =~ ^# ]] && continue
        if [ "$rule" = "-e 2" ]; then
            # Immutable-Status ueber auditctl -s pruefen statt ueber die Datei.
            local enabled_val
            enabled_val=$(auditctl -s 2>/dev/null | awk '/^enabled /{print $2}')
            if [ "$enabled_val" = "2" ]; then
                log INFO "check: auditd Immutable (-e 2) aktiv"
            else
                log WARN "check: auditd Immutable-Status noch nicht aktiv (enabled=$enabled_val) — Reboot erforderlich, damit -e 2 greift"
            fi
        else
            if auditctl -l 2>/dev/null | grep -qF -- "$rule"; then
                log INFO "check: Audit-Regel vorhanden: $rule"
            else
                log ERROR "check: Audit-Regel fehlt laut 'auditctl -l': $rule"
                rc=1
            fi
        fi
    done <<< "$AUDIT_RULES_CONTENT"

    # (8) sudo-Protokollierung (konv-system.md 3.4 a).
    if [ -f "$SUDOLOG_CONF" ] \
        && grep -q 'logfile="/var/log/sudo\.log"' "$SUDOLOG_CONF"; then
        log INFO "check: sudo-Protokollierung in $SUDOLOG_CONF gesetzt"
    else
        log ERROR "check: sudo-Protokollierung fehlt oder unvollstaendig ($SUDOLOG_CONF)"
        rc=1
    fi

    exit "$rc"
}

do_test() {
    require_root
    load_conf "$SB_CONF"
    require_logging_mail
    validate_journald_sizes

    local rc=0
    local mailto
    mailto=${ADMIN_MAIL:-}

    # (1) journald-Persistenz nachweisen: Header lesen, Verzeichnis pruefen.
    log INFO "test: journald-Header lesen (Persistenz-Nachweis)"
    local out hrc=0
    out=$(journalctl --header 2>&1) || hrc=$?
    if [ -n "$out" ]; then
        local line
        while IFS= read -r line; do log INFO "journald: $line"; done <<<"$out"
    fi
    if [ "$hrc" -eq 0 ] && [ -d "$JOURNAL_DIR" ]; then
        log INFO "test: journald-Persistenz nachgewiesen ($JOURNAL_DIR vorhanden)"
    else
        log ERROR "test: journald-Persistenz nicht nachweisbar (journalctl --header rc=$hrc, Verzeichnis $JOURNAL_DIR)"
        rc=1
    fi

    # (2) logwatch-Report per Mail verschicken (echter Versand).
    if ! pkg_installed logwatch; then
        log ERROR "test: Paket logwatch nicht installiert — kein Funktionstest moeglich"
        exit 1
    fi
    log INFO "test: Logwatch-Report per Mail verschicken (logwatch --output mail, Range gestern) — Empfaenger $mailto"
    local lwout lwrc=0
    lwout=$(logwatch --output mail --format text --range yesterday --detail Med 2>&1) || lwrc=$?
    if [ -n "$lwout" ]; then
        local lwline
        while IFS= read -r lwline; do log INFO "logwatch: $lwline"; done <<<"$lwout"
    fi
    if [ "$lwrc" -ne 0 ]; then
        log ERROR "test: logwatch-Mailversand fehlgeschlagen (Exit $lwrc)"
        rc=1
    else
        log INFO "test: logwatch-Report abgesetzt — im Postfach von $mailto den Eingang der Test-Report-Mail pruefen (Versand laeuft ueber das postfix-Relay)"
    fi

    exit "$rc"
}

#######################################
# Liefert den Markdown-Abschnitt dieses Moduls fuer die Abschluss-Doku.
# Nur lesend; nimmt keine Systemaenderung vor. Gibt ausschliesslich
# Markdown nach stdout aus. Nimmt conf-Werte ueber die von do_doc per
# load_conf geladene Umgebung ab.
# Globals:   JOURNALD_CONF, LOGWATCH_CONF, LOGROTATE_CONF (lesend, via doc_val)
# Outputs:   stdout — Markdown-Abschnitt (beginnt mit "## <Label>")
#######################################
module_doc() {
    doc_section "Protokollierung und Auditing"
    doc_packages logwatch auditd
    doc_services auditd
    doc_files_begin
    doc_file "$JOURNALD_CONF" \
        "Storage = persistent" \
        "SystemMaxUse = $(doc_val JOURNALD_MAX_USE)" \
        "MaxRetentionSec = $(doc_val JOURNALD_MAX_RETENTION)"
    doc_file "$LOGWATCH_CONF" \
        "MailTo = $(doc_val ADMIN_MAIL)" \
        "Detail = Med" \
        "Service = All" \
        "Output = mail"
    doc_file "$LOGROTATE_CONF" \
        "logrotate-Konfig fuer /var/log/secure-base/secure-base.log"
    doc_file "$AUDIT_RULES_FILE" \
        "-w /etc/sudoers -p wa -k scope" \
        "-w /etc/sudoers.d -p wa -k scope" \
        "-w /etc/passwd -p wa -k identity" \
        "-w /etc/shadow -p wa -k identity" \
        "-w /etc/group -p wa -k identity" \
        "-w /var/log/lastlog -p wa -k logins" \
        "-e 2 (Immutable — Regelaenderungen ohne Reboot gesperrt)"
    doc_file "$SUDOLOG_CONF" \
        "Defaults logfile=\"/var/log/sudo.log\""
    doc_timer_cron "logwatch: taeglicher Lauf via /etc/cron.daily/00logwatch"
    doc_note "systemd-journald wird nicht neu installiert (Basis-Infrastruktur); persistentes Journal wird unter $JOURNAL_DIR abgelegt. auditd-Regeln mit -e 2 (Immutable) greifen erst nach dem naechsten Reboot."
}

dispatch "$MODULE" "$@"
