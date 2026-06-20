#!/bin/bash
#
# Linux Secure Base — Modul rkhunter
# Schadsoftware-/Rootkit-Schutz: Paket installieren, /etc/default/rkhunter
# haerten (taeglicher Cron-Lauf, DB-Update, Report-Mail, apt-Hook) und die
# Baseline-Datenbank initialisieren.
# Nicht sitzungs-kritisch; kein eigener systemd-Dienst (Lauf via
# /etc/cron.daily/rkhunter + apt-Hook).
# Aufruf: rkhunter.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="rkhunter"

readonly RK_DEFAULT="/etc/default/rkhunter"
readonly RK_CONF="/etc/rkhunter.conf"
readonly RK_BASELINE="/var/lib/rkhunter/db/rkhunter.dat"

# Fester MAIL_CMD-Wert (Absender wird per rkhunter_mailfrom eingesetzt;
# ${HOST_NAME} bleibt als rkhunter-interne Variable literal erhalten).
rkhunter_mail_cmd() {
    printf '%s' "mail -r $(rkhunter_mailfrom) -s \"[rkhunter] Warnings found for \${HOST_NAME}\""
}

# --- Konfig-Pruefung -------------------------------------------------

# Effektiver Absender: root@<domain>, Domain aus FQDN abgeleitet.
# Leer, wenn aus FQDN keine Domain ableitbar ist (FQDN ohne Punkt).
rkhunter_mailfrom() {
    local fqdn=${FQDN:-}
    local domain=${fqdn#*.}
    if [ -n "$domain" ] && [ "$domain" != "$fqdn" ]; then
        printf '%s' "root@${domain}"
    fi
}

# Prueft Empfaenger (ADMIN_MAIL), FQDN-Zeichensatz und Absender-
# Ableitbarkeit. Bricht sonst ab.
require_rkhunter_mail() {
    if [ -z "${ADMIN_MAIL:-}" ]; then
        die "ADMIN_MAIL nicht gesetzt in secure-base.conf — rkhunter-Empfaenger fehlt."
    fi
    if ! [[ "${FQDN:-}" =~ ^[A-Za-z0-9.-]+$ ]]; then
        die "FQDN ('${FQDN:-}') enthaelt unzulaessige Zeichen (erlaubt: Buchstaben, Ziffern, '.', '-'). FQDN in secure-base.conf korrigieren."
    fi
    if [ -z "$(rkhunter_mailfrom)" ]; then
        die "Kein rkhunter-Absender ableitbar: FQDN ('${FQDN:-}') enthaelt keine Domain. FQDN in secure-base.conf als vollstaendigen Hostnamen mit Domain setzen (z. B. srv001.example.com)."
    fi
}

# Maskiert ERE-Metazeichen, damit ein Wert woertlich in ein grep -E-Muster
# (file_has_line) eingesetzt werden kann.
ere_escape() {
    printf '%s' "$1" | sed 's/[^a-zA-Z0-9_@-]/\\&/g'
}

# --- Subkommandos ----------------------------------------------------

do_install() {
    require_root
    load_conf "$SB_CONF"
    require_rkhunter_mail

    log INFO "rkhunter install: Paket installieren"
    pkg_install rkhunter

    local recipient mailfrom
    recipient=${ADMIN_MAIL:-}
    mailfrom=$(rkhunter_mailfrom)

    log INFO "rkhunter install: $RK_DEFAULT haerten (Report an $recipient)"
    ensure_setting "$RK_DEFAULT" CRON_DAILY_RUN  '"yes"'          "="
    ensure_setting "$RK_DEFAULT" CRON_DB_UPDATE  '"yes"'          "="
    ensure_setting "$RK_DEFAULT" DB_UPDATE_EMAIL '"false"'        "="
    ensure_setting "$RK_DEFAULT" REPORT_EMAIL    "\"$recipient\"" "="
    ensure_setting "$RK_DEFAULT" APT_AUTOGEN     '"yes"'          "="

    # Absender der Report-Mail auf root@<domain> setzen (MAIL_CMD in
    # rkhunter.conf). ${HOST_NAME} ist rkhunter-intern und bleibt literal.
    log INFO "rkhunter install: Absender in $RK_CONF setzen (MAIL_CMD, Absender $mailfrom)"
    ensure_setting "$RK_CONF" MAIL_CMD "$(rkhunter_mail_cmd)" "="

    # Baseline initialisieren (nicht-wiederholbarer Schritt).
    if [ -s "$RK_BASELINE" ]; then
        log INFO "rkhunter install: Baseline bereits vorhanden — --propupd uebersprungen (Baseline stammt aus einem frueheren Lauf, bleibt ueber uninstall hinweg erhalten)"
        log WARN "rkhunter install: bei Verdacht auf Kompromittierung der uebernommenen Baseline NICHT vertrauen, sondern auf gesichertem System manuell neu setzen: rkhunter --propupd"
    else
        log INFO "rkhunter install: Baseline initialisieren (rkhunter --propupd)"
        rkhunter --propupd
    fi
}

do_uninstall() {
    require_root
    # secure-base.conf wird bewusst NICHT geladen: der Rueckbau ist
    # konfig-unabhaengig und muss auch bei fehlender/defekter Conf
    # durchlaufen (fail-safe).
    #
    # Kein Dienst zu stoppen: rkhunter hat keinen eigenen systemd-Dienst.

    # (1) Konfig-Eingriffe in /etc/default/rkhunter zuruecknehmen.
    if [ -f "$RK_DEFAULT" ]; then
        log INFO "rkhunter uninstall: Konfig-Eingriffe in $RK_DEFAULT zuruecknehmen"
        remove_setting "$RK_DEFAULT" CRON_DAILY_RUN
        remove_setting "$RK_DEFAULT" CRON_DB_UPDATE
        remove_setting "$RK_DEFAULT" DB_UPDATE_EMAIL
        remove_setting "$RK_DEFAULT" REPORT_EMAIL
        remove_setting "$RK_DEFAULT" APT_AUTOGEN
    else
        log INFO "rkhunter uninstall: $RK_DEFAULT nicht vorhanden — keine Konfig-Reverts noetig"
    fi

    # (1b) MAIL_CMD-Eingriff in /etc/rkhunter.conf zuruecknehmen.
    if [ -f "$RK_CONF" ]; then
        log INFO "rkhunter uninstall: MAIL_CMD in $RK_CONF zuruecknehmen"
        remove_setting "$RK_CONF" MAIL_CMD
    else
        log INFO "rkhunter uninstall: $RK_CONF nicht vorhanden — kein MAIL_CMD-Revert noetig"
    fi

    # (2) Paket entfernen (ohne --purge — Baseline /var/lib/rkhunter/db/
    # bleibt liegen).
    log INFO "rkhunter uninstall: Paket entfernen (ohne --purge)"
    pkg_remove rkhunter
}

do_check() {
    require_root
    load_conf "$SB_CONF"
    require_rkhunter_mail

    local rc=0

    check_packages rkhunter || exit 1

    local recipient rcpt_re mail_cmd_re
    recipient=${ADMIN_MAIL:-}
    rcpt_re=$(ere_escape "$recipient")
    mail_cmd_re=$(ere_escape "$(rkhunter_mail_cmd)")

    if file_has_line "$RK_DEFAULT" '^CRON_DAILY_RUN="yes"$'; then
        log INFO "check: CRON_DAILY_RUN gesetzt"
    else
        log ERROR "check: CRON_DAILY_RUN nicht aktiv auf \"yes\""
        rc=1
    fi
    if file_has_line "$RK_DEFAULT" '^CRON_DB_UPDATE="yes"$'; then
        log INFO "check: CRON_DB_UPDATE gesetzt"
    else
        log ERROR "check: CRON_DB_UPDATE nicht aktiv auf \"yes\""
        rc=1
    fi
    if file_has_line "$RK_DEFAULT" '^DB_UPDATE_EMAIL="false"$'; then
        log INFO "check: DB_UPDATE_EMAIL gesetzt"
    else
        log ERROR "check: DB_UPDATE_EMAIL nicht aktiv auf \"false\""
        rc=1
    fi
    if file_has_line "$RK_DEFAULT" "^REPORT_EMAIL=\"${rcpt_re}\"$"; then
        log INFO "check: REPORT_EMAIL auf effektiven Empfaenger ($recipient)"
    else
        log ERROR "check: REPORT_EMAIL nicht aktiv auf effektiven Empfaenger ($recipient)"
        rc=1
    fi
    if file_has_line "$RK_DEFAULT" '^APT_AUTOGEN="yes"$'; then
        log INFO "check: APT_AUTOGEN gesetzt"
    else
        log ERROR "check: APT_AUTOGEN nicht aktiv auf \"yes\""
        rc=1
    fi

    if file_has_line "$RK_CONF" "^MAIL_CMD=${mail_cmd_re}$"; then
        log INFO "check: MAIL_CMD auf Absender $(rkhunter_mailfrom) gesetzt"
    else
        log ERROR "check: MAIL_CMD nicht aktiv auf Absender $(rkhunter_mailfrom) ($RK_CONF)"
        rc=1
    fi

    if [ -s "$RK_BASELINE" ]; then
        log INFO "check: Baseline vorhanden ($RK_BASELINE)"
    else
        log ERROR "check: rkhunter Baseline fehlt oder leer ($RK_BASELINE)"
        rc=1
    fi

    exit "$rc"
}

do_test() {
    require_root
    load_conf "$SB_CONF"
    require_rkhunter_mail

    local rc=0

    if ! pkg_installed rkhunter; then
        log ERROR "test: Paket rkhunter nicht installiert — kein Funktionstest moeglich"
        exit 1
    fi

    log INFO "test: rkhunter-Scan startet (lesend, kann einige Sekunden bis Minuten dauern)"
    local out rkrc=0
    out=$(rkhunter --check --sk --nocolors --report-warnings-only 2>&1) || rkrc=$?

    # Scan-Ausgabe ZEILENWEISE ins Log (Audit-Lesbarkeit).
    if [ -n "$out" ]; then
        local line
        while IFS= read -r line; do
            log WARN "rkhunter: $line"
        done <<<"$out"
    fi

    case "$rkrc" in
        0) log INFO "test: rkhunter-Scan ohne Warnungen" ;;
        1) log WARN "test: rkhunter meldet Warnungen (siehe oben) — kein Hard-Fail. Warnungen direkt nach Erstinstallation MANUELL sichten, NICHT ungeprueft als Fehlalarm abtun." ;;
        *) log ERROR "test: rkhunter-Scan nicht ausfuehrbar (Exit $rkrc)"; rc=1 ;;
    esac

    exit "$rc"
}

dispatch "$MODULE" "$@"
