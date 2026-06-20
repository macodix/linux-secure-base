#!/bin/bash
#
# Linux Secure Base — Modul lynis (Haertungspruefung)
# Installiert lynis, legt ein Pruefskript unter /usr/local/sbin und einen
# Cron-Eintrag fuer den monatlichen Audit-Lauf an. Der datierte Befund
# unter /var/lib/secure-base/haertung dient als Pruefnachweis.
# Aufruf: lynis.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="lynis"
readonly LYNIS_PACKAGES=(lynis)
readonly PRUEF_SCRIPT="/usr/local/sbin/secure-base-haertungspruefung.sh"
readonly CRON_FILE="/etc/cron.d/secure-base-haertung"
readonly BERICHTE_DIR="/var/lib/secure-base/haertung"

# -------------------------------------------------------------------------
# Soll-Inhalte (idempotent ueber cmp -s geschrieben)
# -------------------------------------------------------------------------

# Inhalt des Pruefskripts. BERICHTE_DIR woertlich, $(date)/$BERICHTE erst
# zur Laufzeit des Skripts — daher hier maskiert.
pruef_script_inhalt() {
    cat <<EOF
#!/bin/bash
# Von secure-base/modules/lynis.sh verwaltet — nicht von Hand bearbeiten.
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

BERICHTE="${BERICHTE_DIR}"
mkdir -p "\$BERICHTE"

lynis audit system --quiet --no-colors \\
    > "\$BERICHTE/lynis-\$(date +%F).txt" 2>&1
cp /var/log/lynis-report.dat "\$BERICHTE/lynis-report-\$(date +%F).dat"
EOF
}

cron_inhalt() {
    cat <<EOF
# Haertungspruefung (lynis) — Zeitplan aus LYNIS_SCHEDULE (secure-base.conf)
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
${LYNIS_SCHEDULE}  root  ${PRUEF_SCRIPT}
EOF
}

# Setzt LYNIS_SCHEDULE auf den Default (falls leer) und validiert ihn:
# genau 5 Cron-Felder, nur erlaubte Zeichen — Schutz vor kaputter crontab.
require_lynis_keys() {
    LYNIS_SCHEDULE="${LYNIS_SCHEDULE:-0 4 1 * *}"
    [[ "$LYNIS_SCHEDULE" =~ ^[0-9*,/[:space:]-]+$ ]] \
        || die "LYNIS_SCHEDULE enthaelt unerlaubte Zeichen: $LYNIS_SCHEDULE"
    [ "$(awk '{print NF}' <<<"$LYNIS_SCHEDULE")" -eq 5 ] \
        || die "LYNIS_SCHEDULE braucht 5 Cron-Felder (Minute Stunde Tag Monat Wochentag): $LYNIS_SCHEDULE"
}

# Schreibt eine Datei idempotent (cmp -s) mit festem Mode/Owner.
# Arguments: $1 — Zielpfad, $2 — Mode (oktal), $3 — Inhalt
schreibe_datei() {
    local ziel=$1 mode=$2 inhalt=$3 tmp
    tmp=$(mktemp)
    printf '%s\n' "$inhalt" >"$tmp"
    if [ -f "$ziel" ] && cmp -s "$tmp" "$ziel"; then
        log INFO "$ziel unveraendert"
        rm -f "$tmp"
        return 0
    fi
    install -m "$mode" -o root -g root "$tmp" "$ziel"
    rm -f "$tmp"
    log INFO "$ziel geschrieben (Mode $mode)"
}

# -------------------------------------------------------------------------
# Subkommandos
# -------------------------------------------------------------------------

do_install() {
    require_root
    load_conf "$SB_CONF"
    require_lynis_keys
    pkg_install "${LYNIS_PACKAGES[@]}"

    log INFO "Berichtsverzeichnis anlegen: $BERICHTE_DIR"
    install -d -m 0750 -o root -g root "$BERICHTE_DIR"

    schreibe_datei "$PRUEF_SCRIPT" 0700 "$(pruef_script_inhalt)"
    schreibe_datei "$CRON_FILE" 0644 "$(cron_inhalt)"
}

do_uninstall() {
    require_root
    log INFO "Cron-Eintrag und Pruefskript entfernen"
    rm -f "$CRON_FILE" "$PRUEF_SCRIPT"
    # Berichte unter $BERICHTE_DIR bleiben als Pruefnachweis erhalten.
    pkg_remove lynis
}

do_check() {
    require_root
    load_conf "$SB_CONF"
    require_lynis_keys
    check_packages "${LYNIS_PACKAGES[@]}" || exit 1

    local exit_code=0
    check_file_mode "$PRUEF_SCRIPT" 700 root:root || exit_code=1
    check_file_mode "$CRON_FILE" 644 root:root || exit_code=1

    # Cron enthaelt den konfigurierten Zeitplan und ruft das Pruefskript auf.
    if [ -f "$CRON_FILE" ] && grep -qF "${LYNIS_SCHEDULE}  root  ${PRUEF_SCRIPT}" "$CRON_FILE"; then
        log INFO "check: Cron-Zeitplan '$LYNIS_SCHEDULE' aktiv, ruft $PRUEF_SCRIPT auf"
    else
        log ERROR "check: Zeitplan/Aufruf in $CRON_FILE stimmt nicht (soll: '$LYNIS_SCHEDULE' -> $PRUEF_SCRIPT)"
        exit_code=1
    fi

    exit "$exit_code"
}

do_test() {
    require_root
    check_packages "${LYNIS_PACKAGES[@]}" || exit 1
    require_cmd lynis

    log INFO "lynis-Version: $(lynis --version 2>/dev/null | head -1)"
    if [ -x "$PRUEF_SCRIPT" ] && bash -n "$PRUEF_SCRIPT" 2>/dev/null; then
        log INFO "lynis self-test: Pruefskript vorhanden, ausfuehrbar, Syntax ok"
    else
        log ERROR "lynis self-test: $PRUEF_SCRIPT fehlt, nicht ausfuehrbar oder Syntaxfehler"
        exit 1
    fi
}

dispatch "$MODULE" "$@"
