#!/bin/bash
#
# Linux Secure Base — Modul fail2ban
# Brute-Force-Schutz: Paket installieren, /etc/fail2ban/jail.local als
# Kopie der jail.conf anlegen (schuetzt Konfig gegen Ueberschreiben bei
# Updates), optionale ignoreip-Whitelist setzen, Dienst aktivieren und
# starten. Der sshd-Jail ist in der Standardkonfiguration aktiv.
# Nicht sitzungs-kritisch; check/test sind lesend.
# Aufruf: fail2ban.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="fail2ban"
readonly CONF_COMMON="$SCRIPT_DIR/conf/common.conf"

readonly JAIL_CONF="/etc/fail2ban/jail.conf"
readonly JAIL_LOCAL="/etc/fail2ban/jail.local"
# Loopback-Defaults, die im ignoreip-Wert immer erhalten bleiben.
readonly IGNOREIP_LOOPBACK="127.0.0.1/8 ::1"

# --- Konfig-Pruefung -------------------------------------------------

# Grobe Plausibilitaet jedes IGNOREIP-Tokens (IPv4/IPv6/CIDR). Leer ist ok;
# die endgueltige Akzeptanz prueft fail2ban beim Laden.
validate_ignoreip() {
    local val=${IGNOREIP:-}
    [ -n "$val" ] || return 0
    local -a toks
    read -ra toks <<<"$val"
    local tok
    for tok in "${toks[@]}"; do
        # Erlaubt: Hex/Doppelpunkt (IPv6), Ziffern/Punkt (IPv4), optional /CIDR.
        if ! [[ "$tok" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]]; then
            die "IGNOREIP enthaelt einen unplausiblen Eintrag: '$tok' (erwartet IPv4/IPv6/CIDR)."
        fi
    done
}

# Effektiver ignoreip-Wert: Loopback-Defaults plus IGNOREIP-Eintraege.
effective_ignoreip() {
    printf '%s %s' "$IGNOREIP_LOOPBACK" "${IGNOREIP:-}"
}

# Maskiert ERE-Metazeichen, damit ein Wert woertlich in ein grep -E-Muster
# (file_has_line) eingesetzt werden kann.
ere_escape() {
    printf '%s' "$1" | sed 's/[^a-zA-Z0-9_@-]/\\&/g'
}

# Prueft, dass der laufende sshd-Jail jeden IGNOREIP-Eintrag geladen hat.
# Rueckgabe 0 = alle geladen, 1 = mindestens einer fehlt; gibt den fehlenden
# Token ueber stdout zurueck. Nur bei nicht-leerem IGNOREIP aufrufen.
ignoreip_missing_token() {
    local loaded
    loaded=$(fail2ban-client get sshd ignoreip 2>/dev/null || true)
    local -a toks
    read -ra toks <<<"${IGNOREIP:-}"
    local tok
    for tok in "${toks[@]}"; do
        if ! grep -qF -- "$tok" <<<"$loaded"; then
            printf '%s' "$tok"
            return 1
        fi
    done
    return 0
}

# --- Subkommandos ----------------------------------------------------

do_install() {
    require_root
    load_conf "$CONF_COMMON"
    validate_ignoreip

    log INFO "fail2ban install: Paket installieren"
    pkg_install fail2ban

    # jail.local aus jail.conf anlegen (kein Clobber einer eventuell
    # hand-getunten jail.local).
    if [ -e "$JAIL_LOCAL" ]; then
        log INFO "fail2ban install: $JAIL_LOCAL bereits vorhanden — Kopie uebersprungen (hand-getunte jail.local wird NICHT ueberschrieben)"
    else
        log INFO "fail2ban install: $JAIL_LOCAL aus $JAIL_CONF anlegen (schuetzt Konfig gegen Ueberschreiben bei Paket-Updates)"
        cp "$JAIL_CONF" "$JAIL_LOCAL"
    fi

    # Optionale ignoreip-Whitelist setzen (Loopback-Defaults bleiben drin).
    if [ -n "${IGNOREIP:-}" ]; then
        local ign
        ign=$(effective_ignoreip)
        log INFO "fail2ban install: ignoreip-Whitelist setzen (Loopback-Defaults + IGNOREIP)"
        ensure_setting "$JAIL_LOCAL" ignoreip "$ign" " = "
    else
        log INFO "fail2ban install: IGNOREIP leer — keine ignoreip-Anpassung, es gilt der jail.local-Default"
    fi

    log INFO "fail2ban install: Dienst aktivieren und starten"
    svc_enable_now fail2ban

    # Aktiver Lade-Nachweis: hat der laufende sshd-Jail die Eintraege
    # wirklich uebernommen?
    if [ -n "${IGNOREIP:-}" ]; then
        local missing
        if ! missing=$(ignoreip_missing_token); then
            die "fail2ban install: IGNOREIP-Eintrag '$missing' wurde vom sshd-Jail NICHT geladen. jail.local und IGNOREIP-Wert pruefen."
        fi
        log INFO "fail2ban install: ignoreip-Eintraege vom sshd-Jail bestaetigt geladen"
    fi

    # Aussperr-Hinweis.
    if [ -z "${IGNOREIP:-}" ]; then
        log WARN "fail2ban aktiv OHNE IGNOREIP-Whitelist: der sshd-Jail kann die eigene Admin-IP nach wiederholten Fehl-Logins temporaer bannen (Default: bantime 10m, maxretry 5). DRINGEND empfohlen: vor dem Scharfschalten — besonders ohne erreichbare Out-of-Band-/Provider-Konsole — die eigene Management-IP via IGNOREIP in common.conf eintragen. Rettungswege bei Selbst-Bann: in einer noch offenen Sitzung 'fail2ban-client set sshd unbanip <IP>', andernfalls Out-of-Band-/Provider-Konsole."
    else
        log INFO "fail2ban aktiv mit IGNOREIP-Whitelist — Admin-IP vom Bannen ausgenommen."
    fi
}

do_uninstall() {
    require_root
    # common.conf wird bewusst NICHT geladen: der Rueckbau ist
    # konfig-unabhaengig und muss auch bei fehlender/defekter Conf
    # durchlaufen (fail-safe).
    if ! pkg_installed fail2ban; then
        log INFO "fail2ban uninstall: Paket fail2ban nicht installiert — nichts zu tun"
        return 0
    fi

    # (1) Dienst stoppen und deaktivieren — zwingend vor apt remove.
    svc_disable_now fail2ban

    # (2) Eigene Konfig-Eingriffe zuruecknehmen: die ignoreip-Direktive in
    # jail.local. Die Datei jail.local selbst BLEIBT erhalten.
    if [ -e "$JAIL_LOCAL" ]; then
        log INFO "fail2ban uninstall: ignoreip-Eingriff in $JAIL_LOCAL zuruecknehmen (Datei bleibt erhalten)"
        remove_setting "$JAIL_LOCAL" ignoreip
    fi

    # (3) Paket entfernen (ohne --purge — /var/lib/fail2ban/fail2ban.sqlite3
    # und die Konfig bleiben liegen).
    log INFO "fail2ban uninstall: Paket entfernen (ohne --purge)"
    pkg_remove fail2ban
}

do_check() {
    require_root
    load_conf "$CONF_COMMON"
    validate_ignoreip

    local rc=0

    if pkg_installed fail2ban; then
        log INFO "check: Paket fail2ban installiert"
    else
        log ERROR "check: Paket fail2ban nicht installiert — Soll-Zustand nicht erfuellt"
        exit 1
    fi

    check_svc_enabled fail2ban || rc=1

    if [ -e "$JAIL_LOCAL" ]; then
        log INFO "check: $JAIL_LOCAL vorhanden"
    else
        log ERROR "check: $JAIL_LOCAL fehlt"
        rc=1
    fi

    # Pruefpunkt 5: nur bei nicht-leerem IGNOREIP.
    if [ -n "${IGNOREIP:-}" ]; then
        # 5a (Datei): aktive ignoreip-Zeile enthaelt den effektiven Wert.
        local ign ign_re
        ign=$(effective_ignoreip)
        ign_re=$(ere_escape "$ign")
        if file_has_line "$JAIL_LOCAL" "^ignoreip = ${ign_re}$"; then
            log INFO "check: ignoreip-Zeile in $JAIL_LOCAL gesetzt"
        else
            log ERROR "check: ignoreip-Zeile in $JAIL_LOCAL nicht auf effektiven Wert ($ign)"
            rc=1
        fi
        # 5b (Live): laufender sshd-Jail hat die Eintraege geladen.
        local missing
        if missing=$(ignoreip_missing_token); then
            log INFO "check: ignoreip-Eintraege im laufenden sshd-Jail geladen"
        else
            log ERROR "check: IGNOREIP-Eintrag '$missing' nicht im laufenden sshd-Jail geladen"
            rc=1
        fi
    fi

    # Pruefpunkt 6: sshd-Jail laeuft.
    if fail2ban-client status sshd >/dev/null 2>&1; then
        log INFO "check: sshd-Jail laeuft"
    else
        log ERROR "check: sshd-Jail nicht abfragbar (fail2ban-client status sshd)"
        rc=1
    fi

    exit "$rc"
}

do_test() {
    require_root
    load_conf "$CONF_COMMON"
    validate_ignoreip

    local rc=0

    if ! pkg_installed fail2ban; then
        log ERROR "test: Paket fail2ban nicht installiert — kein Funktionstest moeglich"
        exit 1
    fi

    # Daemon-Ping (Hard-Check).
    if fail2ban-client ping 2>&1 | grep -q 'pong'; then
        log INFO "test: fail2ban-Daemon antwortet (pong)"
    else
        log ERROR "test: fail2ban-Daemon antwortet nicht auf ping"
        rc=1
    fi

    # sshd-Jail-Status — Ausgabe zeilenweise ins Log.
    local out jrc=0
    out=$(fail2ban-client status sshd 2>&1) || jrc=$?
    if [ "$jrc" -eq 0 ]; then
        local line
        while IFS= read -r line; do
            log INFO "fail2ban sshd: $line"
        done <<<"$out"
    else
        log ERROR "test: sshd-Jail nicht abfragbar (fail2ban-client status sshd Exit $jrc)"
        rc=1
    fi

    exit "$rc"
}

dispatch "$MODULE" "$@"
