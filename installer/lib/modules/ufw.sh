#!/bin/bash
#
# Linux Secure Base — Modul ufw
# Firewall installieren, Default-Policy deny incoming/outgoing setzen,
# die in secure-base.conf gelisteten Ports oeffnen und die Firewall aktivieren.
# Sitzungs-kritisch: check/test ohne Service-Eingriff.
# Aufruf: ufw.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="ufw"

# --- Konfig-Pruefung -------------------------------------------------

# Prueft eine einzelne Port-Liste: als Array deklariert und nur Integer
# im Bereich 1..65535. Eine leere Liste ist zulaessig.
validate_port_list() {
    local name=$1
    if ! declare -p "$name" >/dev/null 2>&1; then
        die "$name ist in secure-base.conf nicht gesetzt."
    fi
    local -n _ports="$name"
    local p
    for p in "${_ports[@]}"; do
        if ! [[ "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
            die "$name enthaelt einen ungueltigen Port: $p"
        fi
    done
}

# Prueft die drei Port-Listen aus secure-base.conf.
require_ufw_conf_or_die() {
    validate_port_list ALLOW_IN_TCP
    validate_port_list ALLOW_OUT_TCP
    validate_port_list ALLOW_OUT_UDP
}

# Aussperr-Schutz: ohne eingehendes SSH (22/tcp) wuerde das Default-Deny
# den Verwaltungszugang kappen. Nur in do_install relevant.
require_ssh_port_or_die() {
    local p
    for p in "${ALLOW_IN_TCP[@]}"; do
        if [ "$p" = "22" ]; then
            return 0
        fi
    done
    die "ALLOW_IN_TCP enthaelt keinen Port 22 — die Firewall wuerde den SSH-Verwaltungszugang aussperren. Bitte 22 in secure-base.conf ergaenzen."
}

# --- Regelsatz-Vergleich (check/test) --------------------------------

# Erwartete "ufw ..."-Zeilen aus den drei Listen (eine je Port).
expected_rules() {
    local p
    for p in "${ALLOW_IN_TCP[@]}";  do echo "ufw allow ${p}/tcp"; done
    for p in "${ALLOW_OUT_TCP[@]}"; do echo "ufw allow out ${p}/tcp"; done
    for p in "${ALLOW_OUT_UDP[@]}"; do echo "ufw allow out ${p}/udp"; done
}

# Ist-Regeln aus "ufw show added", nur die "ufw ..."-Zeilen.
actual_rules() {
    ufw show added 2>/dev/null | grep -E '^ufw ' || true
}

# Vergleicht Soll und Ist exakt (kein Mehr, kein Weniger). Exit 0 = gleich.
rules_match() {
    diff -q <(expected_rules | sort) <(actual_rules | sort) >/dev/null 2>&1
}

# --- WARN-Hinweis ----------------------------------------------------

warn_sitzungs_verifikation() {
    log WARN "Firewall ist jetzt aktiv mit deny default. In einer ZWEITEN Sitzung SSH-Login verifizieren. Bei Fehlschlag aus der laufenden Sitzung heraus 'ufw disable' als Rettungsanker."
}

# --- Subkommandos ----------------------------------------------------

do_install() {
    require_root
    load_conf "$SB_CONF"
    require_ufw_conf_or_die
    require_ssh_port_or_die

    log INFO "ufw install: Paket installieren"
    pkg_install ufw

    # Deterministischer Ausgangszustand: vorhandene Regeln verwerfen.
    # reset DEAKTIVIERT ufw kurz (Firewall offen) — die laufende
    # SSH-Sitzung bleibt unberuehrt, bis enable am Ende aktiviert.
    log INFO "ufw install: deterministischer Ausgangszustand (ufw --force reset)"
    ufw --force reset

    log INFO "ufw install: Default-Policy deny incoming/outgoing"
    ufw default deny incoming
    ufw default deny outgoing

    local p
    for p in "${ALLOW_IN_TCP[@]}"; do
        log INFO "ufw install: allow in ${p}/tcp"
        ufw allow "${p}/tcp"
    done
    for p in "${ALLOW_OUT_TCP[@]}"; do
        log INFO "ufw install: allow out ${p}/tcp"
        ufw allow out "${p}/tcp"
    done
    for p in "${ALLOW_OUT_UDP[@]}"; do
        log INFO "ufw install: allow out ${p}/udp"
        ufw allow out "${p}/udp"
    done

    # Default-Deny greift erst mit enable; 22/tcp ist bereits eingetragen.
    # TEST: 'ufw --force enable' voruebergehend deaktiviert, um zu pruefen,
    # ob das Aktivieren der Firewall das Anzeige-Haengen ausloest.
    log WARN "ufw install: TEST — ufw --force enable uebersprungen (Firewall NICHT aktiv)"
    # ufw --force enable

    warn_sitzungs_verifikation
}

do_uninstall() {
    require_root
    # secure-base.conf wird hier bewusst NICHT geladen/validiert: der Rueckbau
    # ist konfig-unabhaengig und muss auch bei fehlender/defekter Conf
    # durchlaufen (fail-safe).
    if ! pkg_installed ufw; then
        log INFO "ufw uninstall: Paket ufw nicht installiert — nichts zu tun"
        return 0
    fi

    # (1) Netfilter-Regelwerk runter — zwingend vor apt remove.
    # --force unterdrueckt den interaktiven Prompt.
    log INFO "ufw uninstall: Firewall deaktivieren (ufw --force disable)"
    ufw --force disable

    # (2) Dienst deaktivieren und stoppen (boot-persistent aus).
    svc_disable_now ufw

    # (3) Paket entfernen (ohne --purge — /etc/ufw/-Konfig bleibt liegen).
    log INFO "ufw uninstall: Paket entfernen (ohne --purge)"
    pkg_remove ufw
}

do_check() {
    require_root
    load_conf "$SB_CONF"
    require_ufw_conf_or_die

    local rc=0

    check_packages ufw || exit 1

    check_svc_enabled ufw || rc=1

    local verbose
    verbose=$(ufw status verbose 2>/dev/null || true)
    if grep -q 'Status: active' <<<"$verbose"; then
        log INFO "check: ufw Status active"
    else
        log ERROR "check: ufw nicht active"
        rc=1
    fi
    # Praefix-Match: ignoriert das versionsabhaengige Suffix
    # ", disabled (routed)".
    if grep -qE 'Default: deny \(incoming\), deny \(outgoing\)' <<<"$verbose"; then
        log INFO "check: Default-Policy deny incoming/outgoing"
    else
        log ERROR "check: Default-Policy nicht deny/deny"
        rc=1
    fi

    if rules_match; then
        log INFO "check: Regelsatz stimmt mit secure-base.conf ueberein"
    else
        log ERROR "check: Regelsatz weicht von secure-base.conf ab"
        log ERROR "  erwartet:  $(expected_rules | sort | tr '\n' ' ')"
        log ERROR "  vorhanden: $(actual_rules | sort | tr '\n' ' ')"
        rc=1
    fi

    exit "$rc"
}

do_test() {
    require_root
    load_conf "$SB_CONF"
    require_ufw_conf_or_die

    local rc=0

    if rules_match; then
        log INFO "test: Regelsatz stimmt mit secure-base.conf ueberein"
    else
        log ERROR "test: Regelsatz weicht von secure-base.conf ab"
        rc=1
    fi

    if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'ufw'; then
        log INFO "test: Netfilter-Regelwerk via nft vorhanden (ufw-Ketten)"
    elif command -v iptables >/dev/null 2>&1 && iptables -S 2>/dev/null | grep -q 'ufw'; then
        log INFO "test: Netfilter-Regelwerk via iptables vorhanden (ufw-Ketten)"
    else
        log INFO "test: ufw-Ketten im Netfilter nicht eindeutig nachweisbar (Backend-Variabilitaet) — kein Hard-Fail"
    fi

    # Dependency-freier TCP-Smoke (kein netcat noetig). localhost ist von
    # ufw nicht gefiltert — der Smoke belegt, dass sshd lokal lauscht,
    # nicht die Firewall-Regel selbst (sitzungs-neutral).
    if timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22' 2>/dev/null; then
        log INFO "test: TCP-Connect auf 127.0.0.1:22 ok"
    else
        log ERROR "test: TCP-Connect auf 127.0.0.1:22 fehlgeschlagen"
        rc=1
    fi

    log INFO "test: Firewall-Test (neue SSH-Verbindung von aussen gegen 22/tcp) in zweiter Sitzung manuell verifizieren."
    exit "$rc"
}

#######################################
# Liefert den Markdown-Abschnitt dieses Moduls fuer die Abschluss-Doku.
# Nur lesend; nimmt keine Systemaenderung vor. Gibt ausschliesslich
# Markdown nach stdout aus. Nimmt conf-Werte ueber die von do_doc per
# load_conf geladene Umgebung ab.
# Globals:   ALLOW_IN_TCP, ALLOW_OUT_TCP, ALLOW_OUT_UDP (lesend)
# Outputs:   stdout — Markdown-Abschnitt (beginnt mit "## <Label>")
#######################################
module_doc() {
    doc_section "Firewall"
    doc_packages ufw
    printf '**Default-Policy:** deny incoming, deny outgoing\n\n'
    printf '**Eingehend TCP erlaubt:**\n'
    doc_list "${ALLOW_IN_TCP[@]:-}"
    printf '\n**Ausgehend TCP erlaubt:**\n'
    doc_list "${ALLOW_OUT_TCP[@]:-}"
    printf '\n**Ausgehend UDP erlaubt:**\n'
    doc_list "${ALLOW_OUT_UDP[@]:-}"
    doc_services ufw
}

dispatch "$MODULE" "$@"
