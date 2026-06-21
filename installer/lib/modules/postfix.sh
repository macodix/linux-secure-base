#!/bin/bash
#
# Linux Secure Base — Modul postfix
# Postfix als Satellite gegen einen externen SMTP-Smarthost.
# Aufruf: postfix.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="postfix"

readonly MAIN_CF="/etc/postfix/main.cf"
readonly SASL_PASSWD="/etc/postfix/sasl_passwd"
readonly RECIPIENT_CANONICAL="/etc/postfix/recipient_canonical"
readonly ALIASES="/etc/aliases"
readonly POSTFIX_PACKAGES=(postfix mailutils libsasl2-modules ca-certificates)

# Prueft, dass die fuer postfix noetigen Keys in secure-base.conf gesetzt sind.
# RELAY_PASSWORD ist KEIN Pflicht-Key — leer-Wert loest interaktive Eingabe
# aus. FQDN, RELAY_HOST: sanity-Check gegen Newline/Whitespace, damit der
# debconf-Heredoc und der relayhost-Eintrag nicht durch einen Tippfehler in
# der conf zerschossen werden koennen.
require_postfix_keys() {
    [ -n "${FQDN:-}" ]        || die "FQDN nicht gesetzt in secure-base.conf"
    [ -n "${ADMIN_MAIL:-}" ]  || die "ADMIN_MAIL nicht gesetzt in secure-base.conf"
    [ -n "${RELAY_HOST:-}" ]  || die "RELAY_HOST nicht gesetzt in secure-base.conf"
    : "${RELAY_PORT:=587}"  # optional: Default 587 (Submission/STARTTLS)
    [ -n "${RELAY_USER:-}" ]  || die "RELAY_USER nicht gesetzt in secure-base.conf"
    [[ "$FQDN" =~ ^[A-Za-z0-9.-]+$ ]] \
        || die "FQDN enthaelt unerlaubte Zeichen (nur [A-Za-z0-9.-]): $FQDN"
    [[ "$RELAY_HOST" =~ ^[A-Za-z0-9.-]+$ ]] \
        || die "RELAY_HOST enthaelt unerlaubte Zeichen (nur [A-Za-z0-9.-]): $RELAY_HOST"
    [[ "$RELAY_PORT" =~ ^[0-9]+$ ]] \
        || die "RELAY_PORT muss numerisch sein: $RELAY_PORT"
}

do_install() {
    # 1. Voraussetzungen pruefen.
    require_root
    require_cmd debconf-set-selections
    require_cmd apt-get
    load_conf "$SB_CONF"
    require_postfix_keys

    # 2. debconf-Antworten vor apt install setzen.
    log INFO "debconf-Antworten setzen (Satellite, mailname=$FQDN, relayhost leer)"
    debconf-set-selections <<EOF
postfix postfix/main_mailer_type select Satellite system
postfix postfix/mailname        string $FQDN
postfix postfix/relayhost       string
EOF

    # 3. Pakete installieren.
    pkg_install "${POSTFIX_PACKAGES[@]}"

    # Ab hier sind postmap/newaliases/postconf garantiert vorhanden.
    require_cmd postmap
    require_cmd newaliases
    require_cmd postconf

    # 4. main.cf patchen.
    log INFO "main.cf: relayhost und Smarthost-Direktiven setzen"
    ensure_setting "$MAIN_CF" "relayhost"                      "[$RELAY_HOST]:$RELAY_PORT"                  " = "
    ensure_setting "$MAIN_CF" "smtp_sasl_auth_enable"          "yes"                                        " = "
    ensure_setting "$MAIN_CF" "smtp_sasl_password_maps"        "hash:/etc/postfix/sasl_passwd"              " = "
    ensure_setting "$MAIN_CF" "smtp_sasl_security_options"     "noanonymous"                                " = "
    ensure_setting "$MAIN_CF" "smtp_sasl_tls_security_options" "noanonymous"                                " = "
    ensure_setting "$MAIN_CF" "smtp_tls_security_level"        "encrypt"                                    " = "
    ensure_setting "$MAIN_CF" "smtp_tls_CAfile"                "/etc/ssl/certs/ca-certificates.crt"         " = "
    ensure_setting "$MAIN_CF" "smtp_tls_loglevel"              "1"                                          " = "
    ensure_setting "$MAIN_CF" "inet_interfaces"                "loopback-only"                              " = "
    # Postfix-Variablen $myhostname/$mydomain woertlich in die Datei —
    # single-quoted String verhindert Bash-Expansion (gewollt).
    # shellcheck disable=SC2016
    ensure_setting "$MAIN_CF" "mydestination"                  '$myhostname, localhost.$mydomain, localhost' " = "
    ensure_setting "$MAIN_CF" "recipient_canonical_maps"       "regexp:/etc/postfix/recipient_canonical"    " = "

    # 5. sasl_passwd schreiben und einlesen.
    #    Passwort-Hygiene: relay_password darf NIE per log/printf/echo
    #    ausgegeben werden — read -s-Prompt nur Aufforderungstext, kein
    #    Echo der Eingabe ins Logfile.
    # RELAY_PASSWORD wird per load_conf aus secure-base.conf gesourct;
    # statisch nicht erkennbar, daher SC2153 unterdruecken.
    # shellcheck disable=SC2153
    local relay_password="${RELAY_PASSWORD:-}"
    if [ -z "$relay_password" ]; then
        log INFO "RELAY_PASSWORD leer — interaktive Eingabe (kein Echo)"
        read -r -s -p "SMTP-Passwort fuer $RELAY_USER@$RELAY_HOST: " relay_password
        echo
        [ -n "$relay_password" ] || die "Kein Passwort eingegeben — Abbruch."
    fi
    log INFO "sasl_passwd schreiben (install -m 0600 + printf)"
    install -m 0600 /dev/null "$SASL_PASSWD"
    printf '[%s]:%s %s:%s\n' \
        "$RELAY_HOST" "$RELAY_PORT" "$RELAY_USER" "$relay_password" \
        > "$SASL_PASSWD"
    postmap "$SASL_PASSWD"
    chmod 600 "${SASL_PASSWD}.db"
    unset relay_password

    # 6. recipient_canonical schreiben.
    log INFO "recipient_canonical schreiben (Ziel: $ADMIN_MAIL)"
    printf '/.+/   %s\n' "$ADMIN_MAIL" > "$RECIPIENT_CANONICAL"
    chmod 644 "$RECIPIENT_CANONICAL"
    postmap "$RECIPIENT_CANONICAL"

    # 7. /etc/aliases patchen.
    log INFO "/etc/aliases: aliases-root-Block setzen"
    ensure_block "$ALIASES" "aliases-root" "$(cat <<EOF
postmaster: root
root:       $ADMIN_MAIL
EOF
)"
    newaliases

    # 8. Dienst aktivieren und main.cf neu einlesen.
    svc_enable_now postfix
    log INFO "postfix reload (main.cf und Maps aktivieren)"
    systemctl reload postfix
}

do_uninstall() {
    require_root
    load_conf "$SB_CONF"
    # ADMIN_MAIL wird hier nicht zwingend gebraucht — Pflicht-Key-Pruefung
    # entfaellt deshalb. main.cf-Eingriffe haben das Marker-Schema;
    # remove_setting findet sie ohne Konfig-Werte.

    svc_disable_now postfix

    log INFO "Eigene Dateien entfernen"
    rm -f "$SASL_PASSWD" "${SASL_PASSWD}.db"
    rm -f "$RECIPIENT_CANONICAL" "${RECIPIENT_CANONICAL}.db"

    log INFO "main.cf-Eingriffe zuruecknehmen"
    remove_setting "$MAIN_CF" "relayhost"
    remove_setting "$MAIN_CF" "smtp_sasl_auth_enable"
    remove_setting "$MAIN_CF" "smtp_sasl_password_maps"
    remove_setting "$MAIN_CF" "smtp_sasl_security_options"
    remove_setting "$MAIN_CF" "smtp_sasl_tls_security_options"
    remove_setting "$MAIN_CF" "smtp_tls_security_level"
    remove_setting "$MAIN_CF" "smtp_tls_CAfile"
    remove_setting "$MAIN_CF" "smtp_tls_loglevel"
    remove_setting "$MAIN_CF" "inet_interfaces"
    remove_setting "$MAIN_CF" "mydestination"
    remove_setting "$MAIN_CF" "recipient_canonical_maps"

    log INFO "/etc/aliases: aliases-root-Block entfernen"
    remove_block "$ALIASES" "aliases-root"
    newaliases

    pkg_remove postfix mailutils libsasl2-modules
    # ca-certificates bleibt installiert (Distro-Basis).
}

do_check() {
    require_root
    require_cmd postconf
    load_conf "$SB_CONF"
    require_postfix_keys

    local exit_code=0

    # Pakete.
    check_packages "${POSTFIX_PACKAGES[@]}" || exit_code=1

    # Dienst.
    check_svc_enabled postfix || exit_code=1

    # main.cf-Direktiven via postconf -n.
    local key value soll
    # mydestination enthaelt Postfix-Variablen $myhostname/$mydomain
    # woertlich (gewollt, kein Bash-Expand).
    # shellcheck disable=SC2016
    declare -A SOLL=(
        [relayhost]="[$RELAY_HOST]:$RELAY_PORT"
        [smtp_sasl_auth_enable]="yes"
        [smtp_sasl_password_maps]="hash:/etc/postfix/sasl_passwd"
        [smtp_sasl_security_options]="noanonymous"
        [smtp_sasl_tls_security_options]="noanonymous"
        [smtp_tls_security_level]="encrypt"
        [smtp_tls_CAfile]="/etc/ssl/certs/ca-certificates.crt"
        [smtp_tls_loglevel]="1"
        [inet_interfaces]="loopback-only"
        [mydestination]='$myhostname, localhost.$mydomain, localhost'
        [recipient_canonical_maps]="regexp:/etc/postfix/recipient_canonical"
    )
    for key in "${!SOLL[@]}"; do
        soll="${SOLL[$key]}"
        value=$(postconf -nh "$key" 2>/dev/null || true)
        if [ "$value" = "$soll" ]; then
            log INFO "main.cf $key OK"
        else
            log ERROR "main.cf $key-Mismatch: ist '$value', soll '$soll'"
            exit_code=1
        fi
    done

    # Eigene Dateien.
    check_file_mode "$SASL_PASSWD" 600 "root:root" || exit_code=1
    if [ -f "$RECIPIENT_CANONICAL" ]; then
        log INFO "$RECIPIENT_CANONICAL OK"
    else
        log ERROR "$RECIPIENT_CANONICAL fehlt"
        exit_code=1
    fi

    # /etc/aliases-Block.
    if grep -q '# secure-base:aliases-root:begin' "$ALIASES" \
       && grep -q '# secure-base:aliases-root:end' "$ALIASES"; then
        log INFO "/etc/aliases aliases-root-Block OK"
    else
        log ERROR "/etc/aliases aliases-root-Block fehlt"
        exit_code=1
    fi

    if [ "$exit_code" = 0 ]; then
        log INFO "postfix: alle Sollwerte stimmen"
    fi
    exit "$exit_code"
}

do_test() {
    require_root
    require_cmd mail
    require_cmd mailq
    load_conf "$SB_CONF"
    # do_test braucht nur ADMIN_MAIL — die RELAY_*-Keys sind nur fuer install
    # relevant; zur Testzeit nimmt postfix die in main.cf geschriebenen Werte.
    [ -n "${ADMIN_MAIL:-}" ] || die "ADMIN_MAIL nicht gesetzt in secure-base.conf"

    log INFO "Test-Mail an $ADMIN_MAIL absetzen"
    echo "secure-base postfix self-test ($(date --iso-8601=seconds))" \
        | mail -s "secure-base postfix self-test" "$ADMIN_MAIL"

    sleep 2
    local queue
    queue=$(mailq | head -5)
    if [ "$queue" = "Mail queue is empty" ]; then
        log INFO "postfix self-test: Mail abgesetzt, Queue leer."
    else
        log WARN "postfix self-test: Mail-Queue nicht leer nach 2 s (erste 5 Zeilen):"
        log WARN "$queue"
    fi
}

#######################################
# Liefert den Markdown-Abschnitt dieses Moduls fuer die Abschluss-Doku.
# Nur lesend; nimmt keine Systemaenderung vor. Gibt ausschliesslich
# Markdown nach stdout aus. Nimmt conf-Werte ueber die von do_doc per
# load_conf geladene Umgebung ab.
# Globals:   POSTFIX_PACKAGES, MAIN_CF, ALIASES (lesend, via doc_val)
# Outputs:   stdout — Markdown-Abschnitt (beginnt mit "## <Label>")
#######################################
module_doc() {
    doc_section "Mail-Versand"
    doc_packages "${POSTFIX_PACKAGES[@]}"
    doc_files_begin
    doc_file "$MAIN_CF" \
        "relayhost = [$(doc_val RELAY_HOST)]:$(doc_val RELAY_PORT)" \
        "smtp_tls_security_level = encrypt" \
        "inet_interfaces = loopback-only"
    doc_file "$ALIASES" "root: $(doc_val ADMIN_MAIL)"
    doc_services postfix
    doc_note "SMTP-Passwort wird nicht dokumentiert (Secret)."
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
