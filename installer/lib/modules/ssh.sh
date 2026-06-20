#!/bin/bash
#
# Linux Secure Base — Modul ssh
# Haertung von /etc/ssh/sshd_config, TOTP-PAM-Integration in
# /etc/pam.d/sshd (Bypass-Schutz gegen @include common-auth),
# Login-Mail-Hook (/etc/ssh/login-mail-notification.sh via pam_exec).
# Das Paket openssh-server gilt als System-Infrastruktur und wird vom
# Modul weder installiert noch entfernt.
# Aufruf: ssh.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="ssh"

readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly PAM_SSHD="/etc/pam.d/sshd"
readonly LOGIN_MAIL_SCRIPT="/etc/ssh/login-mail-notification.sh"

# -------------------------------------------------------------------------
# Eingangs-Validierung
# -------------------------------------------------------------------------

#######################################
# Prueft die aus secure-base.conf gelesenen Pflicht-Keys:
#   MAIN_USER  — nicht leer, POSIX-Login-Format, nicht Systembenutzer
#   ADMIN_MAIL — nicht leer, enthaelt '@'
#   FQDN       — nicht leer, enthaelt Punkt
# Globals:   MAIN_USER, ADMIN_MAIL, FQDN
#######################################
require_common_keys_or_die() {
    [ -n "${MAIN_USER:-}" ] \
        || die "MAIN_USER ist leer — bitte in secure-base.conf setzen."
    [[ "$MAIN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] \
        || die "MAIN_USER enthaelt unzulaessige Zeichen: $MAIN_USER"
    case "$MAIN_USER" in
        root | daemon | bin | sys | sync | games | man | lp | mail | news \
            | uucp | proxy | www-data | backup | list | irc | nobody \
            | messagebus | sshd)
            die "MAIN_USER darf kein Systembenutzer sein: $MAIN_USER"
            ;;
        systemd-*)
            die "MAIN_USER darf kein systemd-Systembenutzer sein: $MAIN_USER"
            ;;
    esac
    [ -n "${ADMIN_MAIL:-}" ] \
        || die "ADMIN_MAIL ist leer — bitte in secure-base.conf setzen."
    [[ "$ADMIN_MAIL" == *"@"* ]] \
        || die "ADMIN_MAIL ist kein Mail-Format: $ADMIN_MAIL"
    [ -n "${FQDN:-}" ] \
        || die "FQDN ist leer — bitte in secure-base.conf setzen."
    [[ "$FQDN" == *.* ]] \
        || die "FQDN ist kein voller FQDN (kein Punkt): $FQDN"
}

#######################################
# Aussperr-Schutz: verifiziert Login-Voraussetzungen des users-Moduls,
# BEVOR die Haertung greift. Filtert grobe Fehlbedienung (users-Modul
# vergessen), ersetzt aber nicht die manuelle Zweitsitzungs-Probe.
# Globals:   MAIN_USER
#######################################
require_user_login_artifacts_or_die() {
    local home authkeys ga
    getent passwd "$MAIN_USER" >/dev/null \
        || die "Benutzer $MAIN_USER existiert nicht — users-Modul vorab laufen lassen."
    id -nG "$MAIN_USER" | tr ' ' '\n' | grep -qx ssh-users \
        || die "$MAIN_USER ist nicht Mitglied der Gruppe ssh-users — users-Modul vorab laufen lassen."
    home="$(getent passwd "$MAIN_USER" | cut -d: -f6)"
    authkeys="$home/.ssh/authorized_keys"
    ga="$home/.google_authenticator"
    [ -s "$authkeys" ] \
        || die "$authkeys fehlt oder ist leer — Aussperr-Risiko, users-Modul vorab laufen lassen."
    [ -s "$ga" ] \
        || die "$ga fehlt oder ist leer — TOTP-Login nicht moeglich, users-Modul vorab laufen lassen."
}

#######################################
# Prueft Basis-Pakete. Das ssh-Modul installiert sie nicht selbst:
# openssh-server ist System-Infrastruktur,
# libpam-google-authenticator liefert das users-Modul.
#######################################
require_packages_or_die() {
    pkg_installed openssh-server \
        || die "Paket openssh-server fehlt — Basis-Infrastruktur, bitte vorab installieren."
    pkg_installed libpam-google-authenticator \
        || die "Paket libpam-google-authenticator fehlt — users-Modul vorab laufen lassen."
}

# -------------------------------------------------------------------------
# Helfer
# -------------------------------------------------------------------------

#######################################
# Prueft Datei/Verzeichnis auf exakten Mode und Owner.
# Bei Abweichung ERROR-Log und Rueckgabewert 1.
# Arguments: $1 — Pfad, $2 — Soll-Mode (oktal), $3 — Soll-Owner (user:group)
# Returns:   0 OK, 1 Abweichung
#######################################
check_mode_owner() {
    local path="$1" mode_soll="$2" owner_soll="$3"
    local mode owner
    mode="$(stat -c '%a' "$path")"
    owner="$(stat -c '%U:%G' "$path")"
    if [ "$mode" != "$mode_soll" ]; then
        log ERROR "$path: Mode $mode, erwartet $mode_soll"
        return 1
    fi
    if [ "$owner" != "$owner_soll" ]; then
        log ERROR "$path: Owner $owner, erwartet $owner_soll"
        return 1
    fi
}

#######################################
# Prueft, ob SSH aktiv und beim Boot aktiviert ist — unabhaengig vom
# Aktivierungsmodell (Service- oder Socket-Activation).
# Returns:   0 OK, 1 Fehler
#######################################
check_ssh_enabled_active() {
    local unit
    for unit in ssh.service ssh.socket; do
        if [ "$(systemctl is-active "$unit" 2>/dev/null)" = "active" ]; then
            break
        fi
        if [ "$unit" = "ssh.socket" ]; then
            log ERROR "Weder ssh.service noch ssh.socket ist active"
            return 1
        fi
    done
    for unit in ssh.service ssh.socket; do
        if [ "$(systemctl is-enabled "$unit" 2>/dev/null)" = "enabled" ]; then
            return 0
        fi
    done
    log ERROR "Weder ssh.service noch ssh.socket ist enabled (beim Boot aktiviert)"
    return 1
}

#######################################
# Vergleicht einen sshd -T-Wert (case-insensitive) gegen den Sollwert.
# Arguments: $1 — Schluessel (kleingeschrieben), $2 — Sollwert
# Returns:   0 OK, 1 Mismatch
#######################################
check_sshd_t() {
    local key_lc="$1" soll_lc="$2"
    local ist
    ist=$(sshd -T 2>/dev/null | awk -v k="$key_lc" '$1 == k { $1=""; sub(/^ /, ""); print; exit }')
    if [ "$ist" != "$soll_lc" ]; then
        log ERROR "sshd -T $key_lc=$ist, erwartet $soll_lc"
        return 1
    fi
}

#######################################
# Schreibt /etc/ssh/login-mail-notification.sh.
# Wird ueber pam_exec (session-Zeile in /etc/pam.d/sshd) als root
# aufgerufen. Idempotent ueber cmp -s.
# Globals:   ADMIN_MAIL, LOGIN_MAIL_SCRIPT
#######################################
write_login_mail_script() {
    local tmp
    tmp=$(mktemp "${LOGIN_MAIL_SCRIPT}.XXXXXX")
    cat >"$tmp" <<EOF
#!/bin/sh
# Von secure-base/modules/ssh.sh verwaltet — nicht von Hand bearbeiten.
# Aufruf ueber pam_exec (session open_session) als root.
if [ "\$PAM_TYPE" = "open_session" ]; then
    ADMINMAIL="${ADMIN_MAIL}"
    TEXT="SSH-Login auf dem Server: \$(hostname -f) \\nBenutzer: \$PAM_USER \\nZeitpunkt: \$(date) \\nClient-IP: \$PAM_RHOST"
    echo -e "\$TEXT" | mail -s "SSH Login Info: \$PAM_USER" "\$ADMINMAIL"
fi
EOF
    if [ -f "$LOGIN_MAIL_SCRIPT" ] && cmp -s "$tmp" "$LOGIN_MAIL_SCRIPT"; then
        rm -f "$tmp"
        log INFO "$LOGIN_MAIL_SCRIPT unveraendert"
        return 0
    fi
    install -m 0700 -o root -g root "$tmp" "$LOGIN_MAIL_SCRIPT"
    rm -f "$tmp"
    log INFO "$LOGIN_MAIL_SCRIPT geschrieben"
}

#######################################
# Sicherheitshinweis am Ende von do_install: Zweitsitzungs-Verifikation.
#######################################
warn_sitzungs_verifikation() {
    log WARN "Vor dem Trennen dieser SSH-Sitzung in einer ZWEITEN Sitzung den Login (Public-Key + TOTP) verifizieren. Sonst Gefahr, sich auszusperren."
}

# -------------------------------------------------------------------------
# Subkommandos
# -------------------------------------------------------------------------

do_install() {
    require_root
    load_conf "$SB_CONF"
    require_common_keys_or_die
    require_packages_or_die
    require_user_login_artifacts_or_die

    log INFO "sshd_config haerten: $SSHD_CONFIG"
    ensure_setting "$SSHD_CONFIG" PermitRootLogin no
    ensure_setting "$SSHD_CONFIG" PasswordAuthentication no
    ensure_setting "$SSHD_CONFIG" PubkeyAuthentication yes
    ensure_setting "$SSHD_CONFIG" AllowGroups ssh-users
    ensure_setting "$SSHD_CONFIG" UsePAM yes
    ensure_setting "$SSHD_CONFIG" KbdInteractiveAuthentication yes
    ensure_setting "$SSHD_CONFIG" AuthenticationMethods "publickey,keyboard-interactive"

    # ChallengeResponseAuthentication: deprecated-Alias. Bei yes setzen
    # (Backward-Compat), bei no aktiv entfernen — deterministisch, idempotent.
    if [ "${ENABLE_CHALLENGE_RESPONSE_AUTH:-yes}" = "yes" ]; then
        ensure_setting "$SSHD_CONFIG" ChallengeResponseAuthentication yes
    else
        remove_setting "$SSHD_CONFIG" ChallengeResponseAuthentication
    fi

    log INFO "PAM-Bypass-Schutz: @include common-auth deaktivieren ($PAM_SSHD)"
    ensure_line_commented "$PAM_SSHD" include-common-auth '@include common-auth'
    # Aufrufer-Verifikation: Fall C (Zielzeile nicht gefunden) ist kein
    # sicherer Erfolgsindikator — Distro-Drift wuerde sonst still scheitern.
    if grep -qE '^[[:space:]]*@include[[:space:]]+common-auth' "$PAM_SSHD"; then
        die "PAM-Bypass-Sperre fehlgeschlagen: @include common-auth ist noch aktiv (Distro-Drift? Bitte $PAM_SSHD manuell pruefen)"
    fi

    log INFO "PAM-TOTP-Eintrag anhaengen: pam_google_authenticator.so"
    ensure_block "$PAM_SSHD" pam-google-authenticator \
        "# Google Authenticator
auth required pam_google_authenticator.so"

    if [ "${ENABLE_LOGIN_MAIL:-yes}" != "no" ]; then
        log INFO "Login-Mail-Hook einrichten (ENABLE_LOGIN_MAIL=yes)"
        write_login_mail_script
        # Hook ueber pam_exec als root (nicht sshrc — das liefe als
        # einloggender User und scheiterte an Mode 0700 root:root).
        ensure_block "$PAM_SSHD" login-mail-notification \
            "# secure-base Login-Mail-Benachrichtigung
session optional pam_exec.so seteuid $LOGIN_MAIL_SCRIPT"
    else
        log INFO "Login-Mail-Hook uebersprungen (ENABLE_LOGIN_MAIL=no)"
    fi

    # sshd -t MUSS Exit 0 liefern; sonst kein reload — Daemon laeuft mit
    # alter Konfig weiter. reload statt restart: laufende Sitzungen erhalten.
    if ! sshd -t; then
        die "sshd -t-Fehler — bitte Logfile pruefen, KEIN reload ausgeloest."
    fi
    systemctl reload ssh
    log INFO "sshd-Konfig validiert und neu geladen (reload, kein restart)"

    warn_sitzungs_verifikation
}

do_uninstall() {
    require_root
    load_conf "$SB_CONF"
    # ssh.conf wird nicht geladen — uninstall raeumt bedingungslos auf,
    # damit kein halb angeschaltetes Stadium zurueckbleibt.
    require_common_keys_or_die

    remove_block "$PAM_SSHD" login-mail-notification
    if [ -e "$LOGIN_MAIL_SCRIPT" ]; then
        rm -f "$LOGIN_MAIL_SCRIPT"
        log INFO "$LOGIN_MAIL_SCRIPT entfernt"
    fi

    # sshd_config-Eingriffe in umgekehrter Reihenfolge zuruecknehmen
    remove_setting "$SSHD_CONFIG" ChallengeResponseAuthentication
    remove_setting "$SSHD_CONFIG" AuthenticationMethods
    remove_setting "$SSHD_CONFIG" KbdInteractiveAuthentication
    remove_setting "$SSHD_CONFIG" UsePAM
    remove_setting "$SSHD_CONFIG" AllowGroups
    remove_setting "$SSHD_CONFIG" PubkeyAuthentication
    remove_setting "$SSHD_CONFIG" PasswordAuthentication
    remove_setting "$SSHD_CONFIG" PermitRootLogin

    remove_block "$PAM_SSHD" pam-google-authenticator
    remove_line_commented "$PAM_SSHD" include-common-auth

    if ! sshd -t; then
        die "sshd -t-Fehler nach Rueckbau — Konfig manuell pruefen, KEIN reload ausgeloest."
    fi
    systemctl reload ssh
    log INFO "sshd-Konfig nach Rueckbau validiert und neu geladen"

    log INFO "Paket openssh-server bleibt installiert (Basis-Infrastruktur)"
    log INFO "Paket libpam-google-authenticator bleibt installiert (users-Modul-Bedarf)"
}

do_check() {
    require_root
    load_conf "$SB_CONF"
    require_common_keys_or_die

    local rc=0
    local home authkeys ga

    if ! pkg_installed openssh-server; then
        log ERROR "Paket openssh-server ist nicht installiert"
        rc=1
    fi
    if ! pkg_installed libpam-google-authenticator; then
        log ERROR "Paket libpam-google-authenticator ist nicht installiert"
        rc=1
    fi

    check_ssh_enabled_active || rc=1

    if ! getent group ssh-users >/dev/null; then
        log ERROR "Gruppe ssh-users existiert nicht"
        rc=1
    fi
    if ! id -nG "$MAIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx ssh-users; then
        log ERROR "$MAIN_USER ist nicht Mitglied der Gruppe ssh-users"
        rc=1
    fi

    # challengeresponseauthentication wird nicht geprueft — sshd -T fuehrt
    # den Wert je nach Version als Alias oder gar nicht auf.
    check_sshd_t permitrootlogin no || rc=1
    check_sshd_t passwordauthentication no || rc=1
    check_sshd_t pubkeyauthentication yes || rc=1
    check_sshd_t kbdinteractiveauthentication yes || rc=1
    check_sshd_t usepam yes || rc=1
    check_sshd_t authenticationmethods publickey,keyboard-interactive || rc=1
    check_sshd_t allowgroups ssh-users || rc=1

    if ! grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_google_authenticator\.so' "$PAM_SSHD"; then
        log ERROR "$PAM_SSHD enthaelt keinen aktiven pam_google_authenticator.so-Eintrag"
        rc=1
    fi
    if grep -qE '^[[:space:]]*@include[[:space:]]+common-auth' "$PAM_SSHD"; then
        log ERROR "$PAM_SSHD hat noch eine aktive @include common-auth-Zeile (TOTP-Bypass-Risiko)"
        rc=1
    fi

    if [ "${ENABLE_LOGIN_MAIL:-yes}" != "no" ]; then
        if [ ! -f "$LOGIN_MAIL_SCRIPT" ]; then
            log ERROR "$LOGIN_MAIL_SCRIPT existiert nicht (ENABLE_LOGIN_MAIL=yes)"
            rc=1
        else
            check_mode_owner "$LOGIN_MAIL_SCRIPT" 700 "root:root" || rc=1
            [ -x "$LOGIN_MAIL_SCRIPT" ] \
                || { log ERROR "$LOGIN_MAIL_SCRIPT ist nicht ausfuehrbar"; rc=1; }
        fi
        if ! grep -qE "^[[:space:]]*session[[:space:]].*pam_exec\.so.*${LOGIN_MAIL_SCRIPT//./\\.}" "$PAM_SSHD"; then
            log ERROR "$PAM_SSHD enthaelt keine aktive pam_exec-session-Zeile fuer $LOGIN_MAIL_SCRIPT"
            rc=1
        fi
    else
        if [ -e "$LOGIN_MAIL_SCRIPT" ]; then
            log ERROR "$LOGIN_MAIL_SCRIPT vorhanden, obwohl ENABLE_LOGIN_MAIL=no"
            rc=1
        fi
        if grep -qE "^[[:space:]]*session[[:space:]].*pam_exec\.so.*${LOGIN_MAIL_SCRIPT//./\\.}" "$PAM_SSHD"; then
            log ERROR "pam_exec-Login-Mail-Zeile in $PAM_SSHD vorhanden, obwohl ENABLE_LOGIN_MAIL=no"
            rc=1
        fi
    fi

    home="$(getent passwd "$MAIN_USER" | cut -d: -f6)"
    authkeys="$home/.ssh/authorized_keys"
    ga="$home/.google_authenticator"
    if [ ! -s "$authkeys" ]; then
        log ERROR "$authkeys fehlt oder ist leer"
        rc=1
    fi
    if [ ! -s "$ga" ]; then
        log ERROR "$ga fehlt oder ist leer"
        rc=1
    fi

    return "$rc"
}

do_test() {
    require_root
    load_conf "$SB_CONF"
    require_common_keys_or_die

    # Sitzungs-neutral: einziger Funktionstest ist sshd -t.
    # Kein Login-Probe, kein Restart.
    if sshd -t; then
        log INFO "ssh test: sshd -t ok (syntaktischer Konfig-Test)"
        log INFO "Fuer scharfen Login-Test in zweiter SSH-Sitzung manuell verifizieren (Pubkey + TOTP)."
        return 0
    fi
    log ERROR "ssh test: sshd -t fehlgeschlagen"
    return 1
}

dispatch "$MODULE" "$@"
