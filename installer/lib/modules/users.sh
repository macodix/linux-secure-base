#!/bin/bash
#
# Linux Secure Base — Modul users
# Hauptbenutzer, ssh-users-Gruppe, TOTP. Setzt das root-Passwort
# NICHT — prueft es nur als Vorbedingung.
# Aufruf: users.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="users"

# ---------------------------------------------------------------------
# Eingangs-Validierung
# ---------------------------------------------------------------------

# require_main_user_or_die ist in lib/system.sh definiert.

# Prueft als Vorbedingung, dass das root-Konto bereits ein Passwort
# hat (shadow-Hash weder leer noch '!' noch '*'). Das Modul setzt das
# root-Passwort bewusst NICHT.
require_root_passwd_or_die() {
    local hash
    hash="$(getent shadow root | cut -d: -f2)"
    if [ -z "$hash" ] || [ "$hash" = '!' ] || [ "$hash" = '*' ]; then
        die "root-Passwort ist nicht gesetzt — bitte vor users-Modul-Lauf auf der Server-Konsole per passwd setzen."
    fi
}

# ---------------------------------------------------------------------
# Helfer
# ---------------------------------------------------------------------

# Setzt das Passwort fuer <user>, wenn shadow-Hash leer/!/* ist.
# Bei leerer Globaler (Name in <pwd_var>) interaktive Eingabe ohne Echo.
# Klartextwerte werden nach erfolgreichem chpasswd aus dem Speicher
# entfernt (lokal und referenzierte Global).
set_password_if_missing() {
    local user="$1" pwd_var="$2"
    local pwd="${!pwd_var:-}"
    local hash
    hash="$(getent shadow "$user" | cut -d: -f2)"
    if [ -n "$hash" ] && [ "$hash" != '!' ] && [ "$hash" != '*' ]; then
        log INFO "Passwort fuer $user bereits gesetzt — uebersprungen"
        return 0
    fi
    if [ -z "$pwd" ]; then
        printf 'Passwort fuer %s eingeben: ' "$user" >&2
        IFS= read -rs pwd
        printf '\n' >&2
    fi
    printf '%s:%s\n' "$user" "$pwd" | chpasswd
    unset pwd
    unset "$pwd_var"
    log INFO "Passwort fuer $user gesetzt"
}

# Pause nach TOTP-QR-Anzeige (google-authenticator druckt QR-Code,
# otpauth-URL und Notfall-Codes direkt aufs Terminal).
pause_after_totp() {
    log INFO "QR-Code mit der Authenticator-App scannen, Notfall-Codes sicher hinterlegen."
    printf 'ENTER druecken, sobald erledigt. ' >&2
    read -r _
}

# Versendet das TOTP-Secret als QR-Bild (Anhang) und Text an ADMIN_MAIL.
# Sicherheitskritisch: Secret und Notfall-Codes duerfen NICHT ins Logfile —
# kein log-Aufruf mit diesen Werten. Das temporaere QR-PNG (enthaelt das
# Secret) wird in jedem Pfad wieder entfernt.
# Arguments: $1 — Benutzer, $2 — Pfad der .google_authenticator-Datei
# Globals:   ADMIN_MAIL
totp_per_mail() {
    local user=$1 ga_file=$2
    local secret fqdn url emergency qr_png
    secret=$(head -1 "$ga_file")
    fqdn=$(hostname -f)
    url="otpauth://totp/${user}@${fqdn}?secret=${secret}&issuer=${fqdn}"
    emergency=$(grep -E '^[0-9]{8}$' "$ga_file" || true)

    qr_png=$(mktemp --suffix=.png)
    chmod 600 "$qr_png"
    qrencode -o "$qr_png" "$url"

    if ! {
        printf 'Zwei-Faktor-Einrichtung fuer %s@%s.\n\n' "$user" "$fqdn"
        printf 'QR-Code im Anhang mit der Authenticator-App scannen,\n'
        printf 'oder das Secret manuell eintragen:\n\n'
        printf '  Secret: %s\n' "$secret"
        printf '  URL:    %s\n\n' "$url"
        printf 'Notfall-Codes (getrennt und sicher aufbewahren):\n%s\n\n' "$emergency"
        printf 'Diese Mail nach der Einrichtung loeschen.\n'
    } | mail -A "$qr_png" -s "Einrichtung user $user" "$ADMIN_MAIL"; then
        rm -f "$qr_png"
        die "TOTP-Mail an $ADMIN_MAIL fehlgeschlagen"
    fi
    rm -f "$qr_png"
}

# Prueft, dass Gruppe und "andere" keinen Zugriff haben
# (Mode-Maske & 077 == 0). Verwendet fuer das TOTP-Secret
# ~/.google_authenticator.
check_owner_only_mode() {
    local path="$1" owner_soll="$2"
    local mode owner
    mode="$(stat -c '%a' "$path")"
    owner="$(stat -c '%U:%G' "$path")"
    if (( (8#$mode) & 077 )); then
        log ERROR "$path: Mode $mode erlaubt Gruppe-/Welt-Zugriff — erwartet '?00' (z. B. 0400, 0600, 0700)"
        return 1
    fi
    if [ "$owner" != "$owner_soll" ]; then
        log ERROR "$path: Owner $owner, erwartet $owner_soll"
        return 1
    fi
}

# ---------------------------------------------------------------------
# Subkommandos
# ---------------------------------------------------------------------

do_install() {
    require_root
    load_conf "$SB_CONF"
    require_main_user_or_die

    # TOTP-Zustellung: terminal (QR am Bildschirm, Default) oder mail
    # (Secret/QR an ADMIN_MAIL — schwaecht die Faktor-Trennung, daher optional).
    TOTP_DELIVERY="${TOTP_DELIVERY:-terminal}"
    case "$TOTP_DELIVERY" in
        terminal) ;;
        mail)
            [ -n "${ADMIN_MAIL:-}" ] \
                || die "TOTP_DELIVERY=mail braucht ADMIN_MAIL in secure-base.conf"
            require_cmd mail
            ;;
        *) die "TOTP_DELIVERY muss 'terminal' oder 'mail' sein: $TOTP_DELIVERY" ;;
    esac

    # 1. Pakete installieren (idempotent ueber pkg_installed).
    pkg_install libpam-google-authenticator
    [ "$TOTP_DELIVERY" = "mail" ] && pkg_install qrencode

    # 2. Gruppe ssh-users anlegen.
    if ! getent group ssh-users >/dev/null; then
        groupadd ssh-users
        log INFO "Gruppe ssh-users angelegt"
    else
        log INFO "Gruppe ssh-users existiert bereits — uebersprungen"
    fi

    # 3. Hauptbenutzer anlegen oder Mitgliedschaft/Shell nachziehen.
    if ! getent passwd "$MAIN_USER" >/dev/null; then
        useradd -m -s /bin/bash -G ssh-users "$MAIN_USER"
        log INFO "Benutzer $MAIN_USER angelegt"
    else
        log INFO "Benutzer $MAIN_USER existiert bereits — Mitgliedschaft/Shell pruefen"
        if ! id -nG "$MAIN_USER" | tr ' ' '\n' | grep -qx ssh-users; then
            usermod -a -G ssh-users "$MAIN_USER"
            log INFO "$MAIN_USER zu ssh-users hinzugefuegt"
        fi
        if [ "$(getent passwd "$MAIN_USER" | cut -d: -f7)" != "/bin/bash" ]; then
            usermod -s /bin/bash "$MAIN_USER"
            log INFO "Login-Shell von $MAIN_USER auf /bin/bash gesetzt"
        fi
    fi

    # 4. root-Passwort-Vorbedingung pruefen, dann Hauptbenutzer-Passwort
    #    setzen. Das Modul setzt das root-Passwort NICHT.
    require_root_passwd_or_die
    set_password_if_missing "$MAIN_USER" MAIN_USER_PASSWORD

    # 5. SSH-Pubkey hinterlegen.
    local home pubkey authkeys
    home="$(getent passwd "$MAIN_USER" | cut -d: -f6)"
    install -d -m 0700 -o "$MAIN_USER" -g "$MAIN_USER" "$home/.ssh"
    if [ -n "${MAIN_USER_PUBKEY:-}" ]; then
        pubkey="$MAIN_USER_PUBKEY"
    elif [ -n "${MAIN_USER_PUBKEY_FILE:-}" ] && [ -r "$MAIN_USER_PUBKEY_FILE" ]; then
        pubkey="$(cat "$MAIN_USER_PUBKEY_FILE")"
    else
        printf 'SSH-Public-Key fuer %s einfuegen (eine Zeile): ' "$MAIN_USER" >&2
        IFS= read -r pubkey
    fi
    # Aussperr-Schutz: leerer oder syntaktisch defekter Pubkey darf
    # nicht durchgehen — sonst landet $MAIN_USER unter ssh-Haertung
    # (PasswordAuthentication=no) ohne brauchbaren Pubkey.
    [ -n "$pubkey" ] \
        || die "Kein Pubkey fuer $MAIN_USER — Abbruch (Aussperr-Schutz)."
    [[ "$pubkey" =~ ^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2-nistp[0-9]+)[[:space:]] ]] \
        || die "Pubkey-Format unbekannt: '${pubkey:0:40}...' — Abbruch (Aussperr-Schutz)."
    authkeys="$home/.ssh/authorized_keys"
    if [ ! -e "$authkeys" ]; then
        install -m 0600 -o "$MAIN_USER" -g "$MAIN_USER" /dev/null "$authkeys"
    else
        # Bestehende Datei: Mode/Owner defensiv auf Soll setzen.
        chmod 0600 "$authkeys"
        chown "$MAIN_USER:$MAIN_USER" "$authkeys"
    fi
    if ! grep -qxF "$pubkey" "$authkeys"; then
        printf '%s\n' "$pubkey" >> "$authkeys"
        log INFO "Pubkey fuer $MAIN_USER hinterlegt"
    else
        log INFO "Pubkey fuer $MAIN_USER bereits hinterlegt — uebersprungen"
    fi

    # 6. TOTP-Secret erzeugen; Zustellung per Terminal (Default) oder Mail.
    local ga="$home/.google_authenticator"
    if [ -s "$ga" ]; then
        log INFO "TOTP-Secret von $MAIN_USER bereits vorhanden — google-authenticator uebersprungen"
    elif [ "$TOTP_DELIVERY" = "mail" ]; then
        # google-authenticator fragt trotz aller Flags interaktiv
        # "Enter code from app (-1 to skip)" — '-1' ueberspringt diese
        # Verifikation (im mail-Zweig zwingend, da der Nutzer das Secret
        # erst per Mail erhaelt). Output verwerfen (enthaelt Secret/QR —
        # NICHT ins Logfile, NICHT aufs Terminal).
        printf '%s\n' -1 \
            | su -l "$MAIN_USER" -c 'google-authenticator -t -d -W -r 3 -R 30 -f' \
            >/dev/null 2>&1
        totp_per_mail "$MAIN_USER" "$ga"
        log INFO "TOTP-Secret fuer $MAIN_USER erzeugt und per Mail an ADMIN_MAIL versendet"
    else
        # WICHTIG: TOTP-Output (QR-Code, otpauth-URL, Notfall-Codes)
        # NICHT ins Logfile spiegeln. stdin/stdout/stderr direkt auf das
        # Controlling-Terminal lenken.
        su -l "$MAIN_USER" -c 'google-authenticator -t -d -W -r 3 -R 30 -f' \
            </dev/tty >/dev/tty 2>/dev/tty
        log INFO "TOTP-Secret fuer $MAIN_USER erzeugt"
        pause_after_totp
    fi
}

do_uninstall() {
    require_root
    load_conf "$SB_CONF"
    # Speicher-Hygiene: do_uninstall braucht MAIN_USER_PASSWORD nicht.
    unset MAIN_USER_PASSWORD
    require_main_user_or_die

    local remove="${UNINSTALL_REMOVE_USER:-no}"
    case "$remove" in
        yes|no) ;;
        *) die "UNINSTALL_REMOVE_USER muss 'yes' oder 'no' sein, ist: $remove" ;;
    esac

    if getent passwd "$MAIN_USER" >/dev/null \
        && id -nG "$MAIN_USER" | tr ' ' '\n' | grep -qx ssh-users; then
        gpasswd -d "$MAIN_USER" ssh-users
        log INFO "Mitgliedschaft $MAIN_USER in ssh-users geloest"
    fi
    if getent group ssh-users >/dev/null; then
        groupdel ssh-users
        log INFO "Gruppe ssh-users entfernt"
    fi

    if [ "$remove" = "yes" ]; then
        if getent passwd "$MAIN_USER" >/dev/null; then
            # Aktive Prozesse des Hauptbenutzers beenden — sonst
            # schlaegt userdel -r fehl.
            pkill -TERM -u "$MAIN_USER" || true
            sleep 2
            pkill -KILL -u "$MAIN_USER" || true
            if ! userdel -r "$MAIN_USER"; then
                die "userdel -r $MAIN_USER fehlgeschlagen — laufende Prozesse oder Mountpoints im Home pruefen und manuell entfernen"
            fi
            log INFO "Benutzer $MAIN_USER mit Home-Verzeichnis entfernt (UNINSTALL_REMOVE_USER=yes)"
        else
            log INFO "Benutzer $MAIN_USER existiert nicht — userdel uebersprungen"
        fi
    else
        log INFO "Hauptbenutzer, Home, Passwoerter, TOTP, Pubkey bleiben unveraendert (UNINSTALL_REMOVE_USER=no)"
    fi

    log INFO "root-Passwort bleibt unveraendert"
    log INFO "Paket libpam-google-authenticator bleibt installiert (gehoert zum ssh-Modul-Bedarf)"
}

do_check() {
    require_root
    load_conf "$SB_CONF"
    require_main_user_or_die

    local rc=0
    local home authkeys ga shadowhash

    check_packages libpam-google-authenticator || rc=1

    if ! getent group ssh-users >/dev/null; then
        log ERROR "Gruppe ssh-users existiert nicht"
        rc=1
    fi
    if ! getent passwd "$MAIN_USER" >/dev/null; then
        log ERROR "Benutzer $MAIN_USER existiert nicht"
        # Ohne den User koennen die folgenden Pfad-Pruefungen nicht
        # mehr aufgeloest werden — sofortiger Abbruch.
        return 1
    fi
    if [ "$(getent passwd "$MAIN_USER" | cut -d: -f7)" != "/bin/bash" ]; then
        log ERROR "$MAIN_USER hat nicht /bin/bash als Login-Shell"
        rc=1
    fi
    if ! id -nG "$MAIN_USER" | tr ' ' '\n' | grep -qx ssh-users; then
        log ERROR "$MAIN_USER ist nicht in der Gruppe ssh-users"
        rc=1
    fi
    shadowhash="$(getent shadow "$MAIN_USER" | cut -d: -f2)"
    if [ -z "$shadowhash" ] || [ "$shadowhash" = '!' ] || [ "$shadowhash" = '*' ]; then
        log ERROR "$MAIN_USER hat kein gesetztes Login-Passwort"
        rc=1
    fi
    home="$(getent passwd "$MAIN_USER" | cut -d: -f6)"
    if [ ! -d "$home/.ssh" ]; then
        log ERROR "$home/.ssh existiert nicht"
        rc=1
    else
        check_file_mode "$home/.ssh" 700 "$MAIN_USER:$MAIN_USER" || rc=1
    fi
    authkeys="$home/.ssh/authorized_keys"
    if [ ! -f "$authkeys" ]; then
        log ERROR "$authkeys existiert nicht"
        rc=1
    else
        check_file_mode "$authkeys" 600 "$MAIN_USER:$MAIN_USER" || rc=1
        if [ ! -s "$authkeys" ]; then
            log ERROR "$authkeys ist leer"
            rc=1
        fi
    fi
    ga="$home/.google_authenticator"
    if [ ! -f "$ga" ]; then
        log ERROR "$ga existiert nicht"
        rc=1
    else
        check_owner_only_mode "$ga" "$MAIN_USER:$MAIN_USER" || rc=1
        if [ ! -s "$ga" ]; then
            log ERROR "$ga ist leer"
            rc=1
        fi
    fi

    return "$rc"
}

do_test() {
    require_root
    load_conf "$SB_CONF"
    require_main_user_or_die

    local rc=0
    if ! su -l "$MAIN_USER" -c 'test -r ~/.google_authenticator'; then
        log WARN "TOTP-Secret aus Sicht von $MAIN_USER nicht lesbar"
        rc=1
    fi
    if ! su -l "$MAIN_USER" -c 'test -r ~/.ssh/authorized_keys'; then
        log WARN "authorized_keys aus Sicht von $MAIN_USER nicht lesbar"
        rc=1
    fi
    if [ "$rc" -eq 0 ]; then
        log INFO "users test: Hauptbenutzer kann seine Login-Dateien lesen"
    fi
    return 0
}

#######################################
# Liefert den Markdown-Abschnitt dieses Moduls fuer die Abschluss-Doku.
# Nur lesend; nimmt keine Systemaenderung vor. Gibt ausschliesslich
# Markdown nach stdout aus. Nimmt conf-Werte ueber die von do_doc per
# load_conf geladene Umgebung ab.
# Globals:   MAIN_USER, TOTP_DELIVERY (lesend, via doc_val)
# Outputs:   stdout — Markdown-Abschnitt (beginnt mit "## <Label>")
#######################################
module_doc() {
    doc_section "Hauptbenutzer"
    doc_packages libpam-google-authenticator
    doc_users "$(doc_val MAIN_USER)" ssh-users
    doc_files_begin
    doc_file "/home/$(doc_val MAIN_USER)/.ssh/authorized_keys" \
        "SSH-Public-Key hinterlegt"
    doc_file "/home/$(doc_val MAIN_USER)/.google_authenticator" \
        "TOTP-Secret (Zustellung: $(doc_val TOTP_DELIVERY))"
    doc_note "Passwort und TOTP-Material werden nicht dokumentiert (Secret)."
}

dispatch "$MODULE" "$@"
