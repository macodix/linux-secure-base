# shellcheck shell=bash
#
# secure-base Helper: System-Voraussetzungen
# Bietet require_root, require_cmd.

#######################################
# Prueft MAIN_USER: nicht leer, POSIX-Login-Format, nicht Systembenutzer.
# Wird von users.sh und ssh.sh (require_common_keys_or_die) verwendet.
# Globals:   MAIN_USER
#######################################
require_main_user_or_die() {
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
}

#######################################
# Leitet den Absender-Wert root@<domain> aus FQDN ab.
# Gibt leer aus, wenn FQDN keinen Punkt enthaelt.
# Arguments: keine
# Globals:   FQDN (lesend)
# Outputs:   stdout — "root@<domain>" oder leer
#######################################
mailfrom_from_fqdn() {
    local fqdn=${FQDN:-}
    local domain=${fqdn#*.}
    if [ -n "$domain" ] && [ "$domain" != "$fqdn" ]; then
        printf '%s' "root@${domain}"
    fi
}

#######################################
# Bricht ab, wenn das Skript nicht als root laeuft.
# Globals:   EUID
#######################################
require_root() {
    if [ "$EUID" -ne 0 ]; then
        die "Bitte als root ausfuehren."
    fi
}

#######################################
# Bricht ab, wenn ein Kommando nicht im PATH liegt.
# Arguments: $1 — Kommando-Name
#######################################
require_cmd() {
    local name=$1
    if ! command -v "$name" >/dev/null 2>&1; then
        die "Pflicht-Kommando fehlt: $name"
    fi
}
