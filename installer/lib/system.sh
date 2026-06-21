# shellcheck shell=bash
#
# secure-base Helper: System-Voraussetzungen
# Bietet require_root, require_cmd.

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
