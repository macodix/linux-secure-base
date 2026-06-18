# shellcheck shell=bash
#
# secure-base Helper: System-Voraussetzungen
# Bietet require_root, require_cmd.

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
