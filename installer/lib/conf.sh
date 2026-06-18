# shellcheck shell=bash
#
# secure-base Helper: Konfiguration
# Bietet load_conf.

#######################################
# Sourct eine .conf nach Existenz- und Lesbarkeits-Pruefung.
# Bricht ab, wenn die Datei fehlt oder nicht lesbar ist.
# Arguments: $1 — Pfad zur .conf-Datei
#######################################
load_conf() {
    local pfad=$1
    if [ ! -f "$pfad" ]; then
        die "Konfiguration nicht gefunden: $pfad"
    fi
    if [ ! -r "$pfad" ]; then
        die "Konfiguration nicht lesbar: $pfad"
    fi
    # shellcheck source=/dev/null
    source "$pfad"
}
