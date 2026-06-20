# shellcheck shell=bash
#
# secure-base Helper: Konfiguration
# Bietet die zentrale Konfig-Pfad-Variable SB_CONF und load_conf.

# Pfad zur zentralen Konfigdatei. Default: conf/secure-base.conf neben dem
# aufrufenden Skript (SCRIPT_DIR stammt aus dem sourcenden Skript).
# Ueberschreibbar per Umgebungsvariable SB_CONF — der Installer setzt sie aus
# der -c-Option und exportiert sie, sodass Modul-Subprozesse denselben Pfad
# erben. Nicht readonly, damit -c sie ueberschreiben kann.
# Exportieren, damit Modul-Subprozesse den (ggf. per -c gesetzten) Pfad erben.
# shellcheck disable=SC2154  # SCRIPT_DIR wird vom sourcenden Skript gesetzt
export SB_CONF="${SB_CONF:-${SCRIPT_DIR}/conf/secure-base.conf}"

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
