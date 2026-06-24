# shellcheck shell=bash
#
# secure-base Helper: optionale Pakete
# Bietet den Pfad und das Laden der optional-conf, die Aktivierungs-Pruefung
# fuer optionale Pakete und den vhost-Parser fuer nginx.

# Pfad zur optional-conf. Default: conf/secure-base-optional.conf neben dem
# aufrufenden Skript. Ueberschreibbar per SB_OPTIONAL_CONF (analog SB_CONF).
# shellcheck disable=SC2154  # SCRIPT_DIR wird vom sourcenden Skript gesetzt
export SB_OPTIONAL_CONF="${SB_OPTIONAL_CONF:-${SCRIPT_DIR}/conf/secure-base-optional.conf}"

#######################################
# Prueft, ob mindestens eines der Argumente in OPTIONAL_ORDER steht.
# Globals:   OPTIONAL_ORDER
# Arguments: $* — Argumente (Modulnamen)
# Returns:   0 ja, 1 nein
#######################################
optional_arg_present() {
    local arg
    for arg in "$@"; do
        if in_list "$arg" "${OPTIONAL_ORDER[@]}"; then
            return 0
        fi
    done
    return 1
}

#######################################
# Laedt die optional-conf und stellt OPTIONAL_ENABLED bereit.
# Bei install/check/test: fehlende conf ist ein Fehler (die optionalen
# Pakete sollen ja verarbeitet werden). Bei uninstall: fehlende conf ist
# kein Fehler — Rueckfall auf alle OPTIONAL_ORDER als Kandidaten (fail-safe).
# Validiert das vhost-Schema fuer aktivierte Pakete (nginx).
# Globals:   SB_OPTIONAL_CONF, SB_SUB, OPTIONAL_ORDER, OPTIONAL_ENABLED (setzt)
#######################################
load_optional_conf() {
    if [ ! -f "$SB_OPTIONAL_CONF" ]; then
        if [ "${SB_SUB:-}" = "uninstall" ]; then
            log WARN "optional-conf fehlt ($SB_OPTIONAL_CONF) — Rueckbau-Kandidaten: ${OPTIONAL_ORDER[*]}"
            OPTIONAL_ENABLED=("${OPTIONAL_ORDER[@]}")
            return 0
        fi
        die "Optional-conf nicht gefunden: $SB_OPTIONAL_CONF (aus conf/secure-base-optional.conf.example anlegen)"
    fi
    if [ ! -r "$SB_OPTIONAL_CONF" ]; then
        die "Optional-conf nicht lesbar: $SB_OPTIONAL_CONF"
    fi
    # shellcheck source=/dev/null
    source "$SB_OPTIONAL_CONF"

    # OPTIONAL_ENABLED muss als Array existieren (auch leer zulaessig).
    if ! declare -p OPTIONAL_ENABLED >/dev/null 2>&1; then
        OPTIONAL_ENABLED=()
    fi
    # Jeder Eintrag muss in OPTIONAL_ORDER bekannt sein.
    local p
    for p in "${OPTIONAL_ENABLED[@]}"; do
        if ! in_list "$p" "${OPTIONAL_ORDER[@]}"; then
            die "OPTIONAL_ENABLED enthaelt unbekanntes Paket: '$p' (bekannt: ${OPTIONAL_ORDER[*]})"
        fi
    done
}

#######################################
# Prueft, ob ein optionales Paket in OPTIONAL_ENABLED aktiviert ist.
# Globals:   OPTIONAL_ENABLED
# Arguments: $1 — Paketname
# Returns:   0 aktiviert, 1 nicht
#######################################
_optional_modul_aktiviert() {
    # Muster ${ARRAY[@]:-}: schuetzt unter `set -u` vor dem leeren Array.
    # Bei leerem OPTIONAL_ENABLED expandiert es zu einem einzelnen leeren
    # Argument; in_list findet den gesuchten (nie leeren) Paketnamen darin
    # nicht und liefert korrekt 1. Bestandskonsistenz mit ufw.sh (doc_list).
    in_list "$1" "${OPTIONAL_ENABLED[@]:-}"
}

#######################################
# Entscheidet je nach Liste, ob ein Modul aktiviert ist:
# Kernmodul -> MODULES_ENABLED, optionales Paket -> OPTIONAL_ENABLED.
# Globals:   INSTALL_ORDER, MODULES_ENABLED, OPTIONAL_ENABLED
# Arguments: $1 — Modulname
# Returns:   0 aktiviert, 1 nicht
#######################################
_modul_aktiviert() {
    local m=$1
    if in_list "$m" "${INSTALL_ORDER[@]}"; then
        in_list "$m" "${MODULES_ENABLED[@]}"
    else
        _optional_modul_aktiviert "$m"
    fi
}

#######################################
# Liest die vhost-Definitionen aus der optional-conf in parallele Arrays.
# Schema: je vhost eine Zeile in NGINX_VHOSTS, Format "domain|docroot".
# docroot optional; leer -> Default /var/www/<domain>.
# Setzt: NGINX_VHOST_DOMAIN[], NGINX_VHOST_DOCROOT[] (parallel, gleiche Laenge).
# Validiert Domainnamen (FQDN-Form) und Pflicht "mindestens ein vhost".
# Globals:   NGINX_VHOSTS (lesend), NGINX_VHOST_DOMAIN/_DOCROOT (setzt)
#######################################
nginx_parse_vhosts() {
    NGINX_VHOST_DOMAIN=()
    NGINX_VHOST_DOCROOT=()
    if ! declare -p NGINX_VHOSTS >/dev/null 2>&1 || [ "${#NGINX_VHOSTS[@]}" -eq 0 ]; then
        die "nginx: kein vhost definiert — mindestens ein Eintrag in NGINX_VHOSTS noetig (secure-base-optional.conf)"
    fi
    local zeile domain docroot
    for zeile in "${NGINX_VHOSTS[@]}"; do
        domain=${zeile%%|*}
        docroot=${zeile#*|}
        [ "$docroot" = "$zeile" ] && docroot=""   # kein '|' -> kein docroot
        domain=${domain// /}                       # Leerzeichen tilgen
        if ! [[ "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; then
            die "nginx: ungueltiger Domainname in NGINX_VHOSTS: '$domain'"
        fi
        # DNS-Laengengrenzen: FQDN <= 253 Zeichen, je Label <= 63.
        if [ "${#domain}" -gt 253 ]; then
            die "nginx: Domainname zu lang (>253 Zeichen): '$domain'"
        fi
        local label
        for label in ${domain//./ }; do
            if [ "${#label}" -gt 63 ]; then
                die "nginx: DNS-Label zu lang (>63 Zeichen) in '$domain': '$label'"
            fi
        done
        [ -z "$docroot" ] && docroot="/var/www/${domain}"
        if [[ "$docroot" != /* ]]; then
            die "nginx: docroot muss absolut sein: '$docroot' (vhost $domain)"
        fi
        NGINX_VHOST_DOMAIN+=("$domain")
        NGINX_VHOST_DOCROOT+=("$docroot")
    done
}

#######################################
# Oeffnet einen eingehenden TCP-Port in ufw, falls noch nicht vorhanden.
# Idempotent. Wirkt nur auf das Regelwerk; aktiviert ufw NICHT.
# Arguments: $1 — Portnummer
#######################################
ufw_allow_in_tcp() {
    local port=$1
    if ufw show added 2>/dev/null | grep -qE "^ufw allow ${port}/tcp$"; then
        log INFO "ufw: ${port}/tcp bereits erlaubt — uebersprungen"
    else
        log INFO "ufw: ${port}/tcp eingehend erlauben"
        ufw allow "${port}/tcp"
    fi
}

#######################################
# Entfernt eine zuvor gesetzte eingehende TCP-Regel aus ufw, falls vorhanden.
# Idempotent.
# Arguments: $1 — Portnummer
#######################################
ufw_delete_in_tcp() {
    local port=$1
    if ufw show added 2>/dev/null | grep -qE "^ufw allow ${port}/tcp$"; then
        log INFO "ufw: ${port}/tcp eingehend entfernen"
        ufw delete allow "${port}/tcp"
    else
        log INFO "ufw: ${port}/tcp nicht gesetzt — nichts zu entfernen"
    fi
}
