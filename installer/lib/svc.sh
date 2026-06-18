# shellcheck shell=bash
#
# secure-base Helper: systemd-Services
# Bietet svc_active, svc_enable_now, svc_disable_now.

#######################################
# Prueft, ob ein Service aktiv laeuft.
# Arguments: $1 — Service-Name
# Returns:   0 aktiv, ungleich 0 inaktiv
#######################################
svc_active() {
    local name=$1
    systemctl is-active --quiet "$name"
}

#######################################
# Aktiviert einen Service (boot-persistent) und startet ihn sofort.
# Idempotent.
# Arguments: $1 — Service-Name
#######################################
svc_enable_now() {
    local name=$1
    log INFO "Aktiviere und starte Service: $name"
    systemctl enable --now "$name"
}

#######################################
# Deaktiviert einen Service (boot-persistent) und stoppt ihn sofort.
# Idempotent.
# Arguments: $1 — Service-Name
#######################################
svc_disable_now() {
    local name=$1
    log INFO "Deaktiviere und stoppe Service: $name"
    systemctl disable --now "$name"
}
