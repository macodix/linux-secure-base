#!/bin/bash
#
# Linux Secure Base — optionales Modul nginx
# Multidomain-Webserver fuer statische Inhalte. Je Domain ein eigener
# Server-Block mit eigenem Let's-Encrypt-Zertifikat (certbot, HTTP-01).
# Ergaenzt die Firewall selbst (443/tcp dauerhaft, 80/tcp temporaer fuer
# den Zertifikatsbezug). Setzt das gehaertete Grundsystem voraus (laeuft
# nach den Kernmodulen). Aufruf: nginx.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="nginx"

readonly NGINX_CONF="/etc/nginx/nginx.conf"
readonly SITES_AVAILABLE="/etc/nginx/sites-available"
readonly SITES_ENABLED="/etc/nginx/sites-enabled"
readonly AA_PROFILE="/etc/apparmor.d/usr.sbin.nginx"
readonly HARDENING_DROPIN="/etc/systemd/system/nginx.service.d/secure-base-hardening.conf"

# --- Konfig laden und pruefen ----------------------------------------

# Laedt optional-conf + vhosts und prueft die nginx-Pflichtwerte.
# certbot-Mail: NGINX_CERTBOT_MAIL, sonst ADMIN_MAIL aus secure-base.conf.
require_nginx_conf_or_die() {
    load_conf "$SB_CONF"                 # ADMIN_MAIL als Fallback
    load_optional_conf
    nginx_parse_vhosts                   # setzt NGINX_VHOST_DOMAIN/_DOCROOT, prueft "mind. 1"

    NGINX_MAIL="${NGINX_CERTBOT_MAIL:-${ADMIN_MAIL:-}}"
    [ -n "$NGINX_MAIL" ] \
        || die "nginx: keine Mail fuer certbot (NGINX_CERTBOT_MAIL oder ADMIN_MAIL setzen)"
    NGINX_MODE="${NGINX_CERTBOT_MODE:-live}"
    case "$NGINX_MODE" in
        live | staging) ;;
        *) die "nginx: NGINX_CERTBOT_MODE ungueltig: '$NGINX_MODE' (live|staging)" ;;
    esac
}

# --- Server-Block je Domain (vor Zertifikat) -------------------------

# Schreibt einen minimalen Port-80-Block fuer den Zertifikatsbezug.
# certbot ergaenzt spaeter den 443-Block und den 80->443-Redirect.
# Idempotent: Datei wird deterministisch komplett geschrieben.
write_http_block() {
    local domain=$1 docroot=$2
    local datei="${SITES_AVAILABLE}/${domain}"
    {
        printf '# Von secure-base/nginx angelegt — nicht von Hand bearbeiten.\n'
        printf 'server {\n'
        printf '    listen 80;\n'
        printf '    listen [::]:80;\n'
        printf '    server_name %s;\n' "$domain"
        printf '    root %s;\n' "$docroot"
        # shellcheck disable=SC2016  # $uri ist nginx-Konfig-Variable, kein Bash-Ausdruck
        printf '    location / { try_files $uri $uri/ =404; }\n'
        printf '}\n'
    } > "$datei"
    chmod 644 "$datei"
    ln -sfn "$datei" "${SITES_ENABLED}/${domain}"
}

do_install() {
    require_root
    require_nginx_conf_or_die

    log INFO "nginx install: Pakete installieren"
    # apparmor-utils liefert aa-autodep/aa-complain/aa-enforce/aa-logprof.
    pkg_install nginx certbot python3-certbot-nginx apparmor-utils

    # Distro-Default-Seite deaktivieren (idempotent).
    if [ -L "${SITES_ENABLED}/default" ] || [ -e "${SITES_ENABLED}/default" ]; then
        log INFO "nginx install: Distro-Default-Site deaktivieren"
        rm -f "${SITES_ENABLED}/default"
    fi

    # Versions-Anzeige abschalten (idempotent ueber Marker-Schema).
    ensure_setting "$NGINX_CONF" "server_tokens" "off;" " "

    # Wurzelverzeichnisse und HTTP-Bloecke je vhost.
    local i domain docroot
    for i in "${!NGINX_VHOST_DOMAIN[@]}"; do
        domain=${NGINX_VHOST_DOMAIN[$i]}
        docroot=${NGINX_VHOST_DOCROOT[$i]}
        log INFO "nginx install: vhost ${domain} (docroot ${docroot})"
        mkdir -p "$docroot"
        chown -R www-data:www-data "$docroot"
        write_http_block "$domain" "$docroot"
    done

    nginx -t
    systemctl reload nginx

    # Firewall additiv ergaenzen: 443 dauerhaft, 80 temporaer fuer den
    # Zertifikatsbezug. Unabhaengig vom ufw-Aktivierungszustand:
    #   - ufw inaktiv -> Port 80 ist ohnehin offen, certbot erreichbar.
    #   - ufw aktiv   -> die additive Regel macht Port 80 erreichbar.
    # In beiden Faellen ist Port 80 von aussen erreichbar; kein Abbruch.
    ufw_allow_in_tcp 443

    # Port 80 temporaer oeffnen. Fail-closed (konv-scripting-bash.md 4.7a):
    # Der EXIT-trap schliesst Port 80 in jedem Fall wieder — auch wenn certbot,
    # nginx -t oder eine andere Anweisung unter `set -e` vorzeitig abbricht. So
    # bleibt nie ein offener Port 80 zurueck (analog do_test, N4). 443 bleibt
    # unberuehrt; ufw_delete_in_tcp 80 ist idempotent, das spaetere regulaere
    # Schliessen und der trap stoeren sich daher nicht.
    ufw_allow_in_tcp 80
    trap 'ufw_delete_in_tcp 80' EXIT

    # Zertifikat je Domain (HTTP-01). certbot ergaenzt 443-Block + Redirect.
    local certbot_opts=(--nginx --non-interactive --agree-tos
        -m "$NGINX_MAIL" --redirect)
    [ "$NGINX_MODE" = "staging" ] && certbot_opts+=(--staging)
    for i in "${!NGINX_VHOST_DOMAIN[@]}"; do
        domain=${NGINX_VHOST_DOMAIN[$i]}
        log INFO "nginx install: certbot fuer ${domain} (${NGINX_MODE})"
        if ! certbot "${certbot_opts[@]}" -d "$domain"; then
            # Port 80 schliesst der EXIT-trap; hier nur abbrechen.
            die "nginx install: certbot fuer ${domain} fehlgeschlagen — DNS/Erreichbarkeit (A/AAAA-Record, Port 80 von aussen) pruefen. Port 80 wird wieder geschlossen."
        fi
    done

    nginx -t
    systemctl reload nginx

    # Port 80 im Normalbetrieb wieder schliessen (Redirect-Block bleibt als
    # Absicherung in der Konfig). Erneuerung oeffnet 80 bei Bedarf erneut
    # (siehe Doku 13, Erneuerungs-Fenster — in der Bauphase verfeinert).
    # Danach den trap zuruecknehmen (regulaer geschlossen).
    ufw_delete_in_tcp 80
    trap - EXIT

    # systemd-Haertung als Drop-in (deterministisch geschrieben).
    log INFO "nginx install: systemd-Hardening-Drop-in schreiben"
    mkdir -p "$(dirname "$HARDENING_DROPIN")"
    {
        printf '# Von secure-base/nginx angelegt — nicht von Hand bearbeiten.\n'
        printf '[Service]\n'
        printf 'NoNewPrivileges=true\n'
        printf 'ProtectSystem=strict\n'
        printf 'ProtectHome=true\n'
        printf 'PrivateTmp=true\n'
        printf 'ReadWritePaths=/var/log/nginx /var/lib/nginx /run\n'
    } > "$HARDENING_DROPIN"
    chmod 644 "$HARDENING_DROPIN"
    systemctl daemon-reload
    systemctl restart nginx

    svc_enable_now nginx

    # AppArmor-Basisprofil im complain-Modus einrichten (protokolliert
    # Verstoesse, blockiert nichts). Enforce wird NICHT automatisch gesetzt
    # (Aussperr-/Funktionsrisiko bei abweichenden Pfaden). Der Weg zu enforce
    # ist in der Doku beschrieben (Testbetrieb -> aa-logprof -> enforce).
    nginx_install_apparmor

    log INFO "nginx install: abgeschlossen. Eingehend offen: 22/tcp, 443/tcp."
}

# Richtet das AppArmor-Basisprofil fuer nginx im complain-Modus ein.
# Erzeugt das Profil per aa-autodep (an die nginx-Binaerdatei gebunden) und
# setzt es auf complain (protokolliert, blockiert nicht). Enforce wird NICHT
# gesetzt — der Weg dorthin (Testbetrieb -> aa-logprof -> enforce) ist in der
# Doku beschrieben. Idempotent: ein bereits geladenes Profil wird nicht neu
# erzeugt, aber auf complain gehalten.
nginx_install_apparmor() {
    require_cmd aa-status
    require_cmd aa-autodep
    require_cmd aa-complain
    if [ ! -f "$AA_PROFILE" ]; then
        log INFO "nginx install: AppArmor-Basisprofil per aa-autodep erzeugen"
        aa-autodep nginx
    else
        log INFO "nginx install: AppArmor-Profil ${AA_PROFILE} vorhanden — nicht neu erzeugt"
    fi
    log INFO "nginx install: AppArmor-Profil auf complain setzen (protokolliert, blockiert nicht)"
    aa-complain nginx
    log WARN "nginx install: AppArmor-Profil im complain-Modus. Weg zu enforce: Testbetrieb -> aa-logprof -> aa-enforce (siehe Anleitung 13)."
}

do_uninstall() {
    require_root
    # Konfig-unabhaengig: laeuft auch ohne optional-conf. Domains, soweit
    # ermittelbar, aus den sites-available-Dateien dieses Moduls.
    if ! pkg_installed nginx; then
        log INFO "nginx uninstall: Paket nginx nicht installiert — nichts zu tun"
        return 0
    fi

    # Firewall-Regeln zuruecknehmen (additiv gesetzt, additiv entfernen).
    ufw_delete_in_tcp 80
    ufw_delete_in_tcp 443

    # Dienst stoppen/deaktivieren vor Paketentfernung.
    svc_disable_now nginx 2>/dev/null || true

    # Haertung-Drop-in entfernen.
    if [ -f "$HARDENING_DROPIN" ]; then
        log INFO "nginx uninstall: Hardening-Drop-in entfernen"
        rm -f "$HARDENING_DROPIN"
        rmdir "$(dirname "$HARDENING_DROPIN")" 2>/dev/null || true
        systemctl daemon-reload
    fi

    # server_tokens-Eingriff zuruecknehmen.
    [ -f "$NGINX_CONF" ] && remove_setting "$NGINX_CONF" "server_tokens"

    # Von diesem Modul angelegte Server-Bloecke entfernen (Marker-Kommentar
    # in Zeile 1). Zertifikate unter /etc/letsencrypt bleiben bestehen
    # (manueller Rueckbau, kein Datenverlust durch uninstall).
    local datei
    # nullglob: leeres sites-available liefert keine Treffer statt des
    # woertlichen Glob-Musters (lokal gesetzt, danach zuruecksetzen).
    local nullglob_war_an=0
    shopt -q nullglob && nullglob_war_an=1
    shopt -s nullglob
    for datei in "${SITES_AVAILABLE}"/*; do
        [ -f "$datei" ] || continue
        if head -1 "$datei" | grep -q 'Von secure-base/nginx angelegt'; then
            local name
            name=$(basename "$datei")
            log INFO "nginx uninstall: Server-Block ${name} entfernen"
            rm -f "${SITES_ENABLED}/${name}" "$datei"
        fi
    done
    [ "$nullglob_war_an" -eq 0 ] && shopt -u nullglob

    # AppArmor-Profil entfernen, falls vorhanden. apparmor_parser kann fehlen
    # (Paket bereits entfernt) — dann nur die Profil-Datei loeschen und warnen.
    if [ -f "$AA_PROFILE" ]; then
        if command -v apparmor_parser >/dev/null 2>&1; then
            log INFO "nginx uninstall: AppArmor-Profil entladen und entfernen"
            apparmor_parser -R "$AA_PROFILE" 2>/dev/null || true
        else
            log WARN "nginx uninstall: apparmor_parser nicht verfuegbar — Profil wird nur als Datei entfernt, nicht aktiv entladen (entfaellt mit dem naechsten Neustart/AppArmor-Reload)"
        fi
        rm -f "$AA_PROFILE"
    fi

    log WARN "nginx uninstall: Let's-Encrypt-Zertifikate unter /etc/letsencrypt bleiben bestehen — bei Bedarf manuell entfernen (certbot delete)."
    pkg_remove nginx python3-certbot-nginx
    # certbot-Paket bewusst NICHT entfernen — kann von anderem genutzt werden.
}

do_check() {
    require_root
    require_nginx_conf_or_die
    local rc=0

    check_packages nginx certbot python3-certbot-nginx apparmor-utils || exit 1
    check_svc_enabled nginx || rc=1

    # nginx-Konfig syntaktisch.
    if nginx -t >/dev/null 2>&1; then
        log INFO "check: nginx -t ok"
    else
        log ERROR "check: nginx -t meldet Fehler"
        rc=1
    fi

    # server_tokens off im http-Block.
    if grep -qE '^\s*server_tokens\s+off;' "$NGINX_CONF"; then
        log INFO "check: server_tokens off gesetzt"
    else
        log ERROR "check: server_tokens off fehlt in $NGINX_CONF"
        rc=1
    fi

    # Je vhost: Server-Block, docroot, Zertifikat.
    local i domain docroot
    for i in "${!NGINX_VHOST_DOMAIN[@]}"; do
        domain=${NGINX_VHOST_DOMAIN[$i]}
        docroot=${NGINX_VHOST_DOCROOT[$i]}
        if [ -f "${SITES_AVAILABLE}/${domain}" ] && [ -L "${SITES_ENABLED}/${domain}" ]; then
            log INFO "check: vhost ${domain} aktiviert"
        else
            log ERROR "check: vhost ${domain} fehlt oder nicht aktiviert"
            rc=1
        fi
        if [ -d "$docroot" ]; then
            log INFO "check: docroot ${docroot} vorhanden"
        else
            log ERROR "check: docroot ${docroot} fehlt"
            rc=1
        fi
        if [ -d "/etc/letsencrypt/live/${domain}" ]; then
            log INFO "check: Zertifikat fuer ${domain} vorhanden"
        else
            log ERROR "check: kein Zertifikat fuer ${domain} unter /etc/letsencrypt/live"
            rc=1
        fi
        # TLS-Privatschluessel: nicht fuer andere lesbar (Soll: <= 640,
        # owner root). certbot legt privkey.pem nach /etc/letsencrypt/archive
        # ab und verlinkt aus live/; geprueft wird das Linkziel.
        local privkey="/etc/letsencrypt/live/${domain}/privkey.pem"
        if [ -e "$privkey" ]; then
            local perm
            perm=$(stat -L -c '%a' "$privkey" 2>/dev/null || echo "")
            # Letzte Stelle (Other) muss 0 sein; Gruppe darf nur lesen.
            if [ -n "$perm" ] && [ "${perm: -1}" = "0" ]; then
                log INFO "check: TLS-Privatschluessel ${domain} nicht fuer andere lesbar (${perm})"
            else
                log ERROR "check: TLS-Privatschluessel ${domain} zu offen (${perm:-unbekannt}); 'others' darf keinen Zugriff haben"
                rc=1
            fi
        else
            log ERROR "check: TLS-Privatschluessel fuer ${domain} fehlt (${privkey})"
            rc=1
        fi
        # certbot-TLS-Konfig im 443-Block des Server-Blocks eingebunden
        # (options-ssl-nginx.conf). Nachweis fuer korrekt gesetzte TLS-Parameter.
        if grep -q 'options-ssl-nginx.conf' "${SITES_AVAILABLE}/${domain}" 2>/dev/null; then
            log INFO "check: certbot-TLS-Konfig (options-ssl-nginx.conf) in vhost ${domain} eingebunden"
        else
            log ERROR "check: certbot-TLS-Konfig (options-ssl-nginx.conf) im vhost ${domain} nicht eingebunden — 443-Block/TLS-Parameter pruefen"
            rc=1
        fi
    done

    # Firewall: 443 offen, 80 NICHT (Normalbetrieb).
    if ufw show added 2>/dev/null | grep -qE '^ufw allow 443/tcp$'; then
        log INFO "check: 443/tcp eingehend erlaubt"
    else
        log ERROR "check: 443/tcp eingehend nicht erlaubt"
        rc=1
    fi
    # 80/tcp soll im Normalbetrieb nicht von aussen erreichbar sein. Eine
    # gespeicherte allow-Regel ist nur dann ein offener Port, wenn ufw aktiv
    # ist — bei inaktiver ufw greift keine Regel. Daher den ufw-Status einbeziehen.
    local ufw_aktiv=0
    if ufw status verbose 2>/dev/null | grep -q 'Status: active'; then
        ufw_aktiv=1
    fi
    if ufw show added 2>/dev/null | grep -qE '^ufw allow 80/tcp$'; then
        if [ "$ufw_aktiv" -eq 1 ]; then
            log ERROR "check: 80/tcp eingehend offen (ufw aktiv, Regel gesetzt — soll im Normalbetrieb geschlossen sein)"
            rc=1
        else
            log WARN "check: 80/tcp-Regel gesetzt, aber ufw inaktiv — Regel greift nicht; im Normalbetrieb entfernen"
        fi
    else
        log INFO "check: 80/tcp eingehend nicht erlaubt (Soll)"
    fi

    # systemd-Hardening-Drop-in.
    check_file_mode "$HARDENING_DROPIN" 644 root:root || rc=1

    # AppArmor-Profil (Soll: vorhanden und geladen, mindestens complain).
    # Enforce wird vom Installer nicht automatisch gesetzt; ein complain-Profil
    # ist daher das Soll. Ein zusaetzlicher Hinweis nennt den aktuellen Modus.
    if aa-status 2>/dev/null | grep -q 'usr.sbin.nginx'; then
        if aa-status 2>/dev/null | sed -n '/enforce mode/,/complain mode/p' | grep -q 'usr.sbin.nginx'; then
            log INFO "check: AppArmor-Profil fuer nginx geladen (enforce)"
        else
            log INFO "check: AppArmor-Profil fuer nginx geladen (complain — Weg zu enforce siehe Anleitung 13)"
        fi
    else
        log ERROR "check: AppArmor-Profil fuer nginx nicht geladen"
        rc=1
    fi

    exit "$rc"
}

do_test() {
    require_root
    require_nginx_conf_or_die
    local rc=0

    if systemctl is-active --quiet nginx; then
        log INFO "test: nginx-Dienst aktiv"
    else
        log ERROR "test: nginx-Dienst nicht aktiv"
        rc=1
    fi

    # Lokaler TCP-Connect auf 443 (dependency-frei, sitzungs-neutral).
    if timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/443' 2>/dev/null; then
        log INFO "test: TCP-Connect auf 127.0.0.1:443 ok"
    else
        log ERROR "test: TCP-Connect auf 127.0.0.1:443 fehlgeschlagen"
        rc=1
    fi

    # certbot-Erneuerung als Trockenlauf. Braucht erreichbaren Port 80 —
    # daher temporaer oeffnen. Fail-closed (konv-scripting-bash.md 4.7a):
    # Der EXIT-trap schliesst Port 80 in jedem Fall wieder, auch wenn certbot
    # oder eine andere Anweisung unter `set -e` vorzeitig abbricht. So bleibt
    # kein offener Port 80 zurueck.
    log INFO "test: certbot renew --dry-run (Port 80 temporaer)"
    ufw_allow_in_tcp 80
    trap 'ufw_delete_in_tcp 80' EXIT
    if certbot renew --dry-run >/dev/null 2>&1; then
        log INFO "test: certbot renew --dry-run ok"
    else
        log ERROR "test: certbot renew --dry-run fehlgeschlagen (DNS/Erreichbarkeit pruefen)"
        rc=1
    fi
    ufw_delete_in_tcp 80
    trap - EXIT

    log INFO "test: HTTPS-Abruf der Domains von aussen manuell verifizieren (Zertifikatskette, Redirect 80->443)."
    exit "$rc"
}

#######################################
# Liefert den Markdown-Abschnitt dieses Moduls fuer die Abschluss-Doku.
# Nur lesend; nimmt keine Systemaenderung vor. Gibt ausschliesslich
# Markdown nach stdout aus.
# Globals:   NGINX_VHOST_DOMAIN, NGINX_VHOST_DOCROOT, HARDENING_DROPIN,
#            AA_PROFILE (lesend)
# Outputs:   stdout — Markdown-Abschnitt (beginnt mit "## <Label>")
#######################################
module_doc() {
    load_optional_conf
    nginx_parse_vhosts
    doc_section "Webserver nginx (optional)"
    doc_packages nginx certbot python3-certbot-nginx apparmor-utils
    printf '**Virtuelle Hosts:**\n'
    local i
    for i in "${!NGINX_VHOST_DOMAIN[@]}"; do
        # shellcheck disable=SC2016
        printf -- '- `%s` (root `%s`)\n' \
            "${NGINX_VHOST_DOMAIN[$i]}" "${NGINX_VHOST_DOCROOT[$i]}"
    done
    printf '\n**Firewall:** 443/tcp eingehend dauerhaft; 80/tcp nur temporaer fuer Zertifikatsbezug/-erneuerung.\n\n'
    doc_files_begin
    doc_file "$HARDENING_DROPIN" \
        "NoNewPrivileges=true" "ProtectSystem=strict" "ProtectHome=true" \
        "PrivateTmp=true" "ReadWritePaths=/var/log/nginx /var/lib/nginx /run"
    doc_file "$AA_PROFILE"
    doc_services nginx
    doc_note "TLS je Domain ueber certbot/HTTP-01 (Let's Encrypt). HTTP->HTTPS-Redirect von certbot gesetzt, bleibt als Absicherung erhalten. AppArmor-Basisprofil fuer nginx per aa-autodep erzeugt und im complain-Modus (protokolliert, blockiert nicht; kein Ubuntu-Standardprofil vorhanden, konv-system.md 3.10). Weg zu enforce: Testbetrieb -> aa-logprof -> aa-enforce (siehe Anleitung 13). server_tokens off gesetzt."
}

dispatch "$MODULE" "$@"
