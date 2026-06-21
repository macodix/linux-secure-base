# shellcheck shell=bash
#
# secure-base Helper: Abschluss-Dokumentation
#
# Bietet:
#   doc_val              — conf-Key-Wert aus Allowlist ausgeben (sicherheitskritisch)
#   doc_section          — Markdown-Abschnittsheader schreiben
#   doc_packages         — Paketliste als Markdown ausgeben
#   doc_files_begin      — Einleitung der Datei/Einstellungs-Liste
#   doc_file             — eine Datei mit ihren Einstellungen ausgeben
#   doc_services         — Dienste-Zeile ausgeben
#   doc_timer_cron       — Timer/Cron-Zeile ausgeben
#   doc_list             — eine einfache Aufzaehlungsliste ausgeben
#   doc_note             — Hinweis-Blockquote ausgeben
#   doc_users            — angelegte Benutzer/Gruppen ausgeben (users-Modul)
#   doc_header           — Markdown-Kopf der Gesamt-Doku ausgeben
#   doc_footer           — Markdown-Fuss ausgeben
#   doc_build            — vollstaendige Abschluss-Doku nach stdout bauen
#   sb_install_report    — Doku erzeugen, lokal ablegen, als Mail versenden
#   doc_selftest_no_secrets — erzeugte .md gegen Secrets pruefen
#
# Globals (gesetzt/gelesen):
#   DOC_CONF_WHITELIST   — readonly assoziatives Array der erlaubten Keys
#   SB_REPORT_DIR        — lokales Ablage-Verzeichnis fuer Reports

# Ablage-Verzeichnis fuer lokal gespeicherte Reports (root:adm 0750, Dateien 0600).
readonly SB_REPORT_DIR="/var/log/secure-base/reports"

# -------------------------------------------------------------------------
# Whitelist (sicherheitskritisch — Plan 2.3)
# -------------------------------------------------------------------------

# Allowlist: conf-Keys, deren WERT in die Doku aufgenommen werden darf.
# WHITELIST-PRINZIP (qm-richtlinien.md Kap. 5): Nur hier gelistete Keys
# erscheinen mit Wert. Alles andere — insbesondere jedes Secret — wird
# NICHT ausgegeben. Secrets werden NIE hier eingetragen.
# shellcheck disable=SC2034
declare -rA DOC_CONF_WHITELIST=(
    [FQDN]=1 [ADMIN_MAIL]=1 [TIMEZONE]=1
    [RELAY_HOST]=1 [RELAY_PORT]=1 [RELAY_USER]=1
    [ENABLE_LOGIN_MAIL]=1 [ENABLE_CHALLENGE_RESPONSE_AUTH]=1
    [MAIN_USER]=1 [TOTP_DELIVERY]=1 [UNINSTALL_REMOVE_USER]=1
    [JOURNALD_MAX_USE]=1 [JOURNALD_MAX_RETENTION]=1
    [AUTO_REBOOT]=1 [AUTO_REBOOT_TIME]=1
    [APT_DAILY_TIME]=1 [APT_DAILY_UPGRADE_TIME]=1
    [SFTP_HOST_ALIAS]=1 [SFTP_PATH]=1
    [MONIT_MAIL_FROM]=1 [LYNIS_SCHEDULE]=1
    [IGNOREIP]=1
)

# -------------------------------------------------------------------------
# Helfer-Funktionen fuer module_doc
# -------------------------------------------------------------------------

#######################################
# Gibt den Wert eines conf-Keys aus, NUR wenn er auf der Allowlist steht.
# Sonst Platzhalter + WARN. Setzt das Whitelist-Prinzip durch (Plan 2.3).
# Globals:   DOC_CONF_WHITELIST, <der angefragte Key> (lesend)
# Arguments: $1 — conf-Key-Name (z. B. RELAY_HOST)
# Outputs:   stdout — Wert oder "(nicht dokumentiert)"
#######################################
doc_val() {
    local key=$1
    if [ -z "${DOC_CONF_WHITELIST[$key]:-}" ]; then
        log WARN "doc_val: Key '$key' nicht auf Allowlist — Wert unterdrueckt"
        printf '(nicht dokumentiert)'
        return 0
    fi
    # Indirekte Expansion; leere/ungesetzte Werte als "(leer/Default)".
    local val=${!key:-}
    if [ -z "$val" ]; then
        printf '(leer/Default)'
    else
        printf '%s' "$val"
    fi
}

#######################################
# Schreibt Markdown-Abschnittsheader (## <Label>) nach stdout.
# Arguments: $1 — Abschnitts-Label
# Outputs:   stdout — Markdown
#######################################
doc_section() {
    printf '\n## %s\n\n' "$1"
}

#######################################
# Schreibt die Paketliste als Markdown-Zeile nach stdout.
# Arguments: $* — Paketnamen
# Outputs:   stdout — Markdown
#######################################
doc_packages() {
    if [ "$#" -eq 0 ]; then
        return
    fi
    local joined
    printf -v joined '%s, ' "$@"
    printf '**Pakete:** %s\n\n' "${joined%, }"
}

#######################################
# Leitet den Dateien/Einstellungs-Abschnitt ein.
# Outputs:   stdout — Markdown
#######################################
doc_files_begin() {
    printf '**Dateien/Einstellungen:**\n\n'
}

#######################################
# Schreibt einen Datei-Eintrag mit optionalen Einstellungs-Zeilen.
# Arguments: $1 — Pfad, $2+ — Einstellungs-Zeilen (optional)
# Outputs:   stdout — Markdown
#######################################
doc_file() {
    local path=$1
    shift
    if [ "$#" -eq 0 ]; then
        # shellcheck disable=SC2016  # Backtick ist Markdown-Syntax, keine Shell-Expansion
        # -- verhindert Fehler bei bash >= 5.3 (Formatstring beginnt mit '-').
        printf -- '- `%s`\n' "$path"
    else
        # shellcheck disable=SC2016
        printf -- '- `%s`:\n' "$path"
        local line
        for line in "$@"; do
            # shellcheck disable=SC2016
            printf '  - `%s`\n' "$line"
        done
    fi
}

#######################################
# Schreibt die Dienste-Zeile.
# Arguments: $* — Dienstnamen
# Outputs:   stdout — Markdown
#######################################
doc_services() {
    if [ "$#" -eq 0 ]; then
        return
    fi
    local joined
    printf -v joined '%s, ' "$@"
    printf '\n**Dienste:** %s (enabled, aktiv nach install)\n' "${joined%, }"
}

#######################################
# Schreibt die Timer/Cron-Zeile.
# Arguments: $1 — Beschreibung
# Outputs:   stdout — Markdown
#######################################
doc_timer_cron() {
    printf '\n**Timer/Cron:** %s\n' "$1"
}

#######################################
# Schreibt eine einfache Aufzaehlungsliste.
# Arguments: $* — Listenpunkte
# Outputs:   stdout — Markdown
#######################################
doc_list() {
    local item
    for item in "$@"; do
        # -- verhindert Fehler bei bash >= 5.3 (Formatstring beginnt mit '-').
        printf -- '- %s\n' "$item"
    done
}

#######################################
# Schreibt einen Hinweis als Blockquote.
# Arguments: $* — Hinweistext
# Outputs:   stdout — Markdown
#######################################
doc_note() {
    printf '\n> Hinweis: %s\n' "$*"
}

#######################################
# Schreibt die angelegten Benutzer/Gruppen (users-Modul).
# Arguments: $1 — Benutzername, $2+ — Gruppen
# Outputs:   stdout — Markdown
#######################################
doc_users() {
    local user=$1
    shift
    local groups_joined
    printf -v groups_joined '%s, ' "$@"
    printf '\n**Angelegte Benutzer:** %s (Gruppen: %s)\n' \
        "$user" "${groups_joined%, }"
}

# -------------------------------------------------------------------------
# Markdown-Rahmen
# -------------------------------------------------------------------------

#######################################
# Schreibt den Markdown-Kopf der Gesamt-Doku nach stdout.
# Bei rc != 0 mit Abbruch-Vermerk und Liste der fehlenden Module (Plan 2.7).
# Arguments: $1 — FQDN, $2 — Zeitstempel, $3 — Subkommando,
#            $4 — rc (0=Erfolg), $5 — abgebrochenes Modul (leer bei Erfolg),
#            $6+ — Liste der erfolgreichen Module
# Globals:   INSTALL_ORDER, MODULES_ENABLED
# Outputs:   stdout — Markdown
#######################################
doc_header() {
    local fqdn=$1 ts=$2 sub=$3 rc=$4 abbruch_modul=$5
    shift 5
    local -a erfolgreiche=("$@")
    local n_module=${#erfolgreiche[@]}

    if [ "$rc" -ne 0 ]; then
        printf '# secure-base — Abschluss-Dokumentation (LAUF ABGEBROCHEN)\n\n'
    else
        printf '# secure-base — Abschluss-Dokumentation\n\n'
    fi

    printf 'Host: %s\n' "$fqdn"
    printf 'Erzeugt: %s\n' "$ts"
    if [ "$rc" -ne 0 ] && [ -n "$abbruch_modul" ]; then
        printf 'Lauf: %s — ABGEBROCHEN bei Modul %s\n\n' "$sub" "$abbruch_modul"
    else
        printf 'Lauf: %s (%d Module)\n\n' "$sub" "$n_module"
    fi

    if [ "$rc" -ne 0 ] && [ -n "$abbruch_modul" ]; then
        # Fehlende Module ermitteln: in INSTALL_ORDER und MODULES_ENABLED,
        # aber nicht in den erfolgreichen Modulen.
        local fehlende=()
        if declare -p INSTALL_ORDER >/dev/null 2>&1 \
            && declare -p MODULES_ENABLED >/dev/null 2>&1; then
            local m
            for m in "${INSTALL_ORDER[@]}"; do
                # Nur aktivierte Module beruecksichtigen.
                local aktiviert=0
                local em
                for em in "${MODULES_ENABLED[@]}"; do
                    [ "$em" = "$m" ] && aktiviert=1 && break
                done
                [ "$aktiviert" -eq 0 ] && continue
                # Nicht in den erfolgreichen enthalten?
                local gefunden=0
                local sm
                for sm in "${erfolgreiche[@]}"; do
                    [ "$sm" = "$m" ] && gefunden=1 && break
                done
                [ "$gefunden" -eq 0 ] && fehlende+=("$m")
            done
        fi
        printf '> ACHTUNG: Dieser Lauf wurde bei Modul "%s" abgebrochen.\n' \
            "$abbruch_modul"
        if [ "${#fehlende[@]}" -gt 0 ]; then
            local fl_joined
            printf -v fl_joined '%s, ' "${fehlende[@]}"
            printf '> Folgende Module wurden NICHT abgeschlossen: %s.\n' \
                "${fl_joined%, }"
        fi
        printf '> Diese Dokumentation umfasst nur die zuvor erfolgreich abgeschlossenen Module.\n\n'
    fi

    printf 'Diese Dokumentation listet die in diesem Installationslauf vorgenommenen\n'
    printf 'Aenderungen je aktiviertem Modul. Passwoerter und andere Geheimnisse sind\n'
    printf 'bewusst ausgelassen.\n\n'

    # Inhaltsverzeichnis aus erfolgreichen Modulen.
    if [ "${#erfolgreiche[@]}" -gt 0 ]; then
        printf '## Inhalt\n\n'
        local m
        for m in "${erfolgreiche[@]}"; do
            # Label aus SB_MODUL_LABEL (falls verfuegbar), sonst Modulname.
            local label
            label=${SB_MODUL_LABEL[$m]:-$m}
            # -- verhindert Fehler bei bash >= 5.3 (Formatstring beginnt mit '-').
            printf -- '- %s\n' "$label"
        done
        printf '\n'
    fi
}

#######################################
# Schreibt den Markdown-Fuss nach stdout.
# Globals:   SB_LOG_FILE (aus log.sh)
# Outputs:   stdout — Markdown
#######################################
doc_footer() {
    printf '\n---\n'
    printf 'Logfile dieses Laufs: %s\n' "${SB_LOG_FILE:-/var/log/secure-base/secure-base.log}"
}

# -------------------------------------------------------------------------
# Sammler und Versand
# -------------------------------------------------------------------------

#######################################
# Baut die vollstaendige Abschluss-Doku als Markdown nach stdout.
# Ruft jedes erfolgreiche Modul als eigenen Prozess ("$skript" doc) und
# faengt dessen stdout ab.
# Arguments: $1 — Subkommando, $2 — Lauf-rc (0=Erfolg, sonst Abbruch),
#            $3 — abgebrochenes Modul (nur bei rc!=0 ausgewertet),
#            $4+ — Liste erfolgreicher Module (in Order)
# Globals:   FQDN (lesend), SCRIPT_DIR, INSTALL_ORDER, MODULES_ENABLED
# Outputs:   stdout — Markdown
# Returns:   0 ok, 1 ein Modul-Skript fehlte/war nicht ausfuehrbar
#            oder sein doc-Lauf schlug fehl
#######################################
doc_build() {
    local sub=$1 rc=$2 abbruch_modul=$3
    shift 3
    local ts
    printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1
    # Kopf: bei rc!=0 mit Abbruch-Vermerk und Liste der fehlenden Module.
    # shellcheck disable=SC2153  # FQDN kommt aus load_conf, statisch nicht sichtbar
    doc_header "$FQDN" "$ts" "$sub" "$rc" "$abbruch_modul" "$@"
    local modul skript abschnitt
    for modul in "$@"; do
        skript="${SCRIPT_DIR}/lib/modules/${modul}.sh"
        if [ ! -x "$skript" ]; then
            log ERROR "doc_build: Modul-Skript nicht ausfuehrbar: $skript"
            return 1
        fi
        # Modul als eigener Prozess mit Subkommando doc; stdout abfangen.
        # Eigener Prozess => eigenes SCRIPT_DIR/MODULE, $0 zeigt aufs Modul:
        # keine readonly-/$0-Kollision. Fail-closed: schlaegt der doc-Lauf
        # fehl, Abbruch mit Meldung (kein 2>&1-Verschlucken — Plan 2.3/4.7).
        if ! abschnitt=$("$skript" doc); then
            log ERROR "doc_build: doc-Lauf von '$modul' fehlgeschlagen"
            return 1
        fi
        printf '%s\n' "$abschnitt"
    done
    doc_footer
}

#######################################
# Erzeugt die Abschluss-Doku, legt sie lokal ab und mailt sie an ADMIN_MAIL.
# Fail-soft: schlaegt der Versand fehl oder fehlt der Mailweg, bleibt der
# Lauf-Exit-Code unveraendert (WARN), die Datei liegt lokal vor.
# Bei Abbruch (rc != 0): Teil-Doku der erfolgreichen Module mit Abbruch-Vermerk.
# Arguments: $1 — Subkommando, $2 — Lauf-rc (0=Erfolg),
#            $3 — abgebrochenes Modul (leer bei Erfolg), $4+ — erfolgreiche Module
# Globals:   ADMIN_MAIL, FQDN, ENABLE_INSTALL_REPORT, SB_REPORT_DIR (lesend)
# Returns:   0 versendet/lokal-ok, 1 Mailweg fehlte oder Versand schlug fehl
#######################################
sb_install_report() {
    local sub=$1 rc=$2 abbruch_modul=$3
    shift 3
    [ "$sub" = "install" ] || return 0
    [ "${ENABLE_INSTALL_REPORT:-yes}" = "yes" ] || return 0
    # Keine Module erfolgreich (z. B. Abbruch im ersten Modul): keine Doku.
    [ "$#" -gt 0 ] || return 1

    # FQDN ist Pfadbestandteil des Dateinamens — vor Verwendung validieren
    # (Muster wie postfix.sh), damit kein Tippfehler/Schadwert den Pfad verbiegt.
    if ! [[ "${FQDN:-}" =~ ^[A-Za-z0-9.-]+$ ]]; then
        log WARN "FQDN unzulaessig fuer Report-Dateiname: '${FQDN:-}' — keine Doku"
        return 1
    fi

    local datum stamp md_file betreff
    printf -v datum '%(%Y-%m-%d)T' -1
    printf -v stamp '%(%Y%m%d-%H%M%S)T' -1
    md_file="${SB_REPORT_DIR}/secure-base-report_${FQDN}_${stamp}.md"
    if [ "$rc" -eq 0 ]; then
        betreff="secure-base Installation ${FQDN} — ${datum}"
    else
        betreff="secure-base Installation ${FQDN} — ABGEBROCHEN (${datum})"
    fi

    # Verzeichnis root:adm 0750 (analog log.sh open_log).
    install -d -o root -g adm -m 0750 "$SB_REPORT_DIR"
    # doc_build erhaelt rc + abgebrochenes Modul fuer den Abbruch-Vermerk.
    # Schlaegt doc_build fehl (fehlendes/unsourcbares Modul), keine Mail.
    if ! ( umask 077; doc_build "$sub" "$rc" "$abbruch_modul" "$@" > "$md_file" ); then
        log WARN "Abschluss-Doku konnte nicht erzeugt werden — kein Versand"
        return 1
    fi
    chmod 600 "$md_file"
    log INFO "Abschluss-Doku erzeugt: $md_file"

    # Mailweg pruefen: ADMIN_MAIL gesetzt UND mail da UND postfix aktiv.
    if [ -z "${ADMIN_MAIL:-}" ] \
        || ! command -v mail >/dev/null 2>&1 \
        || ! systemctl is-active --quiet postfix 2>/dev/null; then
        log WARN "Kein Mailweg (postfix/ADMIN_MAIL/mail) — Doku nur lokal: $md_file"
        return 1
    fi

    # Versand als Mail-TEXT (kein Anhang): Markdown ist Klartext und im Body
    # lesbar. Der .md-Datei-Anhang kam beim Empfaenger nicht an (Grund nicht
    # belegt, vermutlich Content-Type-/Endungs-Filter; PNG-Anhaenge kommen
    # dagegen an). Als Body kommt der Report zuverlaessig an; lokaler .md bleibt.
    if mail -s "$betreff" "$ADMIN_MAIL" < "$md_file"; then
        log INFO "Abschluss-Doku an $ADMIN_MAIL versendet"
        return 0
    else
        log WARN "Versand der Abschluss-Doku an $ADMIN_MAIL fehlgeschlagen — Datei liegt lokal: $md_file"
        return 1
    fi
}

#######################################
# Prueft eine erzeugte Doku-Datei gegen Secrets. Schlaegt fehl, wenn ein
# Secret-Variablenname oder -Wert in der Markdown-Datei auftaucht.
# Arguments: $1 — Pfad der erzeugten .md
# Returns:   0 sauber, 1 Secret gefunden
#######################################
doc_selftest_no_secrets() {
    local md=$1
    local key val
    for key in RELAY_PASSWORD MAIN_USER_PASSWORD RESTIC_PASSPHRASE; do
        # Variablenname darf nicht auftauchen.
        if grep -qF -- "$key" "$md"; then
            log ERROR "doc-Selbsttest: Secret-Name '$key' in $md gefunden"
            return 1
        fi
        # Wert (falls gesetzt) darf nicht auftauchen.
        val=${!key:-}
        if [ -n "$val" ] && grep -qF -- "$val" "$md"; then
            log ERROR "doc-Selbsttest: Wert von '$key' in $md gefunden"
            return 1
        fi
    done
    return 0
}
