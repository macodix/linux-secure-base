#!/bin/bash
#
# Linux Secure Base — Modul restic
# Verschluesselte Datensicherung mit restic auf ein externes SFTP-Ziel:
# legt die Repo-Passphrase ab, initialisiert das remote Repo und richtet
# Backup-Skript + taeglichen cron-Job ein. Kein Modul-eigener Dienst
# (cron = Distro-Default). Im Fehlerfall verschickt das Backup-Skript
# selbst eine Mail ueber das postfix-Relay.
#
# VORBEDINGUNG: Der SFTP-Zugang (SSH-Schluessel, /root/.ssh/config-Alias,
# Autorisierung beim Anbieter, Host-Key in known_hosts) ist bereits
# eingerichtet. Dieses Modul richtet KEINE SFTP-Verbindung ein; es prueft
# nur ihre Erreichbarkeit (fail-fast).
#
# Aufruf: restic.sh {install|uninstall|check|test}

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
readonly SCRIPT_DIR

# shellcheck source=../../lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

readonly MODULE="restic"
readonly PASSPHRASE_FILE="/root/config/restic-passphrase"

# --- Hilfsfunktionen -------------------------------------------------

# Non-interaktiver Erreichbarkeits-Test des SFTP-Ziels ueber den
# bestehenden Host-Alias (Vorbedingung). Bewusst per sftp-Subsystem (nicht
# 'ssh host cmd'): viele Backup-Anbieter erlauben KEINE Kommando-Ausfuehrung,
# nur SFTP — genau wie restic die Verbindung nutzt. BatchMode=yes erzwingt
# nicht-interaktiv.
sftp_reachable() {
    printf 'pwd\n' | sftp -o BatchMode=yes -b - "$SFTP_HOST_ALIAS" >/dev/null 2>&1
}

# Legt das Zielverzeichnis idempotent ueber das sftp-Subsystem an. sftp
# kennt kein 'mkdir -p'; daher jede Pfadkomponente einzeln per '-mkdir'
# (fuehrendes '-' ignoriert 'existiert bereits'), zum Schluss 'cd <pfad>'
# OHNE '-' als Erfolgs-Verifikation.
sftp_ensure_dir() {
    local path=$1 acc="" comp batch=""
    local -a parts
    IFS=/ read -ra parts <<<"$path"
    for comp in "${parts[@]}"; do
        [ -n "$comp" ] || continue
        acc="$acc/$comp"
        batch+="-mkdir $acc"$'\n'
    done
    batch+="cd $path"$'\n'
    printf '%s' "$batch" | sftp -o BatchMode=yes -b - "$SFTP_HOST_ALIAS"
}

# Validiert alle Werte, BEVOR sie in die Repo-URL, ssh-Aufrufe, das
# Backup-Skript oder Datei-/Cron-Dateinamen gehen. Anchored Zeichensaetze
# schliessen Whitespace/Newline/Metazeichen aus. RESTIC_PASSPHRASE darf
# leer sein (Leer-Wert-Fallback).
require_restic_conf() {
    if ! [[ "${FQDN:-}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
        die "FQDN ('${FQDN:-}') ist leer oder kein gueltiger Hostname (erwartet z. B. server.example.com). In secure-base.conf korrigieren."
    fi
    if ! [[ "${ADMIN_MAIL:-}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]; then
        die "ADMIN_MAIL ('${ADMIN_MAIL:-}') ist leer oder keine gueltige Mail-Adresse (erwartet z. B. admin@example.com). In secure-base.conf korrigieren."
    fi
    if ! [[ "${SFTP_HOST_ALIAS:-}" =~ ^[A-Za-z0-9._-]+$ ]]; then
        die "SFTP_HOST_ALIAS ('${SFTP_HOST_ALIAS:-}') ist leer oder enthaelt ungueltige Zeichen (erlaubt: A-Z a-z 0-9 . _ -). Muss ein bestehender Alias aus /root/.ssh/config sein. In secure-base.conf korrigieren."
    fi
    if ! [[ "${SFTP_PATH:-}" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
        die "SFTP_PATH ('${SFTP_PATH:-}') ist leer oder kein gueltiger absoluter Pfad (ohne Whitespace/Sonderzeichen). In secure-base.conf korrigieren."
    fi
}

# Schreibt die Repo-Passphrase deterministisch (umask 077, chmod 600).
write_passphrase_file() {
    local value=$1
    ( umask 077; printf '%s\n' "$value" > "$PASSPHRASE_FILE" )
    chmod 600 "$PASSPHRASE_FILE"
}

# Schreibt das Backup-Skript (vollstaendig eigene Datei). repo,
# ADMIN_MAIL und FQDN werden zur Generierungszeit eingesetzt; die
# script-internen $-Ausdruecke bleiben per \$ literal.
write_backup_script() {
    local target=$1 repo=$2
    cat > "$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail

# Von secure-base/restic angelegt - nicht von Hand editieren.
# cron-Umgebung ist spartanisch - PATH explizit setzen.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RESTIC_REPO="$repo"
RESTIC_PASS="$PASSPHRASE_FILE"
ADMIN_MAIL="$ADMIN_MAIL"
LOGFILE="\$(mktemp)"
trap 'rm -f "\$LOGFILE"' EXIT

run() {
    restic -r "\$RESTIC_REPO" -p "\$RESTIC_PASS" backup \\
        /etc /home /var/log /root
    restic -r "\$RESTIC_REPO" -p "\$RESTIC_PASS" forget \\
        --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
}

if ! run >"\$LOGFILE" 2>&1; then
    mail -s "Backup FEHLGESCHLAGEN auf $FQDN" "\$ADMIN_MAIL" \\
        <"\$LOGFILE"
    exit 1
fi

# Erfolgs-Sentinel fuer die monit-Frische-Ueberwachung (restic-Check).
# Nur im Erfolgspfad; ein Fehler hier darf den Backup-Erfolg NICHT
# ueberschreiben (daher '|| true').
mkdir -p /var/lib/secure-base 2>/dev/null || true
touch /var/lib/secure-base/restic-last-success 2>/dev/null || true
EOF
    chmod 700 "$target"
}

# --- Subkommandos ----------------------------------------------------

do_install() {
    require_root
    load_conf "$SB_CONF"
    require_restic_conf

    local repo backup_script cron_file
    repo="sftp:${SFTP_HOST_ALIAS}:${SFTP_PATH}"
    backup_script="/usr/local/sbin/${FQDN}-backup.sh"
    cron_file="/etc/cron.d/${FQDN}-backup"

    # (1) Paket installieren.
    log INFO "restic install: Paket restic installieren"
    pkg_install restic

    # (2) SFTP-Erreichbarkeit pruefen (fail-fast; Verbindung ist
    #     Vorbedingung, wird hier NICHT eingerichtet).
    log INFO "restic install: SFTP-Erreichbarkeit ueber Alias '$SFTP_HOST_ALIAS' pruefen (sftp)"
    if ! sftp_reachable; then
        die "SFTP-Zugang ueber Alias '$SFTP_HOST_ALIAS' nicht nutzbar (sftp). Vorbedingung pruefen: 'sftp $SFTP_HOST_ALIAS' muss non-interaktiv gehen — SSH-Schluessel + /root/.ssh/config-Eintrag + .pub beim Anbieter hinterlegt + Host-Key in known_hosts."
    fi

    # (3) Zielverzeichnis am SFTP-Ziel idempotent sicherstellen (ueber das
    #     sftp-Subsystem; existiert SFTP_PATH bereits, kein Abbruch).
    log INFO "restic install: Zielverzeichnis $SFTP_PATH am SFTP-Ziel sicherstellen (sftp mkdir, idempotent)"
    local mkout
    if ! mkout=$(sftp_ensure_dir "$SFTP_PATH" 2>&1); then
        [ -n "$mkout" ] && while IFS= read -r mkline; do log ERROR "sftp: $mkline"; done <<<"$mkout"
        die "Zielverzeichnis $SFTP_PATH am SFTP-Ziel konnte nicht angelegt/erreicht werden — Pfad bzw. Schreibrechte am Anbieter pruefen."
    fi

    # (4) Passphrase-Datei schreiben.
    install -d -m 0700 /root/config
    local newpass=${RESTIC_PASSPHRASE:-}
    if [ ! -e "$PASSPHRASE_FILE" ]; then
        if [ -n "$newpass" ]; then
            write_passphrase_file "$newpass"
            log INFO "restic install: Repo-Passphrase nach $PASSPHRASE_FILE geschrieben"
        else
            # WICHTIG: stdout/stderr werden per tee ins Logfile (0640,
            # Gruppe adm) gespiegelt. In diesem Geheimnis-Block KEIN
            # 'set -x' aktivieren — read -rs unterdrueckt das Echo, der
            # Wert landet so nicht im Log; ein Trace wuerde ihn leaken.
            local entered
            printf 'Repo-Passphrase fuer restic eingeben: ' >&2
            IFS= read -rs entered
            printf '\n' >&2
            write_passphrase_file "$entered"
            unset entered
            log INFO "restic install: Repo-Passphrase interaktiv gesetzt ($PASSPHRASE_FILE)"
        fi
    elif [ -z "$newpass" ]; then
        log INFO "restic install: Repo-Passphrase bereits vorhanden — uebersprungen"
    else
        local current
        current=$(cat "$PASSPHRASE_FILE")
        if [ "$current" = "$newpass" ]; then
            log INFO "restic install: Repo-Passphrase unveraendert — uebersprungen"
        elif restic -r "$repo" -p "$PASSPHRASE_FILE" cat config >/dev/null 2>&1; then
            die "RESTIC_PASSPHRASE weicht von der bestehenden $PASSPHRASE_FILE ab, mit der das Repo aktuell erreichbar und entschluesselbar ist. Ueberschreiben wuerde das Repo verwaisen lassen. RESTIC_PASSPHRASE in secure-base.conf auf den korrekten Wert setzen, oder Datei/Repo bewusst manuell zuruecksetzen."
        elif ! sftp_reachable >/dev/null 2>&1; then
            die "RESTIC_PASSPHRASE weicht von der bestehenden Passphrase-Datei ab, und das SFTP-Ziel ist gerade NICHT erreichbar — ob dahinter ein mit der alten Passphrase entschluesselbares Repo liegt, laesst sich nicht feststellen. Ueberschreiben unterbleibt. SFTP-Ziel pruefen und install erneut starten."
        else
            log WARN "restic install: RESTIC_PASSPHRASE weicht von der bestehenden Passphrase-Datei ab; Ziel erreichbar, aber Repo mit bestehender Passphrase nicht oeffenbar (nicht initialisiert oder mit anderer Passphrase angelegt) — Datei wird mit neuer Passphrase ueberschrieben. Falls am Ziel ein fremdes/aelteres Repo liegt, manuell pruefen."
            write_passphrase_file "$newpass"
        fi
    fi

    # (5) Repo initialisieren (Skip, wenn schon initialisiert).
    if restic -r "$repo" -p "$PASSPHRASE_FILE" cat config >/dev/null 2>&1; then
        log INFO "restic install: Repo $repo bereits initialisiert — uebersprungen"
    else
        log INFO "restic install: Repo $repo initialisieren"
        restic -r "$repo" -p "$PASSPHRASE_FILE" init
    fi

    # (6) Backup-Skript schreiben (vollstaendig eigene Datei).
    log INFO "restic install: Backup-Skript $backup_script schreiben (0700)"
    write_backup_script "$backup_script" "$repo"

    # (7) Cron-Datei schreiben (vollstaendig eigene Datei, taeglich 02:30).
    log INFO "restic install: Cron-Datei $cron_file schreiben (0644, taeglich 02:30)"
    cat > "$cron_file" <<EOF
# Datensicherung (restic) - taeglich um 02:30
# Von secure-base/restic angelegt - nicht von Hand editieren.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 2 * * *  root  $backup_script
EOF
    chmod 644 "$cron_file"

    # (8) Baseline-Sentinel fuer die monit-Frische-Ueberwachung anlegen,
    #     damit der monit-restic-Check nicht schon vor dem ersten geplanten
    #     Backup alarmiert. Das Verzeichnis bleibt bei uninstall liegen.
    log INFO "restic install: monit-Frische-Sentinel /var/lib/secure-base/restic-last-success anlegen (Baseline)"
    install -d -m 0755 -o root -g root /var/lib/secure-base
    touch /var/lib/secure-base/restic-last-success

    # (9) Klartext-Geheimnis aus dem Speicher entfernen.
    unset newpass current 2>/dev/null || true
    unset RESTIC_PASSPHRASE
    log INFO "restic install: abgeschlossen (Passphrase liegt nur noch in $PASSPHRASE_FILE, 0600)"
}

do_uninstall() {
    require_root
    # restic.conf wird NICHT geladen: der Rueckbau ist konfig-unabhaengig.
    # Ausnahme secure-base.conf: Backup-Skript und Cron-Datei sind FQDN-benannt,
    # daher wird FQDN benoetigt. Direktes source (statt load_conf), damit ein
    # fehlendes/defektes secure-base.conf den fail-safe Teardown nicht abbricht.
    # Der SFTP-Zugang (Schluessel, /root/.ssh/config) gehoert der Vorbedingung
    # und wird NICHT angefasst.
    local fqdn=""
    if [ -r "$SB_CONF" ]; then
        # shellcheck disable=SC1090
        source "$SB_CONF"
        fqdn=${FQDN:-}
        # FQDN gegen den Namens-Zeichensatz pruefen, bevor er in Dateipfade
        # geht (kein Pfad-Traversal aus einem manipulierten secure-base.conf).
        if ! [[ "$fqdn" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
            fqdn=""
        fi
    fi
    if [ -n "$fqdn" ]; then
        local backup_script="/usr/local/sbin/${fqdn}-backup.sh"
        local cron_file="/etc/cron.d/${fqdn}-backup"
        local f
        for f in "$cron_file" "$backup_script"; do
            if [ -f "$f" ]; then
                log INFO "restic uninstall: $f entfernen"
                rm -f "$f"
            fi
        done
    else
        log WARN "restic uninstall: FQDN aus $SB_CONF nicht ermittelbar — Backup-Skript und Cron-Datei NICHT entfernt (manuell pruefen: /usr/local/sbin/<fqdn>-backup.sh, /etc/cron.d/<fqdn>-backup)."
    fi

    # Paket entfernen (ohne --purge). Passphrase und remote Repo bleiben
    # bewusst erhalten (Re-install ohne Neuanlage).
    if pkg_installed restic; then
        log INFO "restic uninstall: Paket restic entfernen (ohne --purge)"
        pkg_remove restic
    else
        log INFO "restic uninstall: Paket restic nicht installiert — nichts zu entfernen"
    fi

    log INFO "restic uninstall: Passphrase ($PASSPHRASE_FILE), remote Repo und SFTP-Zugang (Vorbedingung) bleiben unveraendert."
    log WARN "restic uninstall: $PASSPHRASE_FILE ist ein KLARTEXT-Geheimnis und liegt weiterhin auf der Platte. Bei endgueltiger Ausserdienststellung oder Weitergabe der Maschine manuell loeschen."
}

do_check() {
    require_root
    load_conf "$SB_CONF"
    require_restic_conf

    local rc=0
    local backup_script cron_file
    backup_script="/usr/local/sbin/${FQDN}-backup.sh"
    cron_file="/etc/cron.d/${FQDN}-backup"

    check_packages restic || rc=1
    check_file_mode "$PASSPHRASE_FILE" 600 root:root || rc=1
    check_file_mode "$backup_script"   700 root:root || rc=1
    check_file_mode "$cron_file"       644 root:root || rc=1

    exit "$rc"
}

do_test() {
    require_root
    load_conf "$SB_CONF"
    require_restic_conf

    local rc=0
    local repo
    repo="sftp:${SFTP_HOST_ALIAS}:${SFTP_PATH}"

    if ! pkg_installed restic; then
        log ERROR "test: Paket restic nicht installiert — kein Funktionstest moeglich"
        exit 1
    fi

    # (1) mail-Verfuegbarkeit (Backup-Skript braucht es fuer die Fehlermail).
    if command -v mail >/dev/null 2>&1; then
        log INFO "test: mail-Befehl vorhanden"
    else
        log WARN "test: mail-Befehl fehlt — Fehlermail des Backup-Skripts wuerde nicht zugestellt; postfix-Modul vorab laufen lassen."
    fi

    # (2) SFTP-Erreichbarkeit ueber den bestehenden Alias.
    log INFO "test: SFTP-Erreichbarkeit ueber Alias '$SFTP_HOST_ALIAS' pruefen"
    if sftp_reachable; then
        log INFO "test: SFTP-Ziel erreichbar"
    else
        log ERROR "test: SFTP-Ziel ueber Alias '$SFTP_HOST_ALIAS' nicht erreichbar (Vorbedingung pruefen)"
        rc=1
    fi

    # (3) Repo initialisiert und entschluesselbar.
    local out catrc=0
    out=$(restic -r "$repo" -p "$PASSPHRASE_FILE" cat config 2>&1) || catrc=$?
    if [ -n "$out" ]; then
        local line
        while IFS= read -r line; do log INFO "restic cat config: $line"; done <<<"$out"
    fi
    if [ "$catrc" -eq 0 ]; then
        log INFO "test: Repo $repo initialisiert und mit der Passphrase entschluesselbar"
    else
        log ERROR "test: restic cat config fehlgeschlagen (Exit $catrc) — Repo nicht initialisiert/erreichbar oder Passphrase falsch"
        rc=1
    fi

    # (4) Snapshot-Liste (leere Liste direkt nach install ist kein Fehler).
    local sout snrc=0
    sout=$(restic -r "$repo" -p "$PASSPHRASE_FILE" snapshots 2>&1) || snrc=$?
    if [ -n "$sout" ]; then
        local sline
        while IFS= read -r sline; do log INFO "restic snapshots: $sline"; done <<<"$sout"
    fi
    if [ "$snrc" -ne 0 ]; then
        log ERROR "test: restic snapshots fehlgeschlagen (Exit $snrc)"
        rc=1
    fi

    exit "$rc"
}

#######################################
# Liefert den Markdown-Abschnitt dieses Moduls fuer die Abschluss-Doku.
# Nur lesend; nimmt keine Systemaenderung vor. Gibt ausschliesslich
# Markdown nach stdout aus. Nimmt conf-Werte ueber die von do_doc per
# load_conf geladene Umgebung ab.
# Globals:   PASSPHRASE_FILE (lesend, via doc_val)
# Outputs:   stdout — Markdown-Abschnitt (beginnt mit "## <Label>")
#######################################
module_doc() {
    doc_section "Datensicherung"
    doc_packages restic
    doc_files_begin
    doc_file "$PASSPHRASE_FILE" \
        "Repo-Passphrase (0600 root:root)"
    doc_file "/usr/local/sbin/$(doc_val FQDN)-backup.sh" \
        "Backup-Skript (taeglicher Cron-Lauf)"
    doc_file "/etc/cron.d/$(doc_val FQDN)-backup" \
        "Cron-Eintrag: restic backup + forget"
    # shellcheck disable=SC2016  # Backtick ist Markdown-Syntax, keine Shell-Expansion
    printf '\n**SFTP-Ziel:** `%s:%s`\n\n' \
        "$(doc_val SFTP_HOST_ALIAS)" "$(doc_val SFTP_PATH)"
    doc_timer_cron "taeglicher Lauf via /etc/cron.d/$(doc_val FQDN)-backup"
    doc_note "Repo-Passphrase wird nicht dokumentiert (Secret)."
}

#######################################
# Subkommando "doc": laedt die conf und gibt module_doc nach stdout.
# Nur lesend, kein require_root.
# Globals:   SB_CONF (lesend)
# Outputs:   stdout — Markdown-Abschnitt dieses Moduls
#######################################
do_doc() {
    load_conf "$SB_CONF"
    module_doc
}

dispatch "$MODULE" "$@"
