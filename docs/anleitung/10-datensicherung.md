# Datensicherung (restic)

Die Datensicherung erfolgt mit `restic` auf einen externen SFTP-Raum. Das Repository ist verschlüsselt. Die Passphrase liegt in `/root/config/restic-passphrase` (Mode 600). Ein Cron-Eintrag löst den Lauf täglich um 02:30 aus (RPO 24 h). Bei Fehlschlag verschickt das Backup-Skript selbst eine Mail.

Gesichert werden im Grundzustand `/etc`, `/home`, `/var/log` und `/root`. Werden später weitere Dienste mit eigenen Datenverzeichnissen eingerichtet, kommen deren Pfade hinzu.

## 1. Installation

```
apt install restic
```

## 2. SSH-Zugang zum SFTP-Ziel (Vorbedingung)

Dieser Schritt ist Vorbedingung und vom Betreiber vorab manuell zu erledigen. Das Backup-Skript richtet die Verbindung nicht ein. Es prüft zu Beginn nur non-interaktiv die Erreichbarkeit über das sftp-Subsystem und bricht sonst ab (SFTP-only-Anbieter erlauben kein `ssh host cmd`).

Für `root` einen eigenen SSH-Schlüssel erzeugen und am SFTP-Ziel hinterlegen:

```
ssh-keygen -t ed25519 -f /root/.ssh/id_restic
ssh-copy-id -i /root/.ssh/id_restic.pub <user>@<host>
```

In `/root/.ssh/config` einen Host-Alias anlegen, damit `restic` den Schlüssel ohne weitere Angabe findet:

```
Host restic-backup
    HostName <host>
    User <user>
    IdentityFile /root/.ssh/id_restic
```

Die append-only-Eigenschaft des Ziels (vom Server aus nicht löschbare Stände) leistet der Speicher-Anbieter über Snapshots. Ob der gewählte Anbieter das erfüllt, prüft der Betrieb.

## 3. Passphrase und Repository

Die Repo-Passphrase als `root` außerhalb des Repos ablegen:

```
mkdir -p /root/config
( umask 077; cat > /root/config/restic-passphrase )
<Passphrase eingeben, mit Strg-D abschließen>
chmod 600 /root/config/restic-passphrase
```

Das Repository initialisieren:

```
restic -r sftp:restic-backup:/backups/<server> -p /root/config/restic-passphrase init
```

Passphrase und SFTP-Schlüssel sind für den Notfall sicher und getrennt vom Server zu hinterlegen. Ohne sie ist das Repository nicht wiederherstellbar.

## 4. Backup-Skript

Unter `/usr/local/sbin/<FQDN>-backup.sh` anlegen (der Installer setzt `<FQDN>` auf den Wert aus `secure-base.conf`):

```
#!/usr/bin/env bash
set -euo pipefail

# cron-Umgebung ist spartanisch — PATH explizit setzen
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RESTIC_REPO="sftp:restic-backup:/backups/<server>"
RESTIC_PASS="/root/config/restic-passphrase"
ADMIN_MAIL="<admin@meine-domain.de>"
LOGFILE="$(mktemp)"
trap 'rm -f "$LOGFILE"' EXIT

run() {
    restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" backup \
        /etc /home /var/log /root
    restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" forget \
        --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
}

if ! run >"$LOGFILE" 2>&1; then
    mail -s "Backup FEHLGESCHLAGEN auf $(hostname -f)" "$ADMIN_MAIL" \
        <"$LOGFILE"
    exit 1
fi

# Erfolgs-Kennzeichen fuer die monit-Frische-Ueberwachung (Kapitel 11).
# Nur im Erfolgspfad; ein Fehler hier darf den Backup-Erfolg nicht ueberschreiben.
mkdir -p /var/lib/secure-base 2>/dev/null || true
touch /var/lib/secure-base/restic-last-success 2>/dev/null || true
```

```
chmod 700 /usr/local/sbin/<FQDN>-backup.sh
```

Die `forget`-Politik setzt die Aufbewahrung 7 täglich / 4 wöchentlich / 6 monatlich um. Werden später weitere Datenverzeichnisse gesichert, wird die Pfadliste im `backup`-Aufruf ergänzt. Jede Änderung am Backup-Umfang löst eine RTO-Probe aus (siehe [Systembeschreibung Datensicherung, Kapitel 4 — Wiederherstellung und RTO-Probe](../systembeschreibung/05-datensicherung.md)).

Bei der Einrichtung ein Baseline-Kennzeichen setzen, damit vor dem ersten geplanten Lauf kein Fehlalarm entsteht:

```
mkdir -p /var/lib/secure-base
touch /var/lib/secure-base/restic-last-success
```

## 5. Cron-Eintrag

Datei `/etc/cron.d/<FQDN>-backup` anlegen:

```
# Datensicherung (restic) — täglich um 02:30
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
30 2 * * *  root  /usr/local/sbin/<FQDN>-backup.sh
```

```
chmod 644 /etc/cron.d/<FQDN>-backup
```

Der `cron`-Dienst gehört zum Distro-Default und ist aktiv. Die Datei wird beim nächsten cron-Tick eingelesen. `MAILTO=` bleibt absichtlich aus — bei Fehlschlag mailt das Skript selbst, sonst kämen auch erfolgreiche stdout-Zeilen als Mail.

## 6. Prüfung

Die Sicherung lässt sich über den Installer prüfen, ohne etwas zu verändern:

```
secure-base-installer check restic   # Repo-Integrität (restic check)
secure-base-installer test restic     # zusätzlich Probe-Restore einer Einzeldatei
```

`check restic` führt `restic check` aus (Integrität des Repositorys). `test restic` stellt zusätzlich `/etc/hostname` aus dem neuesten Snapshot in ein temporäres Verzeichnis wieder her — ein automatisierter Kurznachweis, dass ein Restore grundsätzlich funktioniert. Die vollständige RTO-Probe (Sandbox-Restore) bleibt davon unberührt (siehe [Systembeschreibung Datensicherung, Kapitel 4 — Wiederherstellung und RTO-Probe](../systembeschreibung/05-datensicherung.md)).
