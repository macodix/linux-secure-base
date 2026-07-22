# Anpassung Produktivsysteme 63688df → 3b6b79c: Mounts vom Backup ausschließen

Anleitung für einen bereits laufenden Server. Auf einem neu aufgesetzten Server erledigt der Installer alles.

**Ausführung:** alle Befehle als `root` (Wechsel per `su`).

## 1. Geltungsbereich

Gilt für Server, die mit einem Stand **bis einschließlich Commit `63688df`** eingerichtet wurden. Den neuen Stand bringt Commit `3b6b79c`.

Betroffen ist jeder Server mit eingerichtetem Modul `restic`. Akut betroffen sind Server, auf denen unterhalb der Sicherungspfade (`/etc /home /var/log /root /var/backup`) Fremd-Dateisysteme eingehängt sind (sshfs, davfs, NFS, Bind-Mounts) — der Sicherungslauf zieht sie mit ins Repository oder hängt an ihnen fest.

## 2. Hängende Läufe beenden (falls vorhanden)

Prüfen, ob Sicherungsläufe laufen, und alle beenden:

```
pgrep -af 'restic .* backup'
pkill -f '<FQDN>-backup.sh'; pkill -f 'restic .* backup'
```

Ein abgebrochener restic-Lauf hinterlässt kein beschädigtes Repository; ggf. zurückgebliebene Sperren löst der nächste erfolgreiche Lauf nicht selbst — bei einer Meldung „repo already locked" einmalig:

```
restic -r sftp:<alias>:<pfad> -p /root/.config/restic/restic-passphrase unlock
```

## 3. Backup-Skript anpassen

In `/usr/local/sbin/<FQDN>-backup.sh` den backup-Aufruf um `--one-file-system` ergänzen — Ziel-Zustand exakt (entspricht dem neuen Soll des Installers, damit ein späterer `install`-Lauf keine Abweichung meldet):

```
    restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" backup \
        --one-file-system \
        /etc /home /var/log /root /var/backup
```

## 4. Prüfen

Einen Lauf von Hand starten und das Ende abwarten:

```
/usr/local/sbin/<FQDN>-backup.sh && stat -c '%y' /var/lib/secure-base/restic-last-success
```

Erwartung: Exit-Code 0 in normaler Laufzeit (Minuten, nicht Stunden), frisches Erfolgs-Kennzeichen. Anschließend die Snapshot-Liste kontrollieren — versehentlich mitgesicherte Mount-Inhalte lassen sich mit `restic forget <snapshot-id> --prune` wieder entfernen:

```
restic -r sftp:<alias>:<pfad> -p /root/.config/restic/restic-passphrase snapshots
```
