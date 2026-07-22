# Anpassung Produktivsysteme 63688df → 3b6b79c: Mounts vom Backup ausschließen

Anleitung für einen bereits laufenden Server. Auf einem neu aufgesetzten Server erledigt der Installer alles.

**Ausführung:** alle Befehle als `root` (Wechsel per `su`).

## 1. Geltungsbereich

Gilt für Server, die mit einem Stand **bis einschließlich Commit `63688df`** eingerichtet wurden. Den neuen Stand bringt Commit `3b6b79c`.

Betroffen ist jeder Server mit eingerichtetem Modul `restic`. Akut betroffen sind Server, auf denen unterhalb der Sicherungspfade (`/etc /home /var/log /root /var/backup`) Fremd-Dateisysteme eingehängt sind (sshfs, davfs, NFS, Bind-Mounts) — der Sicherungslauf zieht sie mit ins Repository oder hängt an ihnen fest.

## 2. Backup-Skript anpassen

In `/usr/local/sbin/<FQDN>-backup.sh` den backup-Aufruf um `--one-file-system` ergänzen:

```
    restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" backup \
        --one-file-system \
        /etc /home /var/log /root /var/backup
```

Hinweis: Das von Hand angepasste Skript weicht damit weiterhin vom vollständigen Soll des neuen Installer-Stands ab (Kopf- und Kommentarzeilen). Ein späterer `install`-Lauf meldet das als Abweichung — dann per `--force-overwrite` auf das generierte Soll heben.

## 3. Prüfen

Einen Lauf von Hand starten und das Ende abwarten:

```
/usr/local/sbin/<FQDN>-backup.sh && stat -c '%y' /var/lib/secure-base/restic-last-success
```

Erwartung: Exit-Code 0 in normaler Laufzeit (Minuten, nicht Stunden), frisches Erfolgs-Kennzeichen. Anschließend die Snapshot-Liste kontrollieren — versehentlich mitgesicherte Mount-Inhalte lassen sich mit `restic forget <snapshot-id> --prune` wieder entfernen:

```
restic -r sftp:<alias>:<pfad> -p /root/.config/restic/restic-passphrase snapshots
```
