# Anpassung Produktivsysteme für Version fd1824e (lokale Sicherungsablagen nach /var/backup)

Anleitung für einen bereits laufenden Server, der auf den neuen Standard gebracht werden soll. Auf einem neu aufgesetzten Server ist nichts davon nötig — dort erledigt der Installer alles.

**Ausführung:** alle Befehle als `root`.

## 1. Geltungsbereich

Die Anleitung gilt für Server, die mit einem Stand **bis einschließlich Commit `f5278f8`** eingerichtet wurden (Etikett `testbau` vor dem 12. Juli 2026, Version `0.1.0-dev`).

Den neuen Standard bringen die Commits `d0390fe` (postgresql) und `fd1824e` (restic). Wer den Installer ab `fd1824e` bezieht, hat ihn bereits.

Betroffen ist ein Server, wenn eines davon zutrifft:

- Das Modul `restic` ist eingerichtet — die Konfiguration liegt dann offen unter `/root/config`.
- Das optionale Modul `postgresql` ist eingerichtet — der Dump liegt dann als Cluster-Gesamtdump unter `/root/postgresql-dump/dumpall.sql`.

Prüfen:

```
ls -d /root/config /root/postgresql-dump 2>/dev/null
```

## 2. Was sich ändert

| Bisher | Neu |
|---|---|
| `/root/config/restic-passphrase` | `/root/.config/restic/restic-passphrase` |
| `/root/postgresql-dump/dumpall.sql` (ein Gesamtdump) | `/var/backup/postgresql/<datenbank>.sql` je Datenbank, dazu `globals.sql` (Rollen, Tablespaces) |
| `/usr/local/sbin/secure-base-pg-dumpall.sh` | `/usr/local/sbin/secure-base-pg-dump.sh` |
| `/etc/cron.d/secure-base-pg-dumpall` | `/etc/cron.d/secure-base-pg-dump` |
| `/var/lib/secure-base/pg-dumpall-last-success` | entfällt — monit prüft jetzt das Alter von `globals.sql` selbst |
| restic sichert `/etc /home /var/log /root` | restic sichert zusätzlich `/var/backup` |

`/var/backup` ist neu und ist das Sammelverzeichnis für alle lokal abgelegten Sicherungen (Rechte 0700, Eigentümer `root`).

## 3. Neuen Installer-Stand einspielen

Den Installer wie gewohnt beziehen und entpacken (siehe [README](../../README.md)). Die bestehende `etc/secure-base/secure-base.conf` bleibt unverändert gültig — es kommt kein neuer Konfigurationsschlüssel hinzu.

## 4. Module neu einrichten

Der Installer schreibt Verzeichnisse, Skripte, Cron-Einträge und monit-Checks neu. Er ist idempotent; vorhandene Daten fasst er nicht an.

```
sudo bin/secure-base-installer install restic postgresql monit
```

Ohne PostgreSQL-Datenbankserver `postgresql` weglassen.

Damit entstehen:

- `/var/backup` (0700 `root`)
- `/root/.config/restic/restic-passphrase` (0600) — der Wert kommt aus `restic_passphrase` in der Konfiguration, es ist derselbe wie bisher
- `/var/backup/postgresql` (0700 `root`) mit dem neuen Dump-Skript `/usr/local/sbin/secure-base-pg-dump.sh` und `/etc/cron.d/secure-base-pg-dump`
- das restic-Backup-Skript `/usr/local/sbin/<FQDN>-backup.sh` mit `/var/backup` in der Pfadliste
- der monit-Check `postgresql_dump`, der jetzt auf `/var/backup/postgresql/globals.sql` zeigt

Das bestehende restic-Repository bleibt unangetastet: Die Passphrase ist dieselbe, das Repo gilt als initialisiert und wird nicht neu angelegt.

## 5. Ersten Dump erzeugen

Nicht auf den nächsten Nachtlauf warten — sonst schlägt der monit-Check zu, weil `globals.sql` noch fehlt:

```
/usr/local/sbin/secure-base-pg-dump.sh
ls -l /var/backup/postgresql/
```

Erwartet: je Datenbank eine `.sql`-Datei plus `globals.sql`, alle mit Rechten 0600.

## 6. Alte Artefakte entfernen

Der Installer räumt sie nicht ab — sie sind Reste des alten Standes und müssen von Hand weg. Erst nach Schritt 5 ausführen.

Alter Dump-Lauf (Skript, Cron-Eintrag, Markierungsdatei):

```
rm -f /etc/cron.d/secure-base-pg-dumpall
rm -f /usr/local/sbin/secure-base-pg-dumpall.sh
rm -f /var/lib/secure-base/pg-dumpall-last-success
```

Alte restic-Passphrase-Datei. Sie ist ein Klartext-Geheimnis und bleibt sonst auf der Platte liegen. **Vorher prüfen**, dass die neue Datei existiert und das Repo damit lesbar ist:

```
restic -r sftp:<alias>:<pfad> -p /root/.config/restic/restic-passphrase cat config >/dev/null && echo "Repo lesbar"
```

Erst wenn das „Repo lesbar" meldet:

```
shred -u /root/config/restic-passphrase
rmdir /root/config
```

Alte Dumps unter `/root/postgresql-dump`. Sie sind Daten, kein Artefakt — den Gesamtdump behalten, bis mindestens ein vollständiger neuer Sicherungslauf im restic-Repo liegt. Danach:

```
rm -rf /root/postgresql-dump
```

## 7. Prüfen

```
sudo bin/secure-base-installer check restic postgresql monit
sudo bin/secure-base-installer test restic postgresql
monit status
```

`check` gleicht Rechte, Skript- und Cron-Inhalte mit dem Soll ab. `test` prüft die SFTP-Erreichbarkeit, das Repo und einen Probe-Restore.

Der monit-Check `postgresql_dump` bleibt nur ruhig, wenn `/var/backup/postgresql/globals.sql` jünger als 26 Stunden ist. Da das Dump-Skript diese Datei zuletzt schreibt, belegt ihr Zeitstempel einen vollständig erfolgreichen Lauf.

## 8. Wiederherstellung nach der Umstellung

Die Wiederherstellung läuft jetzt in zwei Schritten — zuerst die clusterweiten Objekte, dann die einzelnen Datenbanken:

```
runuser -u postgres -- psql -f /var/backup/postgresql/globals.sql
runuser -u postgres -- psql -f /var/backup/postgresql/<datenbank>.sql postgres
```
