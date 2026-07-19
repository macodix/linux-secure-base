# Anpassung Produktivsysteme 0235470 → d8c517b: Backup-Cron-Dateiname und sudo-Logfile-Direktive

Anleitung für einen bereits laufenden Server. Auf einem neu aufgesetzten Server ist nichts davon nötig — dort erledigt der Installer alles.

**Ausführung:** alle Befehle als `root` (sudo ist auf betroffenen Systemen defekt, siehe Abschnitt 2 — per `su` zu `root` wechseln).

## 1. Geltungsbereich

Die Anleitung gilt für Server, die mit einem Stand **bis einschließlich Commit `0235470`** (Version 0.1.3) eingerichtet wurden. Den neuen Stand bringt Commit `d8c517b`.

Beide Fehler stammen aus der Installation; betroffen ist jeder Server, auf dem die Module `restic` und `logging` eingerichtet sind:

- **Backup lief nie.** Der Installer legte die Cron-Datei als `/etc/cron.d/<FQDN>-backup` an. cron ignoriert Dateien in `/etc/cron.d`, deren Name nicht der run-parts-Namenskonvention `[A-Za-z0-9_-]` folgt (`man cron`, DEBIAN SPECIFIC) — die Punkte im FQDN verhindern jede Ausführung. Sichtbar am monit-Alarm zur Backup-Frische bzw. am unveränderten Zeitstempel von `/var/lib/secure-base/restic-last-success`.
- **sudo verweigert jeden Aufruf.** `/etc/sudoers.d/secure-base-sudolog` setzt `Defaults logfile="/var/log/sudo.log"`. Das unter Ubuntu ausgelieferte sudo-rs kennt diese Direktive nicht; die Datei ist ein Parse-Fehler, mit dem sudo komplett aussteigt.

Prüfen:

```
ls /etc/cron.d/*-backup /etc/sudoers.d/secure-base-sudolog 2>/dev/null
```

## 2. sudo reparieren

```
rm /etc/sudoers.d/secure-base-sudolog
visudo -c
```

Erwartung: `visudo -c` meldet keinen Fehler; danach funktioniert `sudo -v` wieder. Kein Ersatz nötig — sudo-Aufrufe protokolliert sudo-rs ins Syslog/Journal (`journalctl _COMM=sudo`), die auditd-Regeln auf die sudoers-Pfade bleiben bestehen. Eine vorhandene `/var/log/sudo.log` bleibt als Datensicherung erhalten.

## 3. Backup-Cron reparieren

Cron-Datei auf den neuen festen Namen umbenennen (Skriptname unter `/usr/local/sbin` bleibt unverändert):

```
mv /etc/cron.d/<FQDN>-backup /etc/cron.d/secure-base-backup
```

cron liest die Datei beim nächsten Minuten-Tick ein; kein Neustart nötig.

## 4. Ausstehenden Sicherungslauf nachholen

Nicht auf den nächsten Nachtlauf warten — der monit-Check `restic_backup` bleibt sonst im Alarm:

```
/usr/local/sbin/<FQDN>-backup.sh && stat -c '%y' /var/lib/secure-base/restic-last-success
```

Erwartung: Exit-Code 0, Zeitstempel von jetzt. monit nimmt den Alarm im nächsten Prüfzyklus selbst zurück.

## 5. Prüfen

Nach dem nächsten geplanten Lauf (Vorgabe 02:30):

```
journalctl -t CRON --since "02:25" | grep secure-base-backup
stat -c '%y' /var/lib/secure-base/restic-last-success
```

Erwartung: CRON-Eintrag zum Lauf, Sicherungs-Kennzeichen vom selben Zeitpunkt.
