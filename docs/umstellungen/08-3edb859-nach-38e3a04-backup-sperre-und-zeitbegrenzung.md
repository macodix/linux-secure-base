# Anpassung Produktivsysteme 3edb859 → 38e3a04: Sperre und Zeitbegrenzung im Backup-Skript

Anleitung für einen bereits laufenden Server. Auf einem neu aufgesetzten Server erledigt der Installer alles.

**Ausführung:** alle Befehle als `root` (Wechsel per `su`).

## 1. Geltungsbereich

Gilt für Server, die mit einem Stand **bis einschließlich Commit `3edb859`** eingerichtet wurden. Den neuen Stand bringt Commit `38e3a04`.

Betroffen ist jeder Server mit eingerichtetem Modul `restic`.

## 2. Was sich ändert

Das Backup-Skript erhält zwei Schutzvorkehrungen:

- **Zeitbegrenzung:** `timeout 12h` vor dem backup-Aufruf, `timeout 2h` vor dem forget-Aufruf — ein hängender Lauf endet als gewöhnlicher Fehler und meldet sich per Mail.
- **Sperre:** höchstens ein Sicherungslauf zugleich (`flock` auf `/run/secure-base-backup.lock`) — ein parallel gestarteter zweiter Lauf bricht sofort ab und meldet sich per Mail.

## 3. Backup-Skript anpassen

`/usr/local/sbin/<FQDN>-backup.sh` auf den Stand der aktuellen Skript-Vorlage bringen ([Anleitung Datensicherung, Kapitel 4](../anleitung/10-datensicherung.md)) — am einfachsten den dortigen Skriptinhalt vollständig übernehmen und `<server>`/`<admin@meine-domain.de>` durch die Werte des Servers ersetzen. Gegenüber dem Stand aus Umstellung 07 sind das drei Ergänzungen:

1. Variable `LOCKFILE="/run/secure-base-backup.lock"` bei den übrigen Variablen.
2. `timeout 12h` vor dem backup- und `timeout 2h` vor dem forget-Aufruf.
3. Der `flock`-Block vor dem `if ! run …`-Block (wie in der Vorlage).

## 4. Prüfen

Einen Lauf von Hand starten:

```
/usr/local/sbin/<FQDN>-backup.sh && stat -c '%y' /var/lib/secure-base/restic-last-success
```

Erwartung: Exit-Code 0, frisches Erfolgs-Kennzeichen. Die Sperre lässt sich gefahrlos nachweisen, indem während eines laufenden Sicherungslaufs ein zweiter gestartet wird — er endet sofort mit der Fehler-Mail „Sicherungslauf läuft bereits".
