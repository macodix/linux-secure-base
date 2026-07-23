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

Alle Änderungen erfolgen in `/usr/local/sbin/<FQDN>-backup.sh`. Die bestehenden Werte des Servers (`RESTIC_REPO`, `ADMIN_MAIL`, Pfadliste) bleiben unverändert — es kommen ausschließlich die folgenden drei Ergänzungen hinzu.

**a) Sperrdatei-Variable ergänzen** — nach der Zeile `ADMIN_MAIL="…"` einfügen:

```
LOCKFILE="/run/secure-base-backup.lock"
```

**b) Zeitbegrenzung ergänzen** — im `run()`-Block vor die beiden restic-Aufrufe jeweils `timeout` setzen. Vorher:

```
    restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" backup \
        --one-file-system \
        /etc /home /var/log /root /var/backup
    restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" forget \
        --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
```

Nachher (nur `timeout 12h ` bzw. `timeout 2h ` vorangestellt, sonst unverändert):

```
    timeout 12h restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" backup \
        --one-file-system \
        /etc /home /var/log /root /var/backup
    timeout 2h restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" forget \
        --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
```

**c) Sperre ergänzen** — diesen Block als Ganzes zwischen die schließende Klammer `}` von `run()` und die Zeile `if ! run >"$LOGFILE" 2>&1; then` einfügen:

```
exec 9>"$LOCKFILE"
if ! flock -n 9; then
    echo "Sicherungslauf läuft bereits (Sperre $LOCKFILE nicht frei)." >"$LOGFILE"
    mail -s "Backup FEHLGESCHLAGEN auf <FQDN>" "$ADMIN_MAIL" \
        <"$LOGFILE"
    exit 1
fi
```

`<FQDN>` durch den Rechnernamen ersetzen — denselben Wert, der im Skript bereits im `mail -s "Backup FEHLGESCHLAGEN auf …"` des unteren Blocks steht. Beide Zeilen (`exec 9>…` **und** `flock -n 9`) sind nötig: `exec` öffnet die Sperrdatei auf Datei-Deskriptor 9, `flock` sperrt diesen Deskriptor. Fehlt eine der beiden Zeilen oder wird eine Variable falsch geschrieben, beendet sich das Skript wegen `set -euo pipefail` sofort und ohne Meldung.

## 4. Prüfen

Einen Lauf von Hand starten:

```
/usr/local/sbin/<FQDN>-backup.sh && stat -c '%y' /var/lib/secure-base/restic-last-success
```

Erwartung: Exit-Code 0, frisches Erfolgs-Kennzeichen. Die Sperre lässt sich gefahrlos nachweisen, indem während eines laufenden Sicherungslaufs ein zweiter gestartet wird — er endet sofort mit der Fehler-Mail „Sicherungslauf läuft bereits".
