# Anpassung Produktivsysteme 02f7865 → dac64e8: Tagesbericht statt vollständigem Logwatch-Bericht

Anleitung für einen bereits laufenden Server, der auf den neuen Standard gebracht werden soll. Auf einem neu aufgesetzten Server ist nichts davon nötig — dort erledigt der Installer alles.

**Ausführung:** alle Befehle als `root`.

## 1. Geltungsbereich

Die Anleitung gilt für Server, die mit einem Stand **bis einschließlich Commit `02f7865`** eingerichtet wurden. Den neuen Standard bringt Commit `dac64e8`.

Betroffen ist jeder Server mit eingerichtetem Modul `logging` — also jeder nach lsb-Standard aufgesetzte Server. Er verschickt täglich den vollständigen Logwatch-Bericht als Mailtext, rund 2100 Zeilen.

## 2. Was sich ändert

Über neunzig Prozent des bisherigen Berichts sind Aufzählungen abgewiesener Anmeldeversuche und HTTP-Scanner. Diese Hosts hat `fail2ban` bereits gesperrt, die Aufzählung ändert an keiner Entscheidung etwas. Ein Bericht, der zu über neunzig Prozent aus Rauschen besteht, wird nicht gelesen — und verdeckt damit das Wenige, worauf es ankommt.

Künftig trägt der Mailtext eine Zusammenfassung, der vollständige Logwatch-Bericht liegt derselben Mail als Datei bei. Nichts geht verloren, es ist nur anders angeordnet.

Die Zusammenfassung nennt:

- erfolgreiche SSH-Anmeldungen mit Benutzer, Quell-IP und Zeit
- Zwei-Faktor-Vorgänge (angenommene wie abgelehnte TOTP-Codes)
- fehlgeschlagene Anmeldungen bekannter Benutzer
- `sudo`- und `su`-Aufrufe
- die Zahl der fail2ban-Sperren
- fehlgeschlagene Dienste und Cron-Läufe
- Journal-Fehler (höchstens 20) und den Plattenplatz

Abgewiesene Anmeldeversuche unbekannter Benutzer erscheinen nur als Summe — vollständig stehen sie im Anhang.

Neue und geänderte Dateien:

| Datei | Bedeutung |
|---|---|
| `/usr/local/sbin/secure-base-logwatch.sh` | neu — erzeugt Bericht und Zusammenfassung, verschickt die Mail (Mode 700) |
| `/etc/cron.daily/secure-base-logwatch` | neu — täglicher Aufruf des Skripts (Mode 755) |
| `/etc/cron.daily/00logwatch` | stillgelegt — Ausführungsrecht entzogen (Mode 644) |

`/etc/logwatch/conf/logwatch.conf` bleibt unverändert. Der Detailgrad bleibt `Med`, denn der Anhang darf ausführlich sein.

## 3. Neuen Installer-Stand einspielen

Den Installer wie gewohnt beziehen und entpacken (siehe [README](../../README.md)). Die bestehende `etc/secure-base/secure-base.conf` bleibt unverändert gültig — es kommt kein neuer Konfigurationsschlüssel hinzu.

## 4. Modul neu einrichten

```
sudo bin/secure-base-installer install logging
```

Der Lauf schreibt Skript und cron.daily-Eintrag und nimmt `/etc/cron.daily/00logwatch` das Ausführungsrecht. Alle Schritte sind idempotent.

## 5. Prüfen

Den Bericht sofort von Hand erzeugen, statt auf den nächsten Nachtlauf zu warten:

```
/usr/local/sbin/secure-base-logwatch.sh
```

Erwartet: **eine** Mail mit der Zusammenfassung im Text und dem Logwatch-Bericht als Anhang (`logwatch-<datum>.txt`). Kommen **zwei** Mails, ist `/etc/cron.daily/00logwatch` noch ausführbar.

Der Abgleich prüft Skript, Cron-Eintrag und das entzogene Ausführungsrecht:

```
sudo bin/secure-base-installer check logging
```

Der Bericht wertet den **Vortag** aus. Am Tag der Umstellung liegen die Daten also vollständig vor — ein Handlauf liefert sofort ein aussagekräftiges Ergebnis.

## 6. Grenze

Ein Upgrade des Pakets `logwatch` kann `/etc/cron.daily/00logwatch` das Ausführungsrecht zurückgeben. Dann kommen wieder zwei Mails. Der Abgleich (`check logging`) meldet das, ein erneutes `install logging` legt ihn wieder still.
