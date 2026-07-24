# Anpassung Produktivsysteme 468029e → a9fe7a9: monit-Meldungen über Normalverhalten ohne Mail

Anleitung für einen bereits laufenden Server. Auf einem neu aufgesetzten Server erledigt der Installer alles.

**Ausführung:** alle Befehle als `root` (Wechsel per `su`).

## 1. Geltungsbereich

Gilt für Server, die mit einem Stand **bis einschließlich Commit `468029e`** eingerichtet wurden. Den neuen Stand bringt Commit `a9fe7a9`.

Betroffen ist jeder Server mit eingerichtetem Modul `monit`. Symptom: Bei jedem monit-Neustart (etwa durch needrestart nach Updates) kommt eine Mail „Monit instance changed … started" — Normalverhalten ohne Alarmwert.

## 2. Was sich ändert

Die `set alert`-Zeile in `/etc/monit/monitrc` erhält den Zusatz `but not on { instance }`: monits eigene Start-/Stopp-Meldung erzeugt keine Mail mehr. Alle Fehler-Alarme der überwachten Dienste (Backup-Frische, Plattenplatz, Dienst-Ausfälle usw.) bleiben unberührt.

## 3. monitrc anpassen

In `/etc/monit/monitrc` die vorhandene Zeile ändern. Vorher:

```
set alert <admin-adresse>
```

Nachher (nur der Zusatz am Zeilenende, Adresse unverändert):

```
set alert <admin-adresse> but not on { instance }
```

Danach Konfiguration prüfen und neu laden:

```
monit -t
monit reload
```

## 4. Prüfen

`monit -t` meldet „Control file syntax OK". Beim nächsten monit-Neustart (z. B. `systemctl restart monit`) kommt keine „instance changed"-Mail mehr; ein echter Alarm (etwa ein gestoppter überwachter Dienst) erzeugt weiterhin eine Mail.
