# Anpassung Produktivsysteme für Version 02f7865 (rkhunter-Ausnahmen für bekannte Fehlalarme)

Anleitung für einen bereits laufenden Server, der auf den neuen Standard gebracht werden soll. Auf einem neu aufgesetzten Server ist nichts davon nötig — dort erledigt der Installer alles.

**Ausführung:** alle Befehle als `root`.

## 1. Geltungsbereich

Die Anleitung gilt für Server, die mit einem Stand **bis einschließlich Commit `c9e462b`** eingerichtet wurden. Den neuen Standard bringt Commit `02f7865`.

Betroffen ist jeder Server mit eingerichtetem Modul `rkhunter` — also jeder nach lsb-Standard aufgesetzte Server. Der tägliche Lauf schickt dort eine Mail mit Warnungen dieser Art:

```
Warning: Suspicious file types found in /dev:
         /dev/shm/PostgreSQL.1967000986: data
Warning: Hidden file found: /etc/.resolv.conf.systemd-resolved.bak: ASCII text
Warning: Hidden file found: /etc/.updated: ASCII text
```

Die Meldungen zu `/dev/shm/PostgreSQL.*` treten nur auf Servern mit Datenbankserver auf, die beiden versteckten Dateien auf jedem Server.

## 2. Was sich ändert

`/etc/rkhunter.conf` erhält drei Ausnahmen:

```
ALLOWHIDDENFILE=/etc/.resolv.conf.systemd-resolved.bak
ALLOWHIDDENFILE=/etc/.updated
ALLOWDEVFILE=/dev/shm/PostgreSQL.*
```

Alle drei Dateien erzeugt der Normalbetrieb: Die beiden versteckten Dateien unter `/etc` legt systemd an — `.resolv.conf.systemd-resolved.bak` ist die Sicherung, die `systemd-resolved` beim Übernehmen von `/etc/resolv.conf` hinterlässt, `.updated` die Zeitstempel-Datei von `systemd-update-done.service`. Die Dateien unter `/dev/shm` sind Shared-Memory-Segmente des PostgreSQL-Servers (`dynamic_shared_memory_type = posix`, Vorgabe unter Ubuntu). Ihr Zahlenteil ist zufällig und wechselt je Segment, deshalb steht dort ein Muster statt fester Namen.

Der Eintrag `ALLOWDEVFILE` wird auch auf Servern ohne Datenbankserver gesetzt. Dort gibt es keine passenden Dateien, er bleibt wirkungslos.

## 3. Neuen Installer-Stand einspielen

Den Installer wie gewohnt beziehen und entpacken (siehe [README](../../README.md)). Die bestehende `etc/secure-base/secure-base.conf` bleibt unverändert gültig — es kommt kein neuer Konfigurationsschlüssel hinzu.

## 4. Modul neu einrichten

```
sudo bin/secure-base-installer install rkhunter
```

Der Lauf trägt die drei Zeilen in `/etc/rkhunter.conf` ein. Er ist idempotent: bereits vorhandene Zeilen bleiben unverändert, andere `ALLOWHIDDENFILE`- oder `ALLOWDEVFILE`-Einträge fasst er nicht an. Die Baseline-Datenbank bleibt ebenfalls unangetastet, da sie bereits existiert.

## 5. Prüfen

```
sudo bin/secure-base-installer check rkhunter
```

`check` prüft die drei Einträge mit ab.

Der Scan lässt sich sofort von Hand anstoßen, statt auf den nächsten Nachtlauf zu warten:

```
rkhunter --check --sk --nocolors --report-warnings-only
```

Erwartet: Die drei Meldungen aus Kapitel 1 erscheinen nicht mehr. Bleiben andere Warnungen stehen, sind sie zu sichten — sie sind nicht Gegenstand dieser Umstellung.
