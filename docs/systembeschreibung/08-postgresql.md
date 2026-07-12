# postgresql-Grundsatz

Dieses Dokument beschreibt Festlegungen für die Einrichtung des optionalen Datenbankservers PostgreSQL.


## Inhaltsverzeichnis

1. Nur Loopback-Bindung
2. Authentifizierung nur über scram-sha-256
3. Verbindungs-Protokollierung
4. Rechte an Konfiguration und Datenverzeichnis
5. Datensicherung per Dump
6. Frische-Überwachung des Dumps
7. Rückbau belässt die Zugriffskontrolle


## 1. Nur Loopback-Bindung

Der Datenbankserver ist ausschließlich lokal erreichbar: `listen_addresses = 'localhost'`, kein Netz-Port, keine Firewall-Freigabe. Anwendungen greifen über den lokalen Socket oder 127.0.0.1/::1 zu. Entfernter Zugriff ist nicht vorgesehen.

## 2. Authentifizierung nur über scram-sha-256

Passwörter werden mit `scram-sha-256` gespeichert (`password_encryption`). Die Zugriffsliste `pg_hba.conf` wird vollständig durch eine restriktive Fassung ersetzt: lokaler `postgres`-Zugang per `peer`, alle übrigen lokalen und Loopback-Verbindungen ausschließlich per `scram-sha-256`. Kein `trust`, keine Netz-Freigabe außer Loopback, keine Replikationszeile.

## 3. Verbindungs-Protokollierung

Auf- und Abbau jeder Verbindung werden protokolliert (`log_connections`, `log_disconnections`), mit Zeit, Prozess, Benutzer und Datenbank im Präfix (`log_line_prefix`). Die Protokolle sammelt der `logging_collector`.

## 4. Rechte an Konfiguration und Datenverzeichnis

Das Datenverzeichnis hat Mode 0700, Eigentümer `postgres`. Die eigene Drop-in-Datei und `pg_hba.conf` erhalten Mode 0640, Eigentümer `postgres:postgres` — lesbar für den Dienst, nicht für unprivilegierte Nutzer.

## 5. Datensicherung per Dump

Das Datenverzeichnis eines laufenden Clusters wird nicht dateiweise gesichert — eine solche Kopie wäre inkonsistent. Stattdessen erzeugt ein täglicher Cron-Lauf logische Dumps als Benutzer `postgres`: je Datenbank einen Einzeldump mit `pg_dump` nach `/var/backup/postgresql/<datenbank>.sql` und anschließend die clusterweiten Objekte (Rollen inklusive Passwort-Hashes, Tablespaces) mit `pg_dumpall --globals-only` nach `/var/backup/postgresql/globals.sql`. Dumps Mode 0600, Verzeichnisse 0700, Eigentümer `root`. Jeder Dump wird atomar geschrieben; ein Fehlschlag lässt die vorige Sicherung unverändert und bricht den Lauf ab.

Einzeldumps statt eines Gesamt-Dumps: jede Datenbank ist für sich wiederherstellbar, ohne die übrigen anzufassen. Die Einzeldumps sind mit `--create --clean --if-exists` eigenständig — sie legen ihre Datenbank bei der Wiederherstellung selbst neu an. Rollen und Tablespaces gehören dem Cluster und nicht einer einzelnen Datenbank, deshalb der zusätzliche Globals-Dump: ohne ihn kämen die Datenbanken zurück, die Benutzer nicht.

Die Ablage unter `/var/backup` ist bewusst gewählt: das Verzeichnis sammelt alle lokal abgelegten Sicherungen und gehört zu den von der Datensicherung ([Systembeschreibung Datensicherung](05-datensicherung.md)) erfassten Pfaden. Die Dumps werden damit ohne weitere Kopplung mitgesichert. Die Dump-Zeit (`pg_dump_time`, Vorgabe 02:00) liegt vor der restic-Zeit (`restic_backup_time`, Vorgabe 02:30), damit die frischen Dumps im selben Nachtlauf gesichert werden. Die Wiederherstellung erfolgt über `psql`, zuerst `globals.sql`, dann die einzelnen Datenbanken.

## 6. Frische-Überwachung des Dumps

`globals.sql` entsteht als letzte Datei des Dump-Laufs. Ihr Zeitstempel belegt damit einen vollständig erfolgreichen Lauf: scheitert vorher der Dump einer einzelnen Datenbank, bricht das Skript ab und die Datei bleibt alt. Das Monitoring prüft ihr Alter über den Check `postgresql_dump`; bleibt sie länger als 26 Stunden unverändert, alarmiert es per Mail an die Administrator Email Adresse. Ein ausbleibender oder fehlgeschlagener Dump wird so bemerkt. Überwacht wird die Sicherungsdatei selbst, keine gesonderte Markierungsdatei.

## 7. Rückbau belässt die Zugriffskontrolle

Der Rückbau (uninstall) entfernt die eigene Drop-in-Datei sowie Dump-Skript und -Cron, lässt die gehärtete `pg_hba.conf` aber bestehen. Ein Rückbau auf die schwächere Distributionsfassung würde die Zugriffskontrolle absenken und widerspräche dem Schutzziel. Paket, Cluster und vorhandene Dumps bleiben unangetastet, es gehen keine Daten verloren. Die Sicherung `pg_hba.conf.bak-<Zeitstempel>` bleibt als manueller Wiederherstellungsweg erhalten.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-07-10 | macodix | Erstanlage. |
