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

Das Datenverzeichnis eines laufenden Clusters wird nicht dateiweise gesichert — eine solche Kopie wäre inkonsistent. Stattdessen erzeugt ein täglicher Cron-Lauf einen logischen Gesamt-Dump mit `pg_dumpall` (als Benutzer `postgres`, nimmt Rollen und Rechte mit) in die Datei `/root/postgresql-dump/dumpall.sql` (Mode 0600, Verzeichnis 0700, Eigentümer `root`). Der Dump wird atomar geschrieben; ein Fehlschlag lässt die vorige Sicherung unverändert.

Die Ablage unter `/root` ist bewusst gewählt: `/root` gehört zu den von der Datensicherung ([Systembeschreibung Datensicherung](05-datensicherung.md)) erfassten Pfaden, der Dump wird damit ohne weitere Kopplung mitgesichert. Die Dump-Zeit (`pg_dump_time`, Vorgabe 02:00) liegt vor der restic-Zeit (`restic_backup_time`, Vorgabe 02:30), damit der frische Dump im selben Nachtlauf gesichert wird. Die Wiederherstellung erfolgt über `psql`.

## 6. Frische-Überwachung des Dumps

Der Dump-Lauf aktualisiert nur im Erfolgsfall eine Markierungsdatei `/var/lib/secure-base/pg-dumpall-last-success`. Das Monitoring prüft deren Alter über den Check `postgresql_dump`; bleibt sie länger als 26 Stunden unverändert, alarmiert es per Mail an die Administrator Email Adresse. Ein ausbleibender oder fehlgeschlagener Dump wird so bemerkt.

## 7. Rückbau belässt die Zugriffskontrolle

Der Rückbau (uninstall) entfernt die eigene Drop-in-Datei sowie Dump-Skript und -Cron, lässt die gehärtete `pg_hba.conf` aber bestehen. Ein Rückbau auf die schwächere Distributionsfassung würde die Zugriffskontrolle absenken und widerspräche dem Schutzziel. Paket, Cluster und vorhandene Dumps bleiben unangetastet, es gehen keine Daten verloren. Die Sicherung `pg_hba.conf.bak-<Zeitstempel>` bleibt als manueller Wiederherstellungsweg erhalten.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-07-10 | macodix | Erstanlage. |
