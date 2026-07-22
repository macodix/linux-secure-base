# Datensicherung

Dieses Dokument beschreibt die Datensicherung des Grundsystems:
- Sicherungsverfahren und Ziel, 
- Wiederanlaufzeit (RPO/RTO) und Aufbewahrung,
- Backup-Überwachung, Wiederherstellung und RTO-Probe.


## Inhaltsverzeichnis

1. Sicherungsverfahren und Ziel
2. RPO, RTO und Aufbewahrung
3. Backup-Überwachung
4. Wiederherstellung und RTO-Probe

## 1. Sicherungsverfahren und Ziel

Die Datensicherung erfolgt mit `restic` auf einen externen SFTP-Speicher. Das Repository ist verschlüsselt. Die Repo-Passphrase liegt außerhalb des Repos in `/root/.config/restic/restic-passphrase` mit Mode 600 (Verzeichnis 0700). Der Lauf wird täglich zur konfigurierten Zeit (`restic_backup_time`, Vorgabe 02:30) über `/etc/cron.d/secure-base-backup` als `root` ausgelöst (Skript `/usr/local/sbin/<FQDN>-backup.sh`, Mode 700). `<FQDN>` wird zur Installationszeit aus `secure-base.conf` eingesetzt; der Cron-Dateiname bleibt fest und punktfrei (run-parts-Namenskonvention, sonst ignoriert cron die Datei).

Gesichert werden im Grundzustand `/etc`, `/home`, `/var/log`, `/root` und `/var/backup`.

`/var/backup` (Mode 0700, Eigentümer `root`) ist das Sammelverzeichnis für alle lokal abgelegten Sicherungen. Das restic-Modul legt es an, auch wenn kein anderes Modul dort ablegt — ein fehlender Pfad würde bei jedem Sicherungslauf gemeldet. Die optionalen PostgreSQL-Dumps liegen unter `/var/backup/postgresql` und werden damit ohne zusätzlichen Pfad mitgesichert (siehe [postgresql-Grundsatz](08-postgresql.md)). Werden später weitere Dienste mit eigenen Datenverzeichnissen eingerichtet, kommen ggf. weitere Pfade hinzu.

Unter `/var/backup/secure-base/<JJJJ-MM-TT-HHMMSS>/` legt der secure-base-installer die Vorher-Stände der Dateien ab, die er in einem Lauf tatsächlich ändert — ein Verzeichnis je Lauf, je Datei höchstens eine Sicherung, gespiegelt unter dem vollen Pfad der Zieldatei. Ein Lauf ohne Änderungen legt nichts ab. Dateien mit Geheimniswert (restic-Passphrase, `sasl_passwd`) werden nie dorthin kopiert. Alte Lauf-Verzeichnisse werden nicht automatisch gelöscht; sie liegen im restic-Sicherungsumfang und werden bei Bedarf von Hand entfernt. Schreibverhalten des Installers im Einzelnen: [secure-base-installer, Kapitel 6.1](../installer/secure-base-installer.md).

Der SSH-Zugang zum SFTP-Ziel ist Vorbedingung. Das Backup-Skript prüft zu Beginn non-interaktiv die Erreichbarkeit über das SFTP-Subsystem (`BatchMode`, kein `ssh host cmd`, da SFTP-only-Anbieter kein Kommando erlauben) und bricht nei Nichterreichbarkeit ab.

Das Ziel ist vom Quellsystem getrennt und verschlüsselt. Append-only-Schutz des Ziels gegen Überschreiben oder Löschen ist im BSI-Grundschutz gefordert, restic über SFTP kann diesen allerdings nicht erzwingen. Daher sollte auf dem SFTP-Server ein Mechnaismu implementiert werden, der die restic-Dateinsicheurngen an nicht löschbarer Stelle vorhält.

## 2. RPO, RTO und Aufbewahrung

| Größe | Sollwert | Maßgröße |
|---|---|---|
| Wiederherstellungspunkt (RPO) | maximal 24 h Datenverlust | Abstand zweier Sicherungsläufe |
| Wiederherstellungszeit (RTO) | maximal 48 h bis Wiederherstellung | Dauer Neuaufbau plus Restore |
| Aufbewahrung | 7 täglich, 4 wöchentlich, 6 monatlich | restic-`forget`-Politik |

Der tägliche Lauf erfüllt RPO 24 h. Die Aufbewahrung folgt der restic-`forget`-Politik mit anschließendem `prune`.

```mermaid
flowchart LR
    B["letzte Sicherung<br/>(restic, täglich 02:30)"] -->|"RPO: max. 24 h<br/>möglicher Datenverlust"| X["Ausfall"]
    X -->|"RTO: max. 48 h<br/>Neuaufbau Grundsystem + restic-Restore"| W["System wiederhergestellt"]
```

## 3. Backup-Überwachung

Das Backup-Skript meldet einen Fehlschlag direkt per Mail an die Administrator Email Adresse. Zusätzlich prüft das Monitoring die Aktualität der "Erfolgs"-Flag-Datei (`/var/lib/secure-base/restic-last-success`), welche das Skript nur im Erfolgspfad aktualisiert. Bleibt es länger als 26 Stunden unverändert, alarmiert das Monitoring im Rahmen seines Monitoringberichtes.

## 4. Wiederherstellung und RTO-Probe

Die Wiederherstellung binnen 48 h durch den Betreiber setzt eine dokumentierte, erprobte Wiederherstellungsanweisung voraus. Die Anweisung beschreibt zwei Schritte:
1. den Neuaufbau des gehärteten Grundsystems (skriptiert/dokumentiert),
2. den Restore der gesicherten Pfade aus dem restic-Repository.

Die Wiederherstellung wird regelmäßig durch einen Test-Restore in eine Sandbox erprobt. Der Test erfolgt halbjährlich sowie zusätzlich nach jeder Änderung am Backup-Umfang. Zugangs- und Schlüsseldaten für die Wiederherstellung (restic-Passphrase, SFTP-Schlüssel) sind für den Notfall sicher und getrennt vom Server zu hinterlegen.

Ergänzend bringt das restic-Modul technische Prüfungen mit: `secure-base-installer check restic` führt `restic check` aus (Integrität des Repositorys), `secure-base-installer test restic` zusätzlich einen automatisierten Probe-Restore (Wiederherstellung von `/etc/hostname` aus dem neuesten Snapshot in ein temporäres Verzeichnis). Diese ergänzen die halbjährliche Sandbox-Probe, ersetzen sie aber nicht.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage durch bereinigte Übernahme. |
| 0.02 | 2026-06-22 | macodix | restic check und Probe-Restore (check/test) ergänzt; unvollständigen Satz korrigiert. |
