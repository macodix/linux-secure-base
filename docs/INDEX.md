# INDEX

Navigation für die Dokumentation von linux-secure-base. Gegliedert nach Dokumenttyp.

## A. Systembeschreibung

01 [systembeschreibung/01-systembeschreibung.md](systembeschreibung/01-systembeschreibung.md) — Aufbau des Grundsystems: Betriebssystem, Dienste, Verzeichnis-Layout, Port-Plan, ausgehende Firewall-Zielliste (in Bearbeitung)

02 [systembeschreibung/02-haertung.md](systembeschreibung/02-haertung.md) — Sicherheitsanforderungen und Härtung: Maßstab, Schutzziele, Authentifizierung, Angriffsfläche, Brute-Force-Schutz, Zugangsdaten, Dienst-Isolation, Härtungsprüfung (in Bearbeitung)

03 [systembeschreibung/03-mail-versand.md](systembeschreibung/03-mail-versand.md) — Mail-Versand für Systembenachrichtigungen über Postfix als Satellite (in Bearbeitung)

04 [systembeschreibung/04-protokollierung-und-automatische-updates.md](systembeschreibung/04-protokollierung-und-automatische-updates.md) — Protokollierung mit Auditing und automatische Sicherheitsupdates (in Bearbeitung)

05 [systembeschreibung/05-datensicherung.md](systembeschreibung/05-datensicherung.md) — Datensicherung mit restic: Verfahren, RPO/RTO, Überwachung, Wiederherstellung (in Bearbeitung)

06 [systembeschreibung/06-monitoring.md](systembeschreibung/06-monitoring.md) — Monitoring mit monit: überwachte Größen, Verfügbarkeitsnachweis, Benachrichtigung (in Bearbeitung)

07 [systembeschreibung/07-nginx.md](systembeschreibung/07-nginx.md) — Webserver-Grundsatz: Multidomain, TLS je Name über certbot/HTTP-01, Port-Strategie, Redirect, Härtung (in Bearbeitung)

08 [systembeschreibung/08-postgresql.md](systembeschreibung/08-postgresql.md) — Datenbankserver-Grundsatz: nur Loopback, scram-sha-256, restriktive pg_hba, Verbindungs-Logging, Rechte (in Bearbeitung)

## B. Anleitung

01 [anleitung/INDEX.md](anleitung/INDEX.md) — Schritt-für-Schritt-Einrichtung des gehärteten Grundsystems, des optionalen nginx-Webservers und des optionalen PostgreSQL-Datenbankservers (in Bearbeitung)

## C. Installer

01 [installer/secure-base-installer.md](installer/secure-base-installer.md) — Konzept des secure-base-installer: pifos-Grundlage, Ablauf, Module, Konfiguration, Betriebsarten, Bedienoberfläche, Installationsbericht (in Bearbeitung)

02 [installer/pifos-vendoring.md](installer/pifos-vendoring.md) — pifos-Einbettung: Herkunft, lokale Anpassungen, Einbindung, Integritätsprüfung, Upgrade-Verfahren, dist-Auslieferung (in Bearbeitung)

## D. Umstellungen

Anleitungen, die ein bereits laufendes Produktivsystem auf eine neue Version bringen. Auf einem neu aufgesetzten Server sind sie gegenstandslos. Der Dateiname nennt den Versionssprung: `<lfd>-<von>-nach-<nach>-<thema>.md`. Wer den Stand seines Servers kennt, sieht daran ohne Öffnen, welche Anleitungen noch anzuwenden sind.

01 [umstellungen/01-f5278f8-nach-fd1824e-sicherungsablagen-var-backup.md](umstellungen/01-f5278f8-nach-fd1824e-sicherungsablagen-var-backup.md) — lokale Sicherungsablagen nach `/var/backup`, PostgreSQL-Einzeldumps, verstecktes restic-Konfigverzeichnis

02 [umstellungen/02-fd1824e-nach-02f7865-rkhunter-ausnahmen.md](umstellungen/02-fd1824e-nach-02f7865-rkhunter-ausnahmen.md) — rkhunter-Ausnahmen für bekannte Fehlalarme (systemd, PostgreSQL)

03 [umstellungen/03-02f7865-nach-dac64e8-logwatch-tagesbericht.md](umstellungen/03-02f7865-nach-dac64e8-logwatch-tagesbericht.md) — Tagesbericht: Zusammenfassung im Mailtext, vollständiger Logwatch-Bericht als Anhang

04 [umstellungen/04-12e22af-nach-286d19c-anmeldehistorie-und-rsyslog.md](umstellungen/04-12e22af-nach-286d19c-anmeldehistorie-und-rsyslog.md) — Anmeldehistorie (wtmpdb) statt der entfallenen lastlog-Datei, rsyslog sichergestellt, Debian-Unterstützung

05 [umstellungen/05-0235470-nach-d8c517b-cron-dateiname-und-sudo-logfile.md](umstellungen/05-0235470-nach-d8c517b-cron-dateiname-und-sudo-logfile.md) — Backup-Cron-Datei punktfrei umbenennen (lief nie), sudoers-Drop-in mit `Defaults logfile` entfernen (blockierte sudo unter sudo-rs)

06 [umstellungen/06-b4bfe43-nach-7eb5452-drift-schutz-und-alt-sicherungen.md](umstellungen/06-b4bfe43-nach-7eb5452-drift-schutz-und-alt-sicherungen.md) — Drift-Schutz des Installers (Soll-Ist-Vergleich, zentrale Sicherungsablage), alte `.bak-*` neben den Konfigdateien aufräumen

07 [umstellungen/07-63688df-nach-3b6b79c-backup-mounts-ausschliessen.md](umstellungen/07-63688df-nach-3b6b79c-backup-mounts-ausschliessen.md) — `--one-file-system` im Backup-Skript nachziehen: eingehängte Fremd-Dateisysteme nie mitsichern

08 [umstellungen/08-3edb859-nach-38e3a04-backup-sperre-und-zeitbegrenzung.md](umstellungen/08-3edb859-nach-38e3a04-backup-sperre-und-zeitbegrenzung.md) — Backup-Skript: Zeitbegrenzung (hängender Lauf endet als Fehler) und Sperre (höchstens ein Lauf zugleich)

09 [umstellungen/09-f6e9c4c-nach-f3f8751-absender-domain.md](umstellungen/09-f6e9c4c-nach-f3f8751-absender-domain.md) — Systemmails als `root@<domain>` statt `root@<fqdn>` (`myorigin = $mydomain`; Hoster-Relays lehnen fqdn-Absender ab)
