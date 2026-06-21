# Mail-Versand

Dieses Dokument beschreibt den Mail-Versand des Grundsystems für Systembenachrichtigungen.

## Inhaltsverzeichnis
1. Zweck und Aufbau
2. Umleitung auf die Admin-Adresse

## 1. Zweck und Aufbau

Der Mail-Versand dient ausschließlich Systembenachrichtigungen. 

Der MTA ist `postfix` als Satellite-System (Smarthost), ohne lokalen Mail-Empfang aber mit ausgehendem Versand über einen externen SMTP-Server. Postfix ist nur an Loopback (`inet_interfaces = loopback-only`) gebunden.

Der Versand an das Relay läuft i. d. R über Port 587 (Submission) mit SASL-Authentifizierung und erzwungenem STARTTLS (`smtp_tls_security_level = encrypt`, Verifikation des Hoster-Zertifikats mit `ca-certificates`). Die SASL-Zugangsdaten liegen in `/etc/postfix/sasl_passwd` mit Mode 600.

## 2. Umleitung auf die Admin-Adresse

Alle ausgehenden Systemmails werden auf eine Administrator EMail-Adresse umgeleitet. Dazu werden folgende Mechanismen genutzt:
- `root`-Alias in `/etc/aliases` lenkt System-Mail (cron, systemd) auf die Admin-Adresse
- `recipient_canonical_maps` erzwingt über eine Regexp-Map, dass jede ausgehende Mail unabhängig vom Empfänger an die Administrator EMail Adresse versandt wird.

Zu den Mail versendenden Diensten/Komponenten gehören:

- SSH-Login-Benachrichtigung
- rkhunter
- logwatch
- unattended-upgrades
- restic
- monit

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage |
