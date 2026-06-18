# Mail-Versand

Dieses Dokument beschreibt den Mail-Versand des Grundsystems für Systembenachrichtigungen. Es begründet den Aufbau als Satellite-System und die Umleitung aller Systemmails auf eine Admin-Adresse.

**Status:** in Bearbeitung — **Stand:** 2026-06-18

## 1. Zweck und Aufbau

Der Mail-Versand dient ausschließlich Systembenachrichtigungen. Der MTA ist `postfix` als Satellite-System (Smarthost): kein lokaler Mail-Empfang, ausgehender Versand über einen externen SMTP-Server des Hosters. Postfix bindet nur an Loopback (`inet_interfaces = loopback-only`) und ist die erste Komponente des Aufbaus, damit die folgenden Komponenten benachrichtigen können.

Der Versand an das Relay läuft über Port 587 (Submission) mit SASL-Authentifizierung und erzwungenem STARTTLS (`smtp_tls_security_level = encrypt`, Verifikation des Hoster-Zertifikats mit `ca-certificates`). Die SASL-Zugangsdaten liegen in `/etc/postfix/sasl_passwd` mit Mode 600 und gehören nicht ins Repo.

## 2. Umleitung auf die Admin-Adresse

Alle ausgehenden Systemmails werden auf die eine Admin-Adresse umgeleitet. Das leisten zwei Mechanismen: der `root`-Alias in `/etc/aliases` lenkt System-Mail (cron, systemd) auf die Admin-Adresse. Zusätzlich erzwingt `recipient_canonical_maps` über eine Regexp-Map, dass jede ausgehende Mail unabhängig vom Empfänger auf der Admin-Adresse landet.

Über dieses Postfix versenden alle benachrichtigenden Komponenten:

- SSH-Login-Benachrichtigung
- rkhunter
- logwatch
- unattended-upgrades
- restic
- monit

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage durch bereinigte Übernahme. |
