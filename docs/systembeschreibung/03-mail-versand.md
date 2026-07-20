# Mail-Versand

Dieses Dokument beschreibt den Mail-Versand des Grundsystems für Systembenachrichtigungen.

## Inhaltsverzeichnis
1. Zweck und Aufbau
2. Umleitung auf die Administrator Email Adresse

## 1. Zweck und Aufbau

Der Mail-Versand dient ausschließlich Systembenachrichtigungen. 

Der MTA ist `postfix` als Satellite-System (Smarthost), ohne lokalen Mail-Empfang aber mit ausgehendem Versand über einen externen SMTP-Server. Postfix ist nur an Loopback (`inet_interfaces = loopback-only`) gebunden.

Der Versand an das Relay läuft i. d. R über Port 587 (Submission) mit SASL-Authentifizierung und erzwungenem STARTTLS (`smtp_tls_security_level = encrypt`, Verifikation des Hoster-Zertifikats mit `ca-certificates`). Die SASL-Zugangsdaten liegen in `/etc/postfix/sasl_passwd` mit Mode 600.

## 2. Umleitung auf die Administrator Email Adresse

Alle ausgehenden Systemmails werden auf eine Administrator Email Adresse umgeleitet. Dazu werden folgende Mechanismen genutzt:
- `root`-Alias in `/etc/aliases` lenkt System-Mail (cron, systemd) auf die Administrator Email Adresse
- `recipient_canonical_maps` erzwingt über eine Regexp-Map, dass jede ausgehende Mail unabhängig vom Empfänger an die Administrator Email Adresse versandt wird.

Zu den Mail versendenden Diensten/Komponenten gehören:

- SSH-Login-Benachrichtigung
- rkhunter
- logwatch
- unattended-upgrades
- restic
- monit

### Wirkung und Grenzen der Umleitung

Die Umleitung ist zugleich eine Schutzmaßnahme: Der Server kann keine Mail an Dritte versenden. Auch bei Fehlkonfiguration oder einem kompromittierten Dienst taugt er nicht als Spam-Versender, und ungewöhnliches Mail-Aufkommen fällt sofort im Administrator-Postfach auf.

Daraus folgt: Auch Anwendungsmails nachträglich installierter Dienste (z. B. Registrierungs- oder Passwort-Mails eines Webdienstes) erreichen ausschließlich die Administrator Email Adresse, nie den in der Anwendung eingetragenen Empfänger. Soll ein Dienst echte Empfänger erreichen, muss die Regexp-Map in `/etc/postfix/recipient_canonical` bewusst um Ausnahmen ergänzt werden. Gegen Flutung des Administrator-Postfachs selbst schützt die Umleitung nicht.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage |
| 0.02 | 2026-07-20 | macodix | Wirkung und Grenzen der Mail-Umleitung ergänzt |
