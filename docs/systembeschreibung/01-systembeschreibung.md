# Systembeschreibung

Dieses Dokument beschreibt den Aufbau eines gehärteten Linux-Grundsystems auf einem einzelnen Server:

- Betriebssystem,
- die Zuordnung der Dienste,
- das Verzeichnis- und Dienst-Layout,
- den Port-Plan und die ausgehende Firewall-Zielliste.

# Inhaltsverzeichnis
1. Betriebssystem
2. Dienste
3. Verzeichnis- und Dienst-Layout
4. Port-Plan
5. Ausgehende Firewall-Zielliste

## 1. Betriebssystem

Die Dokumentation beschreibt die Einrichtung eines Linux-Server mit Ubuntu Server 26.04 LTS.


## 2. Dienste

Die Dienste gliedern sich in zwei Gruppen: das gehärtete Grundsystem und die optionalen Komponenten wie Webserver und Datenbankserver.

| Gruppe | Dienst | Bindung | Benutzer | Auto-Restart |
|---|---|---|---|---|
| Grundsystem | SSH (`sshd`) | extern, Port 22 | root | systemd |
| Grundsystem | Postfix (Satellite) | Loopback | postfix | systemd |
| Grundsystem | Brute-Force-Schutz (`fail2ban`) | kein Port | root | systemd |
| Grundsystem | Firewall (`ufw`/nftables) | kein Port | root | systemd |
| Grundsystem | Monitoring (`monit`) | Loopback (Status) | root | systemd |
| Grundsystem | Datensicherung (`restic` per cron) | kein Port (ausgehend SFTP) | root | cron-Timer |
| Grundsystem | Auto-Update (`unattended-upgrades`) | kein Port | root | apt-daily-Timer |
| Grundsystem | Schadsoftware-Scan (`rkhunter`) | kein Port | root | cron.daily |
| Grundsystem | Log-Bericht (`logwatch`) | kein Port | root | cron.daily |
| Grundsystem | Auditing (`auditd`) | kein Port | root | systemd |

**Optional:**

| Gruppe | Dienst | Bindung | Benutzer | Auto-Restart |
|---|---|---|---|---|
| Webserver | nginx (TLS-Terminierung, statische Auslieferung) | extern, Ports 80/443 | www-data | systemd |
| Datenbankserver | PostgreSQL (lokal beschränkt) | Loopback | postgres | systemd |

Dienste ohne Netzwerkzugriff/-port laufen unter einem eigenen System-Benutzer ohne Login-Shell und ohne administrative Gruppenrechte. Alle Daemons starten nach Reboot und nach Absturz automatisch wieder.

Der Webserver ist erst aktiv, wenn nginx installiert ist. Bis dahin nimmt der Server eingehend nur SSH an. 

## 3. Verzeichnis- und Dienst-Layout

Das Layout folgt den Unix-Konventionen: Konfiguration unter `/etc`, Laufzeit- und Datenverzeichnisse unter `/var/lib`, System-Skripte unter `/usr/local/sbin`. 

| Pfad | Inhalt | Eigentümer/Rechte |
|---|---|---|
| `/root/config/` | Geheimnis-Dateien (restic-Passphrase u. a.) | `root`, 600 |
| `/var/lib/secure-base/` | Erfolgs-Kennzeichen der Datensicherung, Härtungsberichte | `root` |
| `/usr/local/sbin/` | System-Skripte (Backup, Härtungsprüfung) | `root`, 700 |
| `/etc/nginx/sites-available/` | Server-Blöcke des Webservers | `root` |

Dateien mit Zugangsdaten (z. B. Zugangsdaten für SFTP Backuppfad), die nur Root liest, erhalten Mode 600. Muss ein Dienst-Benutzer eine Datei mit Zugangsdaten lesen, erhält sie Mode 640 mit einer dafür eingerichteten Gruppe.

## 4. Port-Plan

Im Grundzustand ist eingehend nur SSH offen. Die Web-Ports 80 und 443 werden erst mit dem Webserver geöffnet, Port 80 nur temporär zur Zertifikatsausstellung und -erneuerung ([nginx-Grundsatz](07-nginx.md), Kapitel 3). Loopback-Verkehr passiert die Host-Firewall nicht, daher sind lokal gebundene Dienste in der Firewall nicht freigegeben.

| Port | Protokoll | Richtung | Bindung | Zweck | Firewall-Status |
|---|---|---|---|---|---|
| 22 | TCP | eingehend | extern | SSH-Verwaltung | offen (Grundzustand) |
| 80 | TCP | eingehend | extern | ACME-HTTP-01 (TLS-Zertifikat) | nur temporär mit Webserver |
| 443 | TCP | eingehend | extern | HTTPS Webserver | offen mit Webserver |
| 2812 | TCP | lokal | 127.0.0.1 | Monitoring-Status | nicht freigegeben (Loopback) |
| 5432 | TCP | lokal | 127.0.0.1 | PostgreSQL (optional) | nicht freigegeben (Loopback) |

Auf die optionale Verschärfung, den SSH-Port zusätzlich auf bekannte Quell-Netze zu beschränken, wird bewusst verzichtet. Bei wechselndem Standort des SSH-Nutzers führt eine Quell-Netz-Regel zur Aussperrung. Der Zugang ist über Public-Key, TOTP und `fail2ban` dreifach gesichert.

## 5. Ausgehende Firewall-Zielliste

Die Firewall ist `ufw` mit Default-Policy `deny` für beide Richtungen. Erlaubt werden nur die für den Betrieb nötigen Ziele. Im Grundzustand sind die Regeln port-, nicht an einen Zielhost gebunden, weil Paketquellen, DNS-Server und Git-Gegenstellen wechselnde Adressen haben. `ufw` legt zu jeder Regel automatisch das IPv6-Pendant an.

| Ziel-Port | Protokoll | Zweck |
|---|---|---|
| 587 | TCP | Mail-Versand an das Relay (Submission/STARTTLS) |
| 53 | TCP/UDP | DNS-Auflösung |
| 80 | TCP | Paketquellen (apt), ACME-Bezug |
| 443 | TCP | Paketquellen, Git |
| 22 | TCP | Git-Push und SFTP-Backup |

Loopback-Verkehr passiert die Host-Firewall nicht, daher brauchen lokal gebundene Dienste keine `ufw`-Regel.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage durch bereinigte Übernahme. |
