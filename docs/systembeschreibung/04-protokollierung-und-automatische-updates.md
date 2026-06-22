# Protokollierung und automatische Updates

Dieses Dokument beschreibt die persistente Protokollierung mit Auditing und die automatischen Sicherheitsupdates des Grundsystems.

## Inhaltsverzeichnis

1. Protokollierung und Auditing
2. Automatische Sicherheitsupdates

## 1. Protokollierung und Auditing

Die Protokollierung besteht aus mehreren Komponenten aus den Distro-Paketquellen: `journald`, `logwatch` und `auditd`, ergänzt um die Protokollierung von `sudo`-Aufrufen und die Rotation des secure-base-Logs.

`journald` läuft persistent (`Storage=persistent`), begrenzt auf 1 GB Plattenverbrauch (`SystemMaxUse=1G`) und drei Monate Aufbewahrung (`MaxRetentionSec=3month`). Damit überleben Logs den Reboot und die Mindest-Aufbewahrung sicherheitsrelevanter Ereignisse von drei Monaten ist erfüllt.

`logwatch` erzeugt täglich aus `cron.daily` eine Mail-Zusammenfassung des Vortags und versendet diese an die Administrator EMail Adresse. Der Detailgrad ist mittel (`Detail = Med`).

`auditd` protokolliert sicherheitskritische Aktivitäten; das Regelset ist auf administrative Vorgänge beschränkt und nach dem Laden bis zum Reboot unveränderlich (`-e 2`).

Ergänzend wird die Nutzung von `sudo` über `/etc/sudoers.d/secure-base-sudolog` nach `/var/log/sudo.log` protokolliert — auch wenn `sudo` für die Administration nicht genutzt wird, bleibt damit jede Nutzung nachvollziehbar. Das secure-base-Logfile `/var/log/secure-base/secure-base.log` wird über `/etc/logrotate.d/secure-base` wöchentlich rotiert (acht Wochen Vorhaltung); `journald` und `auditd` verwalten ihre Logs selbst.

## 2. Automatische Sicherheitsupdates

Sicherheitsupdates werden durch die Installatio von `unattended-upgrades` automatisch installiert. Die erlaubten Quellen sind auf die Distro-Stände `${distro_codename}`, `-security` und `-updates` beschränkt, `-proposed` und `-backports` bleiben ausgeschlossen.

Die Default-Sequenz für Update ist 23:15 Paketlisten aktualisieren (`apt update ), 23:30 Upgrade (`apt upgrade`), 23:45 Reboot (bei Bedarf). Dafür werden `apt-daily.timer` und `apt-daily-upgrade.timer` auf feste Zeiten gesetzt und ihr Streuwert (`RandomizedDelaySec`) auf 0 gestellt. Die periodische Ausführung wird über `/etc/apt/apt.conf.d/20auto-upgrades` aktiviert.

Ein fehlgeschlagenes Upgrade meldet `unattended-upgrades` per Mail (`MailReport "only-on-error"`) an die Administrator EMail Adresse. Ein erfolgreicher Reboot wird nicht gemeldet.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage |
| 0.02 | 2026-06-22 | macodix | sudo-Protokollierung und Log-Rotation ergänzt. |
