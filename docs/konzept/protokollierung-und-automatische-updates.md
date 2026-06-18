# Protokollierung und automatische Updates

Dieses Dokument beschreibt die persistente Protokollierung mit Auditing und die automatischen Sicherheitsupdates des Grundsystems.

**Status:** in Bearbeitung — **Stand:** 2026-06-18

## Inhaltsverzeichnis

1 Protokollierung und Auditing
2 Automatische Sicherheitsupdates

## 1. Protokollierung und Auditing

Die Protokollierung besteht aus drei Komponenten aus den Distro-Paketquellen: `journald`, `logwatch` und `auditd`.

`journald` läuft persistent (`Storage=persistent`), begrenzt auf 1 GB Plattenverbrauch (`SystemMaxUse=1G`) und drei Monate Aufbewahrung (`MaxRetentionSec=3month`). Damit überleben Logs den Reboot und die Mindest-Aufbewahrung sicherheitsrelevanter Ereignisse von drei Monaten ist erfüllt.

`logwatch` erzeugt täglich aus `cron.daily` eine Mail-Zusammenfassung des Vortags an die Admin-Adresse und versendet über das Postfix (Konzept-Dokument Mail-Versand). Der Detailgrad ist mittel (`Detail = Med`).

`auditd` macht administrative Tätigkeiten nachweisbar. Das Regelset bleibt klein und auf administrative Befehle ausgerichtet. Sein konkreter Umfang wird in der Implementierung festgelegt.

## 2. Automatische Sicherheitsupdates

Sicherheitsupdates installiert `unattended-upgrades` automatisch. Die erlaubten Quellen sind auf die Distro-Stände `${distro_codename}`, `-security` und `-updates` beschränkt. `-proposed` und `-backports` bleiben ausgeschlossen, weil sie für einen automatischen Reboot ohne Aufsicht nicht ausreichend getestet sind.

Der Reboot erfolgt gesteuert in einem Nachtfenster. Die Sequenz ist 23:15 (Paketlisten), 23:30 (Upgrade), 23:45 (Reboot). Dafür werden `apt-daily.timer` und `apt-daily-upgrade.timer` auf feste Zeiten gesetzt und ihr Streuwert (`RandomizedDelaySec`) auf 0 gestellt, sonst greift die geplante Zeit nicht. Die periodische Ausführung wird über `/etc/apt/apt.conf.d/20auto-upgrades` aktiviert.

Ein fehlgeschlagenes Upgrade meldet `unattended-upgrades` per Mail (`MailReport "only-on-error"`). Ein erfolgreicher Reboot wird nicht eigens gemeldet. Seine Nachvollziehbarkeit läuft über `journalctl`/`last` und das Monitoring (Konzept-Dokument Monitoring).

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage durch bereinigte Übernahme. |
