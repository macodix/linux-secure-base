# Protokollierung und automatische Updates

Dieses Dokument beschreibt die persistente Protokollierung mit Auditing und die automatischen Sicherheitsupdates des Grundsystems.

## Inhaltsverzeichnis

1. Protokollierung und Auditing
2. Automatische Sicherheitsupdates

## 1. Protokollierung und Auditing

Die Protokollierung besteht aus mehreren Komponenten aus den Distro-Paketquellen: `journald`, `logwatch` und `auditd`, ergänzt um die Protokollierung von `sudo`-Aufrufen und die Rotation des secure-base-Logs.

`journald` läuft persistent (`Storage=persistent`), begrenzt auf 1 GB Plattenverbrauch (`SystemMaxUse=1G`) und drei Monate Aufbewahrung (`MaxRetentionSec=3month`). Damit überleben Logs den Reboot und die Mindest-Aufbewahrung sicherheitsrelevanter Ereignisse von drei Monaten ist erfüllt.

`logwatch` wertet die Logs des Vortags aus (Detailgrad mittel, `Detail = Med`). Sein Bericht geht nicht als Mailtext hinaus: Über neunzig Prozent davon sind Aufzählungen abgewiesener Anmeldeversuche und HTTP-Scanner, die `fail2ban` bereits gesperrt hat. Ein Bericht, der zu über neunzig Prozent aus Rauschen besteht, wird nicht gelesen.

Stattdessen verschickt `/usr/local/sbin/secure-base-logwatch.sh` täglich aus `cron.daily` einen Tagesbericht an die Administrator Email Adresse: Der Mailtext trägt eine Zusammenfassung der sicherheitsrelevanten Vorgänge, der vollständige Logwatch-Bericht liegt als Datei bei. Die Zusammenfassung nennt erfolgreiche SSH-Anmeldungen mit Benutzer, Quell-IP und Zeit, die Zwei-Faktor-Vorgänge, fehlgeschlagene Anmeldungen bekannter Benutzer, `sudo`- und `su`-Aufrufe, die Zahl der fail2ban-Sperren, fehlgeschlagene Dienste und Cron-Läufe, Journal-Fehler und den Plattenplatz. Abgewiesene Anmeldeversuche unbekannter Benutzer erscheinen nur als Summe.

Quelle der Zusammenfassung ist das Journal, nicht der Logwatch-Text: Die Meldungsmuster von `sshd`, `sudo` und `pam` sind stabil, die Abschnitts-Formatierung von Logwatch ist es nicht. Der mitgelieferte Lauf `/etc/cron.daily/00logwatch` ist stillgelegt (Ausführungsrecht entzogen), sonst käme der vollständige Bericht ein zweites Mal als Mailtext.

`auditd` protokolliert sicherheitskritische Aktivitäten; das Regelset ist auf administrative Vorgänge beschränkt und nach dem Laden bis zum Reboot unveränderlich (`-e 2`).

Ist `sudo` auf dem System vorhanden, wird seine Nutzung ergänzend über `/etc/sudoers.d/secure-base-sudolog` nach `/var/log/sudo.log` protokolliert, und das Audit-Regelset überwacht `/etc/sudoers` und `/etc/sudoers.d`. Administriert wird zwar über `su`, aber damit bleibt jede Nutzung von `sudo` nachvollziehbar. Fehlt `sudo`, entfallen beide Bestandteile; nachinstalliert wird es nicht. Das secure-base-Logfile `/var/log/secure-base/secure-base.log` wird über `/etc/logrotate.d/secure-base` wöchentlich rotiert (acht Wochen Vorhaltung); `journald` und `auditd` verwalten ihre Logs selbst.

## 2. Automatische Sicherheitsupdates

Sicherheitsupdates werden durch die Installatio von `unattended-upgrades` automatisch installiert. Die erlaubten Quellen sind auf die Distro-Stände `${distro_codename}`, `-security` und `-updates` beschränkt, `-proposed` und `-backports` bleiben ausgeschlossen.

Die Default-Sequenz für Update ist 23:15 Paketlisten aktualisieren (`apt update ), 23:30 Upgrade (`apt upgrade`), 23:45 Reboot (bei Bedarf). Dafür werden `apt-daily.timer` und `apt-daily-upgrade.timer` auf feste Zeiten gesetzt und ihr Streuwert (`RandomizedDelaySec`) auf 0 gestellt. Die periodische Ausführung wird über `/etc/apt/apt.conf.d/20auto-upgrades` aktiviert.

Ein fehlgeschlagenes Upgrade meldet `unattended-upgrades` per Mail (`MailReport "only-on-error"`) an die Administrator Email Adresse. Ein erfolgreicher Reboot wird nicht gemeldet.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage |
| 0.02 | 2026-06-22 | macodix | sudo-Protokollierung und Log-Rotation ergänzt. |
| 0.03 | 2026-07-13 | macodix | sudo-Protokollierung und sudoers-Audit-Regeln nur, wenn sudo vorhanden ist. |
