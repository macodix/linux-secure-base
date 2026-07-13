# Protokollierung und automatische Updates

Dieses Dokument beschreibt die persistente Protokollierung mit Auditing und die automatischen Sicherheitsupdates des Grundsystems.

## Inhaltsverzeichnis

1. Protokollierung und Auditing
2. Automatische Sicherheitsupdates

## 1. Protokollierung und Auditing

Die Protokollierung besteht aus mehreren Komponenten aus den Distro-Paketquellen: `journald`, `rsyslog`, `wtmpdb`, `logwatch` und `auditd`, ergänzt um die Protokollierung von `sudo`-Aufrufen und die Rotation des secure-base-Logs.

`rsyslog` schreibt die Protokolldateien unter `/var/log` (`auth.log`, `syslog`, `mail.log`), die Quelle des Logwatch-Berichts sind. Es gehört nicht auf jeder Distribution zur Standardinstallation und wird deshalb installiert, falls es fehlt; beim Rückbau bleibt es bestehen. `journald` läuft daneben und ist die Quelle der Zusammenfassung im Tagesbericht.

`wtmpdb` führt die Anmeldehistorie in einer SQLite-Datenbank unter `/var/log/wtmp.db` (lesbar mit `last`), zusammen mit `libpam-wtmpdb` für die Erfassung über PAM. Die klassischen Dateien `/var/log/wtmp` und `/var/log/lastlog` sind entfallen. Beide Pakete werden installiert, falls sie fehlen, und beim Rückbau nicht entfernt. Die Datenbank ist zugleich das Ziel der Audit-Regel `logins`: Sie überlebt die Rotation des Journals und ist gegen Manipulation überwachbar.

`journald` läuft persistent (`Storage=persistent`), begrenzt auf 1 GB Plattenverbrauch (`SystemMaxUse=1G`) und drei Monate Aufbewahrung (`MaxRetentionSec=3month`). Damit überleben Logs den Reboot und die Mindest-Aufbewahrung sicherheitsrelevanter Ereignisse von drei Monaten ist erfüllt.

`logwatch` wertet die Logs des Vortags aus (Detailgrad mittel, `Detail = Med`). Sein Bericht geht nicht als Mailtext hinaus: Über neunzig Prozent davon sind Aufzählungen abgewiesener Anmeldeversuche und HTTP-Scanner, die `fail2ban` bereits gesperrt hat. Ein Bericht, der zu über neunzig Prozent aus Rauschen besteht, wird nicht gelesen.

Stattdessen verschickt `/usr/local/sbin/secure-base-logwatch.sh` täglich aus `cron.daily` einen Tagesbericht an die Administrator Email Adresse: Der Mailtext trägt eine Zusammenfassung der sicherheitsrelevanten Vorgänge, der vollständige Logwatch-Bericht liegt als Datei bei. Die Zusammenfassung nennt erfolgreiche SSH-Anmeldungen mit Benutzer, Quell-IP und Zeit, die Zwei-Faktor-Vorgänge, fehlgeschlagene Anmeldungen bekannter Benutzer, `sudo`- und `su`-Aufrufe, die Zahl der fail2ban-Sperren, fehlgeschlagene Dienste und Cron-Läufe, Journal-Fehler und den Plattenplatz. Abgewiesene Anmeldeversuche unbekannter Benutzer erscheinen nur als Summe.

Quelle der Zusammenfassung ist das Journal, nicht der Logwatch-Text: Die Meldungsmuster von `sshd`, `sudo` und `pam` sind stabil, die Abschnitts-Formatierung von Logwatch ist es nicht. Der mitgelieferte Lauf `/etc/cron.daily/00logwatch` ist stillgelegt (Ausführungsrecht entzogen), sonst käme der vollständige Bericht ein zweites Mal als Mailtext.

`auditd` protokolliert sicherheitskritische Aktivitäten; das Regelset ist auf administrative Vorgänge beschränkt und nach dem Laden bis zum Reboot unveränderlich (`-e 2`).

Ist `sudo` auf dem System vorhanden, wird seine Nutzung ergänzend über `/etc/sudoers.d/secure-base-sudolog` nach `/var/log/sudo.log` protokolliert, und das Audit-Regelset überwacht `/etc/sudoers` und `/etc/sudoers.d`. Administriert wird zwar über `su`, aber damit bleibt jede Nutzung von `sudo` nachvollziehbar. Fehlt `sudo`, entfallen beide Bestandteile; nachinstalliert wird es nicht. Das secure-base-Logfile `/var/log/secure-base/secure-base.log` wird über `/etc/logrotate.d/secure-base` wöchentlich rotiert (acht Wochen Vorhaltung); `journald` und `auditd` verwalten ihre Logs selbst.

## 2. Automatische Sicherheitsupdates

Sicherheitsupdates werden durch die Installatio von `unattended-upgrades` automatisch installiert. Die erlaubten Quellen sind auf den Release-Stand der Distribution sowie deren `-security`- und `-updates`-Archive beschränkt, `-proposed` und `-backports` bleiben ausgeschlossen.

Wie die Quellen benannt werden, hängt als einziger Punkt der Einrichtung von der Distribution ab. Ubuntu benennt sie mit der Kurzform `Allowed-Origins` („Origin:Archiv"), da dort das Archiv den Codenamen trägt. Debian führt als Archiv `stable` bzw. `stable-security` und den Codenamen in einem eigenen Feld; dort greift nur `Origins-Pattern`, das die Felder der Release-Dateien einzeln vergleicht. Die laufende Distribution wird aus `/etc/os-release` festgestellt; auf einer nicht unterstützten Distribution bricht das Modul ab, statt eine der beiden Benennungen zu unterstellen.

Die Default-Sequenz für Update ist 23:15 Paketlisten aktualisieren (`apt update ), 23:30 Upgrade (`apt upgrade`), 23:45 Reboot (bei Bedarf). Dafür werden `apt-daily.timer` und `apt-daily-upgrade.timer` auf feste Zeiten gesetzt und ihr Streuwert (`RandomizedDelaySec`) auf 0 gestellt. Die periodische Ausführung wird über `/etc/apt/apt.conf.d/20auto-upgrades` aktiviert.

Ein fehlgeschlagenes Upgrade meldet `unattended-upgrades` per Mail (`MailReport "only-on-error"`) an die Administrator Email Adresse. Ein erfolgreicher Reboot wird nicht gemeldet.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage |
| 0.02 | 2026-06-22 | macodix | sudo-Protokollierung und Log-Rotation ergänzt. |
| 0.03 | 2026-07-13 | macodix | sudo-Protokollierung und sudoers-Audit-Regeln nur, wenn sudo vorhanden ist. |
| 0.04 | 2026-07-13 | macodix | Erlaubte Paketquellen je Distribution (Allowed-Origins unter Ubuntu, Origins-Pattern unter Debian). |
| 0.05 | 2026-07-13 | macodix | rsyslog als Bestandteil der Protokollierung aufgenommen. |
| 0.06 | 2026-07-13 | macodix | wtmpdb als Anmeldehistorie aufgenommen; Audit-Regel auf deren Datenbank statt auf /var/log/lastlog. |
