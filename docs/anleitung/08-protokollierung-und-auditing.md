# Protokollierung und Auditing

Mehrere Komponenten aus den Distro-Paketquellen: `journald` als persistentes Systemlog, `rsyslog` als Schreiber der Protokolldateien unter `/var/log`, `wtmpdb` als Anmeldehistorie, `logwatch` als tägliche Auswertung, `auditd` für die Nachweisbarkeit administrativer Tätigkeiten, dazu die Protokollierung von `sudo`-Aufrufen und die Rotation des secure-base-Logs. Den täglichen Bericht verschickt ein eigenes Skript: Zusammenfassung im Mailtext, vollständiger Logwatch-Bericht als Anhang (Kapitel 5).

## 1. journald persistent

In `/etc/systemd/journald.conf` setzen:

```
[Journal]
Storage=persistent
SystemMaxUse=1G
MaxRetentionSec=3month
```

- `Storage=persistent` — Logs überleben Reboots (Ablage in `/var/log/journal/`).
- `SystemMaxUse=1G` — maximaler Plattenverbrauch.
- `MaxRetentionSec=3month` — erfüllt die Mindest-Aufbewahrung sicherheitsrelevanter Logs.

Die Werte `SystemMaxUse` und `MaxRetentionSec` stammen aus `JOURNALD_MAX_USE` bzw. `JOURNALD_MAX_RETENTION` in `secure-base.conf` (Vorgaben: `1G` und `3month`).

Anschließend neu starten:

```
systemctl restart systemd-journald
```

## 2. rsyslog

`rsyslog` schreibt die Protokolldateien unter `/var/log` (`auth.log`, `syslog`, `mail.log`). Sie sind die Quelle des Logwatch-Berichts (Kapitel 4) und werden von Werkzeugen außerhalb von secure-base gelesen.

```
apt install rsyslog
systemctl enable --now rsyslog
```

Nicht jede Distribution führt `rsyslog` in der Standardinstallation mit — unter Debian 13 hat das Paket nur Priorität `optional`. Ist es bereits vorhanden, ändert der Aufruf nichts. Die Vorgabekonfiguration wird unverändert übernommen.

`journald` (Kapitel 1) bleibt daneben bestehen und ist die Quelle der Zusammenfassung im Tagesbericht.

## 3. Anmeldehistorie (wtmpdb)

Die klassische Anmeldehistorie aus `/var/log/wtmp`, `/var/log/btmp` und `/var/log/lastlog` gibt es nicht mehr: `pam_lastlog` ist aus `libpam-modules` entfernt, und die utmp-Dateien sind ersatzlos entfallen (ihr 32-Bit-Zeitformat läuft 2038 über). Ohne Nachfolger gäbe es weder `last` noch eine Datei, die sich mit `auditd` überwachen ließe.

```
apt install wtmpdb libpam-wtmpdb
```

`wtmpdb` führt die Anmelde-, Boot- und Shutdown-Zeiten in einer SQLite-Datenbank unter `/var/log/wtmp.db` und bringt `last` mit. `libpam-wtmpdb` trägt die Anmeldungen über PAM ein; die mitgelieferte PAM-Vorgabe wird unverändert übernommen.

Unter Debian 13 gehören beide Pakete zur Standardinstallation, und `sshd` schreibt zusätzlich direkt über `libwtmpdb0` — die dortige PAM-Vorgabe lässt SSH-Sitzungen deshalb aus, um doppelte Einträge zu vermeiden. Unter Ubuntu ist `sshd` nicht gegen `libwtmpdb0` gebunden; dort erfasst das PAM-Modul auch die SSH-Anmeldungen. In beiden Fällen landet jede Anmeldung genau einmal in der Datenbank.

Zwei Gründe für die Nachinstallation, auch wo sie nicht zum Distributionsstandard gehört: Die Datenbank überlebt die Rotation des Journals (dort gilt `MaxRetentionSec`), und sie ist ein Objekt, das die Audit-Regel überwachen kann (Kapitel 6). Ohne sie bliebe der Audit-Schlüssel `logins` leer.

Überprüfung: `last` listet die Anmeldungen, `ls -l /var/log/wtmp.db` zeigt die Datenbank.

## 4. logwatch als täglicher Mail-Report

```
apt install logwatch
```

In `/etc/logwatch/conf/logwatch.conf` setzen:

```
Output = mail
Format = text
MailTo = <admin@meine-domain.de>
MailFrom = logwatch@meine-domain.de
Detail = Med
Range = yesterday
```

Der Versand nutzt das Postfix aus Kapitel 2 der Installationsanleitung.

## 5. Tagesbericht: Zusammenfassung im Mailtext, Logwatch-Bericht als Anhang

Der vollständige Logwatch-Bericht umfasst leicht zweitausend Zeilen, von denen über neunzig Prozent Aufzählungen abgewiesener Anmeldeversuche und HTTP-Scanner sind. Diese Hosts hat `fail2ban` bereits gesperrt, die Aufzählung ändert an keiner Entscheidung etwas. Steht sie im Mailtext, wird der Bericht nicht mehr gelesen und verdeckt damit das Wenige, worauf es ankommt.

Deshalb verschickt ein eigenes Skript den Bericht: Der Mailtext trägt eine Zusammenfassung der sicherheitsrelevanten Vorgänge, der vollständige Logwatch-Bericht liegt als Datei bei und ist damit bei Bedarf sofort greifbar.

Die Zusammenfassung nennt erfolgreiche SSH-Anmeldungen mit Benutzer, Quell-IP und Zeit, die Zwei-Faktor-Vorgänge (angenommene wie abgelehnte TOTP-Codes), fehlgeschlagene Anmeldungen bekannter Benutzer, `sudo`- und `su`-Aufrufe, die Zahl der fail2ban-Sperren, fehlgeschlagene Dienste und Cron-Läufe, Journal-Fehler und den Plattenplatz. Die abgewiesenen Anmeldeversuche unbekannter Benutzer erscheinen nur als Summe — sie stehen vollständig im Anhang.

Ihre Quelle ist das Journal, nicht der Logwatch-Text: Die Meldungsmuster von `sshd`, `sudo` und `pam` sind stabil, die Abschnitts-Formatierung von Logwatch ist es nicht.

Skript `/usr/local/sbin/secure-base-logwatch.sh` anlegen (Mode 700). Es erzeugt den Logwatch-Bericht mit `--output file`, baut die Zusammenfassung aus `journalctl` und verschickt beides als MIME-Mail über `sendmail`. Der cron.daily-Eintrag `/etc/cron.daily/secure-base-logwatch` (Mode 755) ruft es auf:

```
#!/bin/sh
exec /usr/local/sbin/secure-base-logwatch.sh
```

Der mitgelieferte Lauf `/etc/cron.daily/00logwatch` schreibt den vollständigen Bericht in den Mailtext und ruft `logwatch` mit `--output mail` auf, was jede Vorgabe aus `logwatch.conf` übergeht. Er wird stillgelegt, indem ihm das Ausführungsrecht genommen wird — `run-parts` überspringt nicht ausführbare Dateien, die Paketdatei selbst bleibt unangetastet:

```
chmod 644 /etc/cron.daily/00logwatch
```

Ein Paket-Upgrade kann dieses Recht zurücksetzen. Dann kommen zwei Mails, und der Abgleich (`check`) des Moduls `logging` meldet es.

## 6. auditd

`auditd` protokolliert administrative Änderungen nachweisbar. Das Regelset bleibt klein und auf administrative Vorgänge ausgerichtet.

```
apt install auditd
```

Regeldatei `/etc/audit/rules.d/secure-base.rules` anlegen:

```
# Identität und Konten
-w /etc/passwd      -p wa -k identity
-w /etc/shadow      -p wa -k identity
-w /etc/group       -p wa -k identity

# Anmeldehistorie — nur die Datenbank, die das System tatsächlich führt.
-w /var/log/wtmp.db             -p wa -k logins   # wtmpdb
-w /var/lib/lastlog/lastlog2.db -p wa -k logins   # lastlog2

# Privilegien-Erhöhung und sudo-Konfiguration (su statt sudo)
# Die beiden sudoers-Zeilen nur, wenn sudo vorhanden ist (siehe unten).
-w /usr/bin/su    -p x  -k priv_esc
-w /etc/sudoers   -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

# Administrative Konfiguration
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/pam.d           -p wa -k pam
-w /etc/ufw             -p wa -k firewall
-w /etc/audit           -p wa -k auditconfig

# Regelwerk bis zum Reboot unveränderlich
-e 2
```

Die Regeln für Identität, Anmeldehistorie und sudoers sind das Pflicht-Minimum. Der Watch auf `/usr/bin/su` ergänzt sie um den tatsächlich genutzten Weg der Privilegien-Erhöhung. Da `sudo` nicht genutzt wird, ist zudem jede Änderung an seiner Konfiguration per se verdächtig.

**Anmeldehistorie.** Die klassische Datei `/var/log/lastlog` gibt es nicht mehr — `pam_lastlog` ist aus `libpam-modules` entfernt, unter Debian 13 wie unter Ubuntu 26.04. An ihre Stelle tritt `wtmpdb` (Kapitel 3); überwacht wird dessen Datenbank `/var/log/wtmp.db`. Ist stattdessen `lastlog2` installiert, gilt dessen Datenbank `/var/lib/lastlog/lastlog2.db`. Führt das System keine der beiden, entfällt die Regel, und die Anmeldungen sind nur im Journal nachweisbar.

Eine Regel auf `/var/log/lastlog` beizubehalten wäre die schlechtere Wahl: Sie würde ohne Fehler laden, weil bei einer Datei das Elternverzeichnis genügt, aber nie greifen. Eine leere Regel sieht in `auditctl -l` wie Abdeckung aus und ist keine.

**sudoers.** Die beiden sudoers-Regeln setzen voraus, dass `sudo` installiert ist. `/etc/sudoers.d` ist ein Verzeichnis, und eine Überwachung eines nicht existierenden Verzeichnisses weist `auditctl` ab — das gesamte Regelwerk lädt dann mit Fehler. Auf einem System ohne `sudo` entfallen sie deshalb. Der Installer prüft das und lässt sie in diesem Fall weg.

Dienst aktivieren — beim Start liest `auditd` die Regeldateien aus `/etc/audit/rules.d/`:

```
systemctl enable --now auditd
```

Nach späteren Regeländerungen (vor dem Immutable-Schalten) manuell nachladen mit `augenrules --load`.

Überprüfung: `auditctl -l` listet die Soll-Regeln vollständig, `auditctl -s` meldet `enabled 2`. Wegen des Immutable-Modus (`-e 2`) verlangt jede Regeländerung einen Reboot.

## 7. sudo-Protokollierung

`sudo` wird für die Administration nicht genutzt (der Wechsel zu `root` erfolgt per `su`). Seine Aufrufe protokolliert sudo selbst ins Syslog/Journal (`journalctl _COMM=sudo`); zusätzlich überwachen die Audit-Regeln aus Kapitel 6 die sudoers-Pfade.

Kein Drop-in mit `Defaults logfile` anlegen: Ubuntu liefert `sudo` als sudo-rs aus, das diese Direktive nicht kennt. Eine Datei mit unbekannter Direktive in `/etc/sudoers.d` ist dort ein Parse-Fehler, mit dem sudo **jeden** Aufruf verweigert. Frühere Stände legten `/etc/sudoers.d/secure-base-sudolog` an — auf Bestandssystemen entfernen (siehe Umstellungsanleitung).

## 8. Log-Rotation

Das secure-base-Logfile `/var/log/secure-base/secure-base.log` wird über `/etc/logrotate.d/secure-base` rotiert (`weekly`, `rotate 8` — acht Wochen Vorhaltung). `journald` und `auditd` verwalten die Rotation ihrer Logs selbst.
