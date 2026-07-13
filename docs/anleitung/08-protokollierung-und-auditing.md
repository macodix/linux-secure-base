# Protokollierung und Auditing

Mehrere Komponenten aus den Distro-Paketquellen: `journald` als persistentes Systemlog, `rsyslog` als Schreiber der Protokolldateien unter `/var/log`, `logwatch` als tägliche Auswertung, `auditd` für die Nachweisbarkeit administrativer Tätigkeiten, dazu die Protokollierung von `sudo`-Aufrufen und die Rotation des secure-base-Logs. Den täglichen Bericht verschickt ein eigenes Skript: Zusammenfassung im Mailtext, vollständiger Logwatch-Bericht als Anhang (Kapitel 4).

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

`rsyslog` schreibt die Protokolldateien unter `/var/log` (`auth.log`, `syslog`, `mail.log`). Sie sind die Quelle des Logwatch-Berichts (Kapitel 3) und werden von Werkzeugen außerhalb von secure-base gelesen.

```
apt install rsyslog
systemctl enable --now rsyslog
```

Nicht jede Distribution führt `rsyslog` in der Standardinstallation mit — unter Debian 13 hat das Paket nur Priorität `optional`. Ist es bereits vorhanden, ändert der Aufruf nichts. Die Vorgabekonfiguration wird unverändert übernommen.

`journald` (Kapitel 1) bleibt daneben bestehen und ist die Quelle der Zusammenfassung im Tagesbericht.

## 3. logwatch als täglicher Mail-Report

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

## 4. Tagesbericht: Zusammenfassung im Mailtext, Logwatch-Bericht als Anhang

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

## 5. auditd

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

**Anmeldehistorie.** Die klassische Datei `/var/log/lastlog` gibt es nicht mehr — `pam_lastlog` ist aus `libpam-modules` entfernt, unter Debian 13 wie unter Ubuntu 26.04. An ihre Stelle treten zwei Datenbanken: `wtmpdb` (`/var/log/wtmp.db`; unter Debian die Standard-Anmeldehistorie, `sshd` schreibt direkt hinein) und `lastlog2` (`/var/lib/lastlog/lastlog2.db`). Überwacht wird nur die, deren Paket vorliegt. Führt das System keine der beiden — der Fall auf einer Ubuntu-Standardinstallation —, entfällt die Regel, und die Anmeldungen sind nur im Journal nachweisbar.

Eine Regel auf `/var/log/lastlog` beizubehalten wäre die schlechtere Wahl: Sie würde ohne Fehler laden, weil bei einer Datei das Elternverzeichnis genügt, aber nie greifen. Eine leere Regel sieht in `auditctl -l` wie Abdeckung aus und ist keine.

**sudoers.** Die beiden sudoers-Regeln setzen voraus, dass `sudo` installiert ist. `/etc/sudoers.d` ist ein Verzeichnis, und eine Überwachung eines nicht existierenden Verzeichnisses weist `auditctl` ab — das gesamte Regelwerk lädt dann mit Fehler. Auf einem System ohne `sudo` entfallen sie deshalb. Der Installer prüft das und lässt sie in diesem Fall weg.

Dienst aktivieren — beim Start liest `auditd` die Regeldateien aus `/etc/audit/rules.d/`:

```
systemctl enable --now auditd
```

Nach späteren Regeländerungen (vor dem Immutable-Schalten) manuell nachladen mit `augenrules --load`.

Überprüfung: `auditctl -l` listet die Soll-Regeln vollständig, `auditctl -s` meldet `enabled 2`. Wegen des Immutable-Modus (`-e 2`) verlangt jede Regeländerung einen Reboot.

## 6. sudo-Protokollierung

`sudo` wird für die Administration nicht genutzt (der Wechsel zu `root` erfolgt per `su`), seine Aufrufe werden aber dennoch protokolliert. In `/etc/sudoers.d/secure-base-sudolog` (Mode 440):

```
Defaults logfile="/var/log/sudo.log"
```

Nur auf einem System, auf dem `sudo` vorhanden ist. Fehlt es, entfällt dieser Schritt — `sudo` wird dafür nicht nachinstalliert.

## 7. Log-Rotation

Das secure-base-Logfile `/var/log/secure-base/secure-base.log` wird über `/etc/logrotate.d/secure-base` rotiert (`weekly`, `rotate 8` — acht Wochen Vorhaltung). `journald` und `auditd` verwalten die Rotation ihrer Logs selbst.
