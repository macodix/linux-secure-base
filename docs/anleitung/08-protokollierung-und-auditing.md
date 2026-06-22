# Protokollierung und Auditing

Mehrere Komponenten aus den Distro-Paketquellen: `journald` als persistentes Systemlog, `logwatch` als tägliche Mail-Zusammenfassung, `auditd` für die Nachweisbarkeit administrativer Tätigkeiten, dazu die Protokollierung von `sudo`-Aufrufen und die Rotation des secure-base-Logs.

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

## 2. logwatch als täglicher Mail-Report

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

`logwatch` läuft per Distro-Default täglich aus `cron.daily`. Der Versand nutzt das Postfix aus Kapitel 2 der Installationsanleitung. Erster Probelauf: `logwatch --output mail`.

## 3. auditd

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
-w /var/log/lastlog -p wa -k logins

# Privilegien-Erhöhung und sudo-Konfiguration (su statt sudo)
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

Die Regeln für Identität, sudoers und lastlog sind das Pflicht-Minimum. Der Watch auf `/usr/bin/su` ergänzt sie um den tatsächlich genutzten Weg der Privilegien-Erhöhung. Da `sudo` nicht genutzt wird, ist zudem jede Änderung an seiner Konfiguration per se verdächtig.

Dienst aktivieren — beim Start liest `auditd` die Regeldateien aus `/etc/audit/rules.d/`:

```
systemctl enable --now auditd
```

Nach späteren Regeländerungen (vor dem Immutable-Schalten) manuell nachladen mit `augenrules --load`.

Überprüfung: `auditctl -l` listet die Soll-Regeln vollständig, `auditctl -s` meldet `enabled 2`. Wegen des Immutable-Modus (`-e 2`) verlangt jede Regeländerung einen Reboot.

## 4. sudo-Protokollierung

`sudo` wird für die Administration nicht genutzt (der Wechsel zu `root` erfolgt per `su`), seine Aufrufe werden aber dennoch protokolliert. In `/etc/sudoers.d/secure-base-sudolog` (Mode 440):

```
Defaults logfile="/var/log/sudo.log"
```

## 5. Log-Rotation

Das secure-base-Logfile `/var/log/secure-base/secure-base.log` wird über `/etc/logrotate.d/secure-base` rotiert (`weekly`, `rotate 8` — acht Wochen Vorhaltung). `journald` und `auditd` verwalten die Rotation ihrer Logs selbst.
