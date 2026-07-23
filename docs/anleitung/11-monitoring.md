# Monitoring (monit)

`monit` überwacht Plattenplatz, Systemlast, Speicher und kritische Dienste und alarmiert per Mail über das lokale Postfix. Lokale Lösung, keine Drittanbieter.

## 1. Installation

```
apt install monit
```

## 2. Grundkonfiguration

In `/etc/monit/monitrc` folgende Werte setzen (vorhandene Block-Beispiele anpassen, statt mehrfach zu setzen):

```
set daemon 60
    with start delay 60

set log /var/log/monit.log

set mailserver localhost

set mail-format {
    from:    monit@<meine-domain.de>
    subject: monit [$HOST] $EVENT — $SERVICE
    message: $EVENT — $SERVICE auf $HOST ($DATE)
             $DESCRIPTION
}

set alert <admin@meine-domain.de> but not on { instance }

set httpd port 2812 and
    use address localhost
    allow localhost
```

- `set daemon 60` — Prüfzyklus 60 s. Ein Dienst-Ausfall wird innerhalb eines Zyklus erkannt.
- `set mailserver localhost` — Postfix aus Kapitel 2 der Installationsanleitung übernimmt den Versand.
- `but not on { instance }` — monits eigene Start-/Stopp-Meldung (etwa bei jedem Dienst-Neustart durch needrestart) erzeugt keine Mail; das ist Normalverhalten ohne Alarmwert. Alle Fehler-Alarme der überwachten Dienste bleiben unberührt. Abwägung: Der Verlust ist gering — ein gestoppter monit könnte ohnehin keine Mail schicken.
- `set httpd ... allow localhost` — Status nur über Loopback abrufbar (`monit status` als root).
- `from: …` — Absenderadresse der Alarm-Mails; im Installer aus dem Pflichtwert `MONIT_MAIL_FROM` in `secure-base.conf`.

## 3. Checks

In `/etc/monit/conf.d/` für jeden Check eine eigene Datei anlegen.

`/etc/monit/conf.d/system`:

```
check system $HOST
    if loadavg (1min) > 4    then alert
    if loadavg (5min) > 2    then alert
    if memory usage > 90 %   then alert
    if cpu usage (user) > 90 % for 5 cycles then alert
```

`/etc/monit/conf.d/rootfs`:

```
check filesystem rootfs with path /
    if space usage > 85 % then alert
    if inode usage > 85 % then alert
```

`/etc/monit/conf.d/sshd`:

```
check process sshd matching "sshd"
    start program = "/bin/systemctl start ssh"
    stop  program = "/bin/systemctl stop  ssh"
    if 5 restarts within 5 cycles then alert
```

`/etc/monit/conf.d/postfix`:

```
check process postfix with pidfile /var/spool/postfix/pid/master.pid
    start program = "/bin/systemctl start postfix"
    stop  program = "/bin/systemctl stop  postfix"
```

`/etc/monit/conf.d/fail2ban`:

```
check process fail2ban with pidfile /var/run/fail2ban/fail2ban.pid
    start program = "/bin/systemctl start fail2ban"
    stop  program = "/bin/systemctl stop  fail2ban"
```

`/etc/monit/conf.d/ufw` — die Firewall hat keinen Dauer-Daemon. Geprüft wird der Service-Status über den Exit-Code (kein Parsen einer Ausgabe):

```
check program ufw with path "/bin/systemctl is-active --quiet ufw"
    if status != 0 then alert
```

`/etc/monit/conf.d/cron` — der Cron-Dienst führt die tägliche Datensicherung aus:

```
check process crond with pidfile /var/run/crond.pid
    start program = "/bin/systemctl start cron"
    stop  program = "/bin/systemctl stop  cron"
    if 5 restarts within 5 cycles then alert
```

`/etc/monit/conf.d/rkhunter` — Frische des Logs, das der tägliche Lauf schreibt:

```
check file rkhunter with path /var/log/rkhunter.log
    if mtime > 25 hours then alert
```

`/etc/monit/conf.d/restic` — Backup-Frische über das Erfolgs-Kennzeichen aus Kapitel 10 der Installationsanleitung (Alarm spätestens 26 h nach letztem Erfolg):

```
check file restic_backup with path /var/lib/secure-base/restic-last-success
    if mtime > 26 hours then alert
```

Mit dem Webserver wird ein Prozess-Check für nginx ergänzt (Kapitel 13 der Installationsanleitung).

## 4. Aktivieren

```
monit -t
systemctl enable --now monit
```
