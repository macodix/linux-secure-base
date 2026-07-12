# Schadsoftware-Schutz (rkhunter)

`rkhunter` läuft täglich aus `cron.daily` mit Mail-Bericht an die Administrator Email Adresse.

```
apt install rkhunter
```

In `/etc/default/rkhunter` prüfen bzw. anpassen:

```
CRON_DAILY_RUN="yes"
CRON_DB_UPDATE="yes"
DB_UPDATE_EMAIL="false"
REPORT_EMAIL="<admin@meine-domain.de>"
APT_AUTOGEN="yes"
```

Damit die Report-Mail einen domänen-gültigen Absender hat, in `/etc/rkhunter.conf` die `MAIL_CMD`-Direktive ergänzen:

```
MAIL_CMD=mail -r root@<FQDN> -s "[rkhunter] Warnings found for ${HOST_NAME}"
```

`${HOST_NAME}` ist eine rkhunter-interne Variable und bleibt unverändert. Der Empfänger wird durch die `recipient_canonical`-Umleitung (Kapitel 2 der Installationsanleitung) ohnehin auf die Administrator Email Adresse gelenkt.

Ebenfalls in `/etc/rkhunter.conf` die Ausnahmen für die bekannten Fehlalarme eintragen. Ohne sie meldet jeder Lauf dieselben Dateien, und die wiederkehrenden Meldungen verdecken echte Funde:

```
ALLOWHIDDENFILE=/etc/.resolv.conf.systemd-resolved.bak
ALLOWHIDDENFILE=/etc/.updated
ALLOWDEVFILE=/dev/shm/PostgreSQL.*
```

Die beiden versteckten Dateien legt systemd an: `.resolv.conf.systemd-resolved.bak` ist die Sicherung, die `systemd-resolved` beim Übernehmen von `/etc/resolv.conf` hinterlässt, `.updated` die Zeitstempel-Datei von `systemd-update-done.service`. Die Dateien unter `/dev/shm` sind Shared-Memory-Segmente des PostgreSQL-Servers (`dynamic_shared_memory_type = posix`, Vorgabe unter Ubuntu). Ihr Zahlenteil ist zufällig und wechselt je Segment — deshalb ein Muster statt fester Namen. Auf einem Server ohne Datenbankserver bleibt der Eintrag wirkungslos.

Baseline-Datenbank initialisieren und initialen Check ausführen:

```
rkhunter --propupd
rkhunter --cronjob
```

Das Monitoring prüft die Frische des Scan-Logs (Kapitel 11 der Installationsanleitung).
