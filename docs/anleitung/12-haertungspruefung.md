# Härtungsprüfung

Der Prüflauf erfolgt monatlich mit `lynis`, ergänzt um den Abgleich mit der CIS-Checkliste für Ubuntu Server Level 1. Der datierte Befund ist der Prüfnachweis.

```
apt install lynis
```

Prüfskript `/usr/local/sbin/secure-base-haertungspruefung.sh` anlegen:

```
#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

BERICHTE="/var/lib/secure-base/haertung"
mkdir -p "$BERICHTE"

lynis audit system --quiet --no-colors \
    > "$BERICHTE/lynis-$(date +%F).txt" 2>&1
cp /var/log/lynis-report.dat "$BERICHTE/lynis-report-$(date +%F).dat"
```

```
chmod 700 /usr/local/sbin/secure-base-haertungspruefung.sh
```

Monatlichen Lauf über `/etc/cron.d/secure-base-haertung` auslösen:

```
# Härtungsprüfung (lynis) — monatlich am 1. um 04:00
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 4 1 * *  root  /usr/local/sbin/secure-base-haertungspruefung.sh
```

```
chmod 644 /etc/cron.d/secure-base-haertung
```

Die Berichte unter `/var/lib/secure-base/haertung/` sind nicht Teil der gesicherten Pfade. Sollen sie ins Backup, ist der Pfad in der Pfadliste des Backup-Skripts (Kapitel 10 der Installationsanleitung) zu ergänzen. Der CIS-Abgleich und die Bewertung der Befunde je BSI-Maßnahmenklasse (Schweregrad, Handlungsempfehlung) erfolgen manuell. Ablage in der Betriebsdokumentation.
