# Datenbankserver postgresql (optional)

Einrichtung eines lokal beschränkten PostgreSQL-Datenbankservers. Der Server ist nur über den lokalen Socket und Loopback (127.0.0.1/::1) erreichbar, kein Netz-Port. Die Begründung der Festlegungen steht in der [Systembeschreibung postgresql-Grundsatz](../systembeschreibung/08-postgresql.md).

Die Pfade enthalten die PostgreSQL-Hauptversion `<version>` und den Cluster-Namen (Ubuntu-Vorgabe `main`). Die installierte Version zeigt `pg_lsclusters`.

## 1. Installation

```
apt install postgresql
```

Der Dienst läuft unter dem Distro-Default-Benutzer `postgres` (keine Login-Shell, keine administrativen Gruppen).

## 2. Verbindungs- und Protokollierungshärtung

Eine eigene Drop-in-Datei `/etc/postgresql/<version>/main/conf.d/secure-base-hardening.conf` anlegen — Ubuntu bindet `conf.d` per `include_dir` ein:

```
listen_addresses = 'localhost'
password_encryption = scram-sha-256
logging_collector = on
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %u@%d '
log_timezone = '<zeitzone>'
```

`<zeitzone>` ist die Systemzeitzone (`TIMEZONE` aus `secure-base.conf`). Rechte setzen:

```
chown postgres:postgres /etc/postgresql/<version>/main/conf.d/secure-base-hardening.conf
chmod 640 /etc/postgresql/<version>/main/conf.d/secure-base-hardening.conf
```

## 3. Zugriffsliste pg_hba.conf

`/etc/postgresql/<version>/main/pg_hba.conf` vollständig durch die restriktive Fassung ersetzen:

```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     scram-sha-256
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
```

Kein `trust`, keine Netz-Freigabe außer Loopback, keine Replikationszeile. Rechte setzen:

```
chown postgres:postgres /etc/postgresql/<version>/main/pg_hba.conf
chmod 640 /etc/postgresql/<version>/main/pg_hba.conf
```

## 4. Datenverzeichnis-Rechte

Das Datenverzeichnis `/var/lib/postgresql/<version>/main` erhält Mode 0700 mit Eigentümer `postgres`:

```
chown postgres:postgres /var/lib/postgresql/<version>/main
chmod 700 /var/lib/postgresql/<version>/main
```

## 5. Übernahme und Prüfung

Dienst neu starten und die lokale Verbindung prüfen:

```
systemctl restart postgresql@<version>-main
runuser -u postgres -- psql -c 'select 1'
```

## 6. Tägliche Datensicherung (Dump)

Das Datenverzeichnis eines laufenden Clusters lässt sich nicht konsistent dateiweise sichern. Stattdessen täglich einen logischen Gesamt-Dump erzeugen und unter `/root` ablegen — `/root` wird von der [Datensicherung](10-datensicherung.md) ohnehin mitgesichert.

Zielverzeichnis anlegen:

```
mkdir -p /root/postgresql-dump
chmod 700 /root/postgresql-dump
```

Dump-Skript `/usr/local/sbin/secure-base-pg-dumpall.sh` anlegen:

```
#!/usr/bin/env bash
set -euo pipefail
DUMP_DIR="/root/postgresql-dump"
SENTINEL="/var/lib/secure-base/pg-dumpall-last-success"
TMP_FILE="$(mktemp "$DUMP_DIR/.dumpall.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT
runuser -u postgres -- pg_dumpall > "$TMP_FILE"
chmod 600 "$TMP_FILE"
mv -f "$TMP_FILE" "$DUMP_DIR/dumpall.sql"
mkdir -p "$(dirname "$SENTINEL")"
touch "$SENTINEL"
```

```
chmod 700 /usr/local/sbin/secure-base-pg-dumpall.sh
```

Der Dump als root schreibt die Datei mit Mode 0600; `pg_dumpall` läuft über `runuser` als `postgres` (lokale peer-Authentifizierung, kein Passwort). Cron-Eintrag `/etc/cron.d/secure-base-pg-dumpall` — vor dem restic-Lauf (Vorgabe 02:30), damit der frische Dump im selben Nachtlauf gesichert wird:

```
0 2 * * *  root  /usr/local/sbin/secure-base-pg-dumpall.sh
```

## 7. Frische-Überwachung

Der Dump aktualisiert die Markierungsdatei `/var/lib/secure-base/pg-dumpall-last-success` nur im Erfolgsfall. Das Monitoring prüft mit dem Check `postgresql_dump` ihr Alter und alarmiert bei Überalterung (>26 h). Dazu `postgresql_dump` in der Konfiguration zu den aktiven monit-Checks aufnehmen.

## 8. Wiederherstellung

Den Gesamt-Dump als `postgres` einspielen:

```
runuser -u postgres -- psql -f /root/postgresql-dump/dumpall.sql
```
