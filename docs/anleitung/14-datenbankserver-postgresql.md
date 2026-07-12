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

Das Datenverzeichnis eines laufenden Clusters lässt sich nicht konsistent dateiweise sichern. Stattdessen täglich je Datenbank einen logischen Dump erzeugen und unter `/var/backup/postgresql` ablegen. `/var/backup` ist das Sammelverzeichnis für alle lokal abgelegten Sicherungen und wird von der [Datensicherung](10-datensicherung.md) mitgesichert.

Einzeldumps statt eines Gesamt-Dumps: jede Datenbank lässt sich einzeln wiederherstellen, ohne die übrigen anzufassen. Rollen und Tablespaces gehören dem Cluster, nicht einer Datenbank — sie kommen zusätzlich über `pg_dumpall --globals-only` nach `globals.sql`.

Zielverzeichnis anlegen:

```
mkdir -p /var/backup/postgresql
chmod 700 /var/backup /var/backup/postgresql
```

Dump-Skript `/usr/local/sbin/secure-base-pg-dump.sh` anlegen:

```
#!/usr/bin/env bash
set -euo pipefail
DUMP_DIR="/var/backup/postgresql"
GLOBALS_FILE="$DUMP_DIR/globals.sql"

TMP_FILE=""
trap 'rm -f "$TMP_FILE"' EXIT

dump_to() {
    local target="$1"
    shift
    TMP_FILE="$(mktemp "$DUMP_DIR/.dump.XXXXXX")"
    if ! "$@" >"$TMP_FILE"; then
        echo "fehlgeschlagen: $* — bisherige Sicherung $target bleibt erhalten" >&2
        return 1
    fi
    chmod 0600 "$TMP_FILE"
    mv -f "$TMP_FILE" "$target"
    TMP_FILE=""
}

if ! databases="$(runuser -u postgres -- psql -tAc \
    "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate")"; then
    echo "Datenbankliste nicht lesbar — kein Dump" >&2
    exit 1
fi

while IFS= read -r db; do
    [ -n "$db" ] || continue
    case "$db" in
        *[!A-Za-z0-9_-]*)
            echo "Datenbankname mit unzulässigen Zeichen: $db — kein Dump" >&2
            exit 1
            ;;
    esac
    dump_to "$DUMP_DIR/$db.sql" runuser -u postgres -- \
        pg_dump --create --clean --if-exists "$db"
done <<< "$databases"

dump_to "$GLOBALS_FILE" runuser -u postgres -- pg_dumpall --globals-only
```

```
chmod 700 /usr/local/sbin/secure-base-pg-dump.sh
```

Das Skript läuft als root und schreibt die Dumps mit Mode 0600; `pg_dump` und `pg_dumpall` laufen über `runuser` als `postgres` (lokale peer-Authentifizierung, kein Passwort). Jeder Dump wird erst in eine Temp-Datei geschrieben und bei Erfolg per `mv` über die Zieldatei gelegt — ein Fehlschlag lässt die vorherige Sicherung unverändert.

`globals.sql` entsteht bewusst als letzte Datei des Laufs. Ihr Zeitstempel belegt damit einen vollständig erfolgreichen Dump — die Frische-Überwachung stützt sich darauf (Kapitel 7).

Cron-Eintrag `/etc/cron.d/secure-base-pg-dump` — vor dem restic-Lauf (Vorgabe 02:30), damit die frischen Dumps im selben Nachtlauf gesichert werden:

```
0 2 * * *  root  /usr/local/sbin/secure-base-pg-dump.sh
```

## 7. Frische-Überwachung

Das Monitoring prüft mit dem Check `postgresql_dump` das Alter von `/var/backup/postgresql/globals.sql` und alarmiert bei Überalterung (>26 h). Da das Skript diese Datei zuletzt schreibt, bleibt sie bei jedem Fehlschlag alt — auch wenn nur der Dump einer einzelnen Datenbank scheitert. Geprüft wird damit die Sicherungsdatei selbst, keine gesonderte Markierungsdatei. Dazu `postgresql_dump` in der Konfiguration zu den aktiven monit-Checks aufnehmen.

## 8. Wiederherstellung

Zuerst die clusterweiten Objekte (Rollen, Tablespaces), dann die gewünschten Datenbanken — jede für sich:

```
runuser -u postgres -- psql -f /var/backup/postgresql/globals.sql
runuser -u postgres -- psql -f /var/backup/postgresql/<datenbank>.sql postgres
```

Die Einzeldumps sind mit `--create --clean --if-exists` erzeugt: der Aufruf verbindet sich mit der Datenbank `postgres`, verwirft die Zieldatenbank, falls vorhanden, und legt sie neu an.
