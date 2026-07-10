"""Modul postgresql — Datenbankserver mit lokal beschränktem Zugriff.

Installiert das Paket postgresql, härtet die Verbindungs- und
Protokollierungseinstellungen über eine eigene Drop-in-Datei unter
conf.d und ersetzt pg_hba.conf durch eine restriktive Zugriffsliste
(kein trust, keine Netz-Freigabe außer Loopback). Prüft/setzt zusätzlich
die Rechte des Datenverzeichnisses. Legt keine Anwendungs-DB/-Benutzer
an und öffnet keinen Netz-Port (kein ufw-Eintrag). Richtet zusätzlich
eine logische Datensicherung ein: ein Cron-Skript führt täglich
pg_dumpall aus und legt den Dump unter /root ab, wo ihn das restic-Modul
mit sichert (/etc /home /var/log /root); ein Erfolgs-Sentinel unter
/var/lib/secure-base ermöglicht eine monit-Frische-Überwachung (Muster
wie beim restic-Modul). Optionales Modul; setzt das gehärtete
Grundsystem voraus. Betriebsart über den Schlüssel operation.
PostgreSQL-Hauptversion und Cluster-Name werden zur Laufzeit unter
/etc/postgresql ermittelt, nie hartkodiert.
"""

import grp
import os
import pwd
import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar
from zoneinfo import available_timezones

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.permissions_action import PermissionsAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Dateiname der eigenen Drop-in-Konfiguration unter conf.d.
_HARDENING_CONF_NAME = "secure-base-hardening.conf"

# Feste GUC-Zeilen der eigenen conf.d-Datei (ohne log_timezone — die hängt
# von der Systemzeitzone ab und wird gesondert angehängt).
_HARDENING_GUC_LINES: tuple[str, ...] = (
    "listen_addresses = 'localhost'",
    "password_encryption = scram-sha-256",
    "logging_collector = on",
    "log_connections = on",
    "log_disconnections = on",
    "log_line_prefix = '%m [%p] %u@%d '",
)

# pg_hba.conf-Zeilen in fester Reihenfolge (Sicherheitspolitik): lokaler
# Administratorzugang per peer, alle übrigen lokalen und Loopback-
# Verbindungen ausschließlich per scram-sha-256. Kein trust, keine
# Remote-/Replikationszeile.
_PG_HBA_LINES: tuple[str, ...] = (
    "local   all             postgres                                peer",
    "local   all             all                                     scram-sha-256",
    "host    all             all             127.0.0.1/32            scram-sha-256",
    "host    all             all             ::1/128                 scram-sha-256",
)

_OWN_FILE_HEADER = (
    "# Von secure-base/postgresql angelegt — nicht von Hand bearbeiten.\n"
)


def _pg_hba_content() -> str:
    """Baut den vollständigen Inhalt von pg_hba.conf.

    Returns:
        Kommentarkopf, Spaltenüberschrift und die vier zulässigen Zeilen
        (siehe _PG_HBA_LINES).
    """
    column_header = (
        "# TYPE  DATABASE        USER            ADDRESS                 METHOD\n"
    )
    body = "".join(f"{line}\n" for line in _PG_HBA_LINES)
    return _OWN_FILE_HEADER + column_header + body


# Grobe Plausibilität einer HH:MM-Uhrzeit (24h, anchored) — gleiches Muster
# wie secure_base.modules.unattended.
_HHMM_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")

_DUMP_SCRIPT_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail

# Von secure-base/postgresql angelegt — nicht von Hand bearbeiten.
# cron-Umgebung ist spartanisch — PATH explizit setzen.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

DUMP_DIR="{dump_dir}"
DUMP_FILE="{dump_file}"
TMP_FILE="$(mktemp "$DUMP_DIR/.dumpall.XXXXXX")"
trap 'rm -f "$TMP_FILE"' EXIT

if ! "{runuser_bin}" -u postgres -- "{pg_dumpall_bin}" >"$TMP_FILE"; then
    echo "pg_dumpall fehlgeschlagen — alte Sicherung bleibt erhalten" >&2
    exit 1
fi

chmod 0600 "$TMP_FILE"
mv -f "$TMP_FILE" "$DUMP_FILE"

# Erfolgs-Sentinel für die monit-Frische-Überwachung (postgresql_dump-Check),
# wird nur nach erfolgreichem pg_dumpall erreicht — Muster wie beim
# restic-Backup-Skript.
mkdir -p "{sentinel_dir}" 2>/dev/null || true
touch "{sentinel_file}" 2>/dev/null || true
"""


def _dump_script_content(
    dump_dir: str,
    dump_file: str,
    runuser_bin: str,
    pg_dumpall_bin: str,
    sentinel_dir: str,
    sentinel_file: str,
) -> str:
    """Baut den Inhalt des Dump-Skripts.

    Args:
        dump_dir: Zielverzeichnis für Temp- und Zieldatei.
        dump_file: Endgültiger Pfad der Dump-Datei.
        runuser_bin: Pfad zu runuser.
        pg_dumpall_bin: Pfad zu pg_dumpall.
        sentinel_dir: Verzeichnis des monit-Frische-Sentinels.
        sentinel_file: Datei des monit-Frische-Sentinels.

    Returns:
        Vollständiger Skriptinhalt.
    """
    return _DUMP_SCRIPT_TEMPLATE.format(
        dump_dir=dump_dir,
        dump_file=dump_file,
        runuser_bin=runuser_bin,
        pg_dumpall_bin=pg_dumpall_bin,
        sentinel_dir=sentinel_dir,
        sentinel_file=sentinel_file,
    )


def _cron_fields(hhmm: str) -> tuple[str, str]:
    """Zerlegt eine geprüfte HH:MM-Uhrzeit in Cron-Minute und -Stunde.

    Args:
        hhmm: Geprüfte Uhrzeit (Muster _HHMM_RE).

    Returns:
        (Minute, Stunde) als Cron-Feld-Strings ohne führende Nullen.
    """
    hour, minute = hhmm.split(":")
    return str(int(minute)), str(int(hour))


def _dump_cron_content(hhmm: str, script_path: str) -> str:
    """Baut den Inhalt der Dump-Cron-Datei.

    Args:
        hhmm: Geprüfte Uhrzeit (Muster _HHMM_RE).
        script_path: Pfad zum Dump-Skript.

    Returns:
        Vollständiger Cron-Dateiinhalt.
    """
    minute, hour = _cron_fields(hhmm)
    return (
        f"# Datensicherung (pg_dumpall) - täglich um {hhmm}\n"
        "# Von secure-base/postgresql angelegt — nicht von Hand bearbeiten.\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        f"{minute} {hour} * * *  root  {script_path}\n"
    )


class Postgresql(Module):
    """Datenbankserver mit lokal beschränktem Zugriff über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = ["operation", "timezone", "pg_dump_time"]

    # Programmpfade und Schreibziele als Klassenattribute (siehe Modul base
    # für die Begründung); eine Testunterklasse kann sie überschreiben.
    PSQL_BIN: ClassVar[str] = "/usr/bin/psql"
    PG_DUMPALL_BIN: ClassVar[str] = "/usr/bin/pg_dumpall"
    RUNUSER_BIN: ClassVar[str] = "/usr/sbin/runuser"
    DPKG_QUERY_BIN: ClassVar[str] = "/usr/bin/dpkg-query"
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"

    PG_ETC_BASE: ClassVar[str] = "/etc/postgresql"
    PG_DATA_BASE: ClassVar[str] = "/var/lib/postgresql"

    PACKAGES: ClassVar[tuple[str, ...]] = ("postgresql",)

    # Eigentümer/Gruppe für Datenverzeichnis und die beiden eigenen
    # Konfigurationsdateien — distributionsüblich postgres:postgres.
    # WriteFileAction schreibt neue Dateien als root; ein nachgelagerter
    # PermissionsAction-Schritt setzt Eigentümer und Rechte explizit
    # (analog zum Datenverzeichnis), statt sich auf world-readable-Rechte
    # zu verlassen.
    PG_OWNER: ClassVar[str] = "postgres"
    PG_GROUP: ClassVar[str] = "postgres"
    DATA_DIR_MODE: ClassVar[int] = 0o700
    HARDENING_CONF_MODE: ClassVar[int] = 0o640
    PG_HBA_MODE: ClassVar[int] = 0o640

    # Logische Datensicherung (pg_dumpall): Skript/Cron nach dem Muster des
    # restic-Moduls (Skript unter /usr/local/sbin, Cron in /etc/cron.d).
    # Der Dump landet unter /root, das restic bereits sichert (/etc /home
    # /var/log /root) — kein eigenes Backup-Ziel, kein eigener Transport.
    DUMP_SCRIPT_PATH: ClassVar[str] = "/usr/local/sbin/secure-base-pg-dumpall.sh"
    DUMP_CRON_PATH: ClassVar[str] = "/etc/cron.d/secure-base-pg-dumpall"
    DUMP_DIR: ClassVar[str] = "/root/postgresql-dump"
    DUMP_FILE_NAME: ClassVar[str] = "dumpall.sql"
    DUMP_SCRIPT_MODE: ClassVar[int] = 0o700
    DUMP_CRON_MODE: ClassVar[int] = 0o644
    DUMP_DIR_MODE: ClassVar[int] = 0o700
    # Eigentümer von Dump-Zielverzeichnis und -Skript — root:root (nicht
    # postgres:postgres wie PG_OWNER/PG_GROUP): das Skript läuft als root
    # und der Dump enthält u. a. scram-Hashes; eigenes Klassenattribut,
    # damit eine Testunterklasse es umlenken kann (siehe PG_OWNER).
    DUMP_OWNER: ClassVar[str] = "root"
    DUMP_GROUP: ClassVar[str] = "root"

    # Erfolgs-Sentinel für die monit-Frische-Überwachung (Check
    # postgresql_dump) — gleiches Verzeichnis wie beim restic-Modul, das
    # es bereits anlegt; hier zusätzlich defensiv sichergestellt, falls
    # restic nicht aktiv ist.
    SENTINEL_DIR: ClassVar[str] = "/var/lib/secure-base"
    SENTINEL_FILE: ClassVar[str] = "/var/lib/secure-base/pg-dumpall-last-success"

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt; hier nur Typdeklaration für
    # mypy --strict, ohne eigenen __init__ (siehe Modul base).
    operation: str
    timezone: str
    pg_dump_time: str

    def start(self) -> int:
        """Führt Einrichtung, Abgleich, Rückbau oder Funktionstest aus.

        uninstall ist konfig-unabhängig (verwendet self.timezone nicht)
        und ruft deshalb _validate() bewusst nicht auf, analog zu den
        Modulen nginx und rkhunter.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei unbekannter timezone; nicht bei
                operation == "uninstall".
        """
        if self.operation == "uninstall":
            return self._uninstall()
        self._validate()
        if self.operation == "check":
            return self._verify()
        if self.operation == "test":
            return self._test()
        return self._install()

    def _validate(self) -> None:
        """Prüft timezone und pg_dump_time, bevor sie in Dateien/Cron gehen.

        Beide Werte gehen in generierte Konfigurations- bzw. Cron-Dateien;
        WriteFileAction schreibt Inhalte ungeprüft, deshalb prüft das
        Modul die Werte vorher (konv-scripting-python.md Abschnitt 4.2).

        Raises:
            ModuleError: Wenn timezone keine bekannte tzdata-Zeitzone ist,
                oder pg_dump_time nicht dem Muster HH:MM entspricht.
        """
        if self.timezone not in available_timezones():
            raise ModuleError(f"postgresql: unbekannte Zeitzone: {self.timezone!r}")
        if not _HHMM_RE.match(self.pg_dump_time):
            raise ModuleError(
                f"postgresql: pg_dump_time ist keine gültige Uhrzeit HH:MM:"
                f" {self.pg_dump_time!r}"
            )

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Markdown-Abschnitt für den Installationsbericht.

        SICHERHEIT: postgresql verwaltet keine Geheimnisse über diesen Weg
        (keine Anwendungs-DB/-Benutzer; der Dump selbst enthält zwar u. a.
        scram-Hashes, sein Inhalt geht aber nie in den Bericht ein); doc()
        liest aus values ausschließlich timezone, pg_dump_time und
        restic_backup_time (rein informativ, für den Zeitplan-Hinweis; kein
        modulübergreifender Abgleich/keine Validierung).

        Args:
            values: Konfigurationswerte des Laufs (u. a. timezone,
                pg_dump_time, restic_backup_time).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Datenbankserver
            postgresql (optional)".
        """
        timezone = values.get("timezone") or "(leer/Default)"
        pg_dump_time = values.get("pg_dump_time") or "(leer/Default)"
        restic_backup_time = values.get("restic_backup_time") or "(leer/Default)"
        hardening_block = "".join(f"  - `{line}`\n" for line in _HARDENING_GUC_LINES)
        hardening_block += f"  - `log_timezone = '{timezone}'`\n"
        pg_hba_block = "".join(f"  - `{line}`\n" for line in _PG_HBA_LINES)
        file_rights = (
            f"Rechte {oct(cls.HARDENING_CONF_MODE)}, Eigentümer"
            f" {cls.PG_OWNER}:{cls.PG_GROUP}"
        )
        dump_file = f"{cls.DUMP_DIR}/{cls.DUMP_FILE_NAME}"

        return (
            "\n## Datenbankserver postgresql (optional)\n\n"
            f"**Pakete:** {', '.join(cls.PACKAGES)}\n\n"
            "**Dateien/Einstellungen** (Pfade unter"
            f" `{cls.PG_ETC_BASE}/<version>/<cluster>`, Version/Cluster zur"
            f" Laufzeit ermittelt; beide Dateien {file_rights}):\n\n"
            f"- `conf.d/{_HARDENING_CONF_NAME}`:\n"
            f"{hardening_block}"
            "- `pg_hba.conf` (vollständig ersetzt):\n"
            f"{pg_hba_block}"
            f"\n**Datenverzeichnis:** Rechte {oct(cls.DATA_DIR_MODE)}, Eigentümer"
            f" {cls.PG_OWNER}:{cls.PG_GROUP}\n"
            "\n**Firewall:** kein eingehender Port geöffnet (listen_addresses"
            " nur Loopback, keine ufw-Regel)\n"
            "\n**Dienste:** postgresql@<version>-<cluster> (enabled, aktiv"
            " nach install)\n"
            "\n**Backup (pg_dumpall):**\n\n"
            f"- `{cls.DUMP_SCRIPT_PATH}` (Rechte {oct(cls.DUMP_SCRIPT_MODE)}"
            f" {cls.DUMP_OWNER}:{cls.DUMP_GROUP})\n"
            f"- `{cls.DUMP_CRON_PATH}`: täglich {pg_dump_time} Uhr (vor dem"
            f" restic-Lauf, restic_backup_time {restic_backup_time} Uhr)\n"
            f"- Ablage: `{dump_file}` (Rechte 0600 {cls.DUMP_OWNER}:"
            f"{cls.DUMP_GROUP}, unter /root — wird vom restic-Modul mit"
            " gesichert: /etc /home /var/log /root)\n"
            f"- Frische-Überwachung: `{cls.SENTINEL_FILE}` wird nur nach"
            " erfolgreichem Dump aktualisiert; monit-Check"
            " `postgresql_dump` alarmiert ab 26 Stunden Alter (siehe Modul"
            " monit)\n"
            "\n> Hinweis: Keine Anwendungs-DB/-Benutzer angelegt, keine"
            " Remote-Zugänge. uninstall entfernt nur die eigene conf.d-Datei"
            " sowie Dump-Skript und -Cron-Eintrag; pg_hba.conf und"
            " vorhandene Dumps bleiben aus Sicherheitsgründen bzw. als Daten"
            " bestehen (Original der pg_hba.conf als .bak-<Zeitstempel> im"
            " selben Verzeichnis abgelegt). Paket und Cluster bleiben in"
            " jedem Fall installiert (Datenverlust vermeiden)."
            " Wiederherstellung aus dem Dump: `psql -f"
            f" {dump_file} postgres` als postgres-Benutzer (vollständiger"
            " Cluster-Restore).\n"
        )

    # --- Cluster-Ermittlung ------------------------------------------------

    def _detect_cluster(self) -> tuple[str, str] | None:
        """Ermittelt PostgreSQL-Hauptversion und Cluster-Namen zur Laufzeit.

        Durchsucht PG_ETC_BASE nach Verzeichnissen <version>/<cluster> mit
        postgresql.conf; die Version wird nie hartkodiert. Mehrere
        gefundene Versionen wählen die numerisch höchste (aktuellste) aus.
        Rein lesend, kein Prozessaufruf.

        Returns:
            (version, cluster) des aktuellsten gefundenen Clusters, oder
            None, wenn keiner gefunden wird.
        """
        base = Path(self.PG_ETC_BASE)
        if not base.is_dir():
            return None
        candidates: list[tuple[int, str, str]] = []
        for version_dir in base.iterdir():
            if not version_dir.is_dir() or not version_dir.name.isdigit():
                continue
            for cluster_dir in version_dir.iterdir():
                if (cluster_dir / "postgresql.conf").is_file():
                    candidates.append(
                        (int(version_dir.name), version_dir.name, cluster_dir.name)
                    )
        if not candidates:
            return None
        candidates.sort(reverse=True)
        _, version, cluster = candidates[0]
        return version, cluster

    def _require_cluster(self) -> tuple[str, str]:
        """Ermittelt Version und Cluster, bricht bei Nichtvorhandensein ab.

        Returns:
            (version, cluster) des zu verwaltenden Clusters.

        Raises:
            ModuleError: Wenn kein Cluster unter PG_ETC_BASE gefunden wird.
        """
        found = self._detect_cluster()
        if found is None:
            raise ModuleError(
                f"postgresql: kein Cluster unter {self.PG_ETC_BASE} gefunden"
            )
        return found

    def _conf_d_dir(self, version: str, cluster: str) -> Path:
        """Baut den Pfad des conf.d-Verzeichnisses eines Clusters.

        Args:
            version: PostgreSQL-Hauptversion.
            cluster: Cluster-Name.

        Returns:
            Pfad des conf.d-Verzeichnisses.
        """
        return Path(self.PG_ETC_BASE) / version / cluster / "conf.d"

    def _pg_hba_path(self, version: str, cluster: str) -> str:
        """Baut den Pfad der pg_hba.conf eines Clusters.

        Args:
            version: PostgreSQL-Hauptversion.
            cluster: Cluster-Name.

        Returns:
            Pfad der pg_hba.conf.
        """
        return str(Path(self.PG_ETC_BASE) / version / cluster / "pg_hba.conf")

    def _data_dir(self, version: str, cluster: str) -> str:
        """Baut den Pfad des Datenverzeichnisses eines Clusters.

        Args:
            version: PostgreSQL-Hauptversion.
            cluster: Cluster-Name.

        Returns:
            Pfad des Datenverzeichnisses.
        """
        return str(Path(self.PG_DATA_BASE) / version / cluster)

    def _unit_name(self, version: str, cluster: str) -> str:
        """Baut den systemd-Einheitennamen eines Clusters.

        Args:
            version: PostgreSQL-Hauptversion.
            cluster: Cluster-Name.

        Returns:
            Einheitenname (postgresql@<version>-<cluster>).
        """
        return f"postgresql@{version}-{cluster}"

    def _expected_hardening_lines(self) -> list[str]:
        """Baut die Sollzeilen der eigenen conf.d-Datei (ohne Kommentarkopf).

        Returns:
            GUC-Zeilen in Schreibreihenfolge, inklusive log_timezone.
        """
        return [*_HARDENING_GUC_LINES, f"log_timezone = '{self.timezone}'"]

    def _hardening_conf_content(self) -> str:
        """Baut den Inhalt der eigenen conf.d-Härtungsdatei.

        Returns:
            Kommentarkopf und die Sollzeilen aus _expected_hardening_lines.
        """
        body = "".join(f"{line}\n" for line in self._expected_hardening_lines())
        return _OWN_FILE_HEADER + body

    def _dump_file_path(self) -> str:
        """Baut den Pfad der endgültigen Dump-Datei.

        Returns:
            Pfad unter DUMP_DIR mit dem Dateinamen DUMP_FILE_NAME.
        """
        return str(Path(self.DUMP_DIR) / self.DUMP_FILE_NAME)

    def _build_dump_script_content(self) -> str:
        """Baut den Inhalt des Dump-Skripts mit den konfigurierten Pfaden.

        Returns:
            Vollständiger Skriptinhalt (siehe _dump_script_content-Funktion).
        """
        return _dump_script_content(
            dump_dir=self.DUMP_DIR,
            dump_file=self._dump_file_path(),
            runuser_bin=self.RUNUSER_BIN,
            pg_dumpall_bin=self.PG_DUMPALL_BIN,
            sentinel_dir=self.SENTINEL_DIR,
            sentinel_file=self.SENTINEL_FILE,
        )

    def _build_dump_cron_content(self) -> str:
        """Baut den Inhalt der Dump-Cron-Datei für die konfigurierte Uhrzeit.

        Returns:
            Vollständiger Cron-Dateiinhalt.
        """
        return _dump_cron_content(self.pg_dump_time, self.DUMP_SCRIPT_PATH)

    # --- Installation --------------------------------------------------

    def _install(self) -> int:
        """Installiert postgresql und wendet die Härtung an.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        for label, action in self._install_steps():
            if self._step(label, action) != 0:
                return 1
        return 0

    def _install_steps(self) -> Iterator[tuple[str, Action]]:
        """Liefert die Installationsschritte in Ausführungsreihenfolge.

        Als Generator: Version und Cluster werden erst ermittelt, wenn der
        Aufrufer den nächsten Schritt anfordert — also nach der
        vorhergehenden Paketinstallation, nicht beim Aufbau der Liste
        (analog zu Modul nginx, _pre_certbot_steps).

        Yields:
            (Label, Aktion)-Paare in Ausführungsreihenfolge.

        Raises:
            ModuleError: Wenn nach der Paketinstallation kein Cluster unter
                PG_ETC_BASE gefunden wird.
        """
        yield (
            "Paket installieren",
            self.APT_ACTION_CLS(packages=list(self.PACKAGES)),
        )

        version, cluster = self._require_cluster()
        conf_d = self._conf_d_dir(version, cluster)
        unit = self._unit_name(version, cluster)

        hardening_path = conf_d / _HARDENING_CONF_NAME
        pg_hba_path = self._pg_hba_path(version, cluster)

        yield (
            "conf.d-Verzeichnis sicherstellen",
            MakeDirAction(path=str(conf_d), mode=0o755, parents=True),
        )
        yield (
            "Verbindungs- und Protokolleinstellungen schreiben",
            WriteFileAction(
                dst=str(hardening_path),
                content=self._hardening_conf_content(),
                mode=self.HARDENING_CONF_MODE,
                overwrite=True,
            ),
        )
        yield (
            "Eigentümer/Rechte der Härtungs-Konfiguration setzen",
            PermissionsAction(
                path=str(hardening_path),
                mode=self.HARDENING_CONF_MODE,
                owner=self.PG_OWNER,
                group=self.PG_GROUP,
            ),
        )
        yield (
            "pg_hba.conf ersetzen",
            WriteFileAction(
                dst=pg_hba_path,
                content=_pg_hba_content(),
                mode=self.PG_HBA_MODE,
                overwrite=True,
            ),
        )
        yield (
            "Eigentümer/Rechte von pg_hba.conf setzen",
            PermissionsAction(
                path=pg_hba_path,
                mode=self.PG_HBA_MODE,
                owner=self.PG_OWNER,
                group=self.PG_GROUP,
            ),
        )
        yield (
            "Datenverzeichnis-Rechte setzen",
            PermissionsAction(
                path=self._data_dir(version, cluster),
                mode=self.DATA_DIR_MODE,
                owner=self.PG_OWNER,
                group=self.PG_GROUP,
            ),
        )
        yield (
            "Dienst aktivieren",
            self.SYSTEMD_ACTION_CLS(operation="enable", unit=unit, timeout=60),
        )
        yield (
            "Dienst neu starten",
            self.SYSTEMD_ACTION_CLS(operation="restart", unit=unit, timeout=60),
        )

        yield (
            "Dump-Zielverzeichnis anlegen",
            MakeDirAction(path=self.DUMP_DIR, mode=self.DUMP_DIR_MODE, parents=True),
        )
        yield (
            "Dump-Zielverzeichnis-Rechte setzen",
            PermissionsAction(
                path=self.DUMP_DIR,
                mode=self.DUMP_DIR_MODE,
                owner=self.DUMP_OWNER,
                group=self.DUMP_GROUP,
            ),
        )
        yield (
            "Dump-Skript schreiben",
            WriteFileAction(
                dst=self.DUMP_SCRIPT_PATH,
                content=self._build_dump_script_content(),
                mode=self.DUMP_SCRIPT_MODE,
                overwrite=True,
                safe_mode=False,
            ),
        )
        yield (
            "Dump-Cron-Datei schreiben",
            WriteFileAction(
                dst=self.DUMP_CRON_PATH,
                content=self._build_dump_cron_content(),
                mode=self.DUMP_CRON_MODE,
                overwrite=True,
                safe_mode=False,
            ),
        )
        yield (
            "Sentinel-Verzeichnis sicherstellen",
            MakeDirAction(path=self.SENTINEL_DIR, mode=0o755, parents=True),
        )
        yield (
            "Dump-Sentinel initialisieren",
            WriteFileAction(
                dst=self.SENTINEL_FILE,
                content="",
                mode=0o644,
                overwrite=True,
                safe_mode=False,
            ),
        )

    def _step(self, label: str, action: Action) -> int:
        """Führt einen einzelnen Installationsschritt aus und meldet ihn.

        Args:
            label: Beschreibung für die Meldung.
            action: Auszuführende Aktion.

        Returns:
            0 bei Erfolg, 1 bei Fehlschlag.
        """
        self.send_message(LogLevel.INFO, "postgresql", label)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "postgresql", f"fehlgeschlagen: {label}")
            return 1
        return 0

    # --- Rückbau (uninstall) ---------------------------------------------

    def _uninstall(self) -> int:
        """Nimmt die eigenen Änderungen zurück; Paket, Cluster und Dumps bleiben.

        Entfernt Dump-Skript und Dump-Cron-Datei — konfig-/cluster-
        unabhängig (wie z. B. beim Modul nginx): diese Artefakte werden
        entfernt, sobald sie existieren, unabhängig davon, ob aktuell ein
        Cluster gefunden wird. Anschließend die eigene conf.d-Härtung, mit
        Dienst-Neustart, damit die überschriebenen GUCs auf die
        Paket-Vorgaben zurückfallen.

        pg_hba.conf bleibt in der gehärteten Fassung bestehen: keine der
        verfügbaren pifos-Aktionen kann die ursprüngliche Datei gezielt
        wiederherstellen, und ein Rückbau würde scram-sha-256 durch das
        schwächere Vorgabe-„peer" ersetzen und die Replikationszeilen
        wieder öffnen — das widerspräche dem Zweck von secure-base.
        DUMP_DIR und vorhandene Dumps bleiben ebenfalls bestehen (Daten,
        analog zur restic-Passphrase-Datei). Paket und Cluster werden nie
        entfernt (Datenverlust).

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        dump_steps: list[tuple[str, Action]] = []
        if Path(self.DUMP_CRON_PATH).exists():
            dump_steps.append(
                (
                    "Dump-Cron-Datei entfernen",
                    DeleteFileAction(path=self.DUMP_CRON_PATH, safe_mode=False),
                )
            )
        if Path(self.DUMP_SCRIPT_PATH).exists():
            dump_steps.append(
                (
                    "Dump-Skript entfernen",
                    DeleteFileAction(path=self.DUMP_SCRIPT_PATH, safe_mode=False),
                )
            )
        for label, action in dump_steps:
            if self._step(label, action) != 0:
                return 1
        if Path(self.DUMP_DIR).exists():
            self.send_message(
                LogLevel.WARN,
                "postgresql",
                f"{self.DUMP_DIR} bleibt bestehen — vorhandene Dumps sind"
                " Daten (wie die restic-Passphrase) und werden nie"
                " automatisch gelöscht; bei Bedarf manuell entfernen",
            )

        found = self._detect_cluster()
        if found is None:
            self.send_message(
                LogLevel.INFO,
                "postgresql",
                "kein Cluster gefunden — nichts zurückzunehmen",
            )
            return 0
        version, cluster = found
        conf_file = self._conf_d_dir(version, cluster) / _HARDENING_CONF_NAME
        pg_hba_path = self._pg_hba_path(version, cluster)
        unit = self._unit_name(version, cluster)

        self.send_message(
            LogLevel.WARN,
            "postgresql",
            f"{pg_hba_path} bleibt in der gehärteten Fassung bestehen (kein"
            " automatischer Rückbau); die ursprüngliche Datei liegt als"
            f" Sicherung {pg_hba_path}.bak-<Zeitstempel> im selben"
            " Verzeichnis (von secure-base beim ersten install angelegt) und"
            " kann bei Bedarf manuell zurückkopiert werden. Paket und"
            " Cluster bleiben installiert.",
        )

        if not conf_file.exists():
            self.send_message(
                LogLevel.INFO,
                "postgresql",
                "eigene conf.d-Datei bereits entfernt — nichts zu tun",
            )
            return 0

        steps: list[tuple[str, Action]] = [
            ("eigene conf.d-Datei entfernen", DeleteFileAction(path=str(conf_file))),
            (
                "Dienst neu starten",
                self.SYSTEMD_ACTION_CLS(operation="restart", unit=unit, timeout=60),
            ),
        ]
        for label, action in steps:
            if self._step(label, action) != 0:
                return 1
        return 0

    # --- Funktionstest (test) --------------------------------------------

    def _test(self) -> int:
        """Führt einen Funktionstest ohne Systemänderung durch.

        Prüft den Dienststatus, eine lokale Verbindung als postgres
        (SELECT 1) über runuser und das Vorhandensein/die Ausführbarkeit
        des Dump-Skripts — sammelnd, kein Abbruch beim ersten Fehlschlag.
        Führt bewusst keinen echten pg_dumpall aus (rein lesend, wie die
        übrigen Prüfungen).

        Returns:
            0, wenn alle Prüfungen erfolgreich waren, sonst 1.
        """
        found = self._detect_cluster()
        if found is None:
            self.send_message(
                LogLevel.ERROR,
                "postgresql",
                f"kein Cluster unter {self.PG_ETC_BASE} gefunden — kein"
                " Funktionstest möglich",
            )
            return 1
        version, cluster = found
        unit = self._unit_name(version, cluster)

        ok = True
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", unit], "active", f"{unit} aktiv"
        )
        ok &= self._check_local_connection()
        ok &= self._check_dump_script_executable()
        return 0 if ok else 1

    def _check_dump_script_executable(self) -> bool:
        """Prüft, ob das Dump-Skript vorhanden und ausführbar ist.

        Rein lesend — führt das Skript nicht aus (kein echter Dump im
        Funktionstest).

        Returns:
            True, wenn das Skript existiert und für den aufrufenden
            Prozess (root) ausführbar ist.
        """
        path = Path(self.DUMP_SCRIPT_PATH)
        if not path.is_file():
            self.send_message(
                LogLevel.ERROR, "postgresql", f"Dump-Skript fehlt: {path}"
            )
            return False
        if not os.access(path, os.X_OK):
            self.send_message(
                LogLevel.ERROR, "postgresql", f"Dump-Skript nicht ausführbar: {path}"
            )
            return False
        self.send_message(
            LogLevel.INFO,
            "postgresql",
            f"Dump-Skript vorhanden und ausführbar: {path}",
        )
        return True

    def _check_local_connection(self) -> bool:
        """Prüft eine lokale Verbindung als postgres über die Unix-Socket.

        Returns:
            True, wenn SELECT 1 als postgres über runuser/psql erfolgreich
            ausgeführt wurde und "1" zurückliefert.
        """
        action = SysCmdAction(
            command=[
                self.RUNUSER_BIN,
                "-u",
                "postgres",
                "--",
                self.PSQL_BIN,
                "-tAc",
                "SELECT 1",
            ],
            timeout=15,
        )
        if self.run_action(action) != 0:
            self.send_message(
                LogLevel.ERROR,
                "postgresql",
                "lokale Verbindung (SELECT 1) fehlgeschlagen",
            )
            return False
        if action.stdout.strip() == "1":
            self.send_message(
                LogLevel.INFO, "postgresql", "lokale Verbindung (SELECT 1): ok"
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "postgresql",
            f"lokale Verbindung: unerwartete Ausgabe {action.stdout.strip()!r}",
        )
        return False

    # --- Abgleich (check) ----------------------------------------------

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit den eigenen Installationsschritten ab.

        Rein lesend: Dateiinhalte und Dienststatus, keine DB-Verbindung
        (die übernimmt _test). Prüft nur, ob die eigenen install-Schritte
        gewirkt haben — kein System-Audit. Läuft alle Prüfungen durch und
        sammelt das Ergebnis.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = self._check_packages()

        found = self._detect_cluster()
        if found is None:
            self.send_message(
                LogLevel.ERROR,
                "postgresql",
                f"kein Cluster unter {self.PG_ETC_BASE} gefunden",
            )
            return 1
        version, cluster = found
        unit = self._unit_name(version, cluster)

        ok &= self._check_svc_enabled(unit)
        ok &= self._check_hardening_conf(version, cluster)
        ok &= self._check_pg_hba(version, cluster)
        ok &= self._check_data_dir(version, cluster)
        ok &= self._check_dump_script()
        ok &= self._check_dump_cron()
        ok &= self._check_dump_dir()
        return 0 if ok else 1

    def _check_packages(self) -> bool:
        """Prüft, ob alle PACKAGES installiert sind.

        Returns:
            True, wenn alle Pakete installiert sind.
        """
        ok = True
        for package in self.PACKAGES:
            ok &= self._check_package(package)
        return ok

    def _check_package(self, package: str) -> bool:
        """Prüft, ob ein einzelnes Paket installiert ist.

        Args:
            package: Zu prüfender Paketname.

        Returns:
            True, wenn dpkg das Paket als installiert führt.
        """
        action = SysCmdAction(
            command=[self.DPKG_QUERY_BIN, "-W", "-f=${Status}", package], timeout=15
        )
        if self.run_action(action) == 0 and "install ok installed" in action.stdout:
            self.send_message(
                LogLevel.INFO, "postgresql", f"Paket installiert: {package}"
            )
            return True
        self.send_message(LogLevel.ERROR, "postgresql", f"Paket fehlt: {package}")
        return False

    def _check_svc_enabled(self, unit: str) -> bool:
        """Prüft, ob die Dienst-Einheit aktiv und boot-persistent ist.

        Args:
            unit: Name der systemd-Einheit.

        Returns:
            True, wenn aktiv und enabled.
        """
        active = self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", unit], "active", f"{unit} aktiv"
        )
        enabled = self._check_value(
            [self.SYSTEMCTL_BIN, "is-enabled", unit],
            "enabled",
            f"{unit} aktiviert (boot-persistent)",
        )
        return active and enabled

    def _check_hardening_conf(self, version: str, cluster: str) -> bool:
        """Prüft Inhalt sowie Rechte/Eigentümer der eigenen conf.d-Datei.

        Args:
            version: PostgreSQL-Hauptversion.
            cluster: Cluster-Name.

        Returns:
            True, wenn alle Sollzeilen vorhanden sind und Rechte/Eigentümer
            stimmen.
        """
        path = self._conf_d_dir(version, cluster) / _HARDENING_CONF_NAME
        content = self._read_text(str(path))
        if content is None:
            self.send_message(LogLevel.ERROR, "postgresql", f"{path} fehlt")
            return False
        lines = content.splitlines()
        missing = [
            line for line in self._expected_hardening_lines() if line not in lines
        ]
        if missing:
            self.send_message(
                LogLevel.ERROR,
                "postgresql",
                f"{path}: fehlende Einstellungen: {missing!r}",
            )
            return False
        self.send_message(
            LogLevel.INFO, "postgresql", f"{path}: alle Einstellungen gesetzt"
        )
        return self._check_file_mode(
            str(path), self.HARDENING_CONF_MODE, self.PG_OWNER, self.PG_GROUP
        )

    def _check_pg_hba(self, version: str, cluster: str) -> bool:
        """Prüft pg_hba.conf auf exakte Übereinstimmung mit dem Sollinhalt.

        Vergleicht den gesamten Dateiinhalt gegen _pg_hba_content()
        (Kommentarkopf, Spaltenüberschrift, die vier zulässigen Zeilen in
        fester Reihenfolge). Eine Voll-Vergleichsprüfung statt einer reinen
        Teilmengenprüfung deckt implizit auch die Abwesenheit von trust-
        sowie Replikations-/Remote-Zeilen ab: jede zusätzliche, fehlende
        oder umgestellte Zeile — etwa eine "replication"-Zeile oder eine
        "host"-Zeile mit einer Adresse außerhalb von 127.0.0.1/32 bzw.
        ::1/128 — gilt als Abweichung.

        Args:
            version: PostgreSQL-Hauptversion.
            cluster: Cluster-Name.

        Returns:
            True bei exakter Übereinstimmung und korrekten Rechten/
            Eigentümer.
        """
        path = self._pg_hba_path(version, cluster)
        content = self._read_text(path)
        if content is None:
            self.send_message(LogLevel.ERROR, "postgresql", f"{path} fehlt")
            return False
        if content != _pg_hba_content():
            self.send_message(
                LogLevel.ERROR,
                "postgresql",
                f"{path}: Inhalt weicht vom Soll ab (erwartet: exakt die vier"
                " zulässigen Zeilen — kein trust, keine"
                " Replikations-/Remote-Zeile)",
            )
            return False
        self.send_message(LogLevel.INFO, "postgresql", f"{path}: Inhalt OK")
        return self._check_file_mode(
            path, self.PG_HBA_MODE, self.PG_OWNER, self.PG_GROUP
        )

    def _check_data_dir(self, version: str, cluster: str) -> bool:
        """Prüft Rechte und Eigentümer des Datenverzeichnisses.

        Args:
            version: PostgreSQL-Hauptversion.
            cluster: Cluster-Name.

        Returns:
            True bei vollständiger Übereinstimmung.
        """
        path = self._data_dir(version, cluster)
        return self._check_file_mode(
            path, self.DATA_DIR_MODE, self.PG_OWNER, self.PG_GROUP
        )

    def _check_dump_script(self) -> bool:
        """Prüft Rechte und Eigentümer des Dump-Skripts.

        Returns:
            True bei vollständiger Übereinstimmung.
        """
        return self._check_file_mode(
            self.DUMP_SCRIPT_PATH,
            self.DUMP_SCRIPT_MODE,
            self.DUMP_OWNER,
            self.DUMP_GROUP,
        )

    def _check_dump_cron(self) -> bool:
        """Prüft, ob die Dump-Cron-Datei exakt dem Sollinhalt entspricht.

        Returns:
            True bei exakter Übereinstimmung.
        """
        content = self._read_text(self.DUMP_CRON_PATH)
        if content is None:
            self.send_message(
                LogLevel.ERROR, "postgresql", f"{self.DUMP_CRON_PATH} fehlt"
            )
            return False
        if content != self._build_dump_cron_content():
            self.send_message(
                LogLevel.ERROR,
                "postgresql",
                f"{self.DUMP_CRON_PATH}: Inhalt weicht vom Soll ab",
            )
            return False
        self.send_message(
            LogLevel.INFO, "postgresql", f"{self.DUMP_CRON_PATH}: Inhalt OK"
        )
        return True

    def _check_dump_dir(self) -> bool:
        """Prüft Rechte und Eigentümer des Dump-Zielverzeichnisses.

        Returns:
            True bei vollständiger Übereinstimmung.
        """
        return self._check_file_mode(
            self.DUMP_DIR, self.DUMP_DIR_MODE, self.DUMP_OWNER, self.DUMP_GROUP
        )

    def _check_file_mode(self, path: str, mode: int, owner: str, group: str) -> bool:
        """Prüft Existenz, Rechte und Eigentümer eines Dateisystemobjekts.

        Args:
            path: Zu prüfender Pfad.
            mode: Erwartete Rechte.
            owner: Erwarteter Eigentümer-Name.
            group: Erwartete Gruppe.

        Returns:
            True bei vollständiger Übereinstimmung.
        """
        try:
            st = Path(path).stat()
        except OSError:
            self.send_message(LogLevel.ERROR, "postgresql", f"{path} fehlt")
            return False

        ok = True
        actual_mode = stat.S_IMODE(st.st_mode)
        if actual_mode != mode:
            self.send_message(
                LogLevel.ERROR,
                "postgresql",
                f"{path}: Rechte {oct(actual_mode)}, erwartet {oct(mode)}",
            )
            ok = False

        try:
            actual_owner = pwd.getpwuid(st.st_uid).pw_name
            actual_group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            self.send_message(
                LogLevel.ERROR, "postgresql", f"{path}: Eigentümer nicht auflösbar"
            )
            return False
        if actual_owner != owner or actual_group != group:
            self.send_message(
                LogLevel.ERROR,
                "postgresql",
                f"{path}: Eigentümer {actual_owner}:{actual_group}, erwartet"
                f" {owner}:{group}",
            )
            ok = False

        if ok:
            self.send_message(
                LogLevel.INFO, "postgresql", f"{path}: Rechte/Eigentümer OK"
            )
        return ok

    def _check_value(self, command: list[str], expected: str, label: str) -> bool:
        """Liest einen Wert über einen Befehl und vergleicht ihn mit dem Soll.

        Args:
            command: Befehl, dessen Ausgabe den Ist-Wert liefert.
            expected: Soll-Wert.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        action = SysCmdAction(command=command, timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "postgresql", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "postgresql", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "postgresql", f"{label}: ist {current}, soll {expected}"
        )
        return False

    def _read_text(self, path: str) -> str | None:
        """Liest eine Textdatei ein, ohne bei fehlender Datei abzubrechen.

        Args:
            path: Zu lesende Datei.

        Returns:
            Dateiinhalt oder None, wenn die Datei nicht lesbar ist.
        """
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError:
            return None
