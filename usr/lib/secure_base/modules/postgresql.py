"""Modul postgresql — Datenbankserver mit lokal beschränktem Zugriff.

Installiert das Paket postgresql, härtet die Verbindungs- und
Protokollierungseinstellungen über eine eigene Drop-in-Datei unter
conf.d und ersetzt pg_hba.conf durch eine restriktive Zugriffsliste
(kein trust, keine Netz-Freigabe außer Loopback). Prüft/setzt zusätzlich
die Rechte des Datenverzeichnisses. Legt keine Anwendungs-DB/-Benutzer
an, öffnet keinen Netz-Port (kein ufw-Eintrag) und erstellt kein
Backup/Dump. Optionales Modul; setzt das gehärtete Grundsystem voraus.
Betriebsart über den Schlüssel operation. PostgreSQL-Hauptversion und
Cluster-Name werden zur Laufzeit unter /etc/postgresql ermittelt, nie
hartkodiert.
"""

import grp
import pwd
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


class Postgresql(Module):
    """Datenbankserver mit lokal beschränktem Zugriff über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = ["operation", "timezone"]

    # Programmpfade und Schreibziele als Klassenattribute (siehe Modul base
    # für die Begründung); eine Testunterklasse kann sie überschreiben.
    PSQL_BIN: ClassVar[str] = "/usr/bin/psql"
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

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt; hier nur Typdeklaration für
    # mypy --strict, ohne eigenen __init__ (siehe Modul base).
    operation: str
    timezone: str

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
        """Prüft timezone, bevor sie in eine Konfigurationsdatei geht.

        Der Wert geht in log_timezone der eigenen conf.d-Datei;
        WriteFileAction schreibt Inhalte ungeprüft, deshalb prüft das
        Modul den Wert vorher (konv-scripting-python.md Abschnitt 4.2).

        Raises:
            ModuleError: Wenn timezone keine bekannte tzdata-Zeitzone ist.
        """
        if self.timezone not in available_timezones():
            raise ModuleError(f"postgresql: unbekannte Zeitzone: {self.timezone!r}")

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Markdown-Abschnitt für den Installationsbericht.

        SICHERHEIT: postgresql verwaltet keine Geheimnisse (keine
        Anwendungs-DB/-Benutzer, kein Backup); doc() liest aus values
        ausschließlich timezone.

        Args:
            values: Konfigurationswerte des Laufs (u. a. timezone).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Datenbankserver
            postgresql (optional)".
        """
        timezone = values.get("timezone") or "(leer/Default)"
        hardening_block = "".join(f"  - `{line}`\n" for line in _HARDENING_GUC_LINES)
        hardening_block += f"  - `log_timezone = '{timezone}'`\n"
        pg_hba_block = "".join(f"  - `{line}`\n" for line in _PG_HBA_LINES)
        file_rights = (
            f"Rechte {oct(cls.HARDENING_CONF_MODE)}, Eigentümer"
            f" {cls.PG_OWNER}:{cls.PG_GROUP}"
        )

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
            "\n> Hinweis: Keine Anwendungs-DB/-Benutzer angelegt, keine"
            " Remote-Zugänge, kein Backup/Dump. uninstall entfernt nur die"
            " eigene conf.d-Datei; pg_hba.conf bleibt aus Sicherheitsgründen"
            " in der gehärteten Fassung bestehen (Original als"
            " .bak-<Zeitstempel> im selben Verzeichnis abgelegt). Paket und"
            " Cluster bleiben in jedem Fall installiert (Datenverlust"
            " vermeiden).\n"
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
        """Nimmt die eigene conf.d-Härtung zurück; Paket und Cluster bleiben.

        Entfernt nur die eigene conf.d-Datei und startet den Dienst neu, so
        dass die überschriebenen GUCs auf die Paket-Vorgaben zurückfallen.
        pg_hba.conf bleibt in der gehärteten Fassung bestehen: keine der
        verfügbaren pifos-Aktionen kann die ursprüngliche Datei gezielt
        wiederherstellen, und ein Rückbau würde scram-sha-256 durch das
        schwächere Vorgabe-„peer" ersetzen und die Replikationszeilen
        wieder öffnen — das widerspräche dem Zweck von secure-base. Paket
        und Cluster werden nie entfernt (Datenverlust).

        Returns:
            0 bei Erfolg oder wenn kein Cluster gefunden wird (nichts
            zurückzunehmen), 1 beim ersten fehlgeschlagenen Schritt.
        """
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

        Prüft den Dienststatus und eine lokale Verbindung als postgres
        (SELECT 1) über runuser — sammelnd, kein Abbruch beim ersten
        Fehlschlag.

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
        return 0 if ok else 1

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
