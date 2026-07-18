"""Abstrakte Basisklasse PifosCaller für Aufrufer.

PifosCaller kapselt die Prozesssteuerung, IPC und das Logging.
Konkrete Aufrufer erben davon und ergänzen nur ihre Fachlogik (CAL-01, CAL-06).
"""

import contextlib
import logging
import multiprocessing
import multiprocessing.connection
import os
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from typing import ClassVar, cast

from pifos.config.config import Config
from pifos.errors import ConfigError
from pifos.ipc import IpcMessage, LogLevel, MessageKind
from pifos.module import Module
from pifos.runner import module_runner


@dataclass
class ModuleHandle:
    """Handle für einen gestarteten Modulprozess.

    Enthält den Prozess, die Pipe-Verbindung zum Modul und die Klasse
    des gestarteten Moduls.

    Attributes:
        process: Der laufende Modulprozess.
        conn: Pipe-Verbindung (Aufruferseite).
        module_cls: Klasse des gestarteten Moduls.
    """

    process: multiprocessing.Process
    conn: Connection
    module_cls: type[Module]
    _finished: bool = field(default=False, repr=False)


def _process_target(
    module_cls: type[Module],
    config: Config | None,
    conn: Connection,
    loglevel: LogLevel,
) -> None:
    """Wrapper für multiprocessing.Process; setzt den Exitcode via sys.exit.

    Top-Level-Funktion, damit sie mit der Startmethode spawn pickelbar ist.

    Args:
        module_cls: Zu instanziierende Modulklasse.
        config: Konfigurationsobjekt oder None.
        conn: Pipe-Verbindung (Kindseite).
        loglevel: Logstufe.
    """
    import sys

    sys.exit(module_runner(module_cls, config, conn, loglevel))


class PifosCaller:
    """Abstrakte Basisklasse für Aufrufer.

    Kapselt Prozessstart, IPC-Kommunikation und Logging. Konkrete Aufrufer
    erben davon und steuern nur ihre Fachlogik und Oberfläche bei (CAL-06).

    Die überschreibbaren Methoden on_module_success, on_module_failure und
    on_module_abort reagieren auf den Ausgang eines Moduls (CAL-07).

    Attributes:
        loglevel: Einstellbare Logstufe des Aufrufers (LOG-04).
        config: Geladene Konfiguration; None vor dem ersten load_config-Aufruf.
    """

    # Abbildung der vier pifos-Logstufen auf die Stufen des logging-Moduls (LOG-03).
    _PY_LEVEL: ClassVar[dict[LogLevel, int]] = {
        LogLevel.INFO: logging.INFO,
        LogLevel.WARN: logging.WARNING,
        LogLevel.ERROR: logging.ERROR,
        LogLevel.CRITICAL: logging.CRITICAL,
    }

    # Vorgabe-Zeitlimits (Sekunden) der gestuften Beendigung (Kapitel 6).
    TERMINATE_TIMEOUT: ClassVar[float] = 5.0
    SIGTERM_TIMEOUT: ClassVar[float] = 5.0
    SIGKILL_TIMEOUT: ClassVar[float] = 2.0

    def __init__(
        self,
        loglevel: LogLevel = LogLevel.INFO,
        terminate_timeout: float | None = None,
        sigterm_timeout: float | None = None,
        sigkill_timeout: float | None = None,
    ) -> None:
        """Initialisiert den Aufrufer mit Logstufe und Beendigungs-Zeitlimits.

        Args:
            loglevel: Anfangsstufe; Standard: INFO.
            terminate_timeout: Wartezeit nach IPC-terminate; None nutzt
                die Vorgabe TERMINATE_TIMEOUT.
            sigterm_timeout: Wartezeit nach SIGTERM; None nutzt SIGTERM_TIMEOUT.
            sigkill_timeout: Wartezeit nach SIGKILL; None nutzt SIGKILL_TIMEOUT.
        """
        self.loglevel = loglevel
        self.config: Config | None = None
        self.terminate_timeout = (
            self.TERMINATE_TIMEOUT if terminate_timeout is None else terminate_timeout
        )
        self.sigterm_timeout = (
            self.SIGTERM_TIMEOUT if sigterm_timeout is None else sigterm_timeout
        )
        self.sigkill_timeout = (
            self.SIGKILL_TIMEOUT if sigkill_timeout is None else sigkill_timeout
        )
        self._logger = logging.getLogger(type(self).__name__)

    def load_config(self, path: str, format: str) -> None:
        """Legt ein Config-Objekt an, lädt es aus einer Datei und stellt es bereit.

        Das geladene Objekt steht danach als self.config zur Verfügung (CAL-08).

        Args:
            path: Pfad zur Konfigurationsdatei.
            format: Dateiformat; erlaubte Werte: ini, json, toml.
        """
        cfg = Config()
        cfg.load_file(path, format)
        self.config = cfg

    def configure_logging(self) -> None:
        """Richtet Logdatei und Logstufe aus der geladenen Konfiguration ein.

        Liest die Schlüssel `logfile` und `loglevel` aus der Konfiguration,
        übernimmt die Logstufe (LOG-04) und legt einen FileHandler auf die
        Logdatei an. Die Logdatei wird mit engen Rechten `0600` angelegt bzw.
        auf diese Rechte gezogen (SIC-27). Nach `load_config` aufzurufen.

        Raises:
            ConfigError: Wenn keine Konfiguration geladen ist, ein Schlüssel
                fehlt oder die Logstufe unbekannt ist.
        """
        if self.config is None:
            raise ConfigError("Keine Konfiguration geladen; erst load_config aufrufen")
        logfile = str(self.config.get_value("logfile"))
        raw_level = str(self.config.get_value("loglevel"))
        try:
            self.loglevel = LogLevel(raw_level)
        except ValueError as e:
            raise ConfigError(f"Unbekannte Logstufe: {raw_level!r}") from e

        # Logdatei mit engen Rechten anlegen bzw. Rechte anziehen (SIC-27)
        fd = os.open(logfile, os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
        os.chmod(logfile, 0o600)

        handler = logging.FileHandler(logfile)
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
        )
        # Bestehende Handler ersetzen, damit configure_logging idempotent ist.
        for old in list(self._logger.handlers):
            self._logger.removeHandler(old)
            old.close()
        self._logger.addHandler(handler)
        self._logger.setLevel(self._PY_LEVEL[self.loglevel])
        self._logger.propagate = False

    def start_module(
        self,
        module_cls: type[Module],
        config: Config | None = None,
    ) -> ModuleHandle:
        """Startet ein Modul als eigenen Prozess.

        Übergibt das Config-Objekt und die aktuelle Logstufe (STR-01, STR-02, LOG-05).
        Verwendet die Startmethode spawn für deterministisches Verhalten.

        Args:
            module_cls: Zu startende Modulklasse.
            config: Konfigurationsobjekt; None für Module ohne Konfiguration.

        Returns:
            Handle zum gestarteten Modulprozess.
        """
        ctx = multiprocessing.get_context("spawn")
        parent_conn, child_conn = multiprocessing.Pipe(duplex=True)
        # SpawnProcess ist zur Laufzeit Unterklasse von Process; cast für mypy.
        process = cast(
            multiprocessing.Process,
            ctx.Process(
                target=_process_target,
                args=(module_cls, config, child_conn, self.loglevel),
            ),
        )
        process.start()
        child_conn.close()
        return ModuleHandle(process=process, conn=parent_conn, module_cls=module_cls)

    def stop_module(self, handle: ModuleHandle) -> None:
        """Hält einen Modulprozess an (kooperativ über IPC).

        Args:
            handle: Handle des Modulprozesses.
        """
        self.send_command(handle, "pause")

    def resume_module(self, handle: ModuleHandle) -> None:
        """Setzt einen angehaltenen Modulprozess fort.

        Args:
            handle: Handle des Modulprozesses.
        """
        self.send_command(handle, "resume")

    def terminate_module(self, handle: ModuleHandle) -> None:
        """Beendet einen Modulprozess gestuft (IPC → SIGTERM → SIGKILL).

        Schritt 1: geordneter Abschluss über IPC.
        Schritt 2: SIGTERM, wenn das Modul nicht reagiert.
        Schritt 3: SIGKILL als letzte Stufe (Kapitel 6 des Implementierungsplans).

        Args:
            handle: Handle des Modulprozesses.
        """
        with contextlib.suppress(Exception):
            self.send_command(handle, "terminate")
            handle.process.join(timeout=self.terminate_timeout)
        if handle.process.is_alive():
            handle.process.terminate()
            handle.process.join(timeout=self.sigterm_timeout)
        if handle.process.is_alive():
            handle.process.kill()
            handle.process.join(timeout=self.sigkill_timeout)
        handle._finished = True

    def send_command(
        self,
        handle: ModuleHandle,
        name: str,
        payload: object = None,
    ) -> None:
        """Sendet einen Befehl über IPC an das Modul.

        Args:
            handle: Handle des Zielmoduls.
            name: Befehlsname.
            payload: Optionale Nutzdaten.
        """
        msg = IpcMessage(
            kind=MessageKind.COMMAND,
            level=None,
            name=name,
            payload=payload,
        )
        handle.conn.send(msg)

    def receive_result(self, handle: ModuleHandle) -> IpcMessage:
        """Empfängt eine Meldung oder ein Ergebnis vom Modul.

        Blockiert, bis eine Nachricht verfügbar ist (CAL-04).

        Args:
            handle: Handle des sendenden Moduls.

        Returns:
            Empfangene IpcMessage.
        """
        return cast(IpcMessage, handle.conn.recv())

    def write_log(self, message: str, level: LogLevel = LogLevel.INFO) -> None:
        """Schreibt eine Meldung mit ihrer Logstufe ins Logfile.

        Bildet die pifos-Logstufe auf die passende Stufe des logging-Moduls
        ab, damit ERROR und CRITICAL auch als solche im Logfile erscheinen
        (LOG-01, LOG-03). Bereinigt Steuerzeichen vor dem Schreiben (SIC-19).

        Args:
            message: Zu protokollierende Meldung.
            level: Logstufe der Meldung; Standard: INFO.
        """
        # Steuerzeichen entfernen (SIC-19, insbesondere Zeilenumbrüche)
        clean = message.translate(str.maketrans("\n\r\t", "   "))
        self._logger.log(self._PY_LEVEL[level], clean)

    def check_module_exit(self, handle: ModuleHandle) -> None:
        """Wertet den Exitcode eines beendeten Moduls aus und ruft den Handler.

        Ruft on_module_success, on_module_failure oder on_module_abort
        abhängig vom Prozess-Exitcode (STR-05, CAL-07).

        Args:
            handle: Handle des beendeten Moduls.
        """
        exitcode = handle.process.exitcode
        if exitcode is None:
            self.on_module_abort(handle)
        elif exitcode == 0:
            self.on_module_success(handle)
        else:
            self.on_module_failure(handle, exitcode)

    def on_module_success(self, handle: ModuleHandle) -> None:
        """Wird nach erfolgreichem Modulabschluss aufgerufen.

        Standardimplementierung: keine Aktion. Überschreiben für eigene Reaktion.

        Args:
            handle: Handle des abgeschlossenen Moduls.
        """

    def on_module_failure(self, handle: ModuleHandle, returncode: int) -> None:
        """Wird nach fehlerhaftem Modulabschluss aufgerufen.

        Standardimplementierung: keine Aktion. Überschreiben für eigene Reaktion.

        Args:
            handle: Handle des fehlgeschlagenen Moduls.
            returncode: Exitcode ungleich 0.
        """

    def on_module_abort(self, handle: ModuleHandle) -> None:
        """Wird nach erzwungenem Modulabbruch aufgerufen.

        Standardimplementierung: keine Aktion. Überschreiben für eigene Reaktion.

        Args:
            handle: Handle des abgebrochenen Moduls.
        """
