"""Abstrakte Basisklasse für Module.

Ein Modul erledigt eine fachliche Aufgabe unter Nutzung von Aktionen
und kommuniziert über IPC mit dem aufrufenden Prozess (MOD-01, MOD-05).
"""

import importlib
import re
from abc import ABC, abstractmethod
from multiprocessing.connection import Connection
from typing import ClassVar

from pifos.action import Action
from pifos.config.config import Config
from pifos.errors import ActionError, ConfigError, ModuleError
from pifos.ipc import IpcMessage, LogLevel, MessageKind


def _module_name_for(class_name: str) -> str:
    """Bildet den Modulnamen (snake_case) zum Aktions-Klassennamen (CamelCase).

    Beispiele: "SysCmdAction" -> "sys_cmd_action", "CopyFileAction" ->
    "copy_file_action". Aufeinanderfolgende Großbuchstaben (Akronyme) werden
    korrekt behandelt: "HTTPServerAction" -> "http_server_action".

    Args:
        class_name: Klassenname der Aktion in CamelCase.

    Returns:
        Modulname in snake_case.
    """
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", class_name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


class Module(ABC):
    """Abstrakte Basisklasse für alle pifos-Module.

    Stellt gemeinsame Methoden zur Ausführung und Steuerung von Aktionen
    sowie zur IPC-Kommunikation mit dem Aufrufer bereit.

    Die Konfigurationsdeklaration CONFIG enthält die Namen der benötigten
    Konfigurationswerte. check_config prüft deren Vorhandensein beim Start
    und legt sie als Instanzvariablen ab (MOD-09, MOD-04).

    Attributes:
        CONFIG: Klassenattribut mit den Namen der benötigten Konfigurationswerte.
        loglevel: Aktuelle Logstufe; wird vom Aufrufer beim Start gesetzt (LOG-05).

    Example:
        class InstModule(Module):
            CONFIG = ["target_dir", "package_name"]
            def start(self) -> int:
                action = SysCmdAction(cmd=["apt", "install", self.package_name])
                return self.run_action(action)
    """

    CONFIG: ClassVar[list[str]] = []

    def __init__(self, conn: Connection, loglevel: LogLevel) -> None:
        """Initialisiert das Modul mit IPC-Verbindung und Logstufe.

        Args:
            conn: Pipe-Verbindung zum Aufrufer (duplexe multiprocessing.Pipe).
            loglevel: Logstufe, weitergegeben vom Aufrufer (LOG-05).
        """
        self._conn = conn
        self.loglevel = loglevel

    @abstractmethod
    def start(self) -> int:
        """Führt die Modulaufgabe aus.

        Returns:
            Rückgabewert: 0 bei Erfolg, ungleich 0 bei Fehler (STR-05).
        """

    def check_config(self, config: Config) -> None:
        """Prüft das Vorhandensein der deklarierten Konfigurationswerte.

        Liest alle in CONFIG genannten Schlüssel aus dem Config-Objekt
        und legt sie als gleichnamige Instanzvariablen ab (MOD-09, MOD-04).

        Args:
            config: Konfigurationsobjekt des Aufrufers.

        Raises:
            ConfigError: Wenn ein Pflicht-Konfigurationswert fehlt.
        """
        for key in self.CONFIG:
            try:
                setattr(self, key, config.get_value(key))
            except ConfigError as e:
                raise ConfigError(f"Pflicht-Konfigurationswert '{key}' fehlt") from e

    def run_action(self, action: Action) -> int:
        """Führt eine Aktion aus und übernimmt deren Status.

        Bei Fehlschlag wird die Ursache als ERROR-Meldung an den Aufrufer
        gemeldet, damit sie in der Logdatei erscheint: der Text der
        ActionError (Returncode und stderr, soweit die Aktion sie erfasst)
        bzw. bei nicht abgeschlossenem Status die erfassten Werte. Andernfalls
        bliebe von einem gescheiterten Werkzeugaufruf (z. B. apt) nur der
        Rückgabewert 1 übrig — die eigentliche Fehlermeldung ginge verloren.

        Args:
            action: Die auszuführende Aktion.

        Returns:
            0 bei status == "finished", 1 sonst.
        """
        try:
            status = action.run()
        except ActionError as exc:
            self.send_message(LogLevel.ERROR, type(action).__name__, str(exc))
            return 1
        if status != "finished":
            self.send_message(
                LogLevel.ERROR,
                type(action).__name__,
                self._action_failure_detail(action, status),
            )
            return 1
        return 0

    @staticmethod
    def _action_failure_detail(action: Action, status: str) -> str:
        """Baut aus einer gescheiterten Aktion einen Fehlertext für das Log.

        Nutzt Returncode und stderr, falls die Aktion sie führt (z. B.
        SysCmdAction/AptAction); sonst nur den Status.

        Args:
            action: Die gescheiterte Aktion.
            status: Von run() gelieferter Status ungleich "finished".

        Returns:
            Fehlertext mit Returncode und stderr, soweit vorhanden.
        """
        returncode = getattr(action, "returncode", None)
        stderr = getattr(action, "stderr", "")
        detail = f"Aktion nicht abgeschlossen (Status {status!r})"
        if returncode is not None:
            detail += f", Returncode {returncode}"
        if stderr:
            detail += f"; stderr: {stderr.strip()!r}"
        return detail

    def control_action(self, action: Action, **options: object) -> None:
        """Steuert eine Aktion über Parameter oder Instanzvariablen.

        Setzt die übergebenen Schlüssel-Wert-Paare als Attribute der Aktion.

        Args:
            action: Die zu steuernde Aktion.
            **options: Attributname → Wert-Paare.
        """
        for key, value in options.items():
            setattr(action, key, value)

    def resolve_action(self, name: str) -> type[Action]:
        """Schlägt eine Aktionsklasse im Aktions-Unterpaket nach.

        Der Modulname wird aus dem Klassennamen in snake_case gebildet:
        `SysCmdAction` → Modul `pifos.actions.sys_cmd_action`, aus dem die
        gleichnamige Klasse gelesen wird. Ermöglicht die Auswahl einer
        Aktion über ihren Namen zur Laufzeit im Code.

        Args:
            name: Klassenname der gesuchten Aktion in CamelCase.

        Returns:
            Die Action-Klasse.

        Raises:
            ModuleError: Wenn die Aktion nicht gefunden wird oder keine
                Action-Unterklasse ist.
        """
        try:
            mod = importlib.import_module(f"pifos.actions.{_module_name_for(name)}")
            cls = getattr(mod, name)
        except (ImportError, AttributeError) as e:
            raise ModuleError(f"Aktion '{name}' nicht gefunden") from e
        if not (isinstance(cls, type) and issubclass(cls, Action)):
            raise ModuleError(f"'{name}' ist keine Action-Unterklasse")
        return cls

    def send_message(
        self,
        level: LogLevel | None,
        name: str,
        payload: object,
    ) -> None:
        """Reicht eine Meldung an den Aufrufer weiter.

        Filtert Meldungen unterhalb der eingestellten Logstufe heraus (LOG-02).

        Args:
            level: Logstufe der Meldung; None für nicht-logging-relevante Meldungen.
            name: Meldungskennung.
            payload: Nutzdaten der Meldung.
        """
        if level is not None and self._below_loglevel(level):
            return
        msg = IpcMessage(
            kind=MessageKind.LOG if level is not None else MessageKind.MESSAGE,
            level=level,
            name=name,
            payload=payload,
        )
        self._conn.send(msg)

    def receive_message(self) -> IpcMessage:
        """Nimmt einen Befehl des Aufrufers an.

        Blockiert, bis eine Nachricht verfügbar ist.

        Returns:
            Empfangene IpcMessage.
        """
        from typing import cast

        return cast(IpcMessage, self._conn.recv())

    def check(self) -> bool | None:
        """Optionale Überprüfung der Modulwirkung.

        Überschreibbar: gibt True zurück, wenn die Modulwirkung bestätigt ist,
        False bei Abweichung, None wenn check nicht implementiert ist (MOD-12).

        Returns:
            True, False oder None (Standard: nicht implementiert).
        """
        return None

    def rollback(self) -> bool | None:
        """Optionaler Rückbau der Modulwirkung.

        Überschreibbar: gibt True zurück, wenn der Rückbau gelang,
        False bei Fehler, None wenn rollback nicht implementiert ist (MOD-13).

        Returns:
            True, False oder None (Standard: nicht implementiert).
        """
        return None

    def _below_loglevel(self, level: LogLevel) -> bool:
        """Prüft, ob eine Logstufe unterhalb des eingestellten Levels liegt.

        Args:
            level: Zu prüfende Logstufe.

        Returns:
            True, wenn level unterhalb von self.loglevel liegt.
        """
        order = [LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR, LogLevel.CRITICAL]
        return order.index(level) < order.index(self.loglevel)
