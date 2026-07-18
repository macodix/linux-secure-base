"""systemd-Einheiten-Steuerungs-Aktion für pifos.

Setzt SIC-03 (kein Shell-Aufruf), SIC-04 (Argumentliste) und SIC-06
(kontrollierter PATH) um; nutzt intern SysCmdAction.
"""

from typing import ClassVar

from pifos.action import Action
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.errors import ActionError

_SYSTEMCTL = "/usr/bin/systemctl"
_CONTROLLED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_ALLOWED_OPERATIONS = frozenset(
    {
        "enable",
        "disable",
        "start",
        "stop",
        "restart",
        "reload",
        "daemon-reload",
    }
)


class SystemdServiceAction(Action):
    """Steuert eine systemd-Einheit über systemctl.

    Führt genau eine operation je Ausführung aus ("enable", "disable",
    "start", "stop", "restart", "reload", "daemon-reload"), ohne Shell,
    mit einer Zeitgrenze. unit ist für alle Operationen außer
    "daemon-reload" Pflicht; bei "daemon-reload" ist unit nicht erlaubt
    (dort gibt es keine Einheit). Beide Verstöße sowie eine unbekannte
    operation erzeugen ActionError, bevor ein Kommando gebaut wird.
    Einheitenname und operation werden inhaltlich nicht weiter geprüft —
    das macht das aufrufende Modul. Die Aktion delegiert den
    Prozessaufruf an SysCmdAction und übernimmt deren stdout, stderr
    und returncode.

    Das Kommando erhält --no-pager als Option und SYSTEMD_PAGER="" im
    env, damit systemctl bei etwaiger Ausgabe nicht auf ein Pager-
    Terminal wartet. Ist ein Einheitenname gesetzt, steht im Kommando
    immer der Optionsterminator "--" davor, damit systemctl ihn nicht
    als Option interpretiert. Zusätzlich weist die Aktion Einheitennamen
    mit führendem "-" mit ActionError zurück. Das ist keine inhaltliche
    Prüfung des Einheitennamens (die bleibt beim aufrufenden Modul),
    sondern Schutz des Kommandoaufbaus vor Optionsinjektion.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        operation: Auszuführende Operation.
        unit: Einheitenname oder None (nur bei "daemon-reload" zulässig).
        timeout: Zeitgrenze in Sekunden. Voreinstellung 60.0.
        stdout: Standardausgabe von systemctl nach run().
        stderr: Fehlerausgabe von systemctl nach run().
        returncode: Rückgabewert von systemctl nach run(); -1 vor der
            Ausführung.

    Example:
        action = SystemdServiceAction("restart", unit="nginx.service")
        action.run()
    """

    PARAMS: ClassVar[list[str]] = ["operation", "unit", "timeout"]

    def __init__(
        self,
        operation: str,
        unit: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        """Initialisiert die systemd-Einheiten-Steuerungs-Aktion.

        Args:
            operation: "enable", "disable", "start", "stop", "restart",
                "reload" oder "daemon-reload".
            unit: Einheitenname. Pflicht außer bei operation=
                "daemon-reload", dort nicht erlaubt.
            timeout: Zeitgrenze in Sekunden für systemctl (SIC-05).
                Voreinstellung 60.0.
        """
        super().__init__()
        self.operation = operation
        self.unit = unit
        self.timeout = timeout
        self.stdout: str = ""
        self.stderr: str = ""
        self.returncode: int = -1

    def run(self) -> str:
        """Führt systemctl aus und liefert den Ausführungsstatus.

        Setzt self.stdout, self.stderr und self.returncode aus der
        zugrunde liegenden SysCmdAction — auch im Fehlerfall.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei unbekannter operation, fehlender/unzulässiger
                unit, Einheitenname mit führendem "-" (Schutz vor
                Optionsinjektion), bei Timeout, Returncode != 0 oder
                Startfehler von systemctl.
        """
        self.status = "running"

        if self.operation not in _ALLOWED_OPERATIONS:
            self.status = "failed"
            raise ActionError(f"Unbekannte operation: {self.operation!r}")

        if self.operation == "daemon-reload":
            if self.unit is not None:
                self.status = "failed"
                raise ActionError(
                    f"unit ist bei operation='daemon-reload' nicht erlaubt:"
                    f" {self.unit!r}"
                )
        else:
            if self.unit is None:
                self.status = "failed"
                raise ActionError(
                    f"unit ist bei operation={self.operation!r} erforderlich"
                )
            if self.unit.startswith("-"):
                self.status = "failed"
                raise ActionError(
                    f"Einheitenname beginnt mit '-', als Option"
                    f" interpretierbar: {self.unit!r}"
                )

        command = [_SYSTEMCTL, "--no-pager", self.operation]
        if self.unit is not None:
            command += ["--", self.unit]

        env = {
            "PATH": _CONTROLLED_PATH,
            "SYSTEMD_PAGER": "",
        }
        cmd_action = SysCmdAction(command, timeout=self.timeout, env=env)
        try:
            cmd_action.run()
        except ActionError:
            self.status = "failed"
            raise
        finally:
            self.stdout = cmd_action.stdout
            self.stderr = cmd_action.stderr
            self.returncode = cmd_action.returncode

        self.status = "finished"
        return self.status
