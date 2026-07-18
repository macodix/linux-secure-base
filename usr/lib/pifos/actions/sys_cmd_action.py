"""Generische Systembefehl-Aktion für pifos.

Setzt SIC-03 (kein Shell-Aufruf), SIC-04 (Argumentliste),
SIC-05 (explizite Zeitgrenze) und AKT-08 um.
"""

import subprocess
from typing import ClassVar

from pifos.action import Action
from pifos.errors import ActionError


class SysCmdAction(Action):
    """Führt einen Systembefehl ohne Shell aus; erfasst stdout, stderr, Returncode.

    Der Befehl wird als Liste einzelner Elemente übergeben (SIC-04); eine
    Zeichenkette wird nicht angenommen. Jede Ausführung trägt eine explizite
    Zeitgrenze (SIC-05); nach deren Ablauf wird der Prozess beendet.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        command: Befehl als Liste einzelner Elemente.
        timeout: Zeitgrenze in Sekunden.
        cwd: Arbeitsverzeichnis oder None.
        env: Umgebungsvariablen oder None.
        stdout: Standardausgabe des Befehls nach run().
        stderr: Fehlerausgabe des Befehls nach run().
        returncode: Rückgabewert des Befehls nach run(); -1 vor der Ausführung.

    Example:
        action = SysCmdAction(["/bin/ls", "-la"], timeout=10.0, cwd="/tmp")
        action.run()
        print(action.stdout)
    """

    PARAMS: ClassVar[list[str]] = ["command", "timeout", "cwd", "env"]

    def __init__(
        self,
        command: list[str],
        timeout: float,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        """Initialisiert die Systembefehl-Aktion.

        Args:
            command: Befehl als Liste einzelner Elemente (SIC-04). Das erste
                Element ist der Programmpfad (absolut oder im PATH), alle
                weiteren sind Argumente.
            timeout: Zeitgrenze in Sekunden. Nach Ablauf wird der Prozess
                mit SIGKILL beendet und ActionError erzeugt (SIC-05).
            cwd: Arbeitsverzeichnis für den Prozess; None übernimmt das
                aktuelle Verzeichnis des aufrufenden Prozesses.
            env: Umgebungsvariablen für den Prozess; None übernimmt die
                aktuelle Umgebung. Für sicherheitsrelevante Programme
                empfiehlt sich ein explizites env mit kontrolliertem PATH
                (SIC-06).
        """
        super().__init__()
        self.command = command
        self.timeout = timeout
        self.cwd = cwd
        self.env = env
        self.stdout: str = ""
        self.stderr: str = ""
        self.returncode: int = -1

    def run(self) -> str:
        """Führt den Befehl aus und liefert den Ausführungsstatus.

        Setzt self.stdout, self.stderr und self.returncode. Bei Timeout
        wird der Prozess beendet. Bei Returncode ungleich 0 oder bei
        Timeout wird ActionError erzeugt.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei Timeout, Returncode != 0 oder Startfehler.
        """
        self.status = "running"
        try:
            with subprocess.Popen(
                self.command,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.cwd,
                env=self.env,
            ) as proc:
                try:
                    stdout_b, stderr_b = proc.communicate(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout_b, stderr_b = proc.communicate()
                    self.stdout = stdout_b.decode("utf-8", errors="replace")
                    self.stderr = stderr_b.decode("utf-8", errors="replace")
                    self.returncode = (
                        proc.returncode if proc.returncode is not None else -1
                    )
                    self.status = "failed"
                    raise ActionError(
                        f"Zeitgrenze ({self.timeout}s) überschritten:"
                        f" {self.command[0]!r}"
                    ) from None
                self.stdout = stdout_b.decode("utf-8", errors="replace")
                self.stderr = stderr_b.decode("utf-8", errors="replace")
                self.returncode = proc.returncode if proc.returncode is not None else -1
                if self.returncode != 0:
                    self.status = "failed"
                    raise ActionError(
                        f"Befehl {self.command[0]!r} endete mit Code"
                        f" {self.returncode}; stderr: {self.stderr.strip()!r}"
                    )
        except ActionError:
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Befehl konnte nicht gestartet werden: {exc}") from exc
        self.status = "finished"
        return self.status
