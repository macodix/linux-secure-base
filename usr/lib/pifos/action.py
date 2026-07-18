"""Abstrakte Basisklasse für Aktionen.

Eine Aktion erledigt genau eine atomare Aufgabe und stellt Status
und Ausgaben dem aufrufenden Modul vollständig bereit (AKT-01, AKT-02).
"""

from abc import ABC, abstractmethod
from typing import ClassVar


class Action(ABC):
    """Abstrakte Basisklasse für alle pifos-Aktionen.

    Konkrete Aktionen erben von dieser Klasse und implementieren run().
    Die Klasse prüft Parameter NICHT — Prüfung liegt beim aufrufenden Modul.

    Attributes:
        PARAMS: Klassenattribut mit den Namen der erlaubten Parameter.
            Leer, wenn die Aktion keine Parameter hat.
        status: Ausführungszustand; Werte: not_runned, running,
            finished, failed.

    Example:
        class CopyAction(Action):
            PARAMS = ["src", "dst"]
            def __init__(self, src: str, dst: str) -> None:
                super().__init__()
                self.src = src
                self.dst = dst
            def run(self) -> str:
                self.status = "running"
                # ... konkrete Ausführung ...
                self.status = "finished"
                return self.status
    """

    PARAMS: ClassVar[list[str]] = []

    def __init__(self) -> None:
        """Initialisiert den Ausführungszustand mit not_runned."""
        self.status: str = "not_runned"

    @abstractmethod
    def run(self) -> str:
        """Führt die Aktion aus und gibt den Status zurück.

        Setzt status vor der Ausführung auf running, danach auf
        finished oder failed. Im Fehlerfall wird ActionError erzeugt
        und an das aufrufende Modul weitergereicht (AKT-03).

        Returns:
            Aktueller Wert von self.status nach der Ausführung.

        Raises:
            ActionError: Bei einem Fehler während der Ausführung.
        """
