"""Statusanzeige des Installers auf Basis von rich."""

import contextlib
from collections.abc import Iterator
from enum import Enum

from pifos.ipc import LogLevel
from rich.console import Console
from rich.live import Live
from rich.table import Table

from lsb.module_spec import ModuleSpec


class State(Enum):
    """Zustand eines Moduls in der Anzeige."""

    WAITING = "wartet"
    RUNNING = "läuft"
    OK = "OK"
    FAILED = "Fehler"


class StatusView:
    """Zeigt Modulübersicht, Betriebsanzeige und laufende Meldungen."""

    def __init__(self, specs: list[ModuleSpec]) -> None:
        """Initialisiert die Anzeige mit den ausgewählten Modulen.

        Args:
            specs: Ausgewählte Registratureinträge in Reihenfolge.
        """
        self._console = Console()
        self._specs = specs
        self._state = {s.name: State.WAITING for s in specs}
        self._line = {s.name: "" for s in specs}
        self._error_line = {s.name: "" for s in specs}
        self._live: Live | None = None

    @contextlib.contextmanager
    def live(self) -> Iterator[None]:
        """Hält die Live-Anzeige für die Dauer des Laufs offen."""
        with Live(self._render(), console=self._console, refresh_per_second=8) as live:
            self._live = live
            try:
                yield
            finally:
                self._live = None

    def set_running(self, name: str) -> None:
        """Setzt ein Modul auf den Zustand läuft."""
        self._state[name] = State.RUNNING
        self._refresh()

    def set_status_line(self, name: str, text: str, level: LogLevel) -> None:
        """Übernimmt die zuletzt gemeldete Statuszeile eines Moduls.

        Die erste Meldung der Stufe ERROR oder CRITICAL wird zusätzlich
        festgehalten: Schlägt das Modul fehl, zeigt die Meldungsspalte
        sonst nur die zuletzt gemeldete Zeile — bei einem Soll-Ist-Abgleich
        eine OK-Meldung einer späteren Prüfung statt der Fehlerursache.
        """
        self._line[name] = text
        if level in (LogLevel.ERROR, LogLevel.CRITICAL) and not self._error_line[name]:
            self._error_line[name] = text
        self._refresh()

    def set_result(self, name: str, ok: bool) -> None:
        """Setzt das Endergebnis eines Moduls.

        Bei Fehlschlag tritt die festgehaltene erste Fehlermeldung an die
        Stelle der zuletzt gemeldeten Zeile.
        """
        self._state[name] = State.OK if ok else State.FAILED
        if not ok and self._error_line[name]:
            self._line[name] = self._error_line[name]
        self._refresh()

    def summary(self) -> None:
        """Gibt die Gesamtbilanz nach dem Lauf aus."""
        failed = [n for n, s in self._state.items() if s is State.FAILED]
        if failed:
            self._console.print(f"Fehlgeschlagen: {', '.join(failed)}")
        else:
            self._console.print("Alle Module erfolgreich.")

    def _refresh(self) -> None:
        """Zeichnet die Anzeige neu, falls die Live-Anzeige offen ist."""
        if self._live is not None:
            self._live.update(self._render())

    def _render(self) -> Table:
        """Baut die Tabelle aus Modulzustand und letzter Meldung."""
        table = Table(title="Linux Secure Base — Installation")
        table.add_column("Komponente")
        table.add_column("Status")
        table.add_column("Meldung")
        for spec in self._specs:
            table.add_row(
                spec.label, self._state[spec.name].value, self._line[spec.name]
            )
        return table
