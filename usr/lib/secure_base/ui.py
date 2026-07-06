"""Statusanzeige des Installers auf Basis von rich.

Aufbau der Live-Anzeige:
- Kopfzeile: Produkt, Betriebsart, Zielsystem.
- Modulliste: Statussymbol (Spinner im Lauf), Modul, Zustand, Laufzeit,
  zuletzt gemeldete Zeile.
- Meldungsfenster: die letzten Meldungen aller Module, nach Logstufe
  eingefärbt — Fehler bleiben so sichtbar, auch wenn danach weitere
  Meldungen eintreffen.
- Fortschritt: Balken, Modulzähler, Gesamtlaufzeit.

Alle Breiten und Höhen stehen ab dem Start fest; die Anzeige behält über
den ganzen Lauf dieselbe Geometrie.
"""

import contextlib
import time
from collections import deque
from collections.abc import Iterator
from enum import Enum

from pifos.ipc import LogLevel
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskProgressColumn, TimeElapsedColumn
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from secure_base.module_spec import ModuleSpec


class State(Enum):
    """Zustand eines Moduls in der Anzeige."""

    WAITING = "wartet"
    RUNNING = "läuft"
    OK = "OK"
    FAILED = "Fehler"


# Statussymbol und Farbe je Zustand; RUNNING bekommt statt eines festen
# Symbols einen Spinner (siehe _glyph).
_STATE_STYLE = {
    State.WAITING: ("○", "dim"),
    State.RUNNING: ("", "cyan"),
    State.OK: ("✓", "green"),
    State.FAILED: ("✗", "red"),
}

_LEVEL_STYLE = {
    LogLevel.INFO: "dim",
    LogLevel.WARN: "yellow",
    LogLevel.ERROR: "bold red",
    LogLevel.CRITICAL: "bold red",
}

_OPERATION_TITLE = {
    "install": "Installation",
    "uninstall": "Rücknahme",
    "check": "Soll-Ist-Abgleich",
    "test": "Funktionstest",
}

# Zeilenzahl des Meldungsfensters; fest, damit die Anzeige nicht wächst.
_LOG_LINES = 8


class StatusView:
    """Zeigt Kopf, Modulliste, Meldungsfenster und Fortschritt live an."""

    def __init__(
        self, specs: list[ModuleSpec], operation: str = "install", host: str = ""
    ) -> None:
        """Initialisiert die Anzeige mit den ausgewählten Modulen.

        Args:
            specs: Ausgewählte Registratureinträge in Reihenfolge.
            operation: Betriebsart für die Kopfzeile (install/check).
            host: Rechnername des Zielsystems für die Kopfzeile.
        """
        self._console = Console()
        self._specs = specs
        self._operation = operation
        self._host = host
        self._state = {s.name: State.WAITING for s in specs}
        self._line = {s.name: "" for s in specs}
        self._error_line = {s.name: "" for s in specs}
        self._started: dict[str, float] = {}
        self._duration: dict[str, float] = {}
        self._log: deque[Text] = deque(maxlen=_LOG_LINES)
        self._live: Live | None = None
        self._spinner = Spinner("dots", style="cyan")
        self._progress = Progress(
            BarColumn(bar_width=None),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            expand=True,
        )
        self._task = self._progress.add_task("", total=len(specs) or 1)
        # Feste Spaltenbreiten, einmalig aus den Inhalten bestimmt.
        self._label_width = max(len(s.label) for s in specs) if specs else 10
        self._name_width = max(len(s.name) for s in specs) if specs else 8
        self._state_width = max(len(state.value) for state in State)
        self._layout(self._console.size.height)

    def _layout(self, terminal_rows: int) -> None:
        """Legt Meldungsfenster- und Gesamthöhe für die aktuelle Schirmhöhe fest.

        Passt sich der Terminalhöhe an: Ist der Schirm zu niedrig für das
        volle Meldungsfenster, schrumpft es (mindestens 3 Zeilen), und die
        Gesamthöhe bleibt unter der Schirmhöhe. Eine Live-Anzeige, die
        höher ist als das Terminal, kann nicht am Ort neu zeichnen; sie
        scrollt stattdessen — das sieht aus, als stünde nach jeder Zeile
        eine Leerzeile, und die Anzeige wächst und springt zurück.

        Wird bei jeder Änderung der Terminalhöhe erneut aufgerufen (Größe
        zu Beginn oft noch unbekannt, später Fenstergröße geändert).
        """
        self._term_rows = terminal_rows
        # Feste Zeilen: Rahmen+Innenabstand (4), Kopf (1), Modulliste,
        # drei Leerzeilen, Fortschritt (1).
        fixed_rows = 4 + 1 + len(self._specs) + 3 + 1
        log_lines = _LOG_LINES
        if terminal_rows > 0:
            log_lines = max(3, min(_LOG_LINES, terminal_rows - 1 - fixed_rows - 2))
        self._log_lines = log_lines
        self._log = deque(self._log, maxlen=log_lines)
        self._height = fixed_rows + log_lines + 2
        if terminal_rows > 0:
            self._height = min(self._height, terminal_rows - 1)

    @contextlib.contextmanager
    def live(self) -> Iterator[None]:
        """Hält die Live-Anzeige für die Dauer des Laufs offen."""
        # Geometrie auf die Schirmhöhe bei Anzeigenstart festlegen: bei der
        # Objekterzeugung ist sie oft noch unbekannt.
        self._layout(self._console.size.height)
        with Live(
            self._render(),
            console=self._console,
            refresh_per_second=8,
            vertical_overflow="crop",
        ) as live:
            self._live = live
            try:
                yield
            finally:
                self._live = None

    def set_running(self, name: str) -> None:
        """Setzt ein Modul auf den Zustand läuft."""
        self._state[name] = State.RUNNING
        self._started[name] = time.monotonic()
        self._refresh()

    def set_status_line(self, name: str, text: str, level: LogLevel) -> None:
        """Übernimmt eine gemeldete Statuszeile eines Moduls.

        Die Zeile erscheint in der Modulliste (dort nur die jeweils
        letzte) und im Meldungsfenster (dort die letzten _LOG_LINES,
        nach Logstufe eingefärbt). Die erste Meldung der Stufe ERROR
        oder CRITICAL wird zusätzlich festgehalten: Schlägt das Modul
        fehl, zeigt die Modulliste die Fehlerursache statt der zuletzt
        gemeldeten Zeile.
        """
        self._line[name] = text
        if level in (LogLevel.ERROR, LogLevel.CRITICAL) and not self._error_line[name]:
            self._error_line[name] = text
        # Logzeilen dürfen nie umbrechen: eine lange Meldung würde das
        # Meldungsfenster sonst vorübergehend wachsen lassen, bis sie
        # herausrotiert (springende Anzeige, Servertest-Befund).
        line = Text.assemble(
            (f"{name:>{self._name_width}}  ", "cyan dim"),
            (text, _LEVEL_STYLE.get(level, "dim")),
        )
        line.no_wrap = True
        line.overflow = "ellipsis"
        self._log.append(line)
        self._refresh()

    def set_result(self, name: str, ok: bool) -> None:
        """Setzt das Endergebnis eines Moduls.

        Bei Fehlschlag tritt die festgehaltene erste Fehlermeldung an die
        Stelle der zuletzt gemeldeten Zeile.
        """
        self._state[name] = State.OK if ok else State.FAILED
        if name in self._started:
            self._duration[name] = time.monotonic() - self._started[name]
        if not ok and self._error_line[name]:
            self._line[name] = self._error_line[name]
        self._progress.update(self._task, advance=1)
        self._refresh()

    def summary(self) -> None:
        """Gibt die Gesamtbilanz nach dem Lauf aus."""
        failed = [s.label for s in self._specs if self._state[s.name] is State.FAILED]
        skipped = [s.label for s in self._specs if self._state[s.name] is State.WAITING]
        if failed:
            lines = [Text(f"✗ Fehlgeschlagen: {', '.join(failed)}", style="bold red")]
            if skipped:
                lines.append(
                    Text(f"○ Nicht ausgeführt: {', '.join(skipped)}", style="dim")
                )
            self._console.print(Panel(Group(*lines), border_style="red"))
        else:
            self._console.print(
                Panel(
                    Text("✓ Alle Module erfolgreich.", style="bold green"),
                    border_style="green",
                )
            )

    def _refresh(self) -> None:
        """Zeichnet die Anzeige neu, falls die Live-Anzeige offen ist.

        Vor jedem Neuzeichnen die Geometrie an die aktuelle Terminalhöhe
        anpassen: Zu Beginn ist sie oft noch unbekannt, später kann sich
        die Fenstergröße ändern. Nur bei tatsächlicher Änderung neu
        auslegen, um das Meldungsfenster nicht unnötig zu kürzen.
        """
        if self._live is None:
            return
        rows = self._console.size.height
        if rows != self._term_rows:
            self._layout(rows)
        self._live.update(self._render())

    def _glyph(self, state: State) -> RenderableType:
        """Liefert das Statussymbol; RUNNING animiert als Spinner."""
        if state is State.RUNNING:
            return self._spinner
        symbol, style = _STATE_STYLE[state]
        return Text(symbol, style=style)

    def _elapsed(self, name: str) -> str:
        """Liefert die Laufzeit eines Moduls als knappe Sekundenangabe."""
        if name in self._duration:
            return f"{self._duration[name]:.0f}s"
        if name in self._started:
            return f"{time.monotonic() - self._started[name]:.0f}s"
        return ""

    def _header(self) -> Text:
        """Baut die Kopfzeile aus Betriebsart und Zielsystem."""
        title = _OPERATION_TITLE.get(self._operation, self._operation)
        header = Text(no_wrap=True, overflow="ellipsis")
        header.append("Linux Secure Base", style="bold")
        header.append(f"  ·  {title}", style="cyan")
        if self._host:
            header.append(f"  ·  {self._host}", style="dim")
        return header

    def _modules(self) -> Table:
        """Baut die Modulliste mit Symbol, Zustand, Laufzeit und Meldung."""
        rows = Table.grid(expand=True, padding=(0, 1))
        rows.add_column(width=1, no_wrap=True)
        rows.add_column(width=self._label_width, no_wrap=True)
        rows.add_column(width=self._state_width, no_wrap=True)
        rows.add_column(width=4, no_wrap=True, justify="right")
        rows.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        for spec in self._specs:
            state = self._state[spec.name]
            _, style = _STATE_STYLE[state]
            line_style = "red" if state is State.FAILED else "dim"
            rows.add_row(
                self._glyph(state),
                Text(spec.label),
                Text(state.value, style=style),
                Text(self._elapsed(spec.name), style="dim"),
                Text(self._line[spec.name], style=line_style),
            )
        return rows

    def _log_window(self) -> Panel:
        """Baut das Meldungsfenster mit fester Höhe."""
        lines: list[RenderableType] = list(self._log)
        while len(lines) < self._log_lines:
            lines.append(Text(""))
        return Panel(
            Group(*lines),
            title="Meldungen",
            title_align="left",
            border_style="grey50",
            height=self._log_lines + 2,
        )

    def _footer(self) -> Table:
        """Baut die Fortschrittszeile aus Balken und Modulzähler."""
        done = sum(1 for s in self._state.values() if s in (State.OK, State.FAILED))
        row = Table.grid(expand=True, padding=(0, 1))
        row.add_column(ratio=1)
        row.add_column(justify="right")
        row.add_row(
            self._progress,
            Text(f"{done}/{len(self._specs)} Module", style="dim"),
        )
        return row

    def _render(self) -> Panel:
        """Baut die Gesamtanzeige: Kopf, Modulliste, Meldungen, Fortschritt."""
        body = Group(
            self._header(),
            Text(),
            self._modules(),
            Text(),
            self._log_window(),
            Text(),
            self._footer(),
        )
        return Panel(body, border_style="grey50", padding=(1, 2), height=self._height)
