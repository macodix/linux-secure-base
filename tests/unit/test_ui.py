"""Unit-Tests für secure_base.ui."""

import io

from pifos.ipc import LogLevel
from rich.console import Console
from secure_base.module_spec import ModuleSpec
from secure_base.ui import State, StatusView


class _DummyModuleCls:
    """Platzhalter für eine Modulklasse; StatusView liest sie nie."""


def _specs() -> list[ModuleSpec]:
    return [
        ModuleSpec("base", "Grundkonfiguration", _DummyModuleCls, optional=False),  # type: ignore[arg-type]
        ModuleSpec("ssh", "SSH-Härtung", _DummyModuleCls, optional=False),  # type: ignore[arg-type]
    ]


def _silent_view(operation: str = "install", host: str = "") -> StatusView:
    """Baut eine StatusView mit einer stummen Konsole (kein echtes Terminal)."""
    view = StatusView(_specs(), operation, host)
    view._console = Console(file=io.StringIO(), width=100)
    return view


def _output(view: StatusView) -> str:
    """Liest den bisherigen Ausgabetext der stummen Konsole."""
    buf = view._console.file
    assert isinstance(buf, io.StringIO)
    return buf.getvalue()


def _render_text(view: StatusView) -> str:
    """Rendert die Live-Anzeige in Text (ohne Farben)."""
    console = Console(file=io.StringIO(), width=100)
    console.print(view._render())
    out = console.file
    assert isinstance(out, io.StringIO)
    return out.getvalue()


def test_initial_state_is_waiting() -> None:
    """Jedes Modul startet im Zustand WAITING mit leerer Statuszeile."""
    view = _silent_view()
    assert view._state == {"base": State.WAITING, "ssh": State.WAITING}
    assert view._line == {"base": "", "ssh": ""}


def test_set_running_updates_state() -> None:
    """set_running setzt genau das benannte Modul auf RUNNING."""
    view = _silent_view()
    view.set_running("base")
    assert view._state["base"] is State.RUNNING
    assert view._state["ssh"] is State.WAITING


def test_set_status_line_updates_line() -> None:
    """set_status_line übernimmt den Text als letzte Statuszeile."""
    view = _silent_view()
    view.set_status_line("base", "Rechnername setzen", LogLevel.INFO)
    assert view._line["base"] == "Rechnername setzen"


def test_set_result_ok_and_failed() -> None:
    """set_result setzt OK bzw. FAILED je nach Ergebnis."""
    view = _silent_view()
    view.set_result("base", True)
    view.set_result("ssh", False)
    assert view._state["base"] is State.OK
    assert view._state["ssh"] is State.FAILED


def test_failed_module_shows_first_error_line() -> None:
    """Bei Fehlschlag zeigt die Statuszeile die erste Fehlermeldung.

    Spätere INFO-Meldungen (etwa OK-Zeilen nachfolgender Prüfungen eines
    Soll-Ist-Abgleichs) verdrängen die Fehlerursache nicht.
    """
    view = _silent_view()
    view.set_status_line(
        "base", "NTP-Synchronisation: ist no, soll yes", LogLevel.ERROR
    )
    view.set_status_line(
        "base", "sysctl kernel.yama.ptrace_scope: 1 — OK", LogLevel.INFO
    )

    view.set_result("base", False)

    assert view._line["base"] == "NTP-Synchronisation: ist no, soll yes"


def test_failed_module_keeps_first_of_several_errors() -> None:
    """Bei mehreren Fehlermeldungen bleibt die erste erhalten."""
    view = _silent_view()
    view.set_status_line(
        "base", "NTP-Synchronisation: ist no, soll yes", LogLevel.ERROR
    )
    view.set_status_line(
        "base", "sysctl kernel.kptr_restrict: ist 1, soll 2", LogLevel.ERROR
    )

    view.set_result("base", False)

    assert view._line["base"] == "NTP-Synchronisation: ist no, soll yes"


def test_successful_module_keeps_last_line() -> None:
    """Bei Erfolg bleibt die zuletzt gemeldete Zeile stehen."""
    view = _silent_view()
    view.set_status_line("base", "Rechnername setzen", LogLevel.INFO)
    view.set_result("base", True)
    assert view._line["base"] == "Rechnername setzen"


def test_summary_reports_success_when_nothing_failed() -> None:
    """summary meldet Erfolg, wenn kein Modul fehlgeschlagen ist."""
    view = _silent_view()
    view.set_result("base", True)
    view.set_result("ssh", True)

    view.summary()

    assert "Alle Module erfolgreich." in _output(view)


def test_summary_reports_failed_and_skipped_modules() -> None:
    """summary nennt fehlgeschlagene und nicht ausgeführte Module."""
    view = _silent_view()
    view.set_result("base", False)

    view.summary()

    out = _output(view)
    assert "Fehlgeschlagen: Grundkonfiguration" in out
    assert "Nicht ausgeführt: SSH-Härtung" in out


def test_live_sets_and_clears_live_attribute() -> None:
    """Innerhalb von live() ist _live gesetzt, danach wieder None."""
    view = _silent_view()
    assert view._live is None
    with view.live():
        assert view._live is not None
    assert view._live is None


def test_render_shows_header_modules_and_progress() -> None:
    """Die Anzeige enthält Kopfzeile, Modulliste und Modulzähler."""
    view = _silent_view(host="server.example.com")
    view.set_result("base", True)

    out = _render_text(view)

    assert "Linux Secure Base" in out
    assert "Installation" in out
    assert "server.example.com" in out
    assert "Grundkonfiguration" in out
    assert "SSH-Härtung" in out
    assert "1/2 Module" in out
    assert "✓" in out


def test_render_title_names_operation() -> None:
    """Die Kopfzeile nennt die Betriebsart des Laufs."""
    assert "Soll-Ist-Abgleich" in _render_text(_silent_view(operation="check"))
    assert "Installation" in _render_text(_silent_view(operation="install"))


def test_render_log_window_shows_recent_messages_with_module_name() -> None:
    """Das Meldungsfenster zeigt die letzten Meldungen mit Modulname."""
    view = _silent_view()
    view.set_status_line("base", "Rechnername setzen", LogLevel.INFO)
    view.set_status_line("ssh", "sshd_config härten", LogLevel.INFO)

    out = _render_text(view)

    assert "Meldungen" in out
    assert "Rechnername setzen" in out
    assert "sshd_config härten" in out


def test_render_geometry_is_stable_under_long_messages() -> None:
    """Lange Meldungen ändern die Zeilenzahl der Anzeige nicht.

    Deckt den Servertest-Befund ab: umbrechende Logzeilen ließen das
    Meldungsfenster vorübergehend wachsen (springende Anzeige).
    """
    view = _silent_view()
    before = _render_text(view).count("\n")
    for i in range(12):
        view.set_status_line("base", f"Meldung {i}: " + "x" * 500, LogLevel.INFO)
    after = _render_text(view).count("\n")
    assert before == after
    assert after == view._height


def test_layout_shrinks_log_window_on_small_terminal() -> None:
    """Bei niedrigem Terminal schrumpft das Meldungsfenster.

    Deckt den Servertest-Befund ab: eine Anzeige höher als das Terminal
    zeichnet sichtbar springend.
    """
    view = _silent_view()
    # Feste Zeilen bei 2 Modulen: 4+1+2+3+1 = 11.
    view._layout(20)
    assert view._log_lines == 6
    assert view._height <= 19

    view._layout(16)
    assert view._log_lines == 3
    assert view._height <= 15

    view._layout(50)
    assert view._log_lines == 8


class _FakeSize:
    def __init__(self, height: int) -> None:
        self.height = height


class _FakeConsole:
    """Konsole, deren gemeldete Schirmhöhe der Test steuert."""

    def __init__(self, height: int) -> None:
        self._height = height

    @property
    def size(self) -> _FakeSize:
        return _FakeSize(self._height)


class _CapturingLive:
    """Live-Ersatz, der nur die letzte Übergabe festhält."""

    def __init__(self) -> None:
        self.last: object | None = None

    def update(self, renderable: object) -> None:
        self.last = renderable


def test_refresh_relayouts_when_terminal_shrinks() -> None:
    """Schrumpft das Terminal, passt _refresh die Geometrie neu an.

    Deckt den Servertest-Befund ab: eine bei Anzeigenstart festgelegte
    Höhe, die später über der Terminalhöhe liegt, kann nicht am Ort neu
    zeichnen — die Anzeige scrollt (Leerzeilen-/Wachstums-Eindruck).
    """
    view = _silent_view()
    view._console = _FakeConsole(40)  # type: ignore[assignment]
    view._live = _CapturingLive()  # type: ignore[assignment]

    view._refresh()
    tall = view._height

    view._console = _FakeConsole(14)  # type: ignore[assignment]
    view._refresh()

    assert view._term_rows == 14
    assert view._height < tall
    assert view._height <= 13
