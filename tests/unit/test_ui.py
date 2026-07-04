"""Unit-Tests für lsb.ui."""

import io

from lsb.module_spec import ModuleSpec
from lsb.ui import State, StatusView
from pifos.ipc import LogLevel
from rich.console import Console


class _DummyModuleCls:
    """Platzhalter für eine Modulklasse; StatusView liest sie nie."""


def _specs() -> list[ModuleSpec]:
    return [
        ModuleSpec("base", "Grundkonfiguration", _DummyModuleCls, optional=False),  # type: ignore[arg-type]
        ModuleSpec("ssh", "SSH-Härtung", _DummyModuleCls, optional=False),  # type: ignore[arg-type]
    ]


def _silent_view() -> StatusView:
    """Baut eine StatusView mit einer stummen Konsole (kein echtes Terminal)."""
    view = StatusView(_specs())
    view._console = Console(file=io.StringIO())
    return view


def _output(view: StatusView) -> str:
    """Liest den bisherigen Ausgabetext der stummen Konsole."""
    buf = view._console.file
    assert isinstance(buf, io.StringIO)
    return buf.getvalue()


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


def test_summary_reports_success_when_nothing_failed() -> None:
    """summary meldet Erfolg, wenn kein Modul fehlgeschlagen ist."""
    view = _silent_view()
    view.set_result("base", True)
    view.set_result("ssh", True)

    view.summary()

    assert "Alle Module erfolgreich." in _output(view)


def test_summary_reports_failed_modules() -> None:
    """summary listet fehlgeschlagene Module namentlich auf."""
    view = _silent_view()
    view.set_result("base", True)
    view.set_result("ssh", False)

    view.summary()

    assert "Fehlgeschlagen: ssh" in _output(view)


def test_live_sets_and_clears_live_attribute() -> None:
    """Innerhalb von live() ist _live gesetzt, danach wieder None."""
    view = _silent_view()
    assert view._live is None
    with view.live():
        assert view._live is not None
    assert view._live is None
