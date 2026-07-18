"""Regressionstest zur vendorten pifos-Anpassung in run_action.

Sichert zu, dass ein gescheiterter Werkzeugaufruf nicht nur den Rückgabewert 1
liefert, sondern die Ursache (Returncode und stderr) als ERROR-Meldung an den
Aufrufer geht — damit sie in der Logdatei erscheint.
"""

from dataclasses import dataclass, field

from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.ipc import IpcMessage, LogLevel
from pifos.module import Module


@dataclass
class _CapturingConn:
    """Fängt gesendete IPC-Nachrichten, statt sie über eine Pipe zu schicken."""

    sent: list[IpcMessage] = field(default_factory=list)

    def send(self, message: IpcMessage) -> None:
        self.sent.append(message)


class _DummyModule(Module):
    """Minimales Modul, nur um run_action zu prüfen."""

    def start(self) -> int:
        return 0


def _make_module() -> tuple[_DummyModule, _CapturingConn]:
    """Baut ein Dummy-Modul mit nachrichtenfangender Verbindung (Logstufe INFO)."""
    conn = _CapturingConn()
    mod = _DummyModule(conn, LogLevel.INFO)  # type: ignore[arg-type]
    return mod, conn


def test_run_action_logs_returncode_and_stderr_on_failure() -> None:
    """Ein fehlgeschlagener Befehl meldet Returncode und stderr als ERROR."""
    mod, conn = _make_module()
    action = SysCmdAction(
        command=["/bin/sh", "-c", "echo boom 1>&2; exit 3"], timeout=10
    )

    rc = mod.run_action(action)

    assert rc == 1
    errors = [m for m in conn.sent if m.level == LogLevel.ERROR]
    assert errors, "keine ERROR-Meldung gesendet"
    text = str(errors[-1].payload)
    assert "3" in text
    assert "boom" in text


def test_run_action_silent_on_success() -> None:
    """Ein erfolgreicher Befehl erzeugt keine ERROR-Meldung."""
    mod, conn = _make_module()
    action = SysCmdAction(command=["/bin/sh", "-c", "exit 0"], timeout=10)

    rc = mod.run_action(action)

    assert rc == 0
    assert not [m for m in conn.sent if m.level == LogLevel.ERROR]
