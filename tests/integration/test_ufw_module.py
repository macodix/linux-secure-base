"""Integrationstest für lsb.modules.ufw.

Startet Ufw.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn); Begründung siehe test_base_module.py. Die
Systembefehle laufen über harmlose Platzhalter oder — für den
Regelabgleich (check) — über ein kleines Fake-Skript, das die Ausgabe
von `ufw show added` nachbildet.
"""

import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from lsb.modules.ufw import Ufw
from pifos.actions.apt_action import AptAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel


class _NoOpAptAction(AptAction):
    """Ersetzt AptAction für Tests: läuft immer erfolgreich durch, ohne apt-get."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


def _make_executable(path: Path, content: str) -> str:
    """Legt ein ausführbares Shell-Skript an und liefert seinen Pfad."""
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def _make_module(monkeypatch: pytest.MonkeyPatch) -> tuple[Ufw, MagicMock]:
    """Baut ein Ufw-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(Ufw, "UFW_BIN", "/usr/bin/true")
    monkeypatch.setattr(Ufw, "APT_ACTION_CLS", _NoOpAptAction)

    conn = MagicMock()
    mod = Ufw(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.allow_in_tcp = "22"
    mod.allow_out_tcp = "443,80"
    mod.allow_out_udp = "53"
    return mod, conn


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, keine Fehlermeldung."""
    mod, conn = _make_module(monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("NICHT aktiv" in str(m) for m in messages)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_install_stops_at_first_failed_step(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(monkeypatch)
    monkeypatch.setattr(Ufw, "UFW_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: deterministischer Ausgangszustand (reset)" in messages
    assert "Default-Policy deny incoming" not in messages


def test_install_rejects_invalid_port_before_any_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein ungültiger Port bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(monkeypatch)
    mod.allow_in_tcp = "22,70000"

    with pytest.raises(ModuleError, match="ungültigen Port"):
        mod.start()

    assert conn.send.call_args_list == []


def test_install_rejects_missing_ssh_port_before_any_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein fehlender SSH-Port bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(monkeypatch)
    mod.allow_in_tcp = "80"

    with pytest.raises(ModuleError, match="SSH-Verwaltungszugang"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stimmt das Fake-Regelwerk mit der Konfiguration überein, liefert check 0."""
    mod, conn = _make_module(monkeypatch)
    mod.operation = "check"
    fake_ufw = _make_executable(
        tmp_path / "fake_ufw",
        "#!/bin/sh\n"
        'if [ "$1" = "show" ] && [ "$2" = "added" ]; then\n'
        '    echo "ufw allow 22/tcp"\n'
        '    echo "ufw allow out 80/tcp"\n'
        '    echo "ufw allow out 443/tcp"\n'
        '    echo "ufw allow out 53/udp"\n'
        "fi\n"
        "exit 0\n",
    )
    monkeypatch.setattr(Ufw, "UFW_BIN", fake_ufw)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("überein" in str(m) for m in messages)


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Weicht das Fake-Regelwerk von der Konfiguration ab, liefert check 1."""
    mod, conn = _make_module(monkeypatch)
    mod.operation = "check"
    fake_ufw = _make_executable(
        tmp_path / "fake_ufw",
        "#!/bin/sh\n"
        'if [ "$1" = "show" ] && [ "$2" = "added" ]; then\n'
        '    echo "ufw allow 22/tcp"\n'
        "fi\n"
        "exit 0\n",
    )
    monkeypatch.setattr(Ufw, "UFW_BIN", fake_ufw)

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("weicht ab" in str(m) for m in messages)
