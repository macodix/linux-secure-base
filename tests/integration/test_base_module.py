"""Integrationstest für lsb.modules.base.

Startet Base.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn): Ein Spawn-Subprozess re-importiert das Modul in
einem frischen Interpreter und teilt keinen Zustand mit dem Testprozess,
sodass ein monkeypatch der Systembefehl-Konstanten dort nicht ankäme. Der
direkte Aufruf im Testprozess ersetzt die Systembefehle durch harmlose
Platzhalter (Plan Abschnitt 2.12) und prüft Ablauf, Meldungen und
Rückgabewert von Base. Die Aktionen selbst sind bereits in pifos getestet.
"""

from pathlib import Path
from unittest.mock import MagicMock

import lsb.modules.base as base_module
import pytest
from lsb.modules.base import Base
from pifos.errors import ModuleError
from pifos.ipc import LogLevel


class _StubAction:
    """Ersetzt AptAction/SystemdServiceAction: läuft immer erfolgreich durch.

    apt-get und systemctl (enable/start) haben keinen über eine
    Modulkonstante austauschbaren Programmpfad; deshalb wird hier die
    ganze Aktionsklasse ersetzt statt nur ein Binärpfad.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.status = "not_runned"
        self.stdout = ""
        self.stderr = ""
        self.returncode = 0

    def run(self) -> str:
        self.status = "finished"
        return self.status


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Base, MagicMock]:
    """Baut ein Base-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(base_module, "HOSTNAMECTL", "/usr/bin/true")
    monkeypatch.setattr(base_module, "HOSTNAME_BIN", "/usr/bin/true")
    monkeypatch.setattr(base_module, "TIMEDATECTL", "/usr/bin/true")
    monkeypatch.setattr(base_module, "SYSTEMCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(base_module, "SYSCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(base_module, "SYSCTL_CONF", str(tmp_path / "sysctl.conf"))
    monkeypatch.setattr(base_module, "MODPROBE_CONF", str(tmp_path / "modprobe.conf"))
    monkeypatch.setattr(base_module, "AptAction", _StubAction)
    monkeypatch.setattr(base_module, "SystemdServiceAction", _StubAction)

    conn = MagicMock()
    mod = Base(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = "server.example.com"
    mod.timezone = "Europe/Berlin"
    return mod, conn


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, keine Fehlermeldung."""
    mod, conn = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "AppArmor starten" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert Path(tmp_path / "sysctl.conf").exists()
    assert Path(tmp_path / "modprobe.conf").exists()


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(base_module, "SYSTEMCTL_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: autofs maskieren" in messages
    assert "AppArmor installieren" not in messages


def test_install_rejects_invalid_hostname_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiger Rechnername bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.fqdn = "-invalid-"

    with pytest.raises(ModuleError, match="Ungültiger Rechnername"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check vergleicht Ist- und Soll-Werte und meldet Abweichungen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"
    # /usr/bin/true liefert keine Ausgabe; weicht daher von jedem Soll-Wert ab.

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("Rechnername" in str(m) and "soll" in str(m) for m in messages)
