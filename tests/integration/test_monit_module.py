"""Integrationstest für secure_base.modules.monit.

Startet Monit.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn) — Begründung siehe test_base_module.py. Der
direkte Aufruf im Testprozess ersetzt die Systembefehle durch harmlose
Platzhalter (Plan Abschnitt 2.12) und prüft Ablauf, Meldungen und
Rückgabewert von Monit. Die Aktionen selbst sind bereits in pifos getestet.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.monit import Monit


class _NoOpAptAction(AptAction):
    """Ersetzt AptAction für Tests: läuft immer erfolgreich durch, ohne apt-get."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


class _NoOpSystemdAction(SystemdServiceAction):
    """Ersetzt SystemdServiceAction für Tests: läuft immer erfolgreich durch."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Monit, MagicMock]:
    """Baut ein Monit-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monitrc = tmp_path / "monitrc"
    monitrc.write_text("# vorhandene monitrc (von apt angelegt)\n")
    confd = tmp_path / "conf.d"
    confd.mkdir()

    monkeypatch.setattr(Monit, "MONIT_BIN", "/usr/bin/true")
    monkeypatch.setattr(Monit, "SYSTEMCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Monit, "MONITRC", str(monitrc))
    monkeypatch.setattr(Monit, "CONFD", str(confd))
    monkeypatch.setattr(Monit, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Monit, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)

    conn = MagicMock()
    mod = Monit(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = "admin@example.com"
    mod.monit_mail_from = "monit@example.com"
    mod.monit_checks = "system,rootfs"
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
    assert "Konfiguration neu einlesen (monit reload)" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert (Path(Monit.CONFD) / "system").exists()
    assert (Path(Monit.CONFD) / "rootfs").exists()
    monitrc_content = Path(Monit.MONITRC).read_text()
    assert "# BEGIN monit-alert" in monitrc_content
    assert "set alert admin@example.com" in monitrc_content


def test_install_writes_only_configured_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nur die in monit_checks genannten Checks werden angelegt."""
    mod, _conn = _make_module(tmp_path, monkeypatch)
    mod.monit_checks = "sshd"

    result = mod.start()

    assert result == 0
    assert (Path(Monit.CONFD) / "sshd").exists()
    assert not (Path(Monit.CONFD) / "system").exists()


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Monit, "MONIT_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Konfiguration prüfen (monit -t)" in messages
    assert "Dienst aktivieren" not in messages


def test_install_rejects_invalid_admin_mail_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine ungültige admin_mail bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.admin_mail = "ungueltig"

    with pytest.raises(ModuleError, match="Ungültige admin_mail"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check vergleicht Ist- und Soll-Werte und meldet Abweichungen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"
    # /usr/bin/true liefert keine Ausgabe; weicht daher von jedem Soll-Wert ab.
    # monitrc-Marker und conf.d-Dateien fehlen ebenfalls (kein install-Lauf).

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("Dienst aktiv" in str(m) and "soll" in str(m) for m in messages)
    assert any("set daemon" in str(m) and "fehlt" in str(m) for m in messages)


def test_check_confirms_markers_and_files_after_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nach install bestätigt check die monitrc-Marker und conf.d-Dateirechte.

    Paket- und Dienststatus bleiben trotzdem als Abweichung gemeldet, da der
    Platzhalter /usr/bin/true keine der erwarteten Ausgaben (z. B. "active")
    liefert — das ist hier unerheblich, geprüft wird nur die eigene Wirkung
    der install-Schritte (Marker, Dateirechte).
    """
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    conn.reset_mock()

    mod.operation = "check"
    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("monitrc-Eingriff 'set alert': vorhanden" in str(m) for m in messages)
    assert any("Check system:" in str(m) and "OK" in str(m) for m in messages)
