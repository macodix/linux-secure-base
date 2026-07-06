"""Integrationstest für secure_base.modules.unattended.

Startet Unattended.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn), siehe Begründung in test_base_module.py. Ersetzt
Systembefehle und Schreibziele durch harmlose Platzhalter bzw.
Pfade unter tmp_path und prüft Ablauf, Meldungen und Rückgabewert.
Die Aktionen selbst sind bereits in pifos getestet.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.unattended import Unattended


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
) -> tuple[Unattended, MagicMock]:
    """Baut ein Unattended-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(Unattended, "APT_GET_BIN", "/usr/bin/true")
    monkeypatch.setattr(Unattended, "DPKG_BIN", "/usr/bin/true")
    monkeypatch.setattr(Unattended, "UU_CONF", str(tmp_path / "50unattended-upgrades"))
    monkeypatch.setattr(Unattended, "PERIODIC_CONF", str(tmp_path / "20auto-upgrades"))
    monkeypatch.setattr(
        Unattended,
        "DAILY_DROPIN",
        str(tmp_path / "apt-daily.timer.d" / "secure-base.conf"),
    )
    monkeypatch.setattr(
        Unattended,
        "UPGRADE_DROPIN",
        str(tmp_path / "apt-daily-upgrade.timer.d" / "secure-base.conf"),
    )
    monkeypatch.setattr(
        Unattended, "REBOOT_REQUIRED_FILE", str(tmp_path / "reboot-required")
    )
    monkeypatch.setattr(
        Unattended,
        "REBOOT_REQUIRED_PKGS_FILE",
        str(tmp_path / "reboot-required.pkgs"),
    )
    monkeypatch.setattr(Unattended, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Unattended, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)

    conn = MagicMock()
    mod = Unattended(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = "admin@example.com"
    mod.auto_reboot = "yes"
    mod.auto_reboot_time = "23:45"
    mod.apt_daily_time = "23:15"
    mod.apt_daily_upgrade_time = "23:30"
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
    assert "apt-daily-upgrade.timer neu starten" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert Path(tmp_path / "50unattended-upgrades").exists()
    assert Path(tmp_path / "20auto-upgrades").exists()
    assert Path(tmp_path / "apt-daily.timer.d" / "secure-base.conf").exists()
    assert Path(tmp_path / "apt-daily-upgrade.timer.d" / "secure-base.conf").exists()


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    # Elternverzeichnis existiert nicht -> WriteFileAction scheitert beim Schreiben.
    monkeypatch.setattr(
        Unattended,
        "UU_CONF",
        str(tmp_path / "fehlt" / "50unattended-upgrades"),
    )

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: 50unattended-upgrades schreiben" in messages
    assert "20auto-upgrades schreiben" not in messages


def test_install_rejects_invalid_admin_mail_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine ungültige admin_mail-Adresse bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.admin_mail = "keine-mail-adresse"

    with pytest.raises(ModuleError, match="Ungültige admin_mail-Adresse"):
        mod.start()

    assert conn.send.call_args_list == []


def test_install_warns_and_fails_when_reboot_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein bestehendes reboot-required meldet den Neustart und liefert 1."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    (tmp_path / "reboot-required").write_text("")
    (tmp_path / "reboot-required.pkgs").write_text("linux-image-generic\n")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("Neustart erforderlich" in str(m) for m in messages)
    assert any("linux-image-generic" in str(m) for m in messages)


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check meldet Abweichungen, solange keine Dateien vorhanden sind."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any(
        "50unattended-upgrades" in str(m) and "nicht lesbar" in str(m) for m in messages
    )


def test_check_succeeds_after_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nach einem erfolgreichen install meldet check keine Abweichungen."""
    mod, _ = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    mod.operation = "check"
    result = mod.start()

    assert result == 0
