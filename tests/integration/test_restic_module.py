"""Integrationstest für secure_base.modules.restic.

Startet Restic.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn) — Begründung wie in test_base_module.py: ein
Spawn-Subprozess teilt keinen Zustand mit dem Testprozess, ein monkeypatch
der Systembefehl-Konstanten käme dort nicht an. Die Systembefehle (sftp,
restic) werden durch /usr/bin/true bzw. /usr/bin/false ersetzt (Plan
Abschnitt 2.12); AptAction durch eine No-Op-Unterklasse. Die Aktionen
selbst sind bereits in pifos getestet.
"""

import os
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.restic import Restic


class _NoOpAptAction(AptAction):
    """Ersetzt AptAction für Tests: läuft immer erfolgreich durch, ohne apt-get."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Restic, MagicMock]:
    """Baut ein Restic-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(Restic, "RESTIC_BIN", "/usr/bin/true")
    monkeypatch.setattr(Restic, "SFTP_BIN", "/usr/bin/true")
    monkeypatch.setattr(
        Restic, "PASSPHRASE_FILE", str(tmp_path / "config/restic-passphrase")
    )
    monkeypatch.setattr(Restic, "CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setattr(Restic, "BACKUP_SCRIPT_DIR", str(tmp_path / "sbin"))
    monkeypatch.setattr(Restic, "CRON_DIR", str(tmp_path / "cron.d"))
    monkeypatch.setattr(Restic, "SENTINEL_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(
        Restic, "SENTINEL_FILE", str(tmp_path / "state/restic-last-success")
    )
    monkeypatch.setattr(Restic, "APT_ACTION_CLS", _NoOpAptAction)

    # Elternverzeichnisse für WriteFileAction/MakeDirAction ohne parents=True
    # (Backup-Skript- und Cron-Zielverzeichnis werden vom Modul nicht mit
    # parents=True angelegt, entsprechend dem Bash-Original: nur CONFIG_DIR
    # und SENTINEL_DIR sind Modul-eigene, mit install -d angelegte Ziele).
    Path(tmp_path / "sbin").mkdir()
    Path(tmp_path / "cron.d").mkdir()

    conn = MagicMock()
    mod = Restic(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = "server.example.com"
    mod.admin_mail = "admin@example.com"
    mod.sftp_host_alias = "backup-alias"
    mod.sftp_path = "/backup/server"
    mod.restic_passphrase = "correct-horse-battery-staple"  # noqa: S105 — Testwert
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
    assert "Monit-Sentinel anlegen" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)

    passphrase_file = Path(Restic.PASSPHRASE_FILE)
    assert (
        passphrase_file.read_text(encoding="utf-8") == "correct-horse-battery-staple\n"
    )
    assert stat.S_IMODE(passphrase_file.stat().st_mode) == 0o600

    backup_script = Path(mod._backup_script_path())
    assert backup_script.exists()
    assert stat.S_IMODE(backup_script.stat().st_mode) == 0o700
    assert "sftp:backup-alias:/backup/server" in backup_script.read_text(
        encoding="utf-8"
    )

    cron_file = Path(mod._cron_file_path())
    assert cron_file.exists()
    assert stat.S_IMODE(cron_file.stat().st_mode) == 0o644

    assert Path(Restic.SENTINEL_FILE).exists()

    # Die Passphrase selbst darf in keiner gesendeten Meldung auftauchen.
    assert not any("correct-horse-battery-staple" in str(m) for m in messages)


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Restic, "SFTP_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: SFTP-Erreichbarkeit prüfen" in messages
    assert "Passphrase-Datei schreiben" not in messages
    assert not Path(Restic.PASSPHRASE_FILE).exists()


def test_install_rejects_invalid_config_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiger Konfigurationswert bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.sftp_host_alias = "-invalid"

    with pytest.raises(ModuleError, match="Ungültiger SFTP-Host-Alias"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check meldet eine abweichende Passphrase-Datei-Berechtigung."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    Path(Restic.PASSPHRASE_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(Restic.PASSPHRASE_FILE).write_text("irgendwas\n", encoding="utf-8")
    os.chmod(Restic.PASSPHRASE_FILE, 0o644)
    mod.operation = "check"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("Passphrase-Datei" in str(m) and "soll" in str(m) for m in messages)


def test_check_all_ok_after_successful_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nach einem erfolgreichen install meldet check keine Abweichung."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    conn.reset_mock()
    mod.operation = "check"

    result = mod.start()

    assert result == 0
