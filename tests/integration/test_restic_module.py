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


class _FailingAptAction(AptAction):
    """Ersetzt AptAction für Tests: scheitert immer."""

    def run(self) -> str:
        self.status = "failed"
        return self.status


def _write_stub(path: Path, content: str) -> str:
    """Schreibt ein ausführbares Shell-Stub-Skript und liefert dessen Pfad.

    Args:
        path: Zielpfad des Stub-Skripts.
        content: Skriptrumpf (ohne Shebang).

    Returns:
        Pfad des Stub-Skripts als Zeichenkette.
    """
    path.write_text(f"#!/bin/sh\n{content}\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _write_dpkg_stub(path: Path, output: str, returncode: int = 0) -> str:
    """Schreibt ein ausführbares Stub-Skript als dpkg-query-Ersatz."""
    return _write_stub(path, f"printf '%s' '{output}'\nexit {returncode}\n")


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Restic, MagicMock]:
    """Baut ein Restic-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(Restic, "RESTIC_BIN", "/usr/bin/true")
    monkeypatch.setattr(Restic, "SFTP_BIN", "/usr/bin/true")
    # Voreinstellung "nicht installiert" (keine Ausgabe) — Tests für uninstall/
    # test setzen bei Bedarf einen eigenen Stub mit "install ok installed".
    monkeypatch.setattr(Restic, "DPKG_QUERY_BIN", "/usr/bin/true")
    monkeypatch.setattr(Restic, "MAIL_BIN", "/usr/bin/true")
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
    mod.restic_backup_time = "02:30"
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


def test_install_writes_cron_with_configured_backup_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Die Cron-Datei nutzt die aus restic_backup_time umgesetzten Cron-Felder."""
    mod, _conn = _make_module(tmp_path, monkeypatch)
    mod.restic_backup_time = "23:15"

    assert mod.start() == 0

    cron_content = Path(mod._cron_file_path()).read_text(encoding="utf-8")
    assert "15 23 * * *  root " in cron_content
    assert mod._backup_script_path() in cron_content


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


# --- Betriebsart uninstall ---


def test_uninstall_removes_cron_backup_script_and_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall entfernt Cron-Datei, Backup-Skript und das Paket."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0  # install: legt Cron-Datei und Backup-Skript an
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    assert not Path(mod._cron_file_path()).exists()
    assert not Path(mod._backup_script_path()).exists()
    messages = _sent_messages(conn)
    assert "Cron-Datei entfernen" in messages
    assert "Backup-Skript entfernen" in messages
    assert "Paket entfernen" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_uninstall_keeps_passphrase_file_and_repo_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Die Passphrase-Datei bleibt unangetastet; uninstall warnt nur davor."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    passphrase_content = Path(Restic.PASSPHRASE_FILE).read_text(encoding="utf-8")
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    assert (
        Path(Restic.PASSPHRASE_FILE).read_text(encoding="utf-8") == passphrase_content
    )
    messages = _sent_messages(conn)
    assert any(
        "Passphrase-Datei" in str(m)
        and "Backup-Repo" in str(m)
        and "unverändert" in str(m)
        for m in messages
    )
    assert any(
        "Klartext-Geheimnis" in str(m) and "manuell löschen" in str(m) for m in messages
    )
    # Die Passphrase selbst darf in keiner gesendeten Meldung auftauchen.
    assert not any("correct-horse-battery-staple" in str(m) for m in messages)


def test_uninstall_is_idempotent_on_second_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter uninstall-Lauf auf bereits entfernten Dateien liefert wieder 0."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    mod.operation = "uninstall"
    assert mod.start() == 0
    conn.reset_mock()

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("Cron-Datei bereits entfernt" in str(m) for m in messages)
    assert any("Backup-Skript bereits entfernt" in str(m) for m in messages)


def test_uninstall_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    # Ein Verzeichnis anstelle der Cron-Datei lässt DeleteFileAction fehlschlagen
    # (os.remove auf ein Verzeichnis).
    Path(mod._cron_file_path()).mkdir(parents=True)
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Cron-Datei entfernen" in messages
    assert "Backup-Skript entfernen" not in messages
    assert "Paket entfernen" not in messages


def test_uninstall_package_removal_failure_stops_before_final_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert die Paketentfernung, bleiben die Abschluss-Meldungen aus."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Restic, "APT_ACTION_CLS", _FailingAptAction)
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Paket entfernen" in messages
    assert not any("bleiben unverändert" in str(m) for m in messages)


# --- Betriebsart test ---


def test_test_fails_when_package_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt das Paket restic, meldet test einen Fehler ohne weitere Prüfungen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "Paket restic nicht installiert — kein Funktionstest möglich" in messages


def test_test_all_checks_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sind Paket, SFTP-Ziel und Repo in Ordnung, liefert test 0."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    monkeypatch.setattr(
        Restic,
        "RESTIC_BIN",
        _write_stub(
            tmp_path / "restic",
            'case "$5" in\n'
            "  cat) exit 0 ;;\n"
            '  snapshots) printf "%s" \'[{"id": "abc123"}]\' ;;\n'
            "  check) exit 0 ;;\n"
            "  restore) exit 0 ;;\n"
            "esac",
        ),
    )
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("SFTP-Ziel erreichbar" in str(m) for m in messages)
    assert any("entschlüsselbar" in str(m) for m in messages)
    assert any("Snapshot-Liste: OK" in str(m) for m in messages)
    assert any("Repo-Integrität: OK" in str(m) for m in messages)
    assert any(
        "Probe-Restore aus Snapshot abc123 erfolgreich" in str(m) for m in messages
    )


def test_test_skips_probe_restore_when_no_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne Snapshot gilt der Probe-Restore als übersprungen, kein Testfehler."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    monkeypatch.setattr(
        Restic,
        "RESTIC_BIN",
        _write_stub(
            tmp_path / "restic",
            'case "$5" in\n'
            "  cat) exit 0 ;;\n"
            "  snapshots) printf \"%s\" '[]' ;;\n"
            "  check) exit 0 ;;\n"
            "esac",
        ),
    )
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any(
        "kein Snapshot vorhanden — Probe-Restore übersprungen" in str(m)
        for m in messages
    )


def test_test_collects_all_failures_without_aborting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """test sammelt alle Befunde, statt beim ersten Fehler abzubrechen (sammelnd)."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    monkeypatch.setattr(Restic, "SFTP_BIN", "/usr/bin/false")
    monkeypatch.setattr(
        Restic,
        "RESTIC_BIN",
        _write_stub(
            tmp_path / "restic",
            'case "$5" in\n'
            "  cat) exit 1 ;;\n"
            "  snapshots) printf \"%s\" '[]' ;;\n"
            "  check) exit 1 ;;\n"
            "esac",
        ),
    )
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("SFTP-Ziel" in str(m) and "nicht erreichbar" in str(m) for m in messages)
    assert any(
        "nicht initialisiert/erreichbar oder Passphrase falsch" in str(m)
        for m in messages
    )
    assert any("Repo-Integrität: fehlgeschlagen" in str(m) for m in messages)
    # Snapshot-Liste (plain) ist Teil desselben Laufs und bleibt erfolgreich —
    # zeigt, dass ein einzelner Fehlschlag die übrigen Prüfungen nicht abbricht.
    assert any("Snapshot-Liste: OK" in str(m) for m in messages)


def test_test_warns_when_mail_binary_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt der mail-Befehl, warnt test, ohne den Rückgabewert zu verschlechtern."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    monkeypatch.setattr(
        Restic,
        "RESTIC_BIN",
        _write_stub(
            tmp_path / "restic",
            'case "$5" in\n'
            "  cat) exit 0 ;;\n"
            "  snapshots) printf \"%s\" '[]' ;;\n"
            "  check) exit 0 ;;\n"
            "esac",
        ),
    )
    monkeypatch.setattr(Restic, "MAIL_BIN", str(tmp_path / "mail-fehlt"))
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any(
        "mail-Befehl fehlt" in str(m) and "postfix-Modul" in str(m) for m in messages
    )
