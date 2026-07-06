"""Unit-Tests für secure_base.modules.restic."""

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.restic import (
    Restic,
    _backup_script_content,
    _cron_content,
    _mkdir_batch_commands,
)


def _make_restic(
    fqdn: str = "server.example.com",
    admin_mail: str = "admin@example.com",
    sftp_host_alias: str = "backup-alias",
    sftp_path: str = "/backup/server",
    restic_passphrase: str = "correct-horse-battery-staple",  # noqa: S107 — Testwert
) -> Restic:
    """Baut ein Restic-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Restic(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.admin_mail = admin_mail
    mod.sftp_host_alias = sftp_host_alias
    mod.sftp_path = sftp_path
    mod.restic_passphrase = restic_passphrase
    return mod


# --- CONFIG ---


def test_restic_config_declares_expected_keys_in_order() -> None:
    """CONFIG nennt operation, fqdn, admin_mail und die restic-eigenen Schlüssel."""
    assert Restic.CONFIG == [
        "operation",
        "fqdn",
        "admin_mail",
        "sftp_host_alias",
        "sftp_path",
        "restic_passphrase",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige Werte lösen keine Ausnahme aus."""
    mod = _make_restic()
    mod._validate()


def test_validate_rejects_invalid_hostname() -> None:
    """Ein ungültiger Rechnername erzeugt ModuleError."""
    mod = _make_restic(fqdn="-invalid-")
    with pytest.raises(ModuleError, match="Ungültiger Rechnername"):
        mod._validate()


def test_validate_rejects_invalid_mail() -> None:
    """Eine ungültige Mail-Adresse erzeugt ModuleError."""
    mod = _make_restic(admin_mail="not-an-address")
    with pytest.raises(ModuleError, match="Ungültige Mail-Adresse"):
        mod._validate()


def test_validate_rejects_invalid_sftp_host_alias() -> None:
    """Ein SFTP-Host-Alias mit unerlaubtem Zeichen erzeugt ModuleError."""
    mod = _make_restic(sftp_host_alias="backup alias")
    with pytest.raises(ModuleError, match="Ungültiger SFTP-Host-Alias"):
        mod._validate()


def test_validate_rejects_sftp_host_alias_starting_with_dash() -> None:
    """Ein mit '-' beginnender Host-Alias erzeugt ModuleError (Optionsinjektion)."""
    mod = _make_restic(sftp_host_alias="-x")
    with pytest.raises(ModuleError, match="Ungültiger SFTP-Host-Alias"):
        mod._validate()


def test_validate_rejects_relative_sftp_path() -> None:
    """Ein nicht-absoluter SFTP-Zielpfad erzeugt ModuleError."""
    mod = _make_restic(sftp_path="relative/path")
    with pytest.raises(ModuleError, match="Ungültiger SFTP-Zielpfad"):
        mod._validate()


def test_validate_rejects_empty_passphrase() -> None:
    """Eine leere restic-Passphrase erzeugt ModuleError."""
    mod = _make_restic(restic_passphrase="")
    with pytest.raises(ModuleError, match="restic_passphrase ist leer"):
        mod._validate()


# --- Pfad-/URL-Aufbau ---


def test_repo_url_combines_alias_and_path() -> None:
    """_repo_url baut sftp:<alias>:<pfad>."""
    mod = _make_restic(sftp_host_alias="myalias", sftp_path="/data/backup")
    assert mod._repo_url() == "sftp:myalias:/data/backup"


def test_backup_script_path_uses_fqdn() -> None:
    """_backup_script_path benennt das Skript nach fqdn."""
    mod = _make_restic(fqdn="host.example.com")
    assert (
        mod._backup_script_path()
        == f"{Restic.BACKUP_SCRIPT_DIR}/host.example.com-backup.sh"
    )


def test_cron_file_path_uses_fqdn() -> None:
    """_cron_file_path benennt die Cron-Datei nach fqdn."""
    mod = _make_restic(fqdn="host.example.com")
    assert mod._cron_file_path() == f"{Restic.CRON_DIR}/host.example.com-backup"


# --- _mkdir_batch_commands ---


def test_mkdir_batch_commands_builds_per_component_mkdir_and_final_cd() -> None:
    """Jede Pfadkomponente erhält ein eigenes -mkdir, zum Schluss ein cd."""
    commands = _mkdir_batch_commands("/a/b/c")
    assert commands == ["-mkdir /a", "-mkdir /a/b", "-mkdir /a/b/c", "cd /a/b/c"]


# --- Inhaltsfunktionen ---


def test_backup_script_content_contains_repo_mail_and_fqdn() -> None:
    """Das Backup-Skript enthält Repo, Passphrase-Pfad, Mail-Adresse und fqdn."""
    content = _backup_script_content(
        repo="sftp:alias:/path",
        admin_mail="admin@example.com",
        fqdn="host.example.com",
        passphrase_file="/root/config/restic-passphrase",  # noqa: S106 — nur Pfad
        sentinel_dir="/var/lib/secure-base",
        sentinel_file="/var/lib/secure-base/restic-last-success",
    )
    assert 'RESTIC_REPO="sftp:alias:/path"' in content
    assert 'RESTIC_PASS="/root/config/restic-passphrase"' in content
    assert 'ADMIN_MAIL="admin@example.com"' in content
    assert "auf host.example.com" in content
    assert "mkdir -p /var/lib/secure-base" in content
    assert "touch /var/lib/secure-base/restic-last-success" in content


def test_backup_script_content_never_contains_passphrase_value() -> None:
    """Die Funktion kennt die Passphrase nicht — sie kann nie im Inhalt stehen."""
    content = _backup_script_content(
        repo="sftp:alias:/path",
        admin_mail="admin@example.com",
        fqdn="host.example.com",
        passphrase_file="/root/config/restic-passphrase",  # noqa: S106 — nur Pfad
        sentinel_dir="/var/lib/secure-base",
        sentinel_file="/var/lib/secure-base/restic-last-success",
    )
    assert "correct-horse-battery-staple" not in content


def test_cron_content_schedules_daily_at_0230() -> None:
    """Die Cron-Datei ruft das Backup-Skript täglich um 02:30 als root auf."""
    content = _cron_content("/usr/local/sbin/host.example.com-backup.sh")
    assert "30 2 * * *  root  /usr/local/sbin/host.example.com-backup.sh" in content


# --- _check_command_succeeds ---


def test_check_command_succeeds_true_on_success() -> None:
    """Ein erfolgreicher Befehl liefert True."""
    mod = _make_restic()
    assert mod._check_command_succeeds(["/bin/true"], "Testbefehl") is True


def test_check_command_succeeds_false_on_failure() -> None:
    """Ein fehlschlagender Befehl liefert False."""
    mod = _make_restic()
    assert mod._check_command_succeeds(["/bin/false"], "Testbefehl") is False


# --- _check_file_mode ---


def test_check_file_mode_matches_expected(tmp_path: Path) -> None:
    """Stimmen die Dateirechte mit dem Soll überein, liefert _check_file_mode True."""
    mod = _make_restic()
    target = tmp_path / "secret"
    target.write_text("x", encoding="utf-8")
    os.chmod(target, 0o600)
    assert mod._check_file_mode(str(target), 0o600, "Testdatei") is True


def test_check_file_mode_mismatch_returns_false(tmp_path: Path) -> None:
    """Weichen die Dateirechte vom Soll ab, liefert _check_file_mode False."""
    mod = _make_restic()
    target = tmp_path / "secret"
    target.write_text("x", encoding="utf-8")
    os.chmod(target, 0o644)
    assert mod._check_file_mode(str(target), 0o600, "Testdatei") is False


def test_check_file_mode_missing_file_returns_false(tmp_path: Path) -> None:
    """Eine fehlende Datei liefert bei _check_file_mode False."""
    mod = _make_restic()
    assert mod._check_file_mode(str(tmp_path / "nichts"), 0o600, "Testdatei") is False


# --- _read_passphrase_file ---


def test_read_passphrase_file_strips_trailing_newline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_read_passphrase_file liefert den Inhalt ohne abschließenden Zeilenumbruch."""
    mod = _make_restic()
    passphrase_file = tmp_path / "restic-passphrase"
    passphrase_file.write_text("geheim\n", encoding="utf-8")
    monkeypatch.setattr(Restic, "PASSPHRASE_FILE", str(passphrase_file))
    assert mod._read_passphrase_file() == "geheim"


def test_read_passphrase_file_missing_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Passphrase-Datei, liefert _read_passphrase_file None."""
    mod = _make_restic()
    monkeypatch.setattr(Restic, "PASSPHRASE_FILE", str(tmp_path / "nichts"))
    assert mod._read_passphrase_file() is None


# --- _remove_if_exists ---


def test_remove_if_exists_removes_existing_file(tmp_path: Path) -> None:
    """Eine vorhandene Datei wird entfernt."""
    mod = _make_restic()
    target = tmp_path / "cronfile"
    target.write_text("x", encoding="utf-8")
    assert mod._remove_if_exists(str(target), "Testdatei") == 0
    assert not target.exists()


def test_remove_if_exists_missing_file_is_noop(tmp_path: Path) -> None:
    """Eine bereits fehlende Datei ist kein Fehler — idempotent."""
    mod = _make_restic()
    assert mod._remove_if_exists(str(tmp_path / "nichts"), "Testdatei") == 0


# --- _package_installed ---


def _make_executable(tmp_path: Path, content: str, name: str = "cmd.sh") -> str:
    """Legt ein ausführbares Shell-Script an und liefert dessen Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{content}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def test_package_installed_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Meldet dpkg-query 'install ok installed', liefert die Prüfung True."""
    mod = _make_restic()
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _make_executable(tmp_path, "echo 'install ok installed'"),
    )
    assert mod._package_installed() is True


def test_package_installed_false_on_other_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein anderer Paketstatus liefert False."""
    mod = _make_restic()
    monkeypatch.setattr(
        Restic,
        "DPKG_QUERY_BIN",
        _make_executable(tmp_path, "echo 'deinstall ok config-files'"),
    )
    assert mod._package_installed() is False


def test_package_installed_false_on_command_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scheitert dpkg-query (unbekanntes Paket), liefert False."""
    mod = _make_restic()
    monkeypatch.setattr(Restic, "DPKG_QUERY_BIN", "/bin/false")
    assert mod._package_installed() is False


# --- _check_sftp_reachable ---


def test_check_sftp_reachable_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein erfolgreicher sftp-Batch-Lauf liefert True."""
    mod = _make_restic()
    monkeypatch.setattr(Restic, "SFTP_BIN", "/bin/true")
    assert mod._check_sftp_reachable() is True


def test_check_sftp_reachable_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein fehlschlagender sftp-Batch-Lauf liefert False."""
    mod = _make_restic()
    monkeypatch.setattr(Restic, "SFTP_BIN", "/bin/false")
    assert mod._check_sftp_reachable() is False


# --- _check_repo_decryptable ---


def test_check_repo_decryptable_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein erfolgreiches 'restic cat config' liefert True."""
    mod = _make_restic()
    monkeypatch.setattr(Restic, "RESTIC_BIN", "/bin/true")
    assert mod._check_repo_decryptable(mod._repo_url()) is True


def test_check_repo_decryptable_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein fehlschlagendes 'restic cat config' liefert False."""
    mod = _make_restic()
    monkeypatch.setattr(Restic, "RESTIC_BIN", "/bin/false")
    assert mod._check_repo_decryptable(mod._repo_url()) is False


# --- _latest_snapshot_id ---


def test_latest_snapshot_id_returns_id_from_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein Snapshot in der JSON-Antwort liefert dessen id."""
    mod = _make_restic()
    monkeypatch.setattr(
        Restic,
        "RESTIC_BIN",
        _make_executable(tmp_path, "printf '%s' '[{\"id\": \"abc123def456\"}]'"),
    )
    assert mod._latest_snapshot_id(mod._repo_url()) == "abc123def456"


def test_latest_snapshot_id_returns_none_when_no_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine leere JSON-Liste (kein Snapshot) liefert None."""
    mod = _make_restic()
    monkeypatch.setattr(
        Restic, "RESTIC_BIN", _make_executable(tmp_path, "printf '%s' '[]'")
    )
    assert mod._latest_snapshot_id(mod._repo_url()) is None


def test_latest_snapshot_id_returns_none_on_invalid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine nicht als JSON lesbare Antwort liefert None statt eines Absturzes."""
    mod = _make_restic()
    monkeypatch.setattr(
        Restic, "RESTIC_BIN", _make_executable(tmp_path, "printf '%s' 'kaputt'")
    )
    assert mod._latest_snapshot_id(mod._repo_url()) is None


def test_latest_snapshot_id_returns_none_on_command_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scheitert der Befehl, liefert _latest_snapshot_id None."""
    mod = _make_restic()
    monkeypatch.setattr(Restic, "RESTIC_BIN", "/bin/false")
    assert mod._latest_snapshot_id(mod._repo_url()) is None


# --- _check_probe_restore ---


def test_check_probe_restore_true_when_no_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne Snapshot gilt der Probe-Restore als bestanden (kein Testfehler)."""
    mod = _make_restic()
    monkeypatch.setattr(
        Restic, "RESTIC_BIN", _make_executable(tmp_path, "printf '%s' '[]'")
    )
    assert mod._check_probe_restore(mod._repo_url()) is True


def test_check_probe_restore_true_on_successful_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein erfolgreicher Restore aus dem jüngsten Snapshot liefert True."""
    mod = _make_restic()
    monkeypatch.setattr(
        Restic,
        "RESTIC_BIN",
        _make_executable(
            tmp_path,
            'case "$5" in\n'
            '  snapshots) printf "%s" \'[{"id": "abc123"}]\' ;;\n'
            "  restore) exit 0 ;;\n"
            "esac",
        ),
    )
    assert mod._check_probe_restore(mod._repo_url()) is True


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, Pakete, Dateien, SFTP-Ziel und Cron."""
    values = {
        "fqdn": "server.example.com",
        "sftp_host_alias": "backup-alias",
        "sftp_path": "/backup/server",
    }
    section = Restic.doc(values)
    assert section.startswith("\n## Datensicherung\n\n")
    assert "**Pakete:** restic" in section
    assert f"`{Restic.PASSPHRASE_FILE}`" in section
    assert "Repo-Passphrase (0600 root:root)" in section
    assert f"`{Restic.BACKUP_SCRIPT_DIR}/server.example.com-backup.sh`" in section
    assert f"`{Restic.CRON_DIR}/server.example.com-backup`" in section
    assert "**SFTP-Ziel:** `backup-alias:/backup/server`" in section
    assert "**Timer/Cron:**" in section
    assert "> Hinweis:" in section


def test_doc_marks_missing_values_as_leer_default() -> None:
    """Fehlende Werte in values erscheinen als "(leer/Default)"."""
    section = Restic.doc({})
    assert "**SFTP-Ziel:** `(leer/Default):(leer/Default)`" in section
    assert "(leer/Default)-backup.sh" in section
    assert "(leer/Default)-backup" in section


def test_doc_never_leaks_restic_passphrase() -> None:
    """restic_passphrase erscheint weder als Name noch als Wert in doc()."""
    values = {
        "fqdn": "server.example.com",
        "sftp_host_alias": "backup-alias",
        "sftp_path": "/backup/server",
        "restic_passphrase": "GEHEIM-X",
    }
    section = Restic.doc(values)
    assert "GEHEIM-X" not in section
    assert "restic_passphrase" not in section


def test_check_probe_restore_false_on_failed_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Restore aus dem jüngsten Snapshot liefert False."""
    mod = _make_restic()
    monkeypatch.setattr(
        Restic,
        "RESTIC_BIN",
        _make_executable(
            tmp_path,
            'case "$5" in\n'
            '  snapshots) printf "%s" \'[{"id": "abc123"}]\' ;;\n'
            "  restore) exit 1 ;;\n"
            "esac",
        ),
    )
    assert mod._check_probe_restore(mod._repo_url()) is False
