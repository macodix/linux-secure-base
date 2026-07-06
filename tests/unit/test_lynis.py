"""Unit-Tests für secure_base.modules.lynis."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.lynis import Lynis, _cron_content, _pruef_script_content


def _make_lynis(schedule: str) -> Lynis:
    """Baut ein Lynis-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Lynis(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.lynis_schedule = schedule
    return mod


# --- CONFIG ---


def test_lynis_config_declares_operation_and_schedule() -> None:
    """CONFIG nennt genau operation und lynis_schedule in dieser Reihenfolge."""
    assert Lynis.CONFIG == ["operation", "lynis_schedule"]


# --- _validate ---


@pytest.mark.parametrize(
    "schedule",
    [
        "0 4 1 * *",
        "* * * * *",
        "*/15 * * * *",
        "0,30 * * * *",
        "0 0 1-15 * 1-5",
        "0-10/5 * * * *",
    ],
)
def test_validate_accepts_valid_schedules(schedule: str) -> None:
    """Gültige Cron-Zeitpläne lösen keine Ausnahme aus."""
    mod = _make_lynis(schedule)
    mod._validate()


def test_validate_rejects_wrong_field_count() -> None:
    """Ein Zeitplan mit zu wenigen Feldern erzeugt ModuleError."""
    mod = _make_lynis("0 4 1 *")
    with pytest.raises(ModuleError, match="braucht 5 Felder"):
        mod._validate()


@pytest.mark.parametrize(
    "schedule",
    [
        "1-2-3 * * * *",
        "1,,2 * * * *",
        "*/ * * * *",
        "a * * * *",
        "0 4 1 * *,,",
    ],
)
def test_validate_rejects_malformed_field(schedule: str) -> None:
    """Ein strukturell ungültiges Cron-Feld erzeugt ModuleError."""
    mod = _make_lynis(schedule)
    with pytest.raises(ModuleError, match="Ungültiges Cron-Feld"):
        mod._validate()


# --- Inhaltsfunktionen ---


def test_pruef_script_content_references_berichte_dir_and_lynis() -> None:
    """Das Prüfskript verweist auf das Berichteverzeichnis und ruft lynis auf."""
    content = _pruef_script_content("/var/lib/secure-base/haertung")
    assert 'BERICHTE="/var/lib/secure-base/haertung"' in content
    assert "lynis audit system --quiet --no-colors" in content


def test_cron_content_contains_schedule_and_script() -> None:
    """Der Cron-Eintrag enthält Zeitplan und Prüfskript-Aufruf."""
    content = _cron_content("0 4 1 * *", "/usr/local/sbin/pruef.sh")
    assert "0 4 1 * *  root  /usr/local/sbin/pruef.sh" in content


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_lynis("0 4 1 * *")
    assert mod._check_value(["/bin/echo", "yes"], "yes", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_lynis("0 4 1 * *")
    assert mod._check_value(["/bin/echo", "nein"], "ja", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_lynis("0 4 1 * *")
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False


# --- _check_mode ---


def test_check_mode_matches_expected(tmp_path: Path) -> None:
    """Stimmen die Rechte überein, liefert _check_mode True."""
    mod = _make_lynis("0 4 1 * *")
    target = tmp_path / "datei"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o640)
    assert mod._check_mode(str(target), 0o640, "Testdatei") is True


def test_check_mode_mismatch_returns_false(tmp_path: Path) -> None:
    """Weichen die Rechte ab, liefert _check_mode False."""
    mod = _make_lynis("0 4 1 * *")
    target = tmp_path / "datei"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o600)
    assert mod._check_mode(str(target), 0o640, "Testdatei") is False


def test_check_mode_missing_path_returns_false(tmp_path: Path) -> None:
    """Fehlt der Pfad, liefert _check_mode False."""
    mod = _make_lynis("0 4 1 * *")
    assert mod._check_mode(str(tmp_path / "fehlt"), 0o640, "Testdatei") is False


# --- _check_file_content ---


def test_check_file_content_matches_expected(tmp_path: Path) -> None:
    """Stimmt der Inhalt überein, liefert _check_file_content True."""
    mod = _make_lynis("0 4 1 * *")
    target = tmp_path / "datei"
    target.write_text("Soll-Inhalt\n", encoding="utf-8")
    assert mod._check_file_content(str(target), "Soll-Inhalt\n", "Testdatei") is True


def test_check_file_content_mismatch_returns_false(tmp_path: Path) -> None:
    """Weicht der Inhalt ab, liefert _check_file_content False."""
    mod = _make_lynis("0 4 1 * *")
    target = tmp_path / "datei"
    target.write_text("Ist-Inhalt\n", encoding="utf-8")
    assert mod._check_file_content(str(target), "Soll-Inhalt\n", "Testdatei") is False


def test_check_file_content_missing_path_returns_false(tmp_path: Path) -> None:
    """Fehlt der Pfad, liefert _check_file_content False."""
    mod = _make_lynis("0 4 1 * *")
    result = mod._check_file_content(str(tmp_path / "fehlt"), "egal", "Testdatei")
    assert result is False


# --- _delete_if_exists ---


def test_delete_if_exists_removes_existing_file(tmp_path: Path) -> None:
    """Existiert die Datei, liefert _delete_if_exists 0 und löscht sie."""
    mod = _make_lynis("0 4 1 * *")
    target = tmp_path / "datei"
    target.write_text("x", encoding="utf-8")
    assert mod._delete_if_exists(str(target), "Testdatei") == 0
    assert not target.exists()


def test_delete_if_exists_missing_path_is_idempotent(tmp_path: Path) -> None:
    """Fehlt der Pfad bereits, liefert _delete_if_exists 0 ohne Fehler."""
    mod = _make_lynis("0 4 1 * *")
    assert mod._delete_if_exists(str(tmp_path / "fehlt"), "Testdatei") == 0


# --- _check_lynis_version ---


def test_check_lynis_version_reads_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Liest der Aufruf eine Version, liefert _check_lynis_version True."""
    mod = _make_lynis("0 4 1 * *")
    monkeypatch.setattr(Lynis, "LYNIS_BIN", "/bin/echo")
    assert mod._check_lynis_version() is True


def test_check_lynis_version_command_failure_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scheitert der Aufruf, liefert _check_lynis_version False."""
    mod = _make_lynis("0 4 1 * *")
    monkeypatch.setattr(Lynis, "LYNIS_BIN", "/bin/false")
    assert mod._check_lynis_version() is False


# --- _check_pruef_script_selftest ---


def test_check_pruef_script_selftest_valid_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ausführbares, syntaktisch gültiges Skript liefert True."""
    mod = _make_lynis("0 4 1 * *")
    script = tmp_path / "pruef.sh"
    script.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    script.chmod(0o700)
    monkeypatch.setattr(Lynis, "PRUEF_SCRIPT", str(script))
    monkeypatch.setattr(Lynis, "BASH_BIN", "/bin/bash")
    assert mod._check_pruef_script_selftest() is True


def test_check_pruef_script_selftest_missing_script_returns_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt das Prüfskript, liefert _check_pruef_script_selftest False."""
    mod = _make_lynis("0 4 1 * *")
    monkeypatch.setattr(Lynis, "PRUEF_SCRIPT", str(tmp_path / "fehlt.sh"))
    assert mod._check_pruef_script_selftest() is False


def test_check_pruef_script_selftest_not_executable_returns_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist das Prüfskript nicht ausführbar, liefert die Prüfung False."""
    mod = _make_lynis("0 4 1 * *")
    script = tmp_path / "pruef.sh"
    script.write_text("#!/bin/bash\necho ok\n", encoding="utf-8")
    script.chmod(0o600)
    monkeypatch.setattr(Lynis, "PRUEF_SCRIPT", str(script))
    assert mod._check_pruef_script_selftest() is False


def test_check_pruef_script_selftest_syntax_error_returns_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Enthält das Prüfskript einen Syntaxfehler, liefert die Prüfung False."""
    mod = _make_lynis("0 4 1 * *")
    script = tmp_path / "pruef.sh"
    script.write_text("#!/bin/bash\nif [ 1 -eq 1\n", encoding="utf-8")
    script.chmod(0o700)
    monkeypatch.setattr(Lynis, "PRUEF_SCRIPT", str(script))
    monkeypatch.setattr(Lynis, "BASH_BIN", "/bin/bash")
    assert mod._check_pruef_script_selftest() is False
