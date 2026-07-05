"""Unit-Tests für lsb.modules.rkhunter."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from lsb.modules.rkhunter import Rkhunter
from pifos.errors import ModuleError
from pifos.ipc import LogLevel


def _make_rkhunter(fqdn: str, admin_mail: str) -> Rkhunter:
    """Baut ein Rkhunter-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Rkhunter(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.admin_mail = admin_mail
    return mod


# --- CONFIG ---


def test_rkhunter_config_declares_operation_fqdn_admin_mail() -> None:
    """CONFIG nennt genau operation, fqdn und admin_mail in dieser Reihenfolge."""
    assert Rkhunter.CONFIG == ["operation", "fqdn", "admin_mail"]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültiger Rechnername und gültige E-Mail-Adresse lösen keine Ausnahme aus."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    mod._validate()


def test_validate_rejects_invalid_fqdn_charset() -> None:
    """Ein Rechnername mit unzulässigen Zeichen erzeugt ModuleError."""
    mod = _make_rkhunter("server_example!com", "admin@example.com")
    with pytest.raises(ModuleError, match="Ungültiger Rechnername"):
        mod._validate()


def test_validate_rejects_fqdn_without_domain() -> None:
    """Ein Rechnername ohne Domain (kein Punkt) erzeugt ModuleError."""
    mod = _make_rkhunter("server", "admin@example.com")
    with pytest.raises(ModuleError, match="Kein Absender ableitbar"):
        mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Eine ungültige E-Mail-Adresse erzeugt ModuleError."""
    mod = _make_rkhunter("server.example.com", "keine-email-adresse")
    with pytest.raises(ModuleError, match="Ungültige E-Mail-Adresse"):
        mod._validate()


# --- Absender-Ableitung ---


def test_domain_returns_part_after_first_dot() -> None:
    """_domain liefert den Domain-Anteil nach dem ersten Punkt."""
    mod = _make_rkhunter("srv001.example.com", "admin@example.com")
    assert mod._domain() == "example.com"


def test_domain_empty_without_dot() -> None:
    """_domain liefert leer, wenn fqdn keinen Punkt enthält."""
    mod = _make_rkhunter("srv001", "admin@example.com")
    assert mod._domain() == ""


def test_mailfrom_builds_root_at_domain() -> None:
    """_mailfrom baut root@<domain> aus fqdn."""
    mod = _make_rkhunter("srv001.example.com", "admin@example.com")
    assert mod._mailfrom() == "root@example.com"


def test_mail_cmd_contains_mailfrom_and_literal_hostname_var() -> None:
    """_mail_cmd enthält den Absender und lässt ${HOST_NAME} literal stehen."""
    mod = _make_rkhunter("srv001.example.com", "admin@example.com")
    cmd = mod._mail_cmd()
    assert "mail -r root@example.com" in cmd
    assert "${HOST_NAME}" in cmd


# --- _file_has_line ---


def test_file_has_line_matches_existing_line(tmp_path: Path) -> None:
    """Eine vorhandene, passende Zeile liefert True."""
    target = tmp_path / "rkhunter"
    target.write_text('CRON_DAILY_RUN="yes"\n', encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._file_has_line(str(target), r'^CRON_DAILY_RUN="yes"$') is True


def test_file_has_line_missing_line_returns_false(tmp_path: Path) -> None:
    """Fehlt die passende Zeile, liefert _file_has_line False."""
    target = tmp_path / "rkhunter"
    target.write_text("# leer\n", encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._file_has_line(str(target), r'^CRON_DAILY_RUN="yes"$') is False


def test_file_has_line_missing_file_returns_false(tmp_path: Path) -> None:
    """Eine fehlende Datei liefert _file_has_line False."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._file_has_line(str(tmp_path / "fehlt"), r".*") is False


# --- _check_setting ---


def test_check_setting_matches_returns_true(tmp_path: Path) -> None:
    """Passt die Zeile auf das Muster, liefert _check_setting True."""
    target = tmp_path / "rkhunter"
    target.write_text('APT_AUTOGEN="yes"\n', encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._check_setting(str(target), r'^APT_AUTOGEN="yes"$', "apt-Hook") is True


def test_check_setting_mismatch_returns_false(tmp_path: Path) -> None:
    """Fehlt die Sollzeile, liefert _check_setting False."""
    target = tmp_path / "rkhunter"
    target.write_text('APT_AUTOGEN="no"\n', encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._check_setting(str(target), r'^APT_AUTOGEN="yes"$', "apt-Hook") is False


# --- _baseline_present / _check_baseline ---


def test_baseline_present_true_for_nonempty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine vorhandene, nicht-leere Baseline-Datei liefert True."""
    baseline = tmp_path / "rkhunter.dat"
    baseline.write_text("baseline-inhalt\n", encoding="utf-8")
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(baseline))
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._baseline_present() is True


def test_baseline_present_false_for_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine leere Baseline-Datei liefert False."""
    baseline = tmp_path / "rkhunter.dat"
    baseline.write_text("", encoding="utf-8")
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(baseline))
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._baseline_present() is False


def test_baseline_present_false_for_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine fehlende Baseline-Datei liefert False."""
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(tmp_path / "fehlt.dat"))
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._baseline_present() is False


def test_check_baseline_reports_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Baseline, liefert _check_baseline False."""
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(tmp_path / "fehlt.dat"))
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._check_baseline() is False
