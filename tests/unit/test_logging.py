"""Unit-Tests für lsb.modules.logging."""

import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from lsb.modules.logging import (
    AUDIT_RULES,
    Logging,
    _audit_rules_content,
    _logrotate_content,
    _sudolog_content,
)
from pifos.errors import ModuleError
from pifos.ipc import LogLevel


def _make_logging(
    fqdn: str = "server.example.com",
    admin_mail: str = "admin@example.com",
    journald_max_use: str = "1G",
    journald_max_retention: str = "3month",
) -> Logging:
    """Baut ein Logging-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Logging(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.admin_mail = admin_mail
    mod.journald_max_use = journald_max_use
    mod.journald_max_retention = journald_max_retention
    return mod


# --- CONFIG ---


def test_logging_config_declares_expected_keys() -> None:
    """CONFIG nennt operation, fqdn, admin_mail und die journald-Schlüssel."""
    assert Logging.CONFIG == [
        "operation",
        "fqdn",
        "admin_mail",
        "journald_max_use",
        "journald_max_retention",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige Werte lösen keine Ausnahme aus."""
    mod = _make_logging()
    mod._validate()


def test_validate_rejects_invalid_fqdn_chars() -> None:
    """fqdn mit unzulässigen Zeichen erzeugt ModuleError."""
    mod = _make_logging(fqdn="server_example!.com")
    with pytest.raises(ModuleError, match="unzulässige Zeichen"):
        mod._validate()


def test_validate_rejects_fqdn_without_domain() -> None:
    """fqdn ohne Punkt lässt keine Domain ableiten und erzeugt ModuleError."""
    mod = _make_logging(fqdn="server")
    with pytest.raises(ModuleError, match="keine Domain ableitbar"):
        mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Ein ungültiges admin_mail erzeugt ModuleError."""
    mod = _make_logging(admin_mail="ungueltig")
    with pytest.raises(ModuleError, match="Ungültige admin_mail"):
        mod._validate()


def test_validate_rejects_invalid_journald_max_use() -> None:
    """Ein journald_max_use außerhalb des Größenmusters erzeugt ModuleError."""
    mod = _make_logging(journald_max_use="viel")
    with pytest.raises(ModuleError, match="Ungültiges journald_max_use"):
        mod._validate()


def test_validate_rejects_invalid_journald_max_retention() -> None:
    """Ein journald_max_retention außerhalb des Zeitmusters erzeugt ModuleError."""
    mod = _make_logging(journald_max_retention="lange")
    with pytest.raises(ModuleError, match="Ungültiges journald_max_retention"):
        mod._validate()


# --- _mailfrom ---


def test_mailfrom_derives_domain_from_fqdn() -> None:
    """_mailfrom leitet root@<domain> aus einem mehrteiligen fqdn ab."""
    mod = _make_logging(fqdn="srv001.example.com")
    assert mod._mailfrom() == "root@example.com"


def test_mailfrom_empty_without_domain() -> None:
    """_mailfrom liefert leer, wenn fqdn keinen Punkt enthält."""
    mod = _make_logging()
    mod.fqdn = "srv001"
    assert mod._mailfrom() == ""


# --- Inhaltsfunktionen ---


def test_audit_rules_content_contains_all_rules() -> None:
    """_audit_rules_content enthält jede Regel aus AUDIT_RULES als eigene Zeile."""
    content = _audit_rules_content()
    lines = content.splitlines()
    assert lines == list(AUDIT_RULES)


def test_audit_rules_content_ends_with_immutable_rule() -> None:
    """Die Immutable-Regel -e 2 steht als letzte Regel."""
    assert AUDIT_RULES[-1] == "-e 2"


def test_logrotate_content_contains_expected_directives() -> None:
    """_logrotate_content enthält die logrotate-Direktiven für das Logfile."""
    content = _logrotate_content()
    assert "/var/log/secure-base/secure-base.log {" in content
    assert "weekly" in content
    assert "size 5M" in content
    assert "rotate 8" in content


def test_sudolog_content_sets_logfile_directive() -> None:
    """_sudolog_content setzt die sudo-Logdatei-Direktive."""
    assert _sudolog_content() == 'Defaults logfile="/var/log/sudo.log"\n'


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_logging()
    assert mod._check_value(["/bin/echo", "aktiv"], "aktiv", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_logging()
    assert mod._check_value(["/bin/echo", "nein"], "ja", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_logging()
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False


# --- _check_file_line ---


def test_check_file_line_present_returns_true(tmp_path: Path) -> None:
    """Eine vorhandene Zeile liefert True."""
    path = tmp_path / "datei.conf"
    path.write_text("Storage=persistent\nAndereZeile\n", encoding="utf-8")
    mod = _make_logging()
    assert mod._check_file_line(str(path), "Storage=persistent", "Testwert") is True


def test_check_file_line_missing_returns_false(tmp_path: Path) -> None:
    """Eine fehlende Zeile liefert False."""
    path = tmp_path / "datei.conf"
    path.write_text("AndereZeile\n", encoding="utf-8")
    mod = _make_logging()
    assert mod._check_file_line(str(path), "Storage=persistent", "Testwert") is False


def test_check_file_line_missing_file_returns_false(tmp_path: Path) -> None:
    """Eine nicht existierende Datei liefert False."""
    mod = _make_logging()
    assert (
        mod._check_file_line(str(tmp_path / "fehlt.conf"), "irrelevant", "Testwert")
        is False
    )


# --- _check_file_exists / _check_dir_exists ---


def test_check_file_exists_true_for_file(tmp_path: Path) -> None:
    """Eine vorhandene Datei liefert True."""
    path = tmp_path / "datei.conf"
    path.write_text("Inhalt\n", encoding="utf-8")
    mod = _make_logging()
    assert mod._check_file_exists(str(path), "Testwert") is True


def test_check_file_exists_false_for_missing(tmp_path: Path) -> None:
    """Eine fehlende Datei liefert False."""
    mod = _make_logging()
    assert mod._check_file_exists(str(tmp_path / "fehlt.conf"), "Testwert") is False


def test_check_dir_exists_true_for_dir(tmp_path: Path) -> None:
    """Ein vorhandenes Verzeichnis liefert True."""
    mod = _make_logging()
    assert mod._check_dir_exists(str(tmp_path), "Testwert") is True


def test_check_dir_exists_false_for_missing(tmp_path: Path) -> None:
    """Ein fehlendes Verzeichnis liefert False."""
    mod = _make_logging()
    assert mod._check_dir_exists(str(tmp_path / "fehlt"), "Testwert") is False


# --- _check_installed ---


def _make_fake_dpkg(tmp_path: Path, output: str, returncode: int = 0) -> str:
    """Baut ein ausführbares Fake-dpkg, das output ausgibt und returncode liefert."""
    script = tmp_path / "fake-dpkg"
    script.write_text(f"#!/bin/sh\nprintf '%s' {output!r}\nexit {returncode}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_check_installed_true_for_installed_status(tmp_path: Path) -> None:
    """Ein Status "install ok installed" liefert True."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "Status: install ok installed\n")
    try:
        assert mod._check_installed("logwatch", "Testwert") is True
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"


def test_check_installed_false_for_other_status(tmp_path: Path) -> None:
    """Ein abweichender Status liefert False."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "Status: deinstall ok config-files\n")
    try:
        assert mod._check_installed("logwatch", "Testwert") is False
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"


def test_check_installed_false_on_command_failure(tmp_path: Path) -> None:
    """Ein fehlschlagender Befehl liefert False."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "unbekanntes Paket\n", returncode=1)
    try:
        assert mod._check_installed("logwatch", "Testwert") is False
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"
