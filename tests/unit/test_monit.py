"""Unit-Tests für secure_base.modules.monit."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.monit import (
    CHECK_CONTENT,
    KNOWN_CHECKS,
    MONITRC_MARKERS,
    Monit,
    _httpd_block,
    _mail_format_block,
)


def _make_monit(
    admin_mail: str = "admin@example.com",
    monit_mail_from: str = "monit@example.com",
    monit_checks: str = "system,rootfs",
) -> Monit:
    """Baut ein Monit-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Monit(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = admin_mail
    mod.monit_mail_from = monit_mail_from
    mod.monit_checks = monit_checks
    return mod


# --- CONFIG ---


def test_monit_config_declares_expected_keys() -> None:
    """CONFIG nennt operation, admin_mail, monit_mail_from und monit_checks."""
    assert Monit.CONFIG == [
        "operation",
        "admin_mail",
        "monit_mail_from",
        "monit_checks",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige E-Mail-Adressen und bekannte Checks lösen keine Ausnahme aus."""
    mod = _make_monit()
    mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Eine ungültige admin_mail erzeugt ModuleError."""
    mod = _make_monit(admin_mail="ungueltig")
    with pytest.raises(ModuleError, match="Ungültige admin_mail"):
        mod._validate()


def test_validate_rejects_invalid_monit_mail_from() -> None:
    """Eine ungültige monit_mail_from erzeugt ModuleError."""
    mod = _make_monit(monit_mail_from="ungueltig")
    with pytest.raises(ModuleError, match="Ungültige monit_mail_from"):
        mod._validate()


def test_validate_rejects_empty_checks() -> None:
    """Leere monit_checks erzeugt ModuleError."""
    mod = _make_monit(monit_checks="")
    with pytest.raises(ModuleError, match="monit_checks ist leer"):
        mod._validate()


def test_validate_rejects_unknown_check() -> None:
    """Ein unbekannter Check-Name erzeugt ModuleError."""
    mod = _make_monit(monit_checks="system,unbekannt")
    with pytest.raises(ModuleError, match="unbekannte Werte"):
        mod._validate()


# --- _parsed_checks ---


def test_parsed_checks_strips_and_splits() -> None:
    """_parsed_checks trennt bei Komma und entfernt umgebende Leerzeichen."""
    mod = _make_monit(monit_checks=" system , rootfs ,sshd")
    assert mod._parsed_checks() == ["system", "rootfs", "sshd"]


def test_parsed_checks_ignores_empty_entries() -> None:
    """Leere Einträge (doppeltes Komma) werden übersprungen."""
    mod = _make_monit(monit_checks="system,,rootfs")
    assert mod._parsed_checks() == ["system", "rootfs"]


# --- KNOWN_CHECKS / CHECK_CONTENT ---


def test_known_checks_has_nine_entries() -> None:
    """KNOWN_CHECKS enthält alle neun Checks aus dem Bash-Original."""
    expected = {
        "system",
        "rootfs",
        "sshd",
        "postfix",
        "fail2ban",
        "ufw",
        "cron",
        "rkhunter",
        "restic",
    }
    assert expected == KNOWN_CHECKS


def test_check_content_covers_all_known_checks() -> None:
    """CHECK_CONTENT enthält für jeden bekannten Check einen Eintrag."""
    assert set(CHECK_CONTENT) == KNOWN_CHECKS


def test_check_content_system_contains_load_and_memory_checks() -> None:
    """Der system-Check prüft loadavg, Speicher und CPU."""
    content = CHECK_CONTENT["system"]
    assert "check system $HOST" in content
    assert "loadavg (1min) > 4" in content
    assert "memory usage > 90 %" in content


def test_check_content_restic_checks_last_success_marker() -> None:
    """Der restic-Check prüft die mtime der Erfolgsdatei."""
    content = CHECK_CONTENT["restic"]
    assert "/var/lib/secure-base/restic-last-success" in content
    assert "mtime > 26 hours" in content


# --- Inhaltsfunktionen ---


def test_mail_format_block_contains_from_address() -> None:
    """_mail_format_block setzt die Absenderadresse in das from-Feld."""
    block = _mail_format_block("monit@example.com")
    assert "set mail-format {" in block
    assert "from:    monit@example.com" in block
    assert block.endswith("}")


def test_httpd_block_restricts_to_localhost() -> None:
    """_httpd_block bindet den Webserver an localhost."""
    block = _httpd_block()
    assert "set httpd port 2812 and" in block
    assert "use address localhost" in block
    assert "allow localhost" in block


def test_monitrc_markers_has_six_entries() -> None:
    """MONITRC_MARKERS deckt alle sechs monitrc-Eingriffe ab."""
    assert len(MONITRC_MARKERS) == 6
    keys = {key_label for _, key_label in MONITRC_MARKERS}
    assert keys == {
        "set daemon",
        "set log",
        "set mailserver",
        "set alert",
        "set mail-format",
        "set httpd",
    }


# --- _monitrc_edits ---


def test_monitrc_edits_use_configured_admin_mail_and_sender() -> None:
    """_monitrc_edits setzt admin_mail und monit_mail_from in die Blöcke ein."""
    mod = _make_monit(
        admin_mail="root@example.com", monit_mail_from="alarm@example.com"
    )
    edits = mod._monitrc_edits()
    by_marker = {marker: block for _, marker, block in edits}
    assert by_marker["monit-alert"] == "set alert root@example.com"
    assert "from:    alarm@example.com" in by_marker["monit-mail-format"]


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_monit()
    assert mod._check_value(["/bin/echo", "active"], "active", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_monit()
    assert mod._check_value(["/bin/echo", "inactive"], "active", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_monit()
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False


# --- _check_marker ---


def test_check_marker_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ist die Begin-Markerzeile vorhanden, liefert _check_marker True."""
    monitrc = tmp_path / "monitrc"
    monitrc.write_text("# BEGIN monit-daemon\nset daemon 60\n# END monit-daemon\n")
    monkeypatch.setattr(Monit, "MONITRC", str(monitrc))
    mod = _make_monit()
    assert mod._check_marker("monit-daemon", "set daemon") is True


def test_check_marker_missing_file_returns_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Datei, liefert _check_marker False."""
    monkeypatch.setattr(Monit, "MONITRC", str(tmp_path / "nicht-vorhanden"))
    mod = _make_monit()
    assert mod._check_marker("monit-daemon", "set daemon") is False


# --- _check_file_mode ---


def test_check_file_mode_matches(tmp_path: Path) -> None:
    """Stimmen Zugriffsrechte überein, liefert _check_file_mode True."""
    check_file = tmp_path / "system"
    check_file.write_text("check system $HOST\n")
    check_file.chmod(0o644)
    mod = _make_monit()
    assert mod._check_file_mode(str(check_file), 0o644, "Check system") is True


def test_check_file_mode_mismatch_returns_false(tmp_path: Path) -> None:
    """Weichen die Zugriffsrechte ab, liefert _check_file_mode False."""
    check_file = tmp_path / "system"
    check_file.write_text("check system $HOST\n")
    check_file.chmod(0o640)
    mod = _make_monit()
    assert mod._check_file_mode(str(check_file), 0o644, "Check system") is False


def test_check_file_mode_missing_returns_false(tmp_path: Path) -> None:
    """Fehlt die Datei, liefert _check_file_mode False."""
    check_file = tmp_path / "fehlt"
    mod = _make_monit()
    assert mod._check_file_mode(str(check_file), 0o644, "Check fehlt") is False
