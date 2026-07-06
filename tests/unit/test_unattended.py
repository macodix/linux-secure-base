"""Unit-Tests für secure_base.modules.unattended."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.unattended import (
    Unattended,
    _periodic_conf_content,
    _timer_override_content,
    _uu_conf_content,
)


def _make_unattended(
    admin_mail: str = "admin@example.com",
    auto_reboot: str = "yes",
    auto_reboot_time: str = "23:45",
    apt_daily_time: str = "23:15",
    apt_daily_upgrade_time: str = "23:30",
) -> Unattended:
    """Baut ein Unattended-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Unattended(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = admin_mail
    mod.auto_reboot = auto_reboot
    mod.auto_reboot_time = auto_reboot_time
    mod.apt_daily_time = apt_daily_time
    mod.apt_daily_upgrade_time = apt_daily_upgrade_time
    return mod


# --- CONFIG ---


def test_unattended_config_declares_all_keys() -> None:
    """CONFIG nennt genau die sechs benötigten Schlüssel in dieser Reihenfolge."""
    assert Unattended.CONFIG == [
        "operation",
        "admin_mail",
        "auto_reboot",
        "auto_reboot_time",
        "apt_daily_time",
        "apt_daily_upgrade_time",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige Werte in korrekter Zeit-Reihenfolge lösen keine Ausnahme aus."""
    mod = _make_unattended()
    mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Eine ungültige admin_mail-Adresse erzeugt ModuleError."""
    mod = _make_unattended(admin_mail="keine-mail-adresse")
    with pytest.raises(ModuleError, match="Ungültige admin_mail-Adresse"):
        mod._validate()


def test_validate_rejects_invalid_auto_reboot() -> None:
    """Ein auto_reboot-Wert außerhalb yes/no erzeugt ModuleError."""
    mod = _make_unattended(auto_reboot="vielleicht")
    with pytest.raises(ModuleError, match="auto_reboot muss"):
        mod._validate()


def test_validate_rejects_invalid_time_format() -> None:
    """Eine Uhrzeit außerhalb HH:MM erzeugt ModuleError."""
    mod = _make_unattended(auto_reboot_time="25:99")
    with pytest.raises(ModuleError, match="auto_reboot_time ist keine gültige"):
        mod._validate()


def test_validate_warns_on_time_order() -> None:
    """Uhrzeiten außer der Reihe lösen eine WARN-Meldung, keine Ausnahme, aus."""
    mod = _make_unattended(
        apt_daily_time="23:45", apt_daily_upgrade_time="23:15", auto_reboot_time="23:30"
    )
    mod._validate()
    conn = mod._conn
    assert isinstance(conn, MagicMock)
    levels = [call.args[0].level for call in conn.send.call_args_list]
    assert LogLevel.WARN in levels


# --- Inhaltsfunktionen ---


def test_uu_conf_content_contains_allowed_origins_and_directives() -> None:
    """_uu_conf_content enthält Allowed-Origins-Block und alle vier Direktiven."""
    content = _uu_conf_content("admin@example.com", "true", "23:45")
    assert "${distro_id}:${distro_codename}" in content
    assert "${distro_id}:${distro_codename}-security" in content
    assert "${distro_id}:${distro_codename}-updates" in content
    assert 'Unattended-Upgrade::Automatic-Reboot "true";' in content
    assert 'Unattended-Upgrade::Automatic-Reboot-Time "23:45";' in content
    assert 'Unattended-Upgrade::Mail "admin@example.com";' in content
    assert 'Unattended-Upgrade::MailReport "only-on-error";' in content


def test_periodic_conf_content_contains_all_directives() -> None:
    """_periodic_conf_content enthält alle drei Periodic-Direktiven."""
    content = _periodic_conf_content()
    assert 'APT::Periodic::Update-Package-Lists "1";' in content
    assert 'APT::Periodic::Unattended-Upgrade "1";' in content
    assert 'APT::Periodic::AutocleanInterval "7";' in content


def test_timer_override_content_pins_oncalendar() -> None:
    """_timer_override_content pinnt OnCalendar auf die übergebene Uhrzeit."""
    content = _timer_override_content("23:15")
    assert "OnCalendar=*-*-* 23:15:00" in content
    assert "RandomizedDelaySec=0" in content


# --- _check_command_succeeds ---


def test_check_command_succeeds_true() -> None:
    """Ein erfolgreicher Befehl liefert True."""
    mod = _make_unattended()
    assert mod._check_command_succeeds(["/bin/true"], "Testwert") is True


def test_check_command_succeeds_false() -> None:
    """Ein scheiternder Befehl liefert False."""
    mod = _make_unattended()
    assert mod._check_command_succeeds(["/bin/false"], "Testwert") is False


# --- _check_file_content ---


def test_check_file_content_matches(tmp_path: Path) -> None:
    """Stimmt der Dateiinhalt mit dem Soll überein, liefert die Prüfung True."""
    mod = _make_unattended()
    target = tmp_path / "datei.conf"
    target.write_text("soll-inhalt\n")
    assert mod._check_file_content(str(target), "soll-inhalt\n", "Testwert") is True


def test_check_file_content_mismatch(tmp_path: Path) -> None:
    """Weicht der Dateiinhalt vom Soll ab, liefert die Prüfung False."""
    mod = _make_unattended()
    target = tmp_path / "datei.conf"
    target.write_text("ist-inhalt\n")
    assert mod._check_file_content(str(target), "soll-inhalt\n", "Testwert") is False


def test_check_file_content_missing_file_returns_false(tmp_path: Path) -> None:
    """Fehlt die Datei, liefert die Prüfung False."""
    mod = _make_unattended()
    target = tmp_path / "fehlt.conf"
    assert mod._check_file_content(str(target), "soll-inhalt\n", "Testwert") is False
