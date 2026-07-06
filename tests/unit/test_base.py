"""Unit-Tests für secure_base.modules.base."""

from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.base import (
    SYSCTL_PARAMS,
    Base,
    _modprobe_content,
    _sysctl_content,
)


def _make_base(fqdn: str, timezone: str) -> Base:
    """Baut ein Base-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Base(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.timezone = timezone
    return mod


# --- CONFIG ---


def test_base_config_declares_operation_fqdn_timezone() -> None:
    """CONFIG nennt genau operation, fqdn und timezone in dieser Reihenfolge."""
    assert Base.CONFIG == ["operation", "fqdn", "timezone"]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültiger Rechnername und bekannte Zeitzone lösen keine Ausnahme aus."""
    mod = _make_base("server.example.com", "Europe/Berlin")
    mod._validate()


def test_validate_rejects_invalid_hostname() -> None:
    """Ein ungültiger Rechnername erzeugt ModuleError."""
    mod = _make_base("-invalid-.example.com", "Europe/Berlin")
    with pytest.raises(ModuleError, match="Ungültiger Rechnername"):
        mod._validate()


def test_validate_rejects_unknown_timezone() -> None:
    """Eine unbekannte Zeitzone erzeugt ModuleError."""
    mod = _make_base("server.example.com", "Nirgendwo/Erfunden")
    with pytest.raises(ModuleError, match="Unbekannte Zeitzone"):
        mod._validate()


# --- Inhaltsfunktionen ---


def test_sysctl_content_contains_all_params() -> None:
    """_sysctl_content enthält jeden Schlüssel/Wert aus SYSCTL_PARAMS."""
    content = _sysctl_content()
    for key, value in SYSCTL_PARAMS:
        assert f"{key} = {value}" in content


def test_modprobe_content_blacklists_usb_storage() -> None:
    """_modprobe_content sperrt usb-storage per install und blacklist."""
    content = _modprobe_content()
    assert "install usb-storage /bin/true" in content
    assert "blacklist usb-storage" in content


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_base("server.example.com", "Europe/Berlin")
    assert mod._check_value(["/bin/echo", "yes"], "yes", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_base("server.example.com", "Europe/Berlin")
    assert mod._check_value(["/bin/echo", "nein"], "ja", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_base("server.example.com", "Europe/Berlin")
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False
