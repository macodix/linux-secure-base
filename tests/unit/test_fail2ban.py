"""Unit-Tests für lsb.modules.fail2ban."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from lsb.modules.fail2ban import (
    IGNOREIP_LOOPBACK,
    Fail2ban,
    _effective_ignoreip,
    _parse_ignoreip,
)
from pifos.errors import ModuleError
from pifos.ipc import LogLevel


def _make_fail2ban(ignoreip: str = "") -> Fail2ban:
    """Baut ein Fail2ban-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Fail2ban(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.ignoreip = ignoreip
    return mod


def _make_executable(tmp_path: Path, content: str) -> str:
    """Legt ein ausführbares Shell-Script an und liefert dessen Pfad."""
    script = tmp_path / "cmd.sh"
    script.write_text(f"#!/bin/sh\n{content}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


# --- CONFIG ---


def test_fail2ban_config_declares_operation_ignoreip() -> None:
    """CONFIG nennt genau operation und ignoreip in dieser Reihenfolge."""
    assert Fail2ban.CONFIG == ["operation", "ignoreip"]


# --- _parse_ignoreip / _effective_ignoreip ---


def test_parse_ignoreip_splits_trims_and_drops_empty() -> None:
    """_parse_ignoreip zerlegt, trimmt und verwirft leere Tokens."""
    assert _parse_ignoreip(" 203.0.113.7 , 198.51.100.0/24 ,, ") == [
        "203.0.113.7",
        "198.51.100.0/24",
    ]


def test_parse_ignoreip_empty_string_yields_empty_list() -> None:
    """Ein leerer Konfigurationswert liefert eine leere Tokenliste."""
    assert _parse_ignoreip("") == []


def test_effective_ignoreip_without_tokens_is_loopback_only() -> None:
    """Ohne zusätzliche Tokens besteht der Wert nur aus den Loopback-Defaults."""
    assert _effective_ignoreip([]) == " ".join(IGNOREIP_LOOPBACK)


def test_effective_ignoreip_appends_tokens_after_loopback() -> None:
    """Zusätzliche Tokens stehen hinter den Loopback-Defaults."""
    result = _effective_ignoreip(["203.0.113.7"])
    assert result == " ".join([*IGNOREIP_LOOPBACK, "203.0.113.7"])


# --- _validate ---


def test_validate_accepts_empty_ignoreip() -> None:
    """Ein leerer ignoreip-Wert löst keine Ausnahme aus."""
    mod = _make_fail2ban("")
    mod._validate()


def test_validate_accepts_ipv4_ipv6_and_cidr_tokens() -> None:
    """IPv4-, IPv6- und CIDR-Tokens werden akzeptiert."""
    mod = _make_fail2ban("203.0.113.7, 198.51.100.0/24, 2001:db8::1")
    mod._validate()


def test_validate_rejects_invalid_token() -> None:
    """Ein ungültiges Token erzeugt ModuleError mit dem Token im Text."""
    mod = _make_fail2ban("nicht-plausibel")
    with pytest.raises(ModuleError, match="nicht-plausibel"):
        mod._validate()


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_fail2ban()
    assert mod._check_value(["/bin/echo", "active"], "active", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_fail2ban()
    assert mod._check_value(["/bin/echo", "inactive"], "active", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_fail2ban()
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False


# --- _check_command_ok ---


def test_check_command_ok_success() -> None:
    """Ein erfolgreicher Befehl liefert True."""
    mod = _make_fail2ban()
    assert mod._check_command_ok(["/bin/true"], "Testbefehl") is True


def test_check_command_ok_failure() -> None:
    """Ein fehlschlagender Befehl liefert False."""
    mod = _make_fail2ban()
    assert mod._check_command_ok(["/bin/false"], "Testbefehl") is False


# --- _check_package_installed ---


def test_check_package_installed_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Meldet dpkg-query 'install ok installed', liefert die Prüfung True."""
    mod = _make_fail2ban()
    monkeypatch.setattr(
        Fail2ban,
        "DPKG_QUERY",
        _make_executable(tmp_path, "echo 'install ok installed'"),
    )
    assert mod._check_package_installed() is True


def test_check_package_installed_false_on_other_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein anderer Paketstatus liefert False."""
    mod = _make_fail2ban()
    monkeypatch.setattr(
        Fail2ban,
        "DPKG_QUERY",
        _make_executable(tmp_path, "echo 'deinstall ok config-files'"),
    )
    assert mod._check_package_installed() is False


def test_check_package_installed_false_on_command_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert dpkg-query, liefert die Prüfung False."""
    mod = _make_fail2ban()
    monkeypatch.setattr(Fail2ban, "DPKG_QUERY", _make_executable(tmp_path, "exit 1"))
    assert mod._check_package_installed() is False


# --- _check_jail_local_exists ---


def test_check_jail_local_exists_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine vorhandene jail.local liefert True."""
    mod = _make_fail2ban()
    jail_local = tmp_path / "jail.local"
    jail_local.write_text("", encoding="utf-8")
    monkeypatch.setattr(Fail2ban, "JAIL_LOCAL", str(jail_local))
    assert mod._check_jail_local_exists() is True


def test_check_jail_local_exists_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine fehlende jail.local liefert False."""
    mod = _make_fail2ban()
    monkeypatch.setattr(Fail2ban, "JAIL_LOCAL", str(tmp_path / "fehlt.local"))
    assert mod._check_jail_local_exists() is False


# --- _check_ignoreip_in_file ---


def test_check_ignoreip_in_file_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine passende ignoreip-Zeile liefert True."""
    mod = _make_fail2ban()
    jail_local = tmp_path / "jail.local"
    tokens = ["203.0.113.7"]
    jail_local.write_text(
        f"[sshd]\nignoreip = {_effective_ignoreip(tokens)}\nenabled = true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(Fail2ban, "JAIL_LOCAL", str(jail_local))
    assert mod._check_ignoreip_in_file(tokens) is True


def test_check_ignoreip_in_file_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine abweichende ignoreip-Zeile liefert False."""
    mod = _make_fail2ban()
    jail_local = tmp_path / "jail.local"
    jail_local.write_text("ignoreip = 127.0.0.1/8 ::1\n", encoding="utf-8")
    monkeypatch.setattr(Fail2ban, "JAIL_LOCAL", str(jail_local))
    assert mod._check_ignoreip_in_file(["203.0.113.7"]) is False


def test_check_ignoreip_in_file_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine fehlende jail.local liefert False."""
    mod = _make_fail2ban()
    monkeypatch.setattr(Fail2ban, "JAIL_LOCAL", str(tmp_path / "fehlt.local"))
    assert mod._check_ignoreip_in_file(["203.0.113.7"]) is False


# --- _check_ignoreip_loaded ---


def test_check_ignoreip_loaded_all_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sind alle Tokens in der Live-Ausgabe enthalten, liefert die Prüfung True."""
    mod = _make_fail2ban()
    monkeypatch.setattr(
        Fail2ban,
        "FAIL2BAN_CLIENT",
        _make_executable(tmp_path, "echo '127.0.0.1/8 ::1 203.0.113.7'"),
    )
    assert mod._check_ignoreip_loaded(["203.0.113.7"]) is True


def test_check_ignoreip_loaded_missing_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt ein Token in der Live-Ausgabe, liefert die Prüfung False."""
    mod = _make_fail2ban()
    monkeypatch.setattr(
        Fail2ban,
        "FAIL2BAN_CLIENT",
        _make_executable(tmp_path, "echo '127.0.0.1/8 ::1'"),
    )
    assert mod._check_ignoreip_loaded(["203.0.113.7"]) is False


def test_check_ignoreip_loaded_command_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert der Live-Abruf, liefert die Prüfung False."""
    mod = _make_fail2ban()
    monkeypatch.setattr(
        Fail2ban, "FAIL2BAN_CLIENT", _make_executable(tmp_path, "exit 1")
    )
    assert mod._check_ignoreip_loaded(["203.0.113.7"]) is False
