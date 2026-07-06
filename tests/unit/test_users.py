"""Unit-Tests für secure_base.modules.users."""

import os
import pwd
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.users import (
    Users,
    _ChpasswdStdinAction,
    _is_password_set,
    _shadow_hash_from_line,
)


def _make_users(
    main_user: str = "alice",
    pubkey: str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test",
    password: str = "s3cret",  # noqa: S107 — Testwert, kein echtes Geheimnis
) -> Users:
    """Baut ein Users-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Users(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.main_user = main_user
    mod.main_user_password = password
    mod.main_user_pubkey = pubkey
    return mod


# --- CONFIG ---


def test_users_config_declares_expected_keys() -> None:
    """CONFIG nennt operation, main_user, main_user_password, main_user_pubkey."""
    assert Users.CONFIG == [
        "operation",
        "main_user",
        "main_user_password",
        "main_user_pubkey",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültiger Benutzername und Pubkey lösen keine Ausnahme aus."""
    mod = _make_users()
    mod._validate()


def test_validate_rejects_invalid_username() -> None:
    """Ein ungültiger Benutzername erzeugt ModuleError."""
    mod = _make_users(main_user="-invalid")
    with pytest.raises(ModuleError, match="Ungültiger Benutzername"):
        mod._validate()


def test_validate_rejects_empty_pubkey() -> None:
    """Ein leerer Pubkey erzeugt ModuleError (Aussperr-Schutz)."""
    mod = _make_users(pubkey="   ")
    with pytest.raises(ModuleError, match="Kein SSH-Pubkey"):
        mod._validate()


def test_validate_rejects_unknown_pubkey_format() -> None:
    """Ein syntaktisch unbekannter Pubkey erzeugt ModuleError."""
    mod = _make_users(pubkey="not-a-key-at-all")
    with pytest.raises(ModuleError, match="Pubkey-Format unbekannt"):
        mod._validate()


@pytest.mark.parametrize(
    "pubkey",
    [
        "ssh-rsa AAAAB3NzaC1yc2EAAAA test",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAA test",
    ],
)
def test_validate_accepts_known_key_types(pubkey: str) -> None:
    """Alle drei bekannten Schlüsseltypen werden akzeptiert."""
    mod = _make_users(pubkey=pubkey)
    mod._validate()


# --- Reine Hilfsfunktionen ---


def test_shadow_hash_from_line_extracts_second_field() -> None:
    """_shadow_hash_from_line liefert Feld 2 einer getent-shadow-Zeile."""
    line = "alice:$6$abc$def:19700:0:99999:7:::"
    assert _shadow_hash_from_line(line) == "$6$abc$def"


def test_shadow_hash_from_line_missing_field_returns_empty() -> None:
    """Ohne zweites Feld liefert _shadow_hash_from_line einen Leerstring."""
    assert _shadow_hash_from_line("alice") == ""


@pytest.mark.parametrize(
    ("hash_value", "expected"),
    [
        ("", False),
        ("!", False),
        ("*", False),
        ("!!", True),
        ("$6$abc$def", True),
    ],
)
def test_is_password_set(hash_value: str, expected: bool) -> None:
    """_is_password_set erkennt leer/!/* als 'nicht gesetzt'."""
    assert _is_password_set(hash_value) is expected


# --- _check_file_mode / _check_owner_only_mode ---


def test_check_file_mode_matches_expected(tmp_path: Path) -> None:
    """Exakt passende Rechte und Eigentümer liefern True."""
    mod = _make_users()
    target = tmp_path / "authorized_keys"
    target.write_text("ssh-ed25519 AAAA test\n", encoding="utf-8")
    target.chmod(0o600)
    owner = pwd.getpwuid(os.getuid()).pw_name
    assert mod._check_file_mode(target, 0o600, owner) is True


def test_check_file_mode_wrong_mode_returns_false(tmp_path: Path) -> None:
    """Abweichende Rechte liefern False."""
    mod = _make_users()
    target = tmp_path / "authorized_keys"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o644)
    owner = pwd.getpwuid(os.getuid()).pw_name
    assert mod._check_file_mode(target, 0o600, owner) is False


def test_check_file_mode_missing_path_returns_false(tmp_path: Path) -> None:
    """Ein nicht existierender Pfad liefert False."""
    mod = _make_users()
    assert mod._check_file_mode(tmp_path / "missing", 0o600, "alice") is False


def test_check_owner_only_mode_rejects_group_access(tmp_path: Path) -> None:
    """Gruppen-lesbare Rechte (0640) verletzen die Owner-only-Maske."""
    mod = _make_users()
    target = tmp_path / ".google_authenticator"
    target.write_text("SECRET\n", encoding="utf-8")
    target.chmod(0o640)
    owner = pwd.getpwuid(os.getuid()).pw_name
    assert mod._check_owner_only_mode(target, owner) is False


def test_check_owner_only_mode_accepts_0600(tmp_path: Path) -> None:
    """0600 erfüllt die Owner-only-Maske."""
    mod = _make_users()
    target = tmp_path / ".google_authenticator"
    target.write_text("SECRET\n", encoding="utf-8")
    target.chmod(0o600)
    owner = pwd.getpwuid(os.getuid()).pw_name
    assert mod._check_owner_only_mode(target, owner) is True


# --- _check_package_installed / _check_group_exists (nur Returncode) ---


def test_check_package_installed_true_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein erfolgreicher Befehl liefert True."""
    mod = _make_users()
    monkeypatch.setattr(Users, "DPKG_BIN", "/bin/true")
    assert mod._check_package_installed("irrelevant") is True


def test_check_package_installed_false_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein fehlschlagender Befehl liefert False."""
    mod = _make_users()
    monkeypatch.setattr(Users, "DPKG_BIN", "/bin/false")
    assert mod._check_package_installed("irrelevant") is False


def test_check_group_exists_true_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein erfolgreicher Befehl liefert True."""
    mod = _make_users()
    monkeypatch.setattr(Users, "GETENT_BIN", "/bin/true")
    assert mod._check_group_exists("ssh-users") is True


def test_check_group_exists_false_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein fehlschlagender Befehl liefert False."""
    mod = _make_users()
    monkeypatch.setattr(Users, "GETENT_BIN", "/bin/false")
    assert mod._check_group_exists("ssh-users") is False


def test_user_exists_true_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """_user_exists liefert True bei Returncode 0."""
    mod = _make_users()
    monkeypatch.setattr(Users, "GETENT_BIN", "/bin/true")
    assert mod._user_exists("alice") is True


def test_user_exists_false_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """_user_exists liefert False bei Returncode != 0."""
    mod = _make_users()
    monkeypatch.setattr(Users, "GETENT_BIN", "/bin/false")
    assert mod._user_exists("alice") is False


# --- _ChpasswdStdinAction ---


def test_chpasswd_action_success_never_exposes_password(tmp_path: Path) -> None:
    """Bei Erfolg (rc 0) endet die Aktion 'finished', Passwort bleibt außen vor."""
    script = tmp_path / "chpasswd_ok.sh"
    script.write_text("#!/bin/sh\ncat >/dev/null\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)

    action = _ChpasswdStdinAction(
        user="alice",
        password="s3cret-value",  # noqa: S106 — Testwert, kein echtes Geheimnis
        chpasswd_bin=str(script),
    )
    status = action.run()

    assert status == "finished"
    assert action.returncode == 0


def test_chpasswd_action_failure_message_omits_password(tmp_path: Path) -> None:
    """Scheitert chpasswd, enthält die ActionError-Meldung nie das Passwort."""
    script = tmp_path / "chpasswd_fail.sh"
    script.write_text("#!/bin/sh\ncat >/dev/null\nexit 1\n", encoding="utf-8")
    script.chmod(0o700)

    action = _ChpasswdStdinAction(
        user="alice",
        password="s3cret-value",  # noqa: S106 — Testwert, kein echtes Geheimnis
        chpasswd_bin=str(script),
    )
    with pytest.raises(ActionError) as exc_info:
        action.run()

    assert "s3cret-value" not in str(exc_info.value)
    assert action.status == "failed"


def test_chpasswd_action_timeout_message_omits_password(tmp_path: Path) -> None:
    """Bei Zeitüberschreitung enthält die Meldung nie das Passwort."""
    script = tmp_path / "chpasswd_hang.sh"
    script.write_text("#!/bin/sh\ncat >/dev/null\nsleep 5\n", encoding="utf-8")
    script.chmod(0o700)

    action = _ChpasswdStdinAction(
        user="alice",
        password="s3cret-value",  # noqa: S106 — Testwert, kein echtes Geheimnis
        chpasswd_bin=str(script),
        timeout=0.2,
    )
    with pytest.raises(ActionError, match="Zeitgrenze") as exc_info:
        action.run()

    assert "s3cret-value" not in str(exc_info.value)


# --- _step_set_password ---


def test_step_set_password_skips_when_already_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ist bereits ein Passwort gesetzt, wird chpasswd nicht aufgerufen."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_shadow_password_set", lambda user: True)

    result = mod._step_set_password()

    assert result == 0


def test_step_set_password_fails_without_configured_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ohne gesetztes Passwort und ohne Konfigurationswert bricht der Schritt ab."""
    mod = _make_users(password="")
    monkeypatch.setattr(mod, "_shadow_password_set", lambda user: False)

    result = mod._step_set_password()

    assert result == 1
