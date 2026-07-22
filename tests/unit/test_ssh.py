"""Unit-Tests für secure_base.modules.ssh."""

import os
import pwd
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.ssh import (
    CHALLENGE_RESPONSE_SETTING,
    LOGIN_MAIL_MARKER,
    PAM_GA_MARKER,
    SSH_USERS_GROUP,
    SSHD_SETTINGS,
    Ssh,
    _login_mail_pam_block,
    _login_mail_script_content,
    _pam_ga_block,
    _parse_sshd_t,
    _setting_match,
)

_VALUES: dict[str, str] = {
    "admin_mail": "admin@example.com",
    "main_user": "alice",
    "ssh_enable_login_mail": "yes",
    "ssh_enable_challenge_response_auth": "yes",
}


def _make_ssh(
    admin_mail: str = "admin@example.com",
    main_user: str = "alice",
    enable_login_mail: str = "yes",
    enable_challenge_response_auth: str = "yes",
) -> Ssh:
    """Baut ein Ssh-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Ssh(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = admin_mail
    mod.main_user = main_user
    mod.ssh_enable_login_mail = enable_login_mail
    mod.ssh_enable_challenge_response_auth = enable_challenge_response_auth
    mod.force_overwrite = "no"
    mod.backup_run_dir = "/var/backup/secure-base/test-lauf"
    return mod


def _make_executable(tmp_path: Path, name: str, content: str) -> str:
    """Legt ein ausführbares Shell-Script an und liefert dessen Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{content}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


# --- CONFIG ---


def test_ssh_config_declares_expected_keys() -> None:
    """CONFIG nennt operation, admin_mail, main_user, ssh-Schalter, Drift-Schutz."""
    assert Ssh.CONFIG == [
        "operation",
        "admin_mail",
        "main_user",
        "ssh_enable_login_mail",
        "ssh_enable_challenge_response_auth",
        "force_overwrite",
        "backup_run_dir",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige Werte lösen keine Ausnahme aus."""
    mod = _make_ssh()
    mod._validate()


def test_validate_rejects_invalid_username() -> None:
    """Ein ungültiger Benutzername erzeugt ModuleError."""
    mod = _make_ssh(main_user="-invalid")
    with pytest.raises(ModuleError, match="Ungültiger Benutzername"):
        mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Eine ungültige admin_mail-Adresse erzeugt ModuleError."""
    mod = _make_ssh(admin_mail="not-an-address")
    with pytest.raises(ModuleError, match="Ungültige admin_mail"):
        mod._validate()


def test_validate_rejects_invalid_enable_login_mail() -> None:
    """Ein Wert außerhalb yes/no bei ssh_enable_login_mail erzeugt ModuleError."""
    mod = _make_ssh(enable_login_mail="vielleicht")
    with pytest.raises(ModuleError, match="ssh_enable_login_mail"):
        mod._validate()


def test_validate_rejects_invalid_enable_challenge_response_auth() -> None:
    """Ungültiger ssh_enable_challenge_response_auth-Wert erzeugt ModuleError."""
    mod = _make_ssh(enable_challenge_response_auth="vielleicht")
    with pytest.raises(ModuleError, match="ssh_enable_challenge_response_auth"):
        mod._validate()


# --- Inhaltsfunktionen ---


def test_setting_match_matches_active_and_commented_line() -> None:
    """_setting_match passt auf aktive und auskommentierte Zeilen."""
    pattern = _setting_match("PermitRootLogin")
    assert re.match(pattern, "PermitRootLogin yes")
    assert re.match(pattern, "#PermitRootLogin yes")
    assert re.match(pattern, "  # PermitRootLogin yes")
    assert not re.match(pattern, "PermitRootLoginX yes")


def test_pam_ga_block_contains_expected_line() -> None:
    """_pam_ga_block enthält den TOTP-PAM-Eintrag."""
    assert "auth required pam_google_authenticator.so" in _pam_ga_block()


def test_login_mail_pam_block_contains_script_path() -> None:
    """_login_mail_pam_block referenziert den übergebenen Skriptpfad."""
    block = _login_mail_pam_block("/etc/ssh/login-mail-notification.sh")
    assert "session optional pam_exec.so seteuid" in block
    assert "/etc/ssh/login-mail-notification.sh" in block


def test_login_mail_script_content_contains_admin_mail() -> None:
    """_login_mail_script_content bettet admin_mail ein und ruft mail auf."""
    content = _login_mail_script_content("admin@example.com")
    assert 'ADMINMAIL="admin@example.com"' in content
    assert content.startswith("#!/bin/sh\n")
    assert "| mail -s" in content


def test_parse_sshd_t_splits_key_and_value() -> None:
    """_parse_sshd_t zerlegt Zeilen in kleingeschriebene Schlüssel und Werte."""
    output = "permitrootlogin no\nallowgroups ssh-users\n"
    assert _parse_sshd_t(output) == {
        "permitrootlogin": "no",
        "allowgroups": "ssh-users",
    }


def test_parse_sshd_t_ignores_lines_without_value() -> None:
    """Zeilen ohne Leerzeichen (kein Wert) werden ignoriert."""
    assert _parse_sshd_t("keinevalue\n") == {}


def test_sshd_settings_contains_allow_groups_ssh_users() -> None:
    """SSHD_SETTINGS setzt AllowGroups auf SSH_USERS_GROUP."""
    assert ("AllowGroups", SSH_USERS_GROUP) in SSHD_SETTINGS


def test_sshd_settings_excludes_challenge_response_authentication() -> None:
    """SSHD_SETTINGS enthält nicht den deprecated-Alias."""
    keys = [key for key, _ in SSHD_SETTINGS]
    assert CHALLENGE_RESPONSE_SETTING not in keys


# --- _apply_setting / _remove_setting ---


def test_apply_setting_writes_directive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_apply_setting schreibt die Direktive in die Zieldatei."""
    mod = _make_ssh()
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text("# leer\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "SSHD_CONFIG", str(sshd_config))
    assert mod._apply_setting("PermitRootLogin", "no") is True
    assert "PermitRootLogin no" in sshd_config.read_text(encoding="utf-8")


def test_apply_setting_replaces_existing_commented_directive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_apply_setting ersetzt eine bereits auskommentierte Direktive."""
    mod = _make_ssh()
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text("#PermitRootLogin yes\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "SSHD_CONFIG", str(sshd_config))
    assert mod._apply_setting("PermitRootLogin", "no") is True
    content = sshd_config.read_text(encoding="utf-8")
    assert "PermitRootLogin no" in content
    assert "#PermitRootLogin yes" not in content


def test_apply_setting_missing_file_returns_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Zieldatei, liefert _apply_setting False."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "SSHD_CONFIG", str(tmp_path / "fehlt"))
    assert mod._apply_setting("PermitRootLogin", "no") is False


def test_remove_setting_removes_all_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_remove_setting entfernt aktive und auskommentierte Direktiven."""
    mod = _make_ssh()
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text(
        "ChallengeResponseAuthentication yes\n# ChallengeResponseAuthentication no\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(Ssh, "SSHD_CONFIG", str(sshd_config))
    assert mod._remove_setting(CHALLENGE_RESPONSE_SETTING) is True
    assert "ChallengeResponseAuthentication" not in sshd_config.read_text(
        encoding="utf-8"
    )


# --- _step_remove_sshd_settings ---


def test_step_remove_sshd_settings_removes_all_directives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entfernt alle SSHD_SETTINGS-Direktiven und den Challenge-Response-Alias."""
    mod = _make_ssh()
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
    sshd_config = tmp_path / "sshd_config"
    lines = [f"{key} {value}\n" for key, value in SSHD_SETTINGS]
    lines.append("ChallengeResponseAuthentication yes\n")
    sshd_config.write_text("".join(lines), encoding="utf-8")
    monkeypatch.setattr(Ssh, "SSHD_CONFIG", str(sshd_config))

    assert mod._step_remove_sshd_settings() == 0

    content = sshd_config.read_text(encoding="utf-8")
    for key, _value in SSHD_SETTINGS:
        assert key not in content
    assert "ChallengeResponseAuthentication" not in content


def test_step_remove_sshd_settings_missing_file_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Zieldatei, liefert der Schritt einen Fehler."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "SSHD_CONFIG", str(tmp_path / "fehlt"))
    assert mod._step_remove_sshd_settings() == 1


# --- _step_remove_pam_totp_entry ---


def test_step_remove_pam_totp_entry_removes_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entfernt den TOTP-PAM-Block vollständig."""
    mod = _make_ssh()
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
    pam_sshd = tmp_path / "sshd"
    pam_sshd.write_text(
        f"# BEGIN {PAM_GA_MARKER}\n{_pam_ga_block()}\n# END {PAM_GA_MARKER}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    assert mod._step_remove_pam_totp_entry() == 0
    assert mod._check_pam_google_authenticator() is False


# --- _step_restore_pam_bypass ---


def test_step_restore_pam_bypass_uncomments_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stellt eine auskommentierte @include common-auth-Zeile wieder aktiv her."""
    mod = _make_ssh()
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
    pam_sshd = tmp_path / "sshd"
    pam_sshd.write_text("# @include common-auth\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    assert mod._step_restore_pam_bypass() == 0
    assert mod._pam_bypass_active() is True


def test_step_restore_pam_bypass_missing_file_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Zieldatei, liefert der Schritt einen Fehler."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(tmp_path / "fehlt"))
    assert mod._step_restore_pam_bypass() == 1


# --- _step_remove_login_mail_hook ---


def test_step_remove_login_mail_hook_removes_block_and_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entfernt PAM-Block und Skriptdatei, wenn beide vorhanden sind."""
    mod = _make_ssh()
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
    pam_sshd = tmp_path / "sshd"
    script = tmp_path / "login-mail.sh"
    pam_sshd.write_text(
        f"# BEGIN {LOGIN_MAIL_MARKER}\n"
        f"{_login_mail_pam_block(str(script))}\n"
        f"# END {LOGIN_MAIL_MARKER}\n",
        encoding="utf-8",
    )
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    monkeypatch.setattr(Ssh, "LOGIN_MAIL_SCRIPT", str(script))

    assert mod._step_remove_login_mail_hook() == 0

    assert not script.exists()
    assert mod._check_login_mail_pam_line() is False


def test_step_remove_login_mail_hook_idempotent_without_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Skriptdatei bereits, bleibt der Schritt erfolgreich (idempotent)."""
    mod = _make_ssh()
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
    pam_sshd = tmp_path / "sshd"
    pam_sshd.write_text("# nichts hier\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    monkeypatch.setattr(Ssh, "LOGIN_MAIL_SCRIPT", str(tmp_path / "fehlt.sh"))

    assert mod._step_remove_login_mail_hook() == 0


# --- PAM-Bypass ---


def test_pam_bypass_active_true_when_uncommented(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine aktive @include common-auth-Zeile wird erkannt."""
    mod = _make_ssh()
    pam_sshd = tmp_path / "sshd"
    pam_sshd.write_text("@include common-auth\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    assert mod._pam_bypass_active() is True


def test_pam_bypass_active_false_when_commented(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine auskommentierte @include common-auth-Zeile gilt als inaktiv."""
    mod = _make_ssh()
    pam_sshd = tmp_path / "sshd"
    pam_sshd.write_text("# @include common-auth\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    assert mod._pam_bypass_active() is False


# --- _check_pam_google_authenticator ---


def test_check_pam_google_authenticator_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein aktiver pam_google_authenticator.so-Eintrag liefert True."""
    mod = _make_ssh()
    pam_sshd = tmp_path / "sshd"
    pam_sshd.write_text(_pam_ga_block() + "\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    assert mod._check_pam_google_authenticator() is True


def test_check_pam_google_authenticator_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlender Eintrag liefert False."""
    mod = _make_ssh()
    pam_sshd = tmp_path / "sshd"
    pam_sshd.write_text("# nichts hier\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    assert mod._check_pam_google_authenticator() is False


# --- _check_login_mail_pam_line ---


def test_check_login_mail_pam_line_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine aktive pam_exec-session-Zeile für das Login-Mail-Skript liefert True."""
    mod = _make_ssh()
    pam_sshd = tmp_path / "sshd"
    script = "/etc/ssh/login-mail-notification.sh"
    pam_sshd.write_text(_login_mail_pam_block(script) + "\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    monkeypatch.setattr(Ssh, "LOGIN_MAIL_SCRIPT", script)
    assert mod._check_login_mail_pam_line() is True


def test_check_login_mail_pam_line_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine fehlende session-Zeile liefert False."""
    mod = _make_ssh()
    pam_sshd = tmp_path / "sshd"
    pam_sshd.write_text("# nichts hier\n", encoding="utf-8")
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    assert mod._check_login_mail_pam_line() is False


# --- _check_sshd_settings ---


def test_check_sshd_settings_all_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stimmen alle sshd -T-Werte, liefert die Prüfung True."""
    mod = _make_ssh()
    lines = [f"{key.lower()} {value}" for key, value in SSHD_SETTINGS]
    script = "\n".join(f"echo '{line}'" for line in lines)
    monkeypatch.setattr(Ssh, "SSHD_BIN", _make_executable(tmp_path, "sshd", script))
    assert mod._check_sshd_settings() is True


def test_check_sshd_settings_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine abweichende Direktive liefert False."""
    mod = _make_ssh()
    lines = [f"{key.lower()} {value}" for key, value in SSHD_SETTINGS]
    lines[0] = "permitrootlogin yes"
    script = "\n".join(f"echo '{line}'" for line in lines)
    monkeypatch.setattr(Ssh, "SSHD_BIN", _make_executable(tmp_path, "sshd", script))
    assert mod._check_sshd_settings() is False


def test_check_sshd_settings_command_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert sshd -T, liefert die Prüfung False."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "SSHD_BIN", _make_executable(tmp_path, "sshd", "exit 1"))
    assert mod._check_sshd_settings() is False


# --- _test / _test_sshd_config_syntax ---


def test_test_sshd_config_syntax_true_on_exit_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Liefert sshd -t Exit 0, liefert die Prüfung True."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "SSHD_BIN", _make_executable(tmp_path, "sshd", "exit 0"))
    assert mod._test_sshd_config_syntax() is True


def test_test_sshd_config_syntax_false_on_exit_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Liefert sshd -t Exit ungleich 0, liefert die Prüfung False."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "SSHD_BIN", _make_executable(tmp_path, "sshd", "exit 1"))
    assert mod._test_sshd_config_syntax() is False


def test_test_returns_zero_on_syntax_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_test liefert 0, wenn sshd -t erfolgreich ist."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "SSHD_BIN", _make_executable(tmp_path, "sshd", "exit 0"))
    assert mod._test() == 0


def test_test_returns_one_on_syntax_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_test liefert 1, wenn sshd -t fehlschlägt."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "SSHD_BIN", _make_executable(tmp_path, "sshd", "exit 1"))
    assert mod._test() == 1


# --- _check_package_installed ---


def test_check_package_installed_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Meldet dpkg-query 'install ok installed', liefert die Prüfung True."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh,
        "DPKG_QUERY_BIN",
        _make_executable(tmp_path, "dpkg-query", "echo 'install ok installed'"),
    )
    assert mod._check_package_installed("openssh-server") is True


def test_check_package_installed_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein anderer Paketstatus liefert False."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh,
        "DPKG_QUERY_BIN",
        _make_executable(tmp_path, "dpkg-query", "echo 'unknown ok not-installed'"),
    )
    assert mod._check_package_installed("openssh-server") is False


def test_check_package_installed_command_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert dpkg-query, liefert die Prüfung False."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh, "DPKG_QUERY_BIN", _make_executable(tmp_path, "dpkg-query", "exit 1")
    )
    assert mod._check_package_installed("openssh-server") is False


# --- _user_exists / _home_dir / _check_group_membership ---


def test_user_exists_true(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein bekannter Benutzer liefert True."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh,
        "GETENT_BIN",
        _make_executable(
            tmp_path, "getent", "echo 'alice:x:1000:1000::/home/alice:/bin/bash'"
        ),
    )
    assert mod._user_exists("alice") is True


def test_user_exists_false(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein unbekannter Benutzer liefert False."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh, "GETENT_BIN", _make_executable(tmp_path, "getent", "exit 2")
    )
    assert mod._user_exists("alice") is False


def test_home_dir_returns_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_home_dir liest das sechste Feld aus getent passwd."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh,
        "GETENT_BIN",
        _make_executable(
            tmp_path, "getent", "echo 'alice:x:1000:1000::/home/alice:/bin/bash'"
        ),
    )
    assert mod._home_dir("alice") == "/home/alice"


def test_home_dir_returns_none_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert getent, liefert _home_dir None."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh, "GETENT_BIN", _make_executable(tmp_path, "getent", "exit 2")
    )
    assert mod._home_dir("alice") is None


def test_check_group_membership_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist die Gruppe in der id-Ausgabe enthalten, liefert die Prüfung True."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh, "ID_BIN", _make_executable(tmp_path, "id", "echo 'alice ssh-users sudo'")
    )
    assert mod._check_group_membership("alice", SSH_USERS_GROUP) is True


def test_check_group_membership_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Gruppe in der id-Ausgabe, liefert die Prüfung False."""
    mod = _make_ssh()
    monkeypatch.setattr(
        Ssh, "ID_BIN", _make_executable(tmp_path, "id", "echo 'alice sudo'")
    )
    assert mod._check_group_membership("alice", SSH_USERS_GROUP) is False


def test_check_group_membership_command_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert id, liefert die Prüfung False."""
    mod = _make_ssh()
    monkeypatch.setattr(Ssh, "ID_BIN", _make_executable(tmp_path, "id", "exit 1"))
    assert mod._check_group_membership("alice", SSH_USERS_GROUP) is False


# --- _check_nonempty_file ---


def test_check_nonempty_file_true(tmp_path: Path) -> None:
    """Eine nicht-leere Datei liefert True."""
    mod = _make_ssh()
    target = tmp_path / "authorized_keys"
    target.write_text("ssh-ed25519 AAAA test\n", encoding="utf-8")
    assert mod._check_nonempty_file(target, "authorized_keys") is True


def test_check_nonempty_file_empty(tmp_path: Path) -> None:
    """Eine leere Datei liefert False."""
    mod = _make_ssh()
    target = tmp_path / "authorized_keys"
    target.write_text("", encoding="utf-8")
    assert mod._check_nonempty_file(target, "authorized_keys") is False


def test_check_nonempty_file_missing(tmp_path: Path) -> None:
    """Eine fehlende Datei liefert False."""
    mod = _make_ssh()
    assert mod._check_nonempty_file(tmp_path / "fehlt", "authorized_keys") is False


# --- _check_file_mode ---


def test_check_file_mode_matches_expected(tmp_path: Path) -> None:
    """Exakt passende Rechte und Eigentümer liefern True."""
    mod = _make_ssh()
    target = tmp_path / "login-mail-notification.sh"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o700)
    owner = pwd.getpwuid(os.getuid()).pw_name
    assert mod._check_file_mode(target, 0o700, owner) is True


def test_check_file_mode_wrong_mode_returns_false(tmp_path: Path) -> None:
    """Abweichende Rechte liefern False."""
    mod = _make_ssh()
    target = tmp_path / "login-mail-notification.sh"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)
    owner = pwd.getpwuid(os.getuid()).pw_name
    assert mod._check_file_mode(target, 0o700, owner) is False


def test_check_file_mode_wrong_owner_returns_false(tmp_path: Path) -> None:
    """Ein abweichender Eigentümer liefert False."""
    mod = _make_ssh()
    target = tmp_path / "login-mail-notification.sh"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o700)
    assert mod._check_file_mode(target, 0o700, "root-oder-sonstwer") is False


def test_check_file_mode_missing_path_returns_false(tmp_path: Path) -> None:
    """Ein nicht existierender Pfad liefert False."""
    mod = _make_ssh()
    assert mod._check_file_mode(tmp_path / "fehlt", 0o700, "root") is False


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, sshd_config-Direktiven und PAM-Einträge."""
    section = Ssh.doc(_VALUES)
    assert section.startswith("\n## SSH-Härtung mit TOTP\n\n")
    assert "**Dateien/Einstellungen:**" in section
    assert f"`{Ssh.SSHD_CONFIG}`" in section
    for key, value in SSHD_SETTINGS:
        assert f"{key} {value}" in section
    assert f"{CHALLENGE_RESPONSE_SETTING} yes" in section
    assert f"`{Ssh.PAM_SSHD}`" in section
    assert "@include common-auth auskommentiert (TOTP-Bypass-Schutz)" in section
    assert "auth required pam_google_authenticator.so" in section
    assert f"`{Ssh.LOGIN_MAIL_SCRIPT}`" in section
    assert "SSH-Login-Mail an admin@example.com (via pam_exec)" in section
    assert "openssh-server und libpam-google-authenticator werden" in section


def test_doc_omits_login_mail_file_when_disabled() -> None:
    """Bei ssh_enable_login_mail=no fehlt der Login-Mail-Dateieintrag."""
    values = dict(_VALUES, ssh_enable_login_mail="no")
    section = Ssh.doc(values)
    assert f"`{Ssh.LOGIN_MAIL_SCRIPT}`" not in section
    assert "SSH-Login-Mail an" not in section


def test_doc_marks_missing_values_as_leer_default() -> None:
    """Fehlende Werte in values erscheinen als "(leer/Default)"."""
    section = Ssh.doc({})
    assert f"{CHALLENGE_RESPONSE_SETTING} (leer/Default)" in section
    assert "SSH-Login-Mail an (leer/Default) (via pam_exec)" in section


def test_doc_never_leaks_secrets() -> None:
    """Ein Kunstgeheimnis in values landet nicht in der Ausgabe von doc()."""
    values = dict(_VALUES, main_user="GEHEIM-X", some_other_key="GEHEIM-X")
    section = Ssh.doc(values)
    assert "GEHEIM-X" not in section
