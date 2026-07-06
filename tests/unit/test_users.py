"""Unit-Tests für secure_base.modules.users."""

import os
import pwd
from email import message_from_bytes, policy
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock

import pytest
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.users import (
    Users,
    _ChpasswdStdinAction,
    _is_password_set,
    _QrEncodeStdinAction,
    _SendMailAction,
    _shadow_hash_from_line,
    _totp_mail_content,
)


def _make_users(
    main_user: str = "alice",
    pubkey: str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test",
    password: str = "s3cret",  # noqa: S107 — Testwert, kein echtes Geheimnis
    uninstall_remove_user: str = "no",
    fqdn: str = "server.example.com",
    admin_mail: str = "admin@example.com",
) -> Users:
    """Baut ein Users-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Users(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.admin_mail = admin_mail
    mod.main_user = main_user
    mod.main_user_password = password
    mod.main_user_pubkey = pubkey
    mod.uninstall_remove_user = uninstall_remove_user
    return mod


# --- CONFIG ---


def test_users_config_declares_expected_keys() -> None:
    """CONFIG nennt operation, fqdn, admin_mail und alle main_user-Schlüssel."""
    assert Users.CONFIG == [
        "operation",
        "fqdn",
        "admin_mail",
        "main_user",
        "main_user_password",
        "main_user_pubkey",
        "uninstall_remove_user",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültiger Benutzername und Pubkey lösen keine Ausnahme aus."""
    mod = _make_users()
    mod._validate()


def test_validate_rejects_invalid_fqdn() -> None:
    """Ein fqdn mit unerlaubten Zeichen erzeugt ModuleError."""
    mod = _make_users(fqdn="server_example!.com")
    with pytest.raises(ModuleError, match="Ungültiger Rechnername"):
        mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Eine ungültige admin_mail erzeugt ModuleError."""
    mod = _make_users(admin_mail="not-an-address")
    with pytest.raises(ModuleError, match="Ungültige Admin-E-Mail-Adresse"):
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


def test_validate_rejects_invalid_uninstall_remove_user() -> None:
    """Ein uninstall_remove_user außerhalb von yes/no erzeugt ModuleError."""
    mod = _make_users(uninstall_remove_user="maybe")
    with pytest.raises(ModuleError, match="uninstall_remove_user"):
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


# --- _group_exists / _readable_as_user (reine Helfer) ---


def test_group_exists_true_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein erfolgreicher Befehl liefert True."""
    mod = _make_users()
    monkeypatch.setattr(Users, "GETENT_BIN", "/bin/true")
    assert mod._group_exists("ssh-users") is True


def test_group_exists_false_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein fehlschlagender Befehl liefert False."""
    mod = _make_users()
    monkeypatch.setattr(Users, "GETENT_BIN", "/bin/false")
    assert mod._group_exists("ssh-users") is False


def test_readable_as_user_true_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein erfolgreicher runuser-Aufruf liefert True."""
    mod = _make_users()
    monkeypatch.setattr(Users, "RUNUSER_BIN", "/bin/true")
    assert mod._readable_as_user("alice", "/some/path") is True


def test_readable_as_user_false_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein fehlschlagender runuser-Aufruf liefert False."""
    mod = _make_users()
    monkeypatch.setattr(Users, "RUNUSER_BIN", "/bin/false")
    assert mod._readable_as_user("alice", "/some/path") is False


# --- _step_drop_membership ---


def test_step_drop_membership_skips_when_user_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existiert der Benutzer nicht, wird gpasswd nicht aufgerufen."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_user_exists", lambda user: False)
    assert mod._step_drop_membership() == 0


def test_step_drop_membership_skips_when_not_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist der Benutzer nicht Mitglied von ssh-users, wird gpasswd übersprungen."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_user_exists", lambda user: True)
    id_script = tmp_path / "id_no_group.sh"
    id_script.write_text("#!/bin/sh\nprintf 'alice wheel\\n'\n", encoding="utf-8")
    id_script.chmod(0o700)
    monkeypatch.setattr(Users, "ID_BIN", str(id_script))
    assert mod._step_drop_membership() == 0


def test_step_drop_membership_removes_membership_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist der Benutzer Mitglied, wird gpasswd -d aufgerufen und meldet Erfolg."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_user_exists", lambda user: True)
    id_script = tmp_path / "id_group.sh"
    id_script.write_text("#!/bin/sh\nprintf 'alice ssh-users\\n'\n", encoding="utf-8")
    id_script.chmod(0o700)
    monkeypatch.setattr(Users, "ID_BIN", str(id_script))
    monkeypatch.setattr(Users, "GPASSWD_BIN", "/bin/true")
    assert mod._step_drop_membership() == 0


def test_step_drop_membership_fails_when_gpasswd_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt gpasswd fehl, liefert der Schritt 1."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_user_exists", lambda user: True)
    id_script = tmp_path / "id_group.sh"
    id_script.write_text("#!/bin/sh\nprintf 'alice ssh-users\\n'\n", encoding="utf-8")
    id_script.chmod(0o700)
    monkeypatch.setattr(Users, "ID_BIN", str(id_script))
    monkeypatch.setattr(Users, "GPASSWD_BIN", "/bin/false")
    assert mod._step_drop_membership() == 1


def test_step_drop_membership_fails_when_id_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ist die Gruppenzugehörigkeit nicht lesbar, liefert der Schritt 1."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_user_exists", lambda user: True)
    monkeypatch.setattr(Users, "ID_BIN", "/bin/false")
    assert mod._step_drop_membership() == 1


# --- _step_remove_group ---


def test_step_remove_group_skips_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existiert die Gruppe nicht, wird groupdel nicht aufgerufen."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_group_exists", lambda group: False)
    assert mod._step_remove_group() == 0


def test_step_remove_group_removes_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Existiert die Gruppe, wird sie entfernt."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_group_exists", lambda group: True)
    monkeypatch.setattr(Users, "GROUPDEL_BIN", "/bin/true")
    assert mod._step_remove_group() == 0


def test_step_remove_group_fails_when_groupdel_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schlägt groupdel fehl, liefert der Schritt 1."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_group_exists", lambda group: True)
    monkeypatch.setattr(Users, "GROUPDEL_BIN", "/bin/false")
    assert mod._step_remove_group() == 1


# --- _step_handle_main_user ---


def test_step_handle_main_user_keeps_user_when_no() -> None:
    """uninstall_remove_user=no liefert 0, ohne userdel aufzurufen."""
    mod = _make_users(uninstall_remove_user="no")
    assert mod._step_handle_main_user() == 0


def test_step_handle_main_user_skips_userdel_when_user_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """uninstall_remove_user=yes ohne vorhandenen Benutzer überspringt userdel."""
    mod = _make_users(uninstall_remove_user="yes")
    monkeypatch.setattr(mod, "_user_exists", lambda user: False)
    assert mod._step_handle_main_user() == 0


def test_step_handle_main_user_removes_user_when_yes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """uninstall_remove_user=yes entfernt den vorhandenen Benutzer per userdel -r."""
    mod = _make_users(uninstall_remove_user="yes")
    monkeypatch.setattr(mod, "_user_exists", lambda user: True)
    monkeypatch.setattr(Users, "PKILL_BIN", "/bin/true")
    monkeypatch.setattr(Users, "PKILL_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(Users, "USERDEL_BIN", "/bin/true")
    assert mod._step_handle_main_user() == 0


def test_step_handle_main_user_fails_when_userdel_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schlägt userdel -r fehl, liefert der Schritt 1."""
    mod = _make_users(uninstall_remove_user="yes")
    monkeypatch.setattr(mod, "_user_exists", lambda user: True)
    monkeypatch.setattr(Users, "PKILL_BIN", "/bin/true")
    monkeypatch.setattr(Users, "PKILL_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(Users, "USERDEL_BIN", "/bin/false")
    assert mod._step_handle_main_user() == 1


# --- _totp_mail_content ---


_EMERGENCY_CODES = ["11111111", "22222222"]


def test_totp_mail_content_includes_secret_url_codes_and_attachment(
    tmp_path: Path,
) -> None:
    """Die TOTP-Mail enthält Betreff, Secret, URL, Notfall-Codes und PNG-Anhang."""
    qr_png = tmp_path / "qr.png"
    qr_png.write_bytes(b"\x89PNG\r\n\x1a\nfake-png-bytes")

    raw = _totp_mail_content(
        user="alice",
        fqdn="server.example.com",
        admin_mail="admin@example.com",
        secret="SECRETVALUE",  # noqa: S106 — Testwert, kein echtes Geheimnis
        url="otpauth://totp/alice@server.example.com?secret=SECRETVALUE"
        "&issuer=server.example.com",
        emergency_codes=_EMERGENCY_CODES,
        qr_png_path=str(qr_png),
    )
    msg = message_from_bytes(raw, policy=policy.default)

    assert (
        msg["Subject"] == "secure-base server.example.com: TOTP-Einrichtung für alice"
    )
    assert msg["To"] == "admin@example.com"
    assert msg.is_multipart()
    body = msg.get_body(preferencelist=("plain",))
    assert body is not None
    body_text = body.get_content()
    assert "SECRETVALUE" in body_text
    assert "otpauth://totp/alice@server.example.com" in body_text
    assert "11111111" in body_text
    assert "22222222" in body_text
    attachments = list(msg.iter_attachments())
    assert len(attachments) == 1
    assert attachments[0].get_content_type() == "image/png"
    assert attachments[0].get_payload(decode=True) == qr_png.read_bytes()


def test_totp_mail_content_is_ascii_only_with_encoded_subject(
    tmp_path: Path,
) -> None:
    """Die serialisierte TOTP-Mail ist ASCII-sicher, der Umlaut-Betreff kodiert.

    Reproduziert den Servertest-Befund (SMTPUTF8 required): ein Umlaut im
    Mailkopf muss als RFC-2047-Encoded-Word stehen, nicht als rohes UTF-8-
    Byte, sonst verlangt das Relay eine Erweiterung, die es nicht anbietet.
    """
    qr_png = tmp_path / "qr.png"
    qr_png.write_bytes(b"\x89PNG\r\n\x1a\nfake-png-bytes")

    raw = _totp_mail_content(
        user="alice",
        fqdn="server.example.com",
        admin_mail="admin@example.com",
        secret="SECRETVALUE",  # noqa: S106 — Testwert, kein echtes Geheimnis
        url="otpauth://totp/alice@server.example.com?secret=SECRETVALUE"
        "&issuer=server.example.com",
        emergency_codes=_EMERGENCY_CODES,
        qr_png_path=str(qr_png),
    )

    assert all(byte < 128 for byte in raw)
    text = raw.decode("ascii")
    assert "=?utf-8?q?" in text
    assert "Content-Transfer-Encoding: quoted-printable" in text


# --- _QrEncodeStdinAction / _SendMailAction ---


def _write_script(tmp_path: Path, name: str, body: str) -> str:
    """Legt ein ausführbares Fake-Programm unter tmp_path an und liefert den Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/usr/bin/env python3\n{body}")
    script.chmod(0o755)
    return str(script)


def test_qr_encode_stdin_action_never_puts_data_in_argv(tmp_path: Path) -> None:
    """qrencode erhält die Daten nur über stdin, nie als Kommandozeilenargument."""
    output = tmp_path / "out.png"
    script = _write_script(
        tmp_path,
        "fake-qrencode",
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "assert 'SECRETVALUE' not in ' '.join(sys.argv)\n"
        "open(sys.argv[2], 'wb').write(data)\n",
    )
    action = _QrEncodeStdinAction(
        data="otpauth://...secret=SECRETVALUE...",
        output_path=str(output),
        qrencode_bin=script,
    )
    assert action.run() == "finished"
    assert output.read_bytes() == b"otpauth://...secret=SECRETVALUE..."


def test_qr_encode_stdin_action_failure_raises() -> None:
    """Ein fehlschlagendes qrencode erzeugt ActionError, status wird failed."""
    action = _QrEncodeStdinAction(
        data="irrelevant", output_path="/nonexistent/out.png", qrencode_bin="/bin/false"
    )
    with pytest.raises(ActionError, match="qrencode endete mit Code"):
        action.run()
    assert action.status == "failed"


def test_send_mail_action_success_with_bytes_content(tmp_path: Path) -> None:
    """Ein erfolgreiches Programm liefert finished; content ist bytes."""
    script = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.buffer.read()\n"
    )
    action = _SendMailAction(
        command=[script, "admin@example.com"], content=b"Subject: x\n\nbody", timeout=5
    )
    assert action.run() == "finished"
    assert action.returncode == 0


def test_send_mail_action_failure_message_omits_content(tmp_path: Path) -> None:
    """Scheitert sendmail, enthält die ActionError-Meldung nie den Mailinhalt."""
    script = _write_script(
        tmp_path,
        "fake-sendmail-fail",
        "import sys\nsys.stdin.buffer.read()\nsys.exit(1)\n",
    )
    action = _SendMailAction(
        command=[script], content=b"Subject: x\n\nSECRETVALUE", timeout=5
    )
    with pytest.raises(ActionError) as exc_info:
        action.run()
    assert "SECRETVALUE" not in str(exc_info.value)
    assert action.status == "failed"


# --- _step_totp / _step_totp_mail ---


def _write_google_authenticator(
    home: Path,
    secret: str = "SECRETVALUE",  # noqa: S107 — Testwert, kein echtes Geheimnis
) -> Path:
    """Legt eine .google_authenticator-Datei mit Secret und Notfall-Codes an."""
    ga_file = home / ".google_authenticator"
    ga_file.write_text(f'{secret}\n" RATE_LIMIT 3 30\n11111111\n22222222\n')
    return ga_file


def test_step_totp_skips_and_marks_not_created_when_secret_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existiert bereits ein Secret, überspringt _step_totp und markiert
    _totp_secret_created als False."""
    mod = _make_users()
    _write_google_authenticator(tmp_path)
    monkeypatch.setattr(mod, "_home_dir", lambda user: str(tmp_path))
    assert mod._step_totp() == 0
    assert mod._totp_secret_created is False


def test_step_totp_mail_skips_when_no_secret_created() -> None:
    """Wurde in diesem Lauf kein neues Secret erzeugt, überspringt
    _step_totp_mail den Versand und liefert 0."""
    mod = _make_users()
    mod._totp_secret_created = False
    assert mod._step_totp_mail() == 0


def _prepare_totp_mail_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Users, Path]:
    """Baut ein Users-Modul mit erzeugtem TOTP-Secret und Platzhalter-Binaries."""
    mod = _make_users()
    mod._totp_secret_created = True
    home = tmp_path / "home"
    home.mkdir()
    _write_google_authenticator(home)
    monkeypatch.setattr(mod, "_home_dir", lambda user: str(home))

    fake_qrencode = _write_script(
        tmp_path,
        "fake-qrencode",
        "import sys\n"
        "data = sys.stdin.buffer.read()\n"
        "open(sys.argv[2], 'wb').write(data)\n",
    )
    monkeypatch.setattr(Users, "QRENCODE_BIN", fake_qrencode)
    fake_sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.buffer.read()\n"
    )
    monkeypatch.setattr(Users, "SENDMAIL_BIN", fake_sendmail)
    return mod, tmp_path


def _apply_sent_mail_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    admin_mail: str = "admin@example.com",
) -> None:
    """Lenkt MAIL_LOG auf eine Datei mit einer status=sent-Zeile für admin_mail um."""
    mail_log = tmp_path / "mail.log"
    mail_log.write_text(
        f"Jul  6 10:00:00 host postfix/smtp[123]: ABC: to=<{admin_mail}>, "
        "relay=smtp.example.com[1.2.3.4]:587, status=sent (250 2.0.0 Ok)\n"
    )
    monkeypatch.setattr(Users, "MAIL_LOG", str(mail_log))
    monkeypatch.setattr(Users, "DELIVERY_LOG_CHECK_INTERVAL", 0)


def test_step_totp_mail_succeeds_and_removes_tmp_qr_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bei nachgewiesener Zustellung liefert _step_totp_mail 0 und entfernt
    die QR-Code-Tmpdatei."""
    mod, base = _prepare_totp_mail_fixture(tmp_path, monkeypatch)
    _apply_sent_mail_log(base, monkeypatch, mod.admin_mail)

    before = set(base.glob("secure-base-totp-qr-*"))
    result = mod._step_totp_mail()
    after = set(base.glob("secure-base-totp-qr-*"))

    assert result == 0
    assert before == after == set()


def test_step_totp_mail_fails_when_qrencode_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt qrencode fehl, liefert _step_totp_mail 1 ohne Mailversand."""
    mod, _base = _prepare_totp_mail_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(Users, "QRENCODE_BIN", "/bin/false")
    assert mod._step_totp_mail() == 1


def test_step_totp_mail_fails_when_sendmail_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt sendmail fehl, liefert _step_totp_mail 1."""
    mod, _base = _prepare_totp_mail_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(Users, "SENDMAIL_BIN", "/bin/false")
    assert mod._step_totp_mail() == 1


def test_step_totp_mail_fails_when_no_delivery_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt der Zustellbeweis im Mail-Log, liefert _step_totp_mail 1."""
    mod, base = _prepare_totp_mail_fixture(tmp_path, monkeypatch)
    mail_log = base / "mail.log"
    mail_log.write_text("keine passende Zeile\n")
    monkeypatch.setattr(Users, "MAIL_LOG", str(mail_log))
    monkeypatch.setattr(Users, "DELIVERY_LOG_CHECK_ATTEMPTS", 1)
    monkeypatch.setattr(Users, "DELIVERY_LOG_CHECK_INTERVAL", 0)
    assert mod._step_totp_mail() == 1


def test_step_totp_mail_never_leaks_secret_in_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Secret, URL und Notfall-Codes erscheinen in keiner gesendeten Meldung,
    weder bei Erfolg noch bei einem Versandfehler."""
    mod, base = _prepare_totp_mail_fixture(tmp_path, monkeypatch)
    _apply_sent_mail_log(base, monkeypatch, mod.admin_mail)

    mod._step_totp_mail()

    conn = cast(MagicMock, mod._conn)
    payloads = [str(call.args[0].payload) for call in conn.send.call_args_list]
    joined = "\n".join(payloads)
    assert "SECRETVALUE" not in joined
    assert "otpauth://" not in joined
    assert "11111111" not in joined
    assert "22222222" not in joined


def test_step_totp_mail_never_leaks_secret_on_send_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Auch bei einem Versandfehler erscheint das Secret in keiner Meldung."""
    mod, _base = _prepare_totp_mail_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(Users, "SENDMAIL_BIN", "/bin/false")

    mod._step_totp_mail()

    conn = cast(MagicMock, mod._conn)
    payloads = [str(call.args[0].payload) for call in conn.send.call_args_list]
    joined = "\n".join(payloads)
    assert "SECRETVALUE" not in joined


# --- _test ---


def test_test_returns_zero_when_home_not_resolvable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ist das Home-Verzeichnis nicht ermittelbar, liefert _test trotzdem 0."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_home_dir", lambda user: None)
    assert mod._test() == 0


def test_test_reports_ok_when_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sind beide Dateien lesbar, liefert _test 0 und meldet den Erfolg."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_home_dir", lambda user: str(tmp_path))
    monkeypatch.setattr(Users, "RUNUSER_BIN", "/bin/true")
    assert mod._test() == 0


def test_test_returns_zero_even_when_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """test ist Beobachtung ohne Abbruch-Tor: liefert 0, auch wenn nichts lesbar ist."""
    mod = _make_users()
    monkeypatch.setattr(mod, "_home_dir", lambda user: str(tmp_path))
    monkeypatch.setattr(Users, "RUNUSER_BIN", "/bin/false")
    assert mod._test() == 0


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, Paket, Benutzer/Gruppe und Dateien."""
    values = {"main_user": "alice"}

    section = Users.doc(values)

    assert section.startswith("\n## Hauptbenutzer\n\n")
    assert (
        f"**Pakete:** {Users.PKG_GOOGLE_AUTHENTICATOR}, {Users.PKG_QRENCODE}" in section
    )
    assert f"**Angelegte Benutzer:** alice (Gruppen: {Users.GROUP_NAME})" in section
    assert "`/home/alice/.ssh/authorized_keys`" in section
    assert "`/home/alice/.google_authenticator`" in section


def test_doc_marks_missing_main_user_as_leer_default() -> None:
    """Fehlt main_user in values, erscheint der Platzhalter "(leer/Default)"."""
    section = Users.doc({})

    assert "**Angelegte Benutzer:** (leer/Default)" in section
    assert "/home/(leer/Default)/.ssh/authorized_keys" in section


def test_doc_never_leaks_password_or_pubkey_value() -> None:
    """main_user_password erscheint weder als Name noch als Wert; der
    Pubkey-Wert wird wie im Bash-Original nicht dokumentiert."""
    values = {
        "main_user": "alice",
        "main_user_password": "GEHEIM-X",
        "main_user_pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test",
    }

    section = Users.doc(values)

    assert "GEHEIM-X" not in section
    assert "main_user_password" not in section
    assert "AAAAC3NzaC1lZDI1NTE5AAAA" not in section
    assert "main_user_pubkey" not in section
