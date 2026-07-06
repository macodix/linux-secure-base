"""Unit-Tests für secure_base.modules.postfix."""

from pathlib import Path
from typing import cast
from unittest.mock import MagicMock

import pytest
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.postfix import (
    Postfix,
    _aliases_block_content,
    _debconf_content,
    _recipient_canonical_content,
    _sasl_passwd_content,
    _SendMailAction,
    _test_mail_content,
)


def _make_postfix(
    fqdn: str = "server.example.com",
    admin_mail: str = "admin@example.com",
    relay_host: str = "smtp.example.com",
    relay_port: str = "587",
    relay_user: str = "relayuser",
    relay_password: str = "s3cret",  # noqa: S107 — Testwert, kein echtes Geheimnis
) -> Postfix:
    """Baut ein Postfix-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Postfix(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.admin_mail = admin_mail
    mod.relay_host = relay_host
    mod.relay_port = relay_port
    mod.relay_user = relay_user
    mod.relay_password = relay_password
    return mod


def _sent_payloads(mod: Postfix) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    conn = cast(MagicMock, mod._conn)
    return [call.args[0].payload for call in conn.send.call_args_list]


# --- CONFIG ---


def test_postfix_config_declares_all_keys_in_order() -> None:
    """CONFIG nennt operation, fqdn, admin_mail und alle relay_-Schlüssel."""
    assert Postfix.CONFIG == [
        "operation",
        "fqdn",
        "admin_mail",
        "relay_host",
        "relay_port",
        "relay_user",
        "relay_password",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige Werte lösen keine Ausnahme aus."""
    mod = _make_postfix()
    mod._validate()


def test_validate_rejects_invalid_fqdn() -> None:
    """Ein fqdn mit unerlaubten Zeichen erzeugt ModuleError."""
    mod = _make_postfix(fqdn="server_example!.com")
    with pytest.raises(ModuleError, match="Ungültiger Rechnername"):
        mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Eine ungültige admin_mail erzeugt ModuleError."""
    mod = _make_postfix(admin_mail="not-an-address")
    with pytest.raises(ModuleError, match="Ungültige Admin-E-Mail-Adresse"):
        mod._validate()


def test_validate_rejects_invalid_relay_host() -> None:
    """Ein relay_host mit unerlaubten Zeichen erzeugt ModuleError."""
    mod = _make_postfix(relay_host="smtp_example!.com")
    with pytest.raises(ModuleError, match="Ungültiger Relay-Host"):
        mod._validate()


@pytest.mark.parametrize("port", ["abc", "0", "70000", "-1", ""])
def test_validate_rejects_invalid_relay_port(port: str) -> None:
    """Ein relay_port außerhalb 1-65535 oder nicht-numerisch erzeugt ModuleError."""
    mod = _make_postfix(relay_port=port)
    with pytest.raises(ModuleError, match="Ungültiger Relay-Port"):
        mod._validate()


def test_validate_rejects_invalid_relay_user() -> None:
    """Ein relay_user mit Leerzeichen oder Doppelpunkt erzeugt ModuleError."""
    mod = _make_postfix(relay_user="user with space")
    with pytest.raises(ModuleError, match="Ungültiger Relay-Benutzer"):
        mod._validate()


def test_validate_rejects_invalid_relay_password() -> None:
    """Ein relay_password mit Leerzeichen erzeugt ModuleError ohne Wert-Ausgabe."""
    mod = _make_postfix(relay_password="pass with space")  # noqa: S106 — Testwert
    with pytest.raises(ModuleError, match="Ungültiges Relay-Passwort") as exc_info:
        mod._validate()
    assert "pass with space" not in str(exc_info.value)


def test_validate_rejects_empty_relay_password() -> None:
    """Ein leeres relay_password erzeugt ModuleError."""
    mod = _make_postfix(relay_password="")
    with pytest.raises(ModuleError, match="Ungültiges Relay-Passwort"):
        mod._validate()


# --- _main_cf_settings ---


def test_main_cf_settings_contains_relayhost_with_host_and_port() -> None:
    """relayhost wird aus relay_host und relay_port zusammengesetzt."""
    mod = _make_postfix(relay_host="smtp.example.com", relay_port="587")
    settings = dict(mod._main_cf_settings())
    assert settings["relayhost"] == "[smtp.example.com]:587"


def test_main_cf_settings_references_sasl_passwd_and_recipient_canonical() -> None:
    """smtp_sasl_password_maps und recipient_canonical_maps referenzieren die
    eigenen Schreibziele SASL_PASSWD und RECIPIENT_CANONICAL."""
    mod = _make_postfix()
    settings = dict(mod._main_cf_settings())
    assert settings["smtp_sasl_password_maps"] == f"hash:{Postfix.SASL_PASSWD}"
    assert (
        settings["recipient_canonical_maps"] == f"regexp:{Postfix.RECIPIENT_CANONICAL}"
    )


# --- Inhaltsfunktionen ---


def test_debconf_content_sets_satellite_and_mailname() -> None:
    """_debconf_content wählt Satellite und setzt den mailname auf fqdn."""
    content = _debconf_content("server.example.com")
    assert "postfix/main_mailer_type select Satellite system" in content
    assert "postfix/mailname string server.example.com" in content


def test_sasl_passwd_content_format() -> None:
    """_sasl_passwd_content baut die Zeile [host]:port user:password."""
    content = _sasl_passwd_content("smtp.example.com", "587", "relayuser", "geheim")
    assert content == "[smtp.example.com]:587 relayuser:geheim\n"


def test_recipient_canonical_content_maps_all_to_admin_mail() -> None:
    """_recipient_canonical_content leitet alle Empfänger auf admin_mail um."""
    content = _recipient_canonical_content("admin@example.com")
    assert content == "/.+/   admin@example.com\n"


def test_aliases_block_content_forwards_root_to_admin_mail() -> None:
    """_aliases_block_content leitet root und postmaster an admin_mail weiter."""
    content = _aliases_block_content("admin@example.com")
    assert "postmaster: root" in content
    assert "root:       admin@example.com" in content


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_postfix()
    assert mod._check_value(["/bin/echo", "enabled"], "enabled", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_postfix()
    assert mod._check_value(["/bin/echo", "disabled"], "enabled", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_postfix()
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False


# --- Dateibasierte Prüfungen ---


def test_check_file_exists_true_for_existing_file(tmp_path: Path) -> None:
    """Eine vorhandene Datei liefert True."""
    mod = _make_postfix()
    target = tmp_path / "recipient_canonical"
    target.write_text("x")
    assert mod._check_file_exists(str(target), "Testdatei") is True


def test_check_file_exists_false_for_missing_file(tmp_path: Path) -> None:
    """Eine fehlende Datei liefert False."""
    mod = _make_postfix()
    target = tmp_path / "missing"
    assert mod._check_file_exists(str(target), "Testdatei") is False


def test_check_file_mode_matches(tmp_path: Path) -> None:
    """Stimmen die Dateirechte mit dem Soll überein, liefert True."""
    mod = _make_postfix()
    target = tmp_path / "sasl_passwd"
    target.write_text("x")
    target.chmod(0o600)
    assert mod._check_file_mode(str(target), 0o600, "Testdatei") is True


def test_check_file_mode_mismatch(tmp_path: Path) -> None:
    """Weichen die Dateirechte vom Soll ab, liefert False."""
    mod = _make_postfix()
    target = tmp_path / "sasl_passwd"
    target.write_text("x")
    target.chmod(0o644)
    assert mod._check_file_mode(str(target), 0o600, "Testdatei") is False


def test_check_file_mode_missing_file_returns_false(
    tmp_path: Path,
) -> None:
    """Eine fehlende Datei liefert bei der Rechteprüfung False."""
    mod = _make_postfix()
    target = tmp_path / "missing"
    assert mod._check_file_mode(str(target), 0o600, "Testdatei") is False


def test_check_aliases_block_true_when_markers_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sind beide Markerzeilen vorhanden, liefert _check_aliases_block True."""
    mod = _make_postfix()
    aliases = tmp_path / "aliases"
    aliases.write_text("# BEGIN aliases-root\npostmaster: root\n# END aliases-root\n")
    monkeypatch.setattr(Postfix, "ALIASES", str(aliases))
    assert mod._check_aliases_block() is True


def test_check_aliases_block_false_when_markers_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlen die Markerzeilen, liefert _check_aliases_block False."""
    mod = _make_postfix()
    aliases = tmp_path / "aliases"
    aliases.write_text("postmaster: root\n")
    monkeypatch.setattr(Postfix, "ALIASES", str(aliases))
    assert mod._check_aliases_block() is False


# --- _test_mail_content ---


def test_test_mail_content_includes_fqdn_admin_mail_and_token() -> None:
    """Die Testmail enthält fqdn im Betreff, admin_mail als Empfänger und token."""
    content = _test_mail_content("server.example.com", "admin@example.com", "abc123")
    assert (
        "Subject: secure-base postfix: Zustellungsnachweis server.example.com"
        in content
    )
    assert "To: admin@example.com" in content
    assert "abc123" in content


# --- _SendMailAction ---


def _write_script(tmp_path: Path, name: str, body: str) -> str:
    """Legt ein ausführbares Fake-Programm unter tmp_path an und liefert den Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/usr/bin/env python3\n{body}")
    script.chmod(0o755)
    return str(script)


def test_send_mail_action_success_reads_stdin(tmp_path: Path) -> None:
    """Ein erfolgreiches Programm liefert Status finished und Returncode 0."""
    script = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    action = _SendMailAction(
        command=[script, "admin@example.com"], content="Subject: x\n\nbody\n", timeout=5
    )
    assert action.run() == "finished"
    assert action.returncode == 0


def test_send_mail_action_failure_raises_with_stderr(tmp_path: Path) -> None:
    """Ein fehlschlagendes Programm erzeugt ActionError; stderr bleibt lesbar."""
    script = _write_script(
        tmp_path,
        "fake-sendmail-fail",
        "import sys\nsys.stdin.read()\n"
        "sys.stderr.write('relay refused\\n')\nsys.exit(1)\n",
    )
    action = _SendMailAction(command=[script], content="x", timeout=5)
    with pytest.raises(ActionError, match="endete mit Code 1"):
        action.run()
    assert action.status == "failed"
    assert "relay refused" in action.stderr


def test_send_mail_action_timeout_raises(tmp_path: Path) -> None:
    """Überschreitet das Programm die Zeitgrenze, erzeugt run() ActionError."""
    script = _write_script(
        tmp_path, "fake-sendmail-slow", "import time\ntime.sleep(5)\n"
    )
    action = _SendMailAction(command=[script], content="x", timeout=0.2)
    with pytest.raises(ActionError, match="Zeitgrenze"):
        action.run()
    assert action.status == "failed"


def test_send_mail_action_missing_program_raises() -> None:
    """Ein nicht startbares Programm erzeugt ActionError."""
    action = _SendMailAction(
        command=["/no/such/sendmail-binary"], content="x", timeout=5
    )
    with pytest.raises(ActionError, match="nicht gestartet werden"):
        action.run()
    assert action.status == "failed"


# --- Zustellungsnachweis: _send_test_mail, _queue_entries, _deferred_reasons ---


def test_send_test_mail_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Läuft sendmail erfolgreich durch, liefert _send_test_mail True."""
    mod = _make_postfix()
    script = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", script)
    assert mod._send_test_mail("token123") is True


def test_send_test_mail_failure_returns_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt sendmail fehl, liefert _send_test_mail False und meldet den Grund."""
    mod = _make_postfix()
    script = _write_script(
        tmp_path,
        "fake-sendmail-fail",
        "import sys\nsys.stdin.read()\n"
        "sys.stderr.write('relay refused\\n')\nsys.exit(1)\n",
    )
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", script)
    assert mod._send_test_mail("token123") is False
    payloads = _sent_payloads(mod)
    assert any(
        "sendmail fehlgeschlagen" in str(p) and "relay refused" in str(p)
        for p in payloads
    )


def test_queue_entries_empty_when_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine leere postqueue-Ausgabe liefert eine leere Liste."""
    mod = _make_postfix()
    script = _write_script(tmp_path, "fake-postqueue-empty", "")
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", script)
    assert mod._queue_entries() == []


def test_queue_entries_parses_json_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Jede JSON-Zeile der postqueue-Ausgabe wird zu einem Eintrag."""
    mod = _make_postfix()
    script = _write_script(
        tmp_path,
        "fake-postqueue",
        'print(\'{"recipients": [{"address": "admin@example.com"}]}\')\n',
    )
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", script)
    assert mod._queue_entries() == [{"recipients": [{"address": "admin@example.com"}]}]


def test_queue_entries_command_failure_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schlägt der postqueue-Aufruf fehl, liefert _queue_entries None."""
    mod = _make_postfix()
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", "/bin/false")
    assert mod._queue_entries() is None


def test_queue_entries_invalid_json_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine nicht als JSON lesbare Zeile liefert _queue_entries None."""
    mod = _make_postfix()
    script = _write_script(tmp_path, "fake-postqueue-bad", "print('not json')\n")
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", script)
    assert mod._queue_entries() is None


def test_deferred_reasons_collects_present_reasons() -> None:
    """Nur Empfänger mit gesetztem delay_reason liefern einen Eintrag."""
    mod = _make_postfix()
    entries = [
        {"recipients": [{"address": "a@x", "delay_reason": "connection timed out"}]},
        {"recipients": [{"address": "b@x"}]},
    ]
    assert mod._deferred_reasons(entries) == ["connection timed out"]


def test_deferred_reasons_empty_when_no_reason_present() -> None:
    """Ohne delay_reason liefert _deferred_reasons eine leere Liste."""
    mod = _make_postfix()
    entries = [{"recipients": [{"address": "a@x"}]}]
    assert mod._deferred_reasons(entries) == []


# --- _check_delivery ---


def test_check_delivery_succeeds_when_queue_empties(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verlässt die Testmail die Queue, liefert _check_delivery 0."""
    mod = _make_postfix()
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(tmp_path, "fake-postqueue-empty", "")
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    assert mod._check_delivery() == 0


def test_check_delivery_fails_when_sendmail_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schlägt bereits sendmail fehl, liefert _check_delivery 1 ohne Queue-Abfrage."""
    mod = _make_postfix()
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", "/bin/false")
    assert mod._check_delivery() == 1


def test_check_delivery_fails_when_deferred(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bleibt die Testmail deferred, liefert _check_delivery 1 mit Queue-Grund."""
    mod = _make_postfix()
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(
        tmp_path,
        "fake-postqueue-deferred",
        "import json\n"
        'print(json.dumps({"recipients": [{"address": "admin@example.com",'
        ' "delay_reason": "relay access denied"}]}))\n',
    )
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_ATTEMPTS", 2)
    assert mod._check_delivery() == 1
    payloads = _sent_payloads(mod)
    assert any("relay access denied" in str(p) for p in payloads)


def test_check_delivery_fails_after_attempts_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bleibt die Queue non-leer ohne Grund, liefert _check_delivery nach den
    Versuchen 1."""
    mod = _make_postfix()
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(
        tmp_path,
        "fake-postqueue-stuck",
        "import json\n"
        'print(json.dumps({"recipients": [{"address": "admin@example.com"}]}))\n',
    )
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_ATTEMPTS", 2)
    assert mod._check_delivery() == 1
