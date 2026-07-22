"""Unit-Tests für secure_base.modules.postfix."""

from pathlib import Path
from typing import cast
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
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


class _NoOpAptAction(AptAction):
    """Ersetzt AptAction für Tests: läuft immer erfolgreich durch, ohne apt-get."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


class _NoOpSystemdAction(SystemdServiceAction):
    """Ersetzt SystemdServiceAction für Tests: läuft immer erfolgreich durch."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


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
    mod.force_overwrite = "no"
    mod.backup_run_dir = "/var/backup/secure-base/test-lauf"
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
        "force_overwrite",
        "backup_run_dir",
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
    assert isinstance(content, bytes)
    text = content.decode("ascii")
    assert "Subject: secure-base server.example.com:" in text
    assert "=?utf-8?q?" in text
    assert "To: admin@example.com" in text
    assert "abc123" in text


def test_test_mail_content_is_ascii_only() -> None:
    """Die serialisierte Testmail besteht ausschließlich aus ASCII-Bytes."""
    content = _test_mail_content("server.example.com", "admin@example.com", "abc123")
    assert all(byte < 128 for byte in content)


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
        command=[script, "admin@example.com"],
        content=b"Subject: x\n\nbody\n",
        timeout=5,
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
    action = _SendMailAction(command=[script], content=b"x", timeout=5)
    with pytest.raises(ActionError, match="endete mit Code 1"):
        action.run()
    assert action.status == "failed"
    assert "relay refused" in action.stderr


def test_send_mail_action_timeout_raises(tmp_path: Path) -> None:
    """Überschreitet das Programm die Zeitgrenze, erzeugt run() ActionError."""
    script = _write_script(
        tmp_path, "fake-sendmail-slow", "import time\ntime.sleep(5)\n"
    )
    action = _SendMailAction(command=[script], content=b"x", timeout=0.2)
    with pytest.raises(ActionError, match="Zeitgrenze"):
        action.run()
    assert action.status == "failed"


def test_send_mail_action_missing_program_raises() -> None:
    """Ein nicht startbares Programm erzeugt ActionError."""
    action = _SendMailAction(
        command=["/no/such/sendmail-binary"], content=b"x", timeout=5
    )
    with pytest.raises(ActionError, match="nicht gestartet werden"):
        action.run()
    assert action.status == "failed"


def _write_mail_log(tmp_path: Path, status_line: str) -> str:
    """Legt eine Mail-Log-Datei mit genau einer Statuszeile an und liefert den Pfad."""
    mail_log = tmp_path / "mail.log"
    mail_log.write_text(status_line + "\n")
    return str(mail_log)


_SENT_LINE = (
    "Jul  6 10:00:00 host postfix/smtp[123]: ABC123: to=<admin@example.com>, "
    "relay=smtp.example.com[1.2.3.4]:587, delay=0.1, delays=0/0/0/0.1, dsn=2.0.0, "
    "status=sent (250 2.0.0 Ok: queued as 12345)"
)
_BOUNCED_LINE = (
    "Jul  6 10:00:00 host postfix/smtp[123]: ABC123: to=<admin@example.com>, "
    "relay=none, delay=0.1, delays=0/0/0/0.1, dsn=5.1.2, "
    "status=bounced (host smtp.example.com said: 550 5.1.2 unknown recipient)"
)


def _apply_sent_mail_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Lenkt MAIL_LOG auf eine Datei mit einer status=sent-Zeile für admin_mail um."""
    monkeypatch.setattr(Postfix, "MAIL_LOG", _write_mail_log(tmp_path, _SENT_LINE))
    monkeypatch.setattr(Postfix, "DELIVERY_LOG_CHECK_INTERVAL", 0)


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


# --- _check_delivery_log (Auswertung selbst: siehe tests/unit/test_mail_check.py) ---


def test_check_delivery_log_fails_when_no_matching_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Findet sich keine passende Zeile, liefert _check_delivery_log
    fail-closed 1."""
    mod = _make_postfix()
    monkeypatch.setattr(Postfix, "MAIL_LOG", _write_mail_log(tmp_path, "no match here"))
    monkeypatch.setattr(Postfix, "DELIVERY_LOG_CHECK_ATTEMPTS", 1)
    monkeypatch.setattr(Postfix, "DELIVERY_LOG_CHECK_INTERVAL", 0)
    assert mod._check_delivery_log("2026-01-01 00:00:00") == 1
    payloads = _sent_payloads(mod)
    assert any("Zustellstatus nicht nachweisbar" in str(p) for p in payloads)


# --- _check_delivery ---


def test_check_delivery_succeeds_when_queue_empties_and_log_shows_sent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verlässt die Testmail die Queue und zeigt das Mail-Log status=sent,
    liefert _check_delivery 0."""
    mod = _make_postfix()
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(tmp_path, "fake-postqueue-empty", "")
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    _apply_sent_mail_log(tmp_path, monkeypatch)
    assert mod._check_delivery() == 0


def test_check_delivery_fails_when_queue_empties_but_log_shows_bounced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Zeigt das Mail-Log status=bounced für admin_mail, liefert _check_delivery
    1 mit dem Fehlertext aus der Zeile — die frühere Falsch-positiv-Lücke
    (Queue leer = Erfolg trotz Bounce)."""
    mod = _make_postfix()
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(tmp_path, "fake-postqueue-empty", "")
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    monkeypatch.setattr(Postfix, "MAIL_LOG", _write_mail_log(tmp_path, _BOUNCED_LINE))
    monkeypatch.setattr(Postfix, "DELIVERY_LOG_CHECK_INTERVAL", 0)
    assert mod._check_delivery() == 1
    payloads = _sent_payloads(mod)
    assert any(
        "unzustellbar" in str(p) and "unknown recipient" in str(p) for p in payloads
    )


def test_check_delivery_fails_when_queue_empty_and_no_log_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist die Queue leer, aber findet sich keine passende Log-Zeile, liefert
    _check_delivery fail-closed 1 (kein stiller Erfolg)."""
    mod = _make_postfix()
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(tmp_path, "fake-postqueue-empty", "")
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    monkeypatch.setattr(Postfix, "MAIL_LOG", _write_mail_log(tmp_path, "no match here"))
    monkeypatch.setattr(Postfix, "DELIVERY_LOG_CHECK_ATTEMPTS", 1)
    monkeypatch.setattr(Postfix, "DELIVERY_LOG_CHECK_INTERVAL", 0)
    assert mod._check_delivery() == 1
    payloads = _sent_payloads(mod)
    assert any("Zustellstatus nicht nachweisbar" in str(p) for p in payloads)


def test_check_delivery_falls_back_to_journalctl_when_mail_log_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt MAIL_LOG, liest _check_delivery den Zustellstatus über
    JOURNALCTL_BIN nach."""
    mod = _make_postfix()
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(tmp_path, "fake-postqueue-empty", "")
    journalctl = _write_script(tmp_path, "fake-journalctl", f"print({_SENT_LINE!r})\n")
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    monkeypatch.setattr(Postfix, "MAIL_LOG", str(tmp_path / "missing-mail.log"))
    monkeypatch.setattr(Postfix, "JOURNALCTL_BIN", journalctl)
    monkeypatch.setattr(Postfix, "DELIVERY_LOG_CHECK_INTERVAL", 0)
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


# --- _test ---


def test_test_reuses_check_delivery_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_test liefert 0, wenn _check_delivery die Zustellung nachweist."""
    mod = _make_postfix()
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(tmp_path, "fake-postqueue-empty", "")
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    _apply_sent_mail_log(tmp_path, monkeypatch)
    assert mod._test() == 0


def test_test_fails_when_check_delivery_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_test liefert 1 und meldet den Fehlschlag, wenn sendmail scheitert."""
    mod = _make_postfix()
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", "/bin/false")
    assert mod._test() == 1
    payloads = _sent_payloads(mod)
    assert any(
        "fehlgeschlagen: Funktionstest: Zustellung prüfen" in str(p) for p in payloads
    )


def test_test_does_not_change_config_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_test schreibt weder main.cf noch sasl_passwd/recipient_canonical/aliases."""
    mod = _make_postfix()
    main_cf = tmp_path / "main.cf"
    sasl_passwd = tmp_path / "sasl_passwd"
    aliases = tmp_path / "aliases"
    monkeypatch.setattr(Postfix, "MAIN_CF", str(main_cf))
    monkeypatch.setattr(Postfix, "SASL_PASSWD", str(sasl_passwd))
    monkeypatch.setattr(Postfix, "ALIASES", str(aliases))
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(tmp_path, "fake-postqueue-empty", "")
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    _apply_sent_mail_log(tmp_path, monkeypatch)

    assert mod._test() == 0

    assert not main_cf.exists()
    assert not sasl_passwd.exists()
    assert not aliases.exists()


# --- _delete_step ---


def test_delete_step_returns_none_for_missing_file(tmp_path: Path) -> None:
    """Fehlt die Datei bereits, liefert _delete_step None (Idempotenz)."""
    mod = _make_postfix()
    target = tmp_path / "missing"
    assert mod._delete_step(str(target), "Testdatei entfernen", safe_mode=True) is None
    payloads = _sent_payloads(mod)
    assert any("Testdatei entfernen: bereits entfernt" in str(p) for p in payloads)


def test_delete_step_returns_action_for_existing_file(tmp_path: Path) -> None:
    """Ist die Datei vorhanden, liefert _delete_step Label und DeleteFileAction."""
    mod = _make_postfix()
    target = tmp_path / "present"
    target.write_text("x")
    step = mod._delete_step(str(target), "Testdatei entfernen", safe_mode=False)
    assert step is not None
    label, action = step
    assert label == "Testdatei entfernen"
    assert action.run() == "finished"
    assert not target.exists()


# --- _uninstall ---


def _write_main_cf(tmp_path: Path, mod: Postfix) -> Path:
    """Legt main.cf mit allen von _install gesetzten Direktiven an."""
    main_cf = tmp_path / "main.cf"
    content = "".join(f"{key} = {value}\n" for key, value in mod._main_cf_settings())
    main_cf.write_text(content)
    return main_cf


def _write_aliases(tmp_path: Path, admin_mail: str) -> Path:
    """Legt /etc/aliases mit gesetztem aliases-root-Block an."""
    aliases = tmp_path / "aliases"
    aliases.write_text(
        f"# BEGIN aliases-root\npostmaster: root\nroot:       {admin_mail}\n"
        "# END aliases-root\n"
    )
    return aliases


def _prepare_uninstall_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Postfix:
    """Baut ein Postfix-Modul mit vollständig „installierten“ eigenen Dateien."""
    mod = _make_postfix()
    mod.operation = "uninstall"
    mod.backup_run_dir = str(tmp_path / "backup-run")
    main_cf = _write_main_cf(tmp_path, mod)
    aliases = _write_aliases(tmp_path, mod.admin_mail)
    sasl_passwd = tmp_path / "sasl_passwd"
    sasl_passwd.write_text("[smtp.example.com]:587 relayuser:s3cret\n")
    sasl_passwd_db = tmp_path / "sasl_passwd.db"
    sasl_passwd_db.write_text("")
    recipient_canonical = tmp_path / "recipient_canonical"
    recipient_canonical.write_text("/.+/   admin@example.com\n")
    recipient_canonical_db = tmp_path / "recipient_canonical.db"
    recipient_canonical_db.write_text("")

    monkeypatch.setattr(Postfix, "MAIN_CF", str(main_cf))
    monkeypatch.setattr(Postfix, "ALIASES", str(aliases))
    monkeypatch.setattr(Postfix, "SASL_PASSWD", str(sasl_passwd))
    monkeypatch.setattr(Postfix, "RECIPIENT_CANONICAL", str(recipient_canonical))
    monkeypatch.setattr(Postfix, "SYSTEMCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postfix, "NEWALIASES_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postfix, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)
    monkeypatch.setattr(Postfix, "APT_ACTION_CLS", _NoOpAptAction)
    return mod


def test_uninstall_removes_all_own_files_and_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall entfernt sasl_passwd, recipient_canonical, main.cf-Direktiven
    und den aliases-Block vollständig."""
    mod = _prepare_uninstall_fixture(tmp_path, monkeypatch)

    result = mod._uninstall()

    assert result == 0
    assert not (tmp_path / "sasl_passwd").exists()
    assert not (tmp_path / "sasl_passwd.db").exists()
    assert not (tmp_path / "recipient_canonical").exists()
    assert not (tmp_path / "recipient_canonical.db").exists()
    main_cf_content = (tmp_path / "main.cf").read_text()
    for key, _ in mod._main_cf_settings():
        assert key not in main_cf_content
    aliases_content = (tmp_path / "aliases").read_text()
    assert "BEGIN aliases-root" not in aliases_content
    assert "root:" not in aliases_content


def test_uninstall_is_idempotent_on_second_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter uninstall-Lauf auf bereits entfernten Dateien liefert
    ebenfalls 0, ohne Fehlermeldung."""
    mod = _prepare_uninstall_fixture(tmp_path, monkeypatch)
    assert mod._uninstall() == 0

    second_conn_payloads_before = len(_sent_payloads(mod))
    result = mod._uninstall()

    assert result == 0
    payloads = _sent_payloads(mod)[second_conn_payloads_before:]
    assert not any(str(p).startswith("fehlgeschlagen:") for p in payloads)
    assert any("sasl_passwd entfernen: bereits entfernt" in str(p) for p in payloads)
    assert any(
        "recipient_canonical entfernen: bereits entfernt" in str(p) for p in payloads
    )


def test_uninstall_does_not_leak_relay_password_in_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Das Klartext-Passwort erscheint in keiner gesendeten Meldung."""
    mod = _prepare_uninstall_fixture(tmp_path, monkeypatch)

    mod._uninstall()

    payloads = _sent_payloads(mod)
    assert not any("s3cret" in str(p) for p in payloads)


def test_uninstall_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden
    Schritten."""
    mod = _prepare_uninstall_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(Postfix, "NEWALIASES_BIN", "/usr/bin/false")

    result = mod._uninstall()

    assert result == 1
    payloads = _sent_payloads(mod)
    assert "fehlgeschlagen: aliases-Datenbank aktualisieren" in payloads
    assert "Pakete entfernen" not in payloads


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, Pakete, Dateien, Werte und Dienst."""
    values = {
        "fqdn": "server.example.com",
        "admin_mail": "admin@example.com",
        "relay_host": "smtp.example.com",
        "relay_port": "587",
        "relay_user": "relayuser",
    }
    section = Postfix.doc(values)
    assert section.startswith("\n## Mail-Versand\n\n")
    assert "**Pakete:**" in section
    for package in Postfix.PACKAGES:
        assert package in section
    assert f"`{Postfix.MAIN_CF}`" in section
    assert "relayhost = [smtp.example.com]:587" in section
    assert "smtp_tls_security_level = encrypt" in section
    assert "inet_interfaces = loopback-only" in section
    assert f"`{Postfix.ALIASES}`" in section
    assert "root: admin@example.com" in section
    assert "**Dienste:** postfix (enabled, aktiv nach install)" in section


def test_doc_marks_missing_values_as_leer_default() -> None:
    """Fehlende Werte in values erscheinen als "(leer/Default)"."""
    section = Postfix.doc({})
    assert "relayhost = [(leer/Default)]:(leer/Default)" in section
    assert "root: (leer/Default)" in section


def test_doc_never_leaks_relay_password() -> None:
    """relay_password erscheint weder als Name noch als Wert in doc()."""
    values = {
        "fqdn": "server.example.com",
        "admin_mail": "admin@example.com",
        "relay_host": "smtp.example.com",
        "relay_port": "587",
        "relay_user": "relayuser",
        "relay_password": "GEHEIM-X",
    }
    section = Postfix.doc(values)
    assert "GEHEIM-X" not in section
    assert "relay_password" not in section


# --- start()-Verzweigung ---


def test_start_dispatches_uninstall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """operation='uninstall' ruft _uninstall auf."""
    mod = _prepare_uninstall_fixture(tmp_path, monkeypatch)
    mod.operation = "uninstall"
    assert mod.start() == 0


def test_start_dispatches_test(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """operation='test' ruft _test auf."""
    mod = _make_postfix()
    mod.operation = "test"
    sendmail = _write_script(
        tmp_path, "fake-sendmail-ok", "import sys\nsys.stdin.read()\n"
    )
    postqueue = _write_script(tmp_path, "fake-postqueue-empty", "")
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", sendmail)
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", postqueue)
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    _apply_sent_mail_log(tmp_path, monkeypatch)
    assert mod.start() == 0
