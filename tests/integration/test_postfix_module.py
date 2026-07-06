"""Integrationstest für secure_base.modules.postfix.

Startet Postfix.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn) — Begründung siehe test_base_module.py. Die
Systembefehle werden durch harmlose Platzhalter ersetzt; für postmap
übernimmt ein winziges Fake-Skript zusätzlich dessen Nebenwirkung (Anlegen
der .db-Datei), da der folgende Schritt (Rechte auf sasl_passwd.db setzen)
davon abhängt. Für den abschließenden Zustellungsnachweis liefert
/usr/bin/true standardmäßig eine leere Postfix-Queue (Erfolgsfall); die
Fehlschlag-Tests setzen dafür eigene Fake-Skripte ein.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.postfix import Postfix


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


def _make_fake_postmap(tmp_path: Path) -> str:
    """Baut ein Fake-postmap: legt <arg>.db an, sonst folgenlos.

    Der echte postmap-Aufruf erzeugt aus der Quelldatei eine .db-Datenbank;
    der nachfolgende Schritt "sasl_passwd.db-Rechte setzen" braucht diese
    Datei. Ein reiner No-Op-Platzhalter (wie /usr/bin/true) würde sie nicht
    anlegen, daher dieses winzige Fake-Skript.
    """
    script = tmp_path / "fake-postmap"
    script.write_text(
        "#!/usr/bin/env python3\nimport sys\nopen(sys.argv[1] + '.db', 'w').close()\n"
    )
    script.chmod(0o755)
    return str(script)


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Postfix, MagicMock]:
    """Baut ein Postfix-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(Postfix, "DEBCONF_SET_SELECTIONS", "/usr/bin/true")
    monkeypatch.setattr(Postfix, "POSTCONF_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postfix, "POSTMAP_BIN", _make_fake_postmap(tmp_path))
    monkeypatch.setattr(Postfix, "NEWALIASES_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postfix, "SYSTEMCTL_BIN", "/usr/bin/true")
    # /usr/bin/true ignoriert stdin/Argumente und liefert Returncode 0 bzw.
    # (als postqueue-Platzhalter) eine leere Ausgabe — entspricht einer
    # zugestellten Testmail bzw. einer leeren Queue.
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postfix, "POSTQUEUE_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_INTERVAL", 0)
    monkeypatch.setattr(Postfix, "MAIN_CF", str(tmp_path / "main.cf"))
    monkeypatch.setattr(Postfix, "SASL_PASSWD", str(tmp_path / "sasl_passwd"))
    monkeypatch.setattr(
        Postfix, "RECIPIENT_CANONICAL", str(tmp_path / "recipient_canonical")
    )
    monkeypatch.setattr(Postfix, "ALIASES", str(tmp_path / "aliases"))
    monkeypatch.setattr(Postfix, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Postfix, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)

    (tmp_path / "main.cf").write_text("")
    (tmp_path / "aliases").write_text("")

    conn = MagicMock()
    mod = Postfix(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = "server.example.com"
    mod.admin_mail = "admin@example.com"
    mod.relay_host = "smtp.example.com"
    mod.relay_port = "587"
    mod.relay_user = "relayuser"
    mod.relay_password = "s3cret"  # noqa: S105 — Testwert, kein echtes Geheimnis
    return mod, conn


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, keine Fehlermeldung."""
    mod, conn = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "postfix neu laden" in messages
    assert "Zustellung prüfen" in messages
    assert "Testmail zugestellt — Queue leer" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert (tmp_path / "sasl_passwd").exists()
    assert (tmp_path / "recipient_canonical").exists()
    assert "relayhost = [smtp.example.com]:587" in (tmp_path / "main.cf").read_text()
    assert "root:       admin@example.com" in (tmp_path / "aliases").read_text()


def test_install_does_not_leak_relay_password_in_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Das Klartext-Passwort erscheint in keiner gesendeten Meldung."""
    mod, conn = _make_module(tmp_path, monkeypatch)

    mod.start()

    messages = _sent_messages(conn)
    assert not any("s3cret" in str(m) for m in messages)


def test_install_sasl_passwd_has_0600_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """sasl_passwd wird mit den Rechten 0600 angelegt."""
    mod, _conn = _make_module(tmp_path, monkeypatch)

    mod.start()

    mode = (tmp_path / "sasl_passwd").stat().st_mode & 0o777
    assert mode == 0o600


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Postfix, "NEWALIASES_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: aliases-Datenbank aktualisieren" in messages
    assert "postfix aktivieren" not in messages


def _make_fake_postqueue_deferred(tmp_path: Path) -> str:
    """Baut ein Fake-postqueue: meldet dauerhaft eine deferred Testmail."""
    script = tmp_path / "fake-postqueue-deferred"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        'print(json.dumps({"recipients": [{"address": "admin@example.com",'
        ' "delay_reason": "relay access denied"}]}))\n'
    )
    script.chmod(0o755)
    return str(script)


def test_install_fails_when_test_mail_stays_deferred(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bleibt die Testmail deferred, liefert install 1 mit dem Queue-Grund."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Postfix, "POSTQUEUE_BIN", _make_fake_postqueue_deferred(tmp_path)
    )
    monkeypatch.setattr(Postfix, "DELIVERY_CHECK_ATTEMPTS", 2)

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Zustellung prüfen" in messages
    assert any("relay access denied" in str(m) for m in messages)


def test_install_fails_when_sendmail_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt sendmail fehl, liefert install 1 ohne Queue-Abfrage."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Postfix, "SENDMAIL_BIN", "/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Zustellung prüfen" in messages
    assert any("sendmail fehlgeschlagen" in str(m) for m in messages)


def test_install_rejects_invalid_relay_host_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiger relay_host bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.relay_host = "smtp_invalid!"

    with pytest.raises(ModuleError, match="Ungültiger Relay-Host"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check vergleicht Ist- und Soll-Werte und meldet Abweichungen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"
    # /usr/bin/true liefert keine Ausgabe; weicht daher von main.cf-Sollwerten ab.
    # Auch sasl_passwd/recipient_canonical/aliases fehlen noch (kein install-Lauf).

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("main.cf relayhost" in str(m) and "soll" in str(m) for m in messages)


def test_check_all_ok_after_successful_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nach erfolgreichem install meldet check main.cf-Direktiven als OK."""
    mod, _conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    check_conn = MagicMock()
    check_mod = Postfix(conn=check_conn, loglevel=LogLevel.INFO)
    check_mod.operation = "check"
    check_mod.fqdn = mod.fqdn
    check_mod.admin_mail = mod.admin_mail
    check_mod.relay_host = mod.relay_host
    check_mod.relay_port = mod.relay_port
    check_mod.relay_user = mod.relay_user
    check_mod.relay_password = mod.relay_password

    # postconf -nh main.cf-Wert simulieren: /usr/bin/true liefert leere Ausgabe,
    # main.cf-Direktiven weichen daher weiterhin ab (kein echtes postconf im
    # Test); die restigen, dateibasierten Prüfungen sind hier von Interesse.
    result = check_mod.start()

    messages = _sent_messages(check_conn)
    assert any("sasl_passwd-Rechte" in str(m) and "OK" in str(m) for m in messages)
    assert any("recipient_canonical" in str(m) and "OK" in str(m) for m in messages)
    assert any("root-Weiterleitung" in str(m) and "OK" in str(m) for m in messages)
    assert result == 1
