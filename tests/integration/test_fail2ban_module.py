"""Integrationstest für secure_base.modules.fail2ban.

Startet Fail2ban.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn): Ein Spawn-Subprozess re-importiert das Modul in
einem frischen Interpreter und teilt keinen Zustand mit dem Testprozess,
sodass ein monkeypatch der Systembefehl-Konstanten dort nicht ankäme. Der
direkte Aufruf im Testprozess ersetzt die Systembefehle durch harmlose
Platzhalter (Plan Abschnitt 2.12) und prüft Ablauf, Meldungen und
Rückgabewert von Fail2ban. Die Aktionen selbst sind bereits in pifos
getestet.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.fail2ban import Fail2ban


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


class _FailingSystemdAction(SystemdServiceAction):
    """Ersetzt SystemdServiceAction für Tests: schlägt immer fehl."""

    def run(self) -> str:
        self.status = "failed"
        return self.status


def _make_executable(tmp_path: Path, content: str, name: str = "cmd.sh") -> str:
    """Legt ein ausführbares Shell-Script an und liefert dessen Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{content}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ignoreip: str = ""
) -> tuple[Fail2ban, MagicMock]:
    """Baut ein Fail2ban-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    jail_conf = tmp_path / "jail.conf"
    jail_conf.write_text("[DEFAULT]\nbantime = 10m\n", encoding="utf-8")

    monkeypatch.setattr(Fail2ban, "JAIL_CONF", str(jail_conf))
    monkeypatch.setattr(Fail2ban, "JAIL_LOCAL", str(tmp_path / "jail.local"))
    monkeypatch.setattr(Fail2ban, "DPKG_QUERY", "/usr/bin/true")
    monkeypatch.setattr(Fail2ban, "SYSTEMCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Fail2ban, "FAIL2BAN_CLIENT", "/usr/bin/true")
    monkeypatch.setattr(Fail2ban, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Fail2ban, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)

    conn = MagicMock()
    mod = Fail2ban(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.ignoreip = ignoreip
    return mod, conn


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, jail.local angelegt."""
    mod, conn = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "Dienst starten" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert Path(tmp_path / "jail.local").exists()
    assert any("ohne ignoreip-Whitelist" in str(m) for m in messages)


def test_install_sets_ignoreip_whitelist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mit gesetztem ignoreip wird die Zeile in jail.local geschrieben."""
    mod, conn = _make_module(tmp_path, monkeypatch, ignoreip="203.0.113.7")

    result = mod.start()

    assert result == 0
    content = Path(tmp_path / "jail.local").read_text(encoding="utf-8")
    assert "ignoreip = 127.0.0.1/8 ::1 203.0.113.7" in content
    messages = _sent_messages(conn)
    assert any("mit ignoreip-Whitelist" in str(m) for m in messages)


def test_install_skips_existing_jail_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine bereits vorhandene jail.local wird nicht überschrieben."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    hand_tuned = "# hand-getunt\n"
    Path(mod.JAIL_LOCAL).write_text(hand_tuned, encoding="utf-8")

    result = mod.start()

    assert result == 0
    assert Path(mod.JAIL_LOCAL).read_text(encoding="utf-8") == hand_tuned
    messages = _sent_messages(conn)
    assert any("Kopie übersprungen" in str(m) for m in messages)


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Fail2ban, "JAIL_CONF", str(tmp_path / "fehlt.conf"))

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: jail.local anlegen" in messages
    assert "Dienst aktivieren" not in messages


def test_install_rejects_invalid_ignoreip_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiges ignoreip-Token bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch, ignoreip="nicht-plausibel")

    with pytest.raises(ModuleError, match="Ungültiger ignoreip-Eintrag"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_missing_jail_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check meldet eine fehlende jail.local als Abweichung."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"
    # /usr/bin/true liefert weder "active"/"enabled" noch existiert jail.local.

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("fehlt" in str(m) for m in messages)


# --- Betriebsart uninstall ---


def test_uninstall_noop_when_package_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne installiertes Paket ist uninstall idempotent ohne weitere Schritte."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    # /usr/bin/true liefert keine Ausgabe — dpkg-query meldet damit "nicht installiert".
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("nichts zu tun" in str(m) for m in messages)
    assert "Dienst stoppen" not in messages


def test_uninstall_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist das Paket installiert, laufen alle Rückbau-Schritte durch."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Fail2ban,
        "DPKG_QUERY",
        _make_executable(tmp_path, "echo 'install ok installed'", "dpkg.sh"),
    )
    Path(mod.JAIL_LOCAL).write_text(
        "[sshd]\nignoreip = 127.0.0.1/8 ::1 203.0.113.7\nenabled = true\n",
        encoding="utf-8",
    )
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "Dienst stoppen" in messages
    assert "Dienst deaktivieren" in messages
    assert "ignoreip-Eingriff zurücknehmen" in messages
    assert "Paket entfernen" in messages
    content = Path(mod.JAIL_LOCAL).read_text(encoding="utf-8")
    assert "ignoreip" not in content
    assert "[sshd]" in content


def test_uninstall_skips_ignoreip_step_when_jail_local_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt jail.local, entfällt der ignoreip-Rückbauschritt."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Fail2ban,
        "DPKG_QUERY",
        _make_executable(tmp_path, "echo 'install ok installed'", "dpkg.sh"),
    )
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "ignoreip-Eingriff zurücknehmen" not in messages
    assert "Paket entfernen" in messages


def test_uninstall_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Fail2ban,
        "DPKG_QUERY",
        _make_executable(tmp_path, "echo 'install ok installed'", "dpkg.sh"),
    )
    monkeypatch.setattr(Fail2ban, "SYSTEMD_ACTION_CLS", _FailingSystemdAction)
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Dienst stoppen" in messages
    assert "Dienst deaktivieren" not in messages


# --- Betriebsart test ---


def test_test_operation_all_checks_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Antwortet der Daemon und ist der sshd-Jail abfragbar, liefert test 0."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Fail2ban,
        "DPKG_QUERY",
        _make_executable(tmp_path, "echo 'install ok installed'", "dpkg.sh"),
    )
    monkeypatch.setattr(
        Fail2ban,
        "FAIL2BAN_CLIENT",
        _make_executable(
            tmp_path,
            'case "$1" in\n'
            "  ping) echo pong ;;\n"
            "  status) echo 'Status for the jail: sshd' ;;\n"
            "esac",
            "fail2ban-client.sh",
        ),
    )
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "Daemon-Ping: pong" in messages
    assert any("sshd-Jail: " in str(m) for m in messages)


def test_test_operation_fails_when_package_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne installiertes Paket liefert test 1, ohne Ping oder Jail-Abfrage."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    # /usr/bin/true liefert keine Ausgabe — dpkg-query meldet "nicht installiert".
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("kein Funktionstest möglich" in str(m) for m in messages)


def test_test_operation_collects_both_checks_without_aborting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlgeschlagener Ping bricht den Jail-Status-Check nicht ab (sammelnd)."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Fail2ban,
        "DPKG_QUERY",
        _make_executable(tmp_path, "echo 'install ok installed'", "dpkg.sh"),
    )
    monkeypatch.setattr(
        Fail2ban,
        "FAIL2BAN_CLIENT",
        _make_executable(
            tmp_path,
            'case "$1" in\n'
            "  ping) echo nope ;;\n"
            "  status) echo 'Status for the jail: sshd' ;;\n"
            "esac",
            "fail2ban-client.sh",
        ),
    )
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("keine Antwort" in str(m) for m in messages)
    assert any("sshd-Jail: " in str(m) for m in messages)
