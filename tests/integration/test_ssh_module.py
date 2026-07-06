"""Integrationstest für secure_base.modules.ssh.

Startet Ssh.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn), analog zu tests/integration/test_base_module.py.
Alle Systembefehle (dpkg-query, getent, id, sshd, systemctl) sind über
Klassenattribute auf harmlose Platzhalter umgelenkt: entweder /usr/bin/true
oder ein kleines, im Test erzeugtes Stellvertreter-Skript. sshd_config und
/etc/pam.d/sshd sind tmp_path-Dateien, da LineInFileAction/BlockInFileAction
eine bestehende Zieldatei voraussetzen.
"""

import os
import pwd
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.ssh import SSHD_SETTINGS, Ssh

_MAIN_USER = "alice"
_ADMIN_MAIL = "admin@example.com"

_FAKE_GETENT = """#!/bin/sh
sub="$1"; shift
case "$sub" in
    passwd)
        user="$1"
        [ "${GETENT_USER_EXISTS:-1}" = "1" ] || exit 2
        printf '%s:x:1000:1000::%s:/bin/bash\\n' "$user" "${GETENT_HOME:?}"
        ;;
    *)
        exit 1
        ;;
esac
"""

_FAKE_ID = """#!/bin/sh
printf '%s\\n' "${FAKE_ID_GROUPS:-ssh-users alice}"
"""

_FAKE_DPKG_QUERY = """#!/bin/sh
printf '%s\\n' "${FAKE_DPKG_STATUS:-install ok installed}"
"""


def _sshd_t_output() -> str:
    """Baut eine sshd -T-Ausgabe, die zu SSHD_SETTINGS passt."""
    return "\n".join(f"{key.lower()} {value}" for key, value in SSHD_SETTINGS)


_FAKE_SSHD = f"""#!/bin/sh
case "$1" in
    -t)
        exit "${{FAKE_SSHD_T_EXIT:-0}}"
        ;;
    -T)
        printf '%s\\n' "${{FAKE_SSHD_CAPITAL_T_OUTPUT:-{_sshd_t_output()}}}"
        ;;
    *)
        exit 1
        ;;
esac
"""


class _NoOpSystemdAction(SystemdServiceAction):
    """Ersetzt SystemdServiceAction für Tests: läuft immer erfolgreich durch."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


def _write_stub(path: Path, content: str) -> str:
    """Schreibt ein ausführbares Stellvertreter-Skript und liefert dessen Pfad."""
    path.write_text(content, encoding="utf-8")
    path.chmod(0o700)
    return str(path)


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Ssh, MagicMock, Path]:
    """Baut ein Ssh-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    home = tmp_path / "home" / _MAIN_USER
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "authorized_keys").write_text(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n", encoding="utf-8"
    )
    (home / ".google_authenticator").write_text(
        "SECRETSECRETSECRET\n", encoding="utf-8"
    )

    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text("# baseline\n", encoding="utf-8")
    pam_sshd = tmp_path / "pam-sshd"
    pam_sshd.write_text("@include common-auth\n", encoding="utf-8")

    monkeypatch.setattr(Ssh, "SSHD_CONFIG", str(sshd_config))
    monkeypatch.setattr(Ssh, "PAM_SSHD", str(pam_sshd))
    monkeypatch.setattr(Ssh, "LOGIN_MAIL_SCRIPT", str(tmp_path / "login-mail.sh"))
    monkeypatch.setattr(
        Ssh, "DPKG_QUERY_BIN", _write_stub(tmp_path / "dpkg-query", _FAKE_DPKG_QUERY)
    )
    monkeypatch.setattr(
        Ssh, "GETENT_BIN", _write_stub(tmp_path / "getent", _FAKE_GETENT)
    )
    monkeypatch.setattr(Ssh, "ID_BIN", _write_stub(tmp_path / "id", _FAKE_ID))
    monkeypatch.setattr(Ssh, "SSHD_BIN", _write_stub(tmp_path / "sshd", _FAKE_SSHD))
    monkeypatch.setattr(Ssh, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)
    # login-mail-notification.sh landet im Test unter der eigenen UID, nicht
    # unter root — LOGIN_MAIL_OWNER existiert genau dafür (Testumlenkung
    # ohne Root-Rechte im Testlauf, siehe Klassenattribut-Kommentar in ssh.py).
    monkeypatch.setattr(Ssh, "LOGIN_MAIL_OWNER", pwd.getpwuid(os.getuid()).pw_name)

    monkeypatch.setenv("GETENT_USER_EXISTS", "1")
    monkeypatch.setenv("GETENT_HOME", str(home))
    monkeypatch.setenv("FAKE_ID_GROUPS", "ssh-users alice")

    conn = MagicMock()
    mod = Ssh(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = _ADMIN_MAIL
    mod.main_user = _MAIN_USER
    mod.ssh_enable_login_mail = "yes"
    mod.ssh_enable_challenge_response_auth = "yes"
    return mod, conn, home


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, keine Fehlermeldung."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert any("Vor dem Trennen" in str(m) for m in messages)

    sshd_config = Path(mod.SSHD_CONFIG).read_text(encoding="utf-8")
    for key, value in SSHD_SETTINGS:
        assert f"{key} {value}" in sshd_config
    assert "ChallengeResponseAuthentication yes" in sshd_config

    pam_sshd = Path(mod.PAM_SSHD).read_text(encoding="utf-8")
    assert not mod._pam_bypass_active()
    assert "# @include common-auth" in pam_sshd
    assert "auth required pam_google_authenticator.so" in pam_sshd
    assert "pam_exec.so seteuid" in pam_sshd

    login_mail_script = Path(mod.LOGIN_MAIL_SCRIPT).read_text(encoding="utf-8")
    assert _ADMIN_MAIL in login_mail_script
    assert Path(mod.LOGIN_MAIL_SCRIPT).stat().st_mode & 0o777 == 0o700


def test_install_challenge_response_disabled_removes_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ssh_enable_challenge_response_auth=no entfernt die Direktive vollständig."""
    mod, _conn, _home = _make_module(tmp_path, monkeypatch)
    mod.ssh_enable_challenge_response_auth = "no"
    Path(mod.SSHD_CONFIG).write_text(
        "ChallengeResponseAuthentication yes\n", encoding="utf-8"
    )

    result = mod.start()

    assert result == 0
    assert "ChallengeResponseAuthentication" not in Path(mod.SSHD_CONFIG).read_text(
        encoding="utf-8"
    )


def test_install_login_mail_disabled_skips_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ssh_enable_login_mail=no überspringt Skript und PAM-Zeile."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.ssh_enable_login_mail = "no"

    result = mod.start()

    assert result == 0
    assert not Path(mod.LOGIN_MAIL_SCRIPT).exists()
    messages = _sent_messages(conn)
    assert any("Login-Mail-Hook übersprungen" in str(m) for m in messages)


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_DPKG_STATUS", "unknown ok not-installed")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Paketvoraussetzungen prüfen" in messages
    assert "sshd_config härten" not in messages


def test_install_stops_when_user_not_in_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlende Gruppenmitgliedschaft von main_user bricht vor der Härtung ab."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_ID_GROUPS", "sudo")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Login-Voraussetzungen von main_user prüfen" in messages
    assert "sshd_config härten" not in messages


def test_install_stops_on_sshd_t_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein sshd -t-Fehler verhindert den Reload."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_SSHD_T_EXIT", "1")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: sshd-Konfiguration validieren und neu laden" in messages


def test_install_rejects_invalid_username_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiger Benutzername bricht vor dem ersten Schritt ab."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.main_user = "-invalid"

    with pytest.raises(ModuleError, match="Ungültiger Benutzername"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_full_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein bereits vollständig gehärteter Zustand liefert bei check 0."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    result = mod.start()
    assert result == 0, _sent_messages(conn)

    mod.operation = "check"
    result = mod.start()

    assert result == 0, _sent_messages(conn)


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine abweichende sshd_config-Direktive liefert bei check 1."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    mod.operation = "check"
    mismatched = _sshd_t_output().replace("permitrootlogin no", "permitrootlogin yes")
    monkeypatch.setenv("FAKE_SSHD_CAPITAL_T_OUTPUT", mismatched)

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("PermitRootLogin: ist yes, soll no" in str(m) for m in messages)


def test_check_reports_missing_pam_bypass_protection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine wieder aktive @include common-auth-Zeile liefert bei check 1."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    Path(mod.PAM_SSHD).write_text(
        Path(mod.PAM_SSHD).read_text(encoding="utf-8") + "@include common-auth\n",
        encoding="utf-8",
    )
    mod.operation = "check"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("weiterhin aktiv" in str(m) for m in messages)


# --- uninstall ---


def test_uninstall_reverts_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall nach install nimmt alle Härtungs-Eingriffe vollständig zurück."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    mod.operation = "uninstall"
    result = mod.start()

    assert result == 0, _sent_messages(conn)

    sshd_config = Path(mod.SSHD_CONFIG).read_text(encoding="utf-8")
    for key, _value in SSHD_SETTINGS:
        assert key not in sshd_config
    assert "ChallengeResponseAuthentication" not in sshd_config

    pam_sshd = Path(mod.PAM_SSHD).read_text(encoding="utf-8")
    assert "auth required pam_google_authenticator.so" not in pam_sshd
    assert "pam_exec.so seteuid" not in pam_sshd
    assert mod._pam_bypass_active() is True

    assert not Path(mod.LOGIN_MAIL_SCRIPT).exists()


def test_uninstall_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter uninstall-Lauf direkt nach dem ersten bleibt erfolgreich."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    mod.operation = "uninstall"
    assert mod.start() == 0
    result = mod.start()

    assert result == 0, _sent_messages(conn)
    assert mod._pam_bypass_active() is True


def test_uninstall_without_prior_install_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall auf einem ungehärteten Ausgangszustand bleibt erfolgreich."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)

    mod.operation = "uninstall"
    result = mod.start()

    assert result == 0, _sent_messages(conn)
    assert mod._pam_bypass_active() is True


def test_uninstall_stops_on_sshd_t_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein sshd -t-Fehler verhindert den Reload beim Rückbau."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    mod.operation = "uninstall"
    monkeypatch.setenv("FAKE_SSHD_T_EXIT", "1")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: sshd-Konfiguration validieren und neu laden" in messages


def test_uninstall_keeps_login_mail_hook_gone_when_disabled_at_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall bleibt erfolgreich, wenn install den Login-Mail-Hook nicht anlegt."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.ssh_enable_login_mail = "no"
    assert mod.start() == 0

    mod.operation = "uninstall"
    result = mod.start()

    assert result == 0, _sent_messages(conn)
    assert not Path(mod.LOGIN_MAIL_SCRIPT).exists()


# --- test ---


def test_test_returns_zero_on_valid_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """test liefert 0 bei syntaktisch gültiger sshd_config, ohne Systemänderung."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    sshd_config_before = Path(mod.SSHD_CONFIG).read_text(encoding="utf-8")
    pam_sshd_before = Path(mod.PAM_SSHD).read_text(encoding="utf-8")

    mod.operation = "test"
    result = mod.start()

    assert result == 0, _sent_messages(conn)
    assert Path(mod.SSHD_CONFIG).read_text(encoding="utf-8") == sshd_config_before
    assert Path(mod.PAM_SSHD).read_text(encoding="utf-8") == pam_sshd_before
    messages = _sent_messages(conn)
    assert any("sshd -t: OK" in str(m) for m in messages)


def test_test_returns_one_on_invalid_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """test liefert 1, wenn sshd -t fehlschlägt."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    monkeypatch.setenv("FAKE_SSHD_T_EXIT", "1")

    mod.operation = "test"
    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("sshd -t fehlgeschlagen" in str(m) for m in messages)
