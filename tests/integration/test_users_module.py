"""Integrationstest für secure_base.modules.users.

Startet Users.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn), analog zu tests/integration/test_base_module.py.
Alle Systembefehle (getent, groupadd, useradd, usermod, chpasswd, runuser,
dpkg, id, qrencode, sendmail) sind über Klassenattribute auf harmlose
Platzhalter umgelenkt: entweder /usr/bin/true oder ein kleines, im Test
erzeugtes Stellvertreter-Skript, dessen Antwort über Umgebungsvariablen
gesteuert wird. Der Fake-runuser legt bei einem google-authenticator-Aufruf
zusätzlich eine .google_authenticator-Testdatei an (Secret + Notfall-Codes),
damit die TOTP-Einrichtungsmail einen Inhalt zum Versenden hat; MAIL_LOG
zeigt eine status=sent-Zeile für admin_mail (Zustellungsnachweis). pwd/grp
sind global auf einen Fake-Eintrag umgelenkt, damit PermissionsAction
(chown auf main_user) ohne echtes Systemkonto und ohne root auskommt: ein
chown auf die eigene, bereits vorhandene UID/GID ist unter Linux auch
unprivilegiert erlaubt (kein Attributwechsel, kein CAP_CHOWN nötig).
"""

import grp
import os
import pwd
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.users import Users

_MAIN_USER = "alice"
_PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test@laptop"
_FQDN = "server.example.com"
_ADMIN_MAIL = "admin@example.com"

_FAKE_GETENT = """#!/bin/sh
sub="$1"; shift
case "$sub" in
    shadow)
        user="$1"
        if [ "$user" = "root" ]; then
            printf 'root:%s:19000:0:99999:7:::\\n' "${GETENT_ROOT_HASH:-!}"
        else
            printf '%s:%s:19000:0:99999:7:::\\n' "$user" "${GETENT_USER_HASH:-!}"
        fi
        ;;
    passwd)
        user="$1"
        if [ "${GETENT_USER_EXISTS:-1}" = "0" ] \
            && [ ! -e "${GETENT_USER_CREATED_MARKER:-/nonexistent-marker}" ]; then
            exit 2
        fi
        printf '%s:x:1000:1000::%s:%s\\n' \
            "$user" "${GETENT_HOME:-/nonexistent}" "${GETENT_SHELL:-/bin/bash}"
        ;;
    group)
        [ "${GETENT_GROUP_EXISTS:-1}" = "1" ] || exit 2
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
"""

_FAKE_ID = """#!/bin/sh
printf '%s\\n' "${FAKE_ID_GROUPS:-ssh-users alice}"
"""

_FAKE_USERADD = """#!/bin/sh
touch "${GETENT_USER_CREATED_MARKER:?}"
"""

_FAKE_USERDEL = """#!/bin/sh
touch "${USERDEL_CALLED_MARKER:?}"
"""

# Bei einem google-authenticator-Aufruf legt der Fake-runuser eine
# .google_authenticator-Testdatei unter $HOME an (Secret + Notfall-Codes),
# sonst folgenlos (entspricht dem bisherigen /usr/bin/true für
# _readable_as_user in der Betriebsart test).
_FAKE_RUNUSER = """#!/bin/sh
case "$*" in
    *google-authenticator*)
        printf '%s\\n' "TESTSECRETNOTREAL" > "$HOME/.google_authenticator"
        printf '11111111\\n22222222\\n' >> "$HOME/.google_authenticator"
        ;;
esac
exit 0
"""

_FAKE_QRENCODE = """#!/bin/sh
cat > "$2"
"""

_FAKE_SENDMAIL = """#!/bin/sh
cat >/dev/null
"""

_SENT_MAIL_LOG_LINE = (
    f"Jul  6 10:00:00 host postfix/smtp[123]: ABC123: to=<{_ADMIN_MAIL}>, "
    "relay=smtp.example.com[1.2.3.4]:587, delay=0.1, delays=0/0/0/0.1, dsn=2.0.0, "
    "status=sent (250 2.0.0 Ok: queued as 12345)"
)


class _NoOpAptAction(AptAction):
    """Ersetzt AptAction für Tests: läuft immer erfolgreich durch, ohne apt-get."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


def _write_stub(path: Path, content: str) -> str:
    """Schreibt ein ausführbares Stellvertreter-Skript und liefert dessen Pfad."""
    path.write_text(content, encoding="utf-8")
    path.chmod(0o700)
    return str(path)


def _patch_pwd_grp(monkeypatch: pytest.MonkeyPatch, user: str) -> None:
    """Lenkt pwd/grp global auf einen Fake-Eintrag für user auf die eigene UID/GID um.

    PermissionsAction löst owner/group über pwd.getpwnam/grp.getgrnam auf; ein
    chown auf die eigene, bereits vorhandene UID/GID gelingt unter Linux auch
    unprivilegiert (kein Attributwechsel). users._check_file_mode löst
    umgekehrt über pwd.getpwuid/grp.getgrgid auf — beide Richtungen werden
    hier auf denselben Fake-Namen abgebildet.
    """
    uid = os.getuid()
    gid = os.getgid()
    real_getpwnam = pwd.getpwnam
    real_getgrnam = grp.getgrnam
    real_pw = pwd.getpwuid(uid)
    real_gr = grp.getgrgid(gid)
    fake_pw = pwd.struct_passwd(
        (
            user,
            real_pw.pw_passwd,
            uid,
            gid,
            real_pw.pw_gecos,
            real_pw.pw_dir,
            real_pw.pw_shell,
        )
    )
    fake_gr = grp.struct_group((user, real_gr.gr_passwd, gid, real_gr.gr_mem))

    def fake_getpwnam(name: str) -> pwd.struct_passwd:
        return fake_pw if name == user else real_getpwnam(name)

    def fake_getpwuid(_uid: int) -> pwd.struct_passwd:
        return fake_pw

    def fake_getgrnam(name: str) -> grp.struct_group:
        return fake_gr if name == user else real_getgrnam(name)

    def fake_getgrgid(_gid: int) -> grp.struct_group:
        return fake_gr

    monkeypatch.setattr(pwd, "getpwnam", fake_getpwnam)
    monkeypatch.setattr(pwd, "getpwuid", fake_getpwuid)
    monkeypatch.setattr(grp, "getgrnam", fake_getgrnam)
    monkeypatch.setattr(grp, "getgrgid", fake_getgrgid)


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Users, MagicMock, Path]:
    """Baut ein Users-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    home = tmp_path / "home" / _MAIN_USER
    home.mkdir(parents=True)

    fake_getent = _write_stub(tmp_path / "fake_getent.sh", _FAKE_GETENT)
    fake_id = _write_stub(tmp_path / "fake_id.sh", _FAKE_ID)
    fake_useradd = _write_stub(tmp_path / "fake_useradd.sh", _FAKE_USERADD)
    fake_userdel = _write_stub(tmp_path / "fake_userdel.sh", _FAKE_USERDEL)
    fake_runuser = _write_stub(tmp_path / "fake_runuser.sh", _FAKE_RUNUSER)
    fake_qrencode = _write_stub(tmp_path / "fake_qrencode.sh", _FAKE_QRENCODE)
    fake_sendmail = _write_stub(tmp_path / "fake_sendmail.sh", _FAKE_SENDMAIL)

    monkeypatch.setattr(Users, "GETENT_BIN", fake_getent)
    monkeypatch.setattr(Users, "ID_BIN", fake_id)
    monkeypatch.setattr(Users, "DPKG_BIN", "/usr/bin/true")
    monkeypatch.setattr(Users, "GROUPADD_BIN", "/usr/bin/true")
    monkeypatch.setattr(Users, "USERADD_BIN", fake_useradd)
    monkeypatch.setattr(Users, "USERMOD_BIN", "/usr/bin/true")
    monkeypatch.setattr(Users, "CHPASSWD_BIN", "/usr/bin/true")
    monkeypatch.setattr(Users, "RUNUSER_BIN", fake_runuser)
    monkeypatch.setattr(Users, "GPASSWD_BIN", "/usr/bin/true")
    monkeypatch.setattr(Users, "GROUPDEL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Users, "USERDEL_BIN", fake_userdel)
    monkeypatch.setattr(Users, "PKILL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Users, "PKILL_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(Users, "TEST_BIN", "/usr/bin/true")
    monkeypatch.setattr(Users, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Users, "QRENCODE_BIN", fake_qrencode)
    monkeypatch.setattr(Users, "SENDMAIL_BIN", fake_sendmail)
    mail_log = tmp_path / "mail.log"
    mail_log.write_text(_SENT_MAIL_LOG_LINE + "\n")
    monkeypatch.setattr(Users, "MAIL_LOG", str(mail_log))
    monkeypatch.setattr(Users, "DELIVERY_LOG_CHECK_INTERVAL", 0)

    monkeypatch.setenv("GETENT_ROOT_HASH", "$6$roothash$xyz")
    monkeypatch.setenv("GETENT_USER_EXISTS", "1")
    monkeypatch.setenv(
        "GETENT_USER_CREATED_MARKER", str(tmp_path / "user_created.marker")
    )
    monkeypatch.setenv("GETENT_USER_HASH", "$6$userhash$xyz")
    monkeypatch.setenv("GETENT_HOME", str(home))
    monkeypatch.setenv("GETENT_SHELL", "/bin/bash")
    monkeypatch.setenv("GETENT_GROUP_EXISTS", "1")
    monkeypatch.setenv("FAKE_ID_GROUPS", "ssh-users alice")
    monkeypatch.setenv("USERDEL_CALLED_MARKER", str(tmp_path / "userdel_called.marker"))

    _patch_pwd_grp(monkeypatch, _MAIN_USER)

    conn = MagicMock()
    mod = Users(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = _FQDN
    mod.admin_mail = _ADMIN_MAIL
    mod.main_user = _MAIN_USER
    mod.main_user_password = "s3cret"  # noqa: S105 — Testwert, kein echtes Geheimnis
    mod.main_user_pubkey = _PUBKEY
    mod.uninstall_remove_user = "no"
    return mod, conn, home


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, keine Fehlermeldung."""
    mod, conn, home = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    authkeys = home / ".ssh" / "authorized_keys"
    assert authkeys.read_text(encoding="utf-8").splitlines() == [_PUBKEY]
    assert (home / ".ssh").stat().st_mode & 0o777 == 0o700
    assert authkeys.stat().st_mode & 0o777 == 0o600
    joined = "\n".join(str(m) for m in messages)
    assert f"TOTP-Einrichtungsmail an {_ADMIN_MAIL} versendet" in joined
    assert f"TOTP-Einrichtungsmail an {_ADMIN_MAIL} zugestellt" in joined
    assert "TESTSECRETNOTREAL" not in joined


def test_install_creates_user_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existiert der Hauptbenutzer nicht, wird er angelegt (nicht übersprungen)."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    monkeypatch.setenv("GETENT_USER_EXISTS", "0")

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert f"Benutzer {_MAIN_USER} angelegt" in messages
    assert not any("übersprungen" in str(m) and "Benutzer" in str(m) for m in messages)


def test_install_skips_password_when_already_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein bereits gesetztes Passwort wird nicht erneut per chpasswd gesetzt."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert f"Passwort für {_MAIN_USER} bereits gesetzt — übersprungen" in messages


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Users, "GROUPADD_BIN", "/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Gruppe ssh-users anlegen" in messages
    assert "Hauptbenutzer anlegen" not in messages


def test_install_fails_when_totp_mail_send_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt der Mailversand fehl (sendmail), liefert install 1 — der
    Aussperr-Schutz greift, install bricht vor dem ssh-Modul ab."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Users, "SENDMAIL_BIN", "/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: TOTP-Einrichtungsmail versenden" in messages
    joined = "\n".join(str(m) for m in messages)
    assert "TESTSECRETNOTREAL" not in joined


def test_install_fails_when_totp_mail_has_no_delivery_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt der Zustellbeweis im Mail-Log, liefert install 1 (fail-closed)."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mail_log = tmp_path / "mail.log"
    mail_log.write_text("keine passende Zeile\n")
    monkeypatch.setattr(Users, "MAIL_LOG", str(mail_log))
    monkeypatch.setattr(Users, "DELIVERY_LOG_CHECK_ATTEMPTS", 1)
    monkeypatch.setattr(Users, "DELIVERY_LOG_CHECK_INTERVAL", 0)

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: TOTP-Einrichtungsmail versenden" in messages


def test_install_aborts_on_missing_root_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt das root-Passwort, bricht install vor allen anderen Schritten ab."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    monkeypatch.setenv("GETENT_ROOT_HASH", "!")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "root-Passwort ist nicht gesetzt" in messages
    assert "fehlgeschlagen: root-Passwort-Vorbedingung prüfen" in messages
    assert "Paket installieren" not in messages


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
    """Betriebsart check bestätigt einen vollständig eingerichteten Hauptbenutzer."""
    mod, conn, home = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"

    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    authkeys = ssh_dir / "authorized_keys"
    authkeys.write_text(_PUBKEY + "\n", encoding="utf-8")
    authkeys.chmod(0o600)
    ga_file = home / ".google_authenticator"
    ga_file.write_text("SECRETSECRETSECRET\n", encoding="utf-8")
    ga_file.chmod(0o600)

    result = mod.start()

    assert result == 0, _sent_messages(conn)


def test_check_reports_missing_authorized_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt authorized_keys, meldet check den Mangel und liefert 1."""
    mod, conn, home = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"

    (home / ".ssh").mkdir(mode=0o700)
    ga_file = home / ".google_authenticator"
    ga_file.write_text("SECRETSECRETSECRET\n", encoding="utf-8")
    ga_file.chmod(0o600)

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("existiert nicht" in str(m) for m in messages)


# --- uninstall ---


def test_uninstall_default_keeps_user_but_drops_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall_remove_user=no (Vorgabe) entfernt nur Mitgliedschaft und Gruppe."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = [str(m) for m in _sent_messages(conn)]
    assert f"Mitgliedschaft {_MAIN_USER} in ssh-users gelöst" in messages
    assert "Gruppe ssh-users entfernt" in messages
    assert any("bleiben" in m and "unverändert" in m for m in messages)
    assert "root-Passwort bleibt unverändert" in messages
    assert not (tmp_path / "userdel_called.marker").exists()


def test_uninstall_remove_user_yes_removes_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall_remove_user=yes entfernt den Hauptbenutzer samt Home per userdel -r."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.operation = "uninstall"
    mod.uninstall_remove_user = "yes"

    result = mod.start()

    assert result == 0
    messages = [str(m) for m in _sent_messages(conn)]
    assert any(
        f"Benutzer {_MAIN_USER} mit Home-Verzeichnis entfernt" in m for m in messages
    )
    assert (tmp_path / "userdel_called.marker").exists()


def test_uninstall_skips_membership_and_group_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne Mitgliedschaft/Gruppe überspringt uninstall beide Schritte (Erfolg)."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.operation = "uninstall"
    monkeypatch.setenv("FAKE_ID_GROUPS", "alice")
    monkeypatch.setenv("GETENT_GROUP_EXISTS", "0")

    result = mod.start()

    assert result == 0
    messages = [str(m) for m in _sent_messages(conn)]
    assert any("nicht Mitglied" in m and "übersprungen" in m for m in messages)
    assert any(
        "Gruppe ssh-users existiert nicht" in m and "übersprungen" in m
        for m in messages
    )


def test_uninstall_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt der erste Schritt fehl, bricht uninstall ab und liefert 1."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.operation = "uninstall"
    monkeypatch.setattr(Users, "ID_BIN", "/bin/false")

    result = mod.start()

    assert result == 1
    messages = [str(m) for m in _sent_messages(conn)]
    assert "fehlgeschlagen: Mitgliedschaft in ssh-users lösen" in messages
    assert "Gruppe ssh-users entfernt" not in messages


def test_uninstall_reports_userdel_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt userdel -r fehl, meldet uninstall den Fehler und liefert 1."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.operation = "uninstall"
    mod.uninstall_remove_user = "yes"
    monkeypatch.setattr(Users, "USERDEL_BIN", "/bin/false")

    result = mod.start()

    assert result == 1
    messages = [str(m) for m in _sent_messages(conn)]
    assert any(f"userdel -r {_MAIN_USER} fehlgeschlagen" in m for m in messages)


# --- test ---


def test_test_reports_ok_when_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart test meldet Erfolg, wenn beide Dateien lesbar sind."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "users test: Hauptbenutzer kann seine Login-Dateien lesen" in messages


def test_test_warns_but_returns_zero_when_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart test ist Beobachtung: WARN bei Unlesbarkeit, aber Exit-Code 0."""
    mod, conn, _home = _make_module(tmp_path, monkeypatch)
    mod.operation = "test"
    monkeypatch.setattr(Users, "RUNUSER_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 0
    messages = [str(m) for m in _sent_messages(conn)]
    assert any(
        f"TOTP-Secret aus Sicht von {_MAIN_USER} nicht lesbar" in m for m in messages
    )
    assert any(
        f"authorized_keys aus Sicht von {_MAIN_USER} nicht lesbar" in m
        for m in messages
    )
    assert "users test: Hauptbenutzer kann seine Login-Dateien lesen" not in messages
