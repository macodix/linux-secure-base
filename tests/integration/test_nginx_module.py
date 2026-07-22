"""Integrationstest für secure_base.modules.nginx.

Startet Nginx.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn), analog zu test_base_module.py: Systembefehle
werden durch harmlose Platzhalter ersetzt (Plan Abschnitt 2.12), Apt-
und Systemd-Aktionen durch No-Op-Unterklassen. Die Aktionen selbst sind
bereits in pifos getestet.
"""

import grp
import os
import pwd
import socket
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.nginx import Nginx


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


class _FailOnStopSystemdAction(SystemdServiceAction):
    """Wie _NoOpSystemdAction, aber operation='stop' schlägt fehl (Abbruch-Test)."""

    def run(self) -> str:
        if self.operation == "stop":
            self.status = "failed"
            raise ActionError("stop absichtlich fehlgeschlagen (Test)")
        self.status = "finished"
        return self.status


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Nginx, MagicMock]:
    """Baut ein Nginx-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(Nginx, "NGINX_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "CERTBOT_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "UFW_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "DPKG_QUERY_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "SYSTEMCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "AA_STATUS_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "AA_AUTODEP_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "AA_COMPLAIN_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "APPARMOR_PARSER_BIN", "/usr/bin/true")
    monkeypatch.setattr(Nginx, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Nginx, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)
    # Eigentümerwechsel auf www-data verlangt Systemrechte; im Test auf den
    # aufrufenden Benutzer umgelenkt (PermissionsAction bleibt unverändert).
    monkeypatch.setattr(Nginx, "DOCROOT_OWNER", pwd.getpwuid(os.getuid()).pw_name)
    monkeypatch.setattr(Nginx, "DOCROOT_GROUP", grp.getgrgid(os.getgid()).gr_name)

    (tmp_path / "nginx.conf").write_text("http {\n}\n", encoding="utf-8")
    sites_available = tmp_path / "sites-available"
    sites_enabled = tmp_path / "sites-enabled"
    sites_available.mkdir()
    sites_enabled.mkdir()
    monkeypatch.setattr(Nginx, "NGINX_CONF", str(tmp_path / "nginx.conf"))
    monkeypatch.setattr(Nginx, "SITES_AVAILABLE", str(sites_available))
    monkeypatch.setattr(Nginx, "SITES_ENABLED", str(sites_enabled))
    monkeypatch.setattr(Nginx, "AA_PROFILE", str(tmp_path / "apparmor-profile"))
    monkeypatch.setattr(
        Nginx, "HARDENING_DROPIN", str(tmp_path / "nginx.service.d" / "hardening.conf")
    )
    monkeypatch.setattr(
        Nginx, "LETSENCRYPT_LIVE", str(tmp_path / "letsencrypt" / "live")
    )

    conn = MagicMock()
    mod = Nginx(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = "admin@example.com"
    mod.nginx_certbot_mail = ""
    mod.nginx_vhosts = f"example.com|{tmp_path}/wwwroot"
    mod.nginx_certbot_mode = "staging"
    mod.force_overwrite = "no"
    mod.backup_run_dir = str(tmp_path / "backup-run")
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
    assert "AppArmor-Profil auf complain setzen" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert Path(tmp_path / "wwwroot").is_dir()
    assert Path(tmp_path / "sites-available" / "example.com").is_file()
    assert Path(tmp_path / "sites-enabled" / "example.com").is_symlink()
    assert Path(tmp_path / "nginx.service.d" / "hardening.conf").exists()


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Nginx, "NGINX_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: nginx-Konfiguration prüfen" in messages
    assert "Firewall 443/tcp öffnen" not in messages


def test_install_closes_port_80_when_certbot_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert certbot, wird Port 80 dennoch geschlossen (fail-closed)."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Nginx, "CERTBOT_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: certbot für example.com" in messages
    assert "Firewall 80/tcp schließen" in messages
    assert "systemd-Hardening-Verzeichnis anlegen" not in messages


def test_install_rejects_invalid_vhost_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiger vhost-Eintrag bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.nginx_vhosts = "-invalid-"

    with pytest.raises(ModuleError, match="ungültiger Domainname"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check meldet Abweichungen, wenn nichts eingerichtet ist."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"
    # /usr/bin/true liefert keine Ausgabe und keine angelegten Dateien;
    # weicht daher von jedem Soll-Wert ab.

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("vhost example.com fehlt" in str(m) for m in messages)


# --- Drift-Schutz (installer-drift-schutz) ---


def test_install_second_run_reports_unchanged_and_writes_nothing_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter, unveränderter install-Lauf überschreibt keine Datei erneut.

    nginx.conf wird beim ersten Lauf zeilenweise geändert (server_tokens off;
    fehlt anfangs) — die zentrale Sicherung dafür entsteht bereits im ersten
    Lauf; geprüft wird hier, dass der zweite Lauf keine weitere Sicherung
    hinzufügt (insbesondere nicht für vhost/Härtung, die unverändert sind).
    """
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    vhost_file = Path(tmp_path / "sites-available" / "example.com")
    vhost_mtime = vhost_file.stat().st_mtime_ns
    hardening_mtime = Path(mod.HARDENING_DROPIN).stat().st_mtime_ns
    backups_after_first_run = sorted(Path(mod.backup_run_dir).rglob("*"))
    conn.reset_mock()

    result = mod.start()

    assert result == 0
    assert vhost_file.stat().st_mtime_ns == vhost_mtime
    assert Path(mod.HARDENING_DROPIN).stat().st_mtime_ns == hardening_mtime
    assert sorted(Path(mod.backup_run_dir).rglob("*")) == backups_after_first_run
    messages = _sent_messages(conn)
    assert any("unverändert — übersprungen" in str(m) for m in messages)


def test_install_rejects_hand_edited_vhost_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine Hand-Änderung am vhost wird ohne Freigabe nicht überschrieben."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    vhost_file = Path(tmp_path / "sites-available" / "example.com")
    vhost_file.write_text("von hand geändert\n", encoding="utf-8")
    conn.reset_mock()

    result = mod.start()

    assert result == 1
    assert vhost_file.read_text(encoding="utf-8") == "von hand geändert\n"
    messages = _sent_messages(conn)
    assert any("--force-overwrite" in str(m) for m in messages)
    assert "vhost aktivieren (example.com)" not in messages


# --- Betriebsart uninstall ---


def test_uninstall_removes_own_artifacts_but_keeps_docroot_and_certs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall entfernt vhost/Härtung/AppArmor-Profil; docroot/Zertifikate bleiben."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    docroot = tmp_path / "wwwroot"
    (docroot / "index.html").write_text("hallo", encoding="utf-8")
    cert_dir = Path(mod.LETSENCRYPT_LIVE) / "example.com"
    cert_dir.mkdir(parents=True)
    (cert_dir / "privkey.pem").write_text("geheim", encoding="utf-8")
    Path(mod.AA_PROFILE).write_text("profil", encoding="utf-8")

    fake_dpkg = tmp_path / "fake-dpkg-query"
    fake_dpkg.write_text("#!/bin/sh\nprintf 'install ok installed'\n", encoding="utf-8")
    fake_dpkg.chmod(0o755)
    monkeypatch.setattr(Nginx, "DPKG_QUERY_BIN", str(fake_dpkg))

    conn.reset_mock()
    # uninstall ist konfig-unabhängig — leere Werte dürfen nicht abbrechen.
    mod.nginx_vhosts = ""
    mod.nginx_certbot_mail = ""
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    assert not Path(tmp_path / "sites-available" / "example.com").exists()
    assert not Path(tmp_path / "sites-enabled" / "example.com").exists()
    assert not Path(mod.HARDENING_DROPIN).exists()
    assert not Path(mod.AA_PROFILE).exists()
    assert docroot.is_dir()
    assert (docroot / "index.html").read_text(encoding="utf-8") == "hallo"
    assert cert_dir.is_dir()
    assert (cert_dir / "privkey.pem").exists()
    messages = _sent_messages(conn)
    assert any("Zertifikate" in str(m) and "bleiben" in str(m) for m in messages)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_uninstall_stops_at_first_failed_step_integration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert ein Schritt, liefert uninstall 1 und stoppt vor den Folgeschritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    fake_dpkg = tmp_path / "fake-dpkg-query"
    fake_dpkg.write_text("#!/bin/sh\nprintf 'install ok installed'\n", encoding="utf-8")
    fake_dpkg.chmod(0o755)
    monkeypatch.setattr(Nginx, "DPKG_QUERY_BIN", str(fake_dpkg))
    monkeypatch.setattr(Nginx, "SYSTEMD_ACTION_CLS", _FailOnStopSystemdAction)

    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: nginx stoppen" in messages
    # Die Pakete dürfen nach dem Abbruch nicht entfernt worden sein.
    assert "Pakete entfernen" not in messages
    # Der vhost muss unangetastet bleiben (Abbruch vor diesem Schritt).
    assert Path(tmp_path / "sites-available" / "example.com").exists()


def test_uninstall_skips_when_package_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist nginx laut dpkg nicht installiert, bleiben alle Artefakte unangetastet."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    # DPKG_QUERY_BIN bleibt /usr/bin/true (fixture-Default) — liefert keine
    # Ausgabe, gilt also als "nicht installiert".

    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "Paket nginx nicht installiert — nichts zu tun" in messages
    assert Path(tmp_path / "sites-available" / "example.com").exists()
    assert Path(mod.HARDENING_DROPIN).exists()


# --- Betriebsart test ---


def test_test_operation_all_checks_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mit erreichbarem Listener und harmlosen Platzhaltern meldet test Erfolg."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    fake_systemctl = tmp_path / "fake-systemctl-active"
    fake_systemctl.write_text("#!/bin/sh\nprintf 'active'\n", encoding="utf-8")
    fake_systemctl.chmod(0o755)
    monkeypatch.setattr(Nginx, "SYSTEMCTL_BIN", str(fake_systemctl))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        monkeypatch.setattr(Nginx, "TEST_TCP_PORT", port)
        monkeypatch.setattr(Nginx, "TEST_TCP_TIMEOUT", 1.0)
        mod.operation = "test"

        result = mod.start()

        assert result == 0
        messages = _sent_messages(conn)
        assert "certbot renew --dry-run ok" in messages
    finally:
        server.close()


def test_test_operation_reports_failure_without_running_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne aktiven Dienst/Listener meldet test einen Fehlschlag."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()
    monkeypatch.setattr(Nginx, "SYSTEMCTL_BIN", "/usr/bin/false")
    monkeypatch.setattr(Nginx, "TEST_TCP_PORT", free_port)
    monkeypatch.setattr(Nginx, "TEST_TCP_TIMEOUT", 1.0)
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("TCP-Connect" in str(m) and "fehlgeschlagen" in str(m) for m in messages)
