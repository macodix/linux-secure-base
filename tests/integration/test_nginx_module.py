"""Integrationstest für lsb.modules.nginx.

Startet Nginx.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn), analog zu test_base_module.py: Systembefehle
werden durch harmlose Platzhalter ersetzt (Plan Abschnitt 2.12), Apt-
und Systemd-Aktionen durch No-Op-Unterklassen. Die Aktionen selbst sind
bereits in pifos getestet.
"""

import grp
import os
import pwd
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from lsb.modules.nginx import Nginx
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel


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
