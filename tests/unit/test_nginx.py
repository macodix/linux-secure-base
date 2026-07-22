"""Unit-Tests für secure_base.modules.nginx."""

import socket
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.nginx import Nginx, _hardening_content, _http_block_content


def _write_script(tmp_path: Path, name: str, body: str) -> str:
    """Legt ein ausführbares Fake-Programm unter tmp_path an und liefert den Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def _make_nginx(
    *,
    admin_mail: str = "admin@example.com",
    nginx_certbot_mail: str = "",
    nginx_vhosts: str = "example.com",
    nginx_certbot_mode: str = "",
    operation: str = "install",
) -> Nginx:
    """Baut ein Nginx-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Nginx(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = operation
    mod.admin_mail = admin_mail
    mod.nginx_certbot_mail = nginx_certbot_mail
    mod.nginx_vhosts = nginx_vhosts
    mod.nginx_certbot_mode = nginx_certbot_mode
    mod.force_overwrite = "no"
    mod.backup_run_dir = "/var/backup/secure-base/test-lauf"
    return mod


# --- CONFIG ---


def test_nginx_config_declares_expected_keys_in_order() -> None:
    """CONFIG nennt operation, admin_mail, nginx_-Schlüssel und Drift-Schutz-Werte."""
    assert Nginx.CONFIG == [
        "operation",
        "admin_mail",
        "nginx_certbot_mail",
        "nginx_vhosts",
        "nginx_certbot_mode",
        "force_overwrite",
        "backup_run_dir",
    ]


# --- _validate: certbot-Mail ---


def test_validate_falls_back_to_admin_mail() -> None:
    """Ohne nginx_certbot_mail greift admin_mail als certbot-Mail."""
    mod = _make_nginx(admin_mail="admin@example.com", nginx_certbot_mail="")
    mod._validate()
    assert mod._certbot_mail == "admin@example.com"


def test_validate_prefers_certbot_mail_over_admin_mail() -> None:
    """Eine gesetzte nginx_certbot_mail hat Vorrang vor admin_mail."""
    mod = _make_nginx(
        admin_mail="admin@example.com", nginx_certbot_mail="certbot@example.com"
    )
    mod._validate()
    assert mod._certbot_mail == "certbot@example.com"


def test_validate_rejects_missing_mail() -> None:
    """Fehlen beide Mail-Quellen, wird ModuleError erzeugt."""
    mod = _make_nginx(admin_mail="", nginx_certbot_mail="")
    with pytest.raises(ModuleError, match="keine Mail"):
        mod._validate()


def test_validate_rejects_malformed_mail() -> None:
    """Eine syntaktisch ungültige Mail wird abgelehnt."""
    mod = _make_nginx(nginx_certbot_mail="keine-email")
    with pytest.raises(ModuleError, match="ungültige certbot-Mail"):
        mod._validate()


def test_validate_rejects_mail_starting_with_dash() -> None:
    """Eine mit '-' beginnende Mail wird als Options-Injection-Schutz abgelehnt."""
    mod = _make_nginx(nginx_certbot_mail="-x@example.com")
    with pytest.raises(ModuleError, match="ungültige certbot-Mail"):
        mod._validate()


# --- _validate: certbot-Modus ---


def test_validate_defaults_certbot_mode_to_live() -> None:
    """Ein leerer certbot-Modus wird zu 'live'."""
    mod = _make_nginx(nginx_certbot_mode="")
    mod._validate()
    assert mod._certbot_mode == "live"


def test_validate_accepts_staging_mode() -> None:
    """'staging' ist ein gültiger certbot-Modus."""
    mod = _make_nginx(nginx_certbot_mode="staging")
    mod._validate()
    assert mod._certbot_mode == "staging"


def test_validate_rejects_unknown_certbot_mode() -> None:
    """Ein unbekannter certbot-Modus erzeugt ModuleError."""
    mod = _make_nginx(nginx_certbot_mode="dev")
    with pytest.raises(ModuleError, match="ungültiger certbot-Modus"):
        mod._validate()


# --- _parse_vhosts ---


def test_parse_vhosts_single_domain_uses_default_docroot() -> None:
    """Ohne docroot-Angabe gilt DOCROOT_BASE/domain."""
    mod = _make_nginx(nginx_vhosts="example.com")
    mod._validate()
    assert mod._vhosts == [("example.com", "/var/www/example.com")]


def test_parse_vhosts_with_custom_docroot() -> None:
    """Ein Eintrag mit '|docroot' übernimmt den angegebenen docroot."""
    mod = _make_nginx(nginx_vhosts="shop.example.com|/srv/www/shop")
    mod._validate()
    assert mod._vhosts == [("shop.example.com", "/srv/www/shop")]


def test_parse_vhosts_sorts_by_domain() -> None:
    """Mehrere vhosts werden deterministisch nach Domainname sortiert."""
    mod = _make_nginx(nginx_vhosts="zebra.example.com,alpha.example.com")
    mod._validate()
    assert [d for d, _ in mod._vhosts] == [
        "alpha.example.com",
        "zebra.example.com",
    ]


def test_parse_vhosts_rejects_empty_list() -> None:
    """Eine leere nginx_vhosts-Angabe erzeugt ModuleError."""
    mod = _make_nginx(nginx_vhosts="   ")
    with pytest.raises(ModuleError, match="kein vhost definiert"):
        mod._validate()


def test_parse_vhosts_rejects_invalid_domain() -> None:
    """Ein ungültiger Domainname erzeugt ModuleError."""
    mod = _make_nginx(nginx_vhosts="-invalid-.example.com")
    with pytest.raises(ModuleError, match="ungültiger Domainname"):
        mod._validate()


def test_parse_vhosts_rejects_single_label_domain() -> None:
    """Ein Domainname ohne Punkt (kein FQDN) wird abgelehnt."""
    mod = _make_nginx(nginx_vhosts="localhost")
    with pytest.raises(ModuleError, match="ungültiger Domainname"):
        mod._validate()


def test_parse_vhosts_rejects_relative_docroot() -> None:
    """Ein nicht absoluter docroot erzeugt ModuleError."""
    mod = _make_nginx(nginx_vhosts="example.com|relative/pfad")
    with pytest.raises(ModuleError, match="ungültiger docroot"):
        mod._validate()


def test_parse_vhosts_rejects_docroot_with_config_characters() -> None:
    """Zeichen außerhalb der Allowlist (etwa ; } Leerzeichen) werden abgelehnt.

    docroot geht als root-Direktive in den nginx-Server-Block; ein
    Semikolon o. Ä. könnte dort weitere Direktiven einschleusen
    (Audit-Befund 2026-07-05).
    """
    for docroot in ("/srv/www;autoindex on", "/srv/www}", "/srv/w w"):
        mod = _make_nginx(nginx_vhosts=f"example.com|{docroot}")
        with pytest.raises(ModuleError, match="ungültiger docroot"):
            mod._validate()


def test_parse_vhosts_rejects_docroot_with_parent_traversal() -> None:
    """Ein docroot mit /../ wird abgelehnt."""
    mod = _make_nginx(nginx_vhosts="example.com|/srv/../etc/nginx")
    with pytest.raises(ModuleError, match="ungültiger docroot"):
        mod._validate()


def test_parse_vhosts_rejects_too_long_label() -> None:
    """Ein DNS-Label über 63 Zeichen erzeugt ModuleError."""
    label = "a" * 64
    mod = _make_nginx(nginx_vhosts=f"{label}.example.com")
    with pytest.raises(ModuleError, match="DNS-Label zu lang"):
        mod._validate()


# --- Inhaltsfunktionen ---


def test_http_block_content_contains_domain_and_docroot() -> None:
    """Der Server-Block enthält server_name und root mit den übergebenen Werten."""
    content = _http_block_content("example.com", "/var/www/example.com")
    assert "server_name example.com;" in content
    assert "root /var/www/example.com;" in content
    assert "listen 80;" in content


def test_hardening_content_contains_expected_directives() -> None:
    """Das Hardening-Drop-in enthält die erwarteten systemd-Direktiven."""
    content = _hardening_content()
    assert "NoNewPrivileges=true" in content
    assert "ProtectSystem=strict" in content
    assert "ReadWritePaths=/var/log/nginx /var/lib/nginx /run" in content


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_nginx()
    assert mod._check_value(["/bin/echo", "aktiv"], "aktiv", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_nginx()
    assert mod._check_value(["/bin/echo", "nein"], "ja", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_nginx()
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False


# --- Datei-basierte check-Helfer ---


def test_check_server_tokens_detects_present_setting(tmp_path: Path) -> None:
    """server_tokens off; wird in der Konfigurationsdatei erkannt."""
    conf = tmp_path / "nginx.conf"
    conf.write_text("http {\n    server_tokens off;\n}\n", encoding="utf-8")
    mod = _make_nginx()
    mod.NGINX_CONF = str(conf)  # type: ignore[misc]
    assert mod._check_server_tokens() is True


def test_check_server_tokens_missing_setting_returns_false(tmp_path: Path) -> None:
    """Fehlt server_tokens off;, liefert die Prüfung False."""
    conf = tmp_path / "nginx.conf"
    conf.write_text("http {\n}\n", encoding="utf-8")
    mod = _make_nginx()
    mod.NGINX_CONF = str(conf)  # type: ignore[misc]
    assert mod._check_server_tokens() is False


def test_check_privkey_perms_rejects_world_readable(tmp_path: Path) -> None:
    """Ein für andere lesbarer Privatschlüssel liefert False."""
    live = tmp_path / "live" / "example.com"
    live.mkdir(parents=True)
    privkey = live / "privkey.pem"
    privkey.write_text("geheim", encoding="utf-8")
    privkey.chmod(0o644)
    mod = _make_nginx()
    mod.LETSENCRYPT_LIVE = str(tmp_path / "live")  # type: ignore[misc]
    assert mod._check_privkey_perms("example.com") is False


def test_check_privkey_perms_accepts_owner_only(tmp_path: Path) -> None:
    """Ein nur für den Eigentümer lesbarer Privatschlüssel liefert True."""
    live = tmp_path / "live" / "example.com"
    live.mkdir(parents=True)
    privkey = live / "privkey.pem"
    privkey.write_text("geheim", encoding="utf-8")
    privkey.chmod(0o600)
    mod = _make_nginx()
    mod.LETSENCRYPT_LIVE = str(tmp_path / "live")  # type: ignore[misc]
    assert mod._check_privkey_perms("example.com") is True


def test_check_privkey_perms_missing_file_returns_false(tmp_path: Path) -> None:
    """Fehlt der Privatschlüssel, liefert die Prüfung False."""
    mod = _make_nginx()
    mod.LETSENCRYPT_LIVE = str(tmp_path / "live")  # type: ignore[misc]
    assert mod._check_privkey_perms("example.com") is False


def test_check_file_mode_matches(tmp_path: Path) -> None:
    """Stimmen Rechte und Eigentümer überein, liefert _check_file_mode True."""
    target = tmp_path / "dropin.conf"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o644)
    mod = _make_nginx()
    import grp
    import os
    import pwd

    owner = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    assert mod._check_file_mode(str(target), 0o644, owner, group) is True


def test_check_file_mode_missing_path_returns_false(tmp_path: Path) -> None:
    """Fehlt der Pfad, liefert _check_file_mode False."""
    mod = _make_nginx()
    assert (
        mod._check_file_mode(str(tmp_path / "nichts"), 0o644, "root", "root") is False
    )


def test_check_file_mode_mismatch_returns_false(tmp_path: Path) -> None:
    """Abweichende Rechte liefern False."""
    target = tmp_path / "dropin.conf"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o600)
    mod = _make_nginx()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert mod._check_file_mode(str(target), 0o644, "root", "root") is False


# --- Marker-Konstante in generierten Dateien ---


def test_http_block_content_contains_own_file_marker() -> None:
    """Der Server-Block trägt den Marker, über den uninstall ihn wiederfindet."""
    content = _http_block_content("example.com", "/var/www/example.com")
    assert "Von secure-base/nginx angelegt" in content.splitlines()[0]


def test_hardening_content_contains_own_file_marker() -> None:
    """Das Hardening-Drop-in trägt denselben Marker wie die Server-Blöcke."""
    content = _hardening_content()
    assert "Von secure-base/nginx angelegt" in content.splitlines()[0]


# --- _own_vhost_names ---


def test_own_vhost_names_detects_marker_and_sorts(tmp_path: Path) -> None:
    """Nur Dateien mit Marker in Zeile 1 werden gefunden, sortiert nach Namen."""
    sites_available = tmp_path / "sites-available"
    sites_available.mkdir()
    (sites_available / "zebra.example.com").write_text(
        _http_block_content("zebra.example.com", "/var/www/zebra.example.com"),
        encoding="utf-8",
    )
    (sites_available / "alpha.example.com").write_text(
        _http_block_content("alpha.example.com", "/var/www/alpha.example.com"),
        encoding="utf-8",
    )
    (sites_available / "default").write_text(
        "server {\n    listen 80 default_server;\n}\n", encoding="utf-8"
    )
    (sites_available / "subdir").mkdir()

    mod = _make_nginx()
    mod.SITES_AVAILABLE = str(sites_available)  # type: ignore[misc]

    assert mod._own_vhost_names() == ["alpha.example.com", "zebra.example.com"]


def test_own_vhost_names_missing_directory_returns_empty(tmp_path: Path) -> None:
    """Fehlt SITES_AVAILABLE, liefert _own_vhost_names eine leere Liste."""
    mod = _make_nginx()
    mod.SITES_AVAILABLE = str(tmp_path / "nichts")  # type: ignore[misc]
    assert mod._own_vhost_names() == []


# --- _ufw_rule_present ---


def test_ufw_rule_present_true(tmp_path: Path) -> None:
    """Eine passende 'ufw allow PORT/tcp'-Zeile liefert True."""
    fake_ufw = _write_script(tmp_path, "fake-ufw", "printf 'ufw allow 443/tcp\\n'")
    mod = _make_nginx()
    mod.UFW_BIN = fake_ufw  # type: ignore[misc]
    assert mod._ufw_rule_present(443) is True


def test_ufw_rule_present_false_when_absent(tmp_path: Path) -> None:
    """Ohne passende Zeile liefert _ufw_rule_present False."""
    fake_ufw = _write_script(tmp_path, "fake-ufw", "printf 'ufw allow 22/tcp\\n'")
    mod = _make_nginx()
    mod.UFW_BIN = fake_ufw  # type: ignore[misc]
    assert mod._ufw_rule_present(443) is False


def test_ufw_rule_present_command_failure_returns_false(tmp_path: Path) -> None:
    """Scheitert der ufw-Aufruf selbst, gilt die Regel als nicht gesetzt."""
    fake_ufw = _write_script(tmp_path, "fake-ufw", "exit 1")
    mod = _make_nginx()
    mod.UFW_BIN = fake_ufw  # type: ignore[misc]
    assert mod._ufw_rule_present(443) is False


# --- _nginx_package_installed ---


def test_nginx_package_installed_true(tmp_path: Path) -> None:
    """Meldet dpkg-query das Paket als installiert, liefert die Prüfung True."""
    fake_dpkg = _write_script(
        tmp_path, "fake-dpkg-query", "printf 'install ok installed'"
    )
    mod = _make_nginx()
    mod.DPKG_QUERY_BIN = fake_dpkg  # type: ignore[misc]
    assert mod._nginx_package_installed() is True


def test_nginx_package_installed_false(tmp_path: Path) -> None:
    """Meldet dpkg-query nichts Passendes, liefert die Prüfung False."""
    fake_dpkg = _write_script(tmp_path, "fake-dpkg-query", "exit 1")
    mod = _make_nginx()
    mod.DPKG_QUERY_BIN = fake_dpkg  # type: ignore[misc]
    assert mod._nginx_package_installed() is False


# --- _uninstall ---


def test_uninstall_short_circuits_when_package_not_installed(tmp_path: Path) -> None:
    """Ist nginx nicht installiert, kehrt _uninstall ohne Schritte zurück."""
    fake_dpkg = _write_script(tmp_path, "fake-dpkg-query", "exit 1")
    mod = _make_nginx(operation="uninstall")
    mod.DPKG_QUERY_BIN = fake_dpkg  # type: ignore[misc]

    assert mod._uninstall() == 0


def test_uninstall_stops_at_first_failed_step(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    conn = MagicMock()
    mod = Nginx(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "uninstall"
    monkeypatch.setattr(mod, "_nginx_package_installed", lambda: True)
    monkeypatch.setattr(
        mod,
        "_uninstall_steps",
        lambda: iter(
            [
                (
                    "Schritt 1 (scheitert)",
                    mod._act(SysCmdAction(["/bin/false"], timeout=5)),
                ),
                (
                    "Schritt 2 (darf nicht laufen)",
                    mod._act(SysCmdAction(["/bin/true"], timeout=5)),
                ),
            ]
        ),
    )

    assert mod._uninstall() == 1
    messages = [call.args[0].payload for call in conn.send.call_args_list]
    assert "fehlgeschlagen: Schritt 1 (scheitert)" in messages
    assert "Schritt 2 (darf nicht laufen)" not in messages


def test_uninstall_is_config_independent() -> None:
    """start() ruft bei operation='uninstall' _validate() nicht auf.

    Eine leere nginx_vhosts-Angabe würde _validate() mit ModuleError
    abbrechen lassen (siehe test_parse_vhosts_rejects_empty_list) — bei
    uninstall darf das nicht passieren.
    """
    fake_dpkg = "/bin/false"
    mod = _make_nginx(nginx_vhosts="", nginx_certbot_mail="", operation="uninstall")
    mod.DPKG_QUERY_BIN = fake_dpkg  # type: ignore[misc]

    assert mod.start() == 0


# --- _check_tcp_connect ---


def test_check_tcp_connect_success() -> None:
    """Ein erreichbarer Listener liefert True."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        mod = _make_nginx()
        mod.TEST_TCP_PORT = port  # type: ignore[misc]
        mod.TEST_TCP_TIMEOUT = 1.0  # type: ignore[misc]
        assert mod._check_tcp_connect() is True
    finally:
        server.close()


def test_check_tcp_connect_failure() -> None:
    """Ohne Listener auf dem Zielport liefert die Prüfung False."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()

    mod = _make_nginx()
    mod.TEST_TCP_PORT = free_port  # type: ignore[misc]
    mod.TEST_TCP_TIMEOUT = 1.0  # type: ignore[misc]
    assert mod._check_tcp_connect() is False


# --- _check_certbot_dry_run ---


def test_check_certbot_dry_run_success(tmp_path: Path) -> None:
    """Gelingen Öffnen, Trockenlauf und Schließen, liefert die Prüfung True."""
    mod = _make_nginx()
    mod.UFW_BIN = "/bin/true"  # type: ignore[misc]
    mod.CERTBOT_BIN = "/bin/true"  # type: ignore[misc]
    assert mod._check_certbot_dry_run() is True


def test_check_certbot_dry_run_open_fails(tmp_path: Path) -> None:
    """Scheitert das Öffnen von Port 80, liefert die Prüfung False."""
    mod = _make_nginx()
    mod.UFW_BIN = "/bin/false"  # type: ignore[misc]
    mod.CERTBOT_BIN = "/bin/true"  # type: ignore[misc]
    assert mod._check_certbot_dry_run() is False


def test_check_certbot_dry_run_renew_fails_but_closes_port(tmp_path: Path) -> None:
    """Scheitert certbot renew, liefert die Prüfung False; Port 80 wird geschlossen."""
    mod = _make_nginx()
    mod.UFW_BIN = "/bin/true"  # type: ignore[misc]
    mod.CERTBOT_BIN = "/bin/false"  # type: ignore[misc]
    assert mod._check_certbot_dry_run() is False


def test_check_certbot_dry_run_close_fails_even_if_renew_succeeds(
    tmp_path: Path,
) -> None:
    """Scheitert das Schließen von Port 80, liefert die Prüfung dennoch False."""
    fake_ufw = _write_script(
        tmp_path,
        "fake-ufw",
        'if [ "$1" = "delete" ]; then exit 1; fi\nexit 0',
    )
    mod = _make_nginx()
    mod.UFW_BIN = fake_ufw  # type: ignore[misc]
    mod.CERTBOT_BIN = "/bin/true"  # type: ignore[misc]
    assert mod._check_certbot_dry_run() is False


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, Pakete, vhosts, Dateien und Dienst."""
    values = {
        "nginx_vhosts": "zebra.example.com,alpha.example.com|/srv/www/alpha",
        "nginx_certbot_mail": "certbot@example.com",
        "nginx_certbot_mode": "staging",
        "admin_mail": "admin@example.com",
    }
    section = Nginx.doc(values)
    assert section.startswith("\n## Webserver nginx (optional)\n\n")
    assert "**Pakete:**" in section
    for package in Nginx.PACKAGES:
        assert package in section
    # Sortiert nach Domainname, wie _parse_vhosts.
    alpha_pos = section.index("alpha.example.com")
    zebra_pos = section.index("zebra.example.com")
    assert alpha_pos < zebra_pos
    assert "- `alpha.example.com` (root `/srv/www/alpha`)" in section
    assert "- `zebra.example.com` (root `/var/www/zebra.example.com`)" in section
    assert "**Firewall:**" in section
    assert "**certbot:** Modus `staging`, Mail `certbot@example.com`" in section
    assert f"`{Nginx.HARDENING_DROPIN}`" in section
    assert "NoNewPrivileges=true" in section
    assert f"`{Nginx.AA_PROFILE}`" in section
    assert "**Dienste:** nginx (enabled, aktiv nach install)" in section


def test_doc_certbot_mail_falls_back_to_admin_mail() -> None:
    """Ohne nginx_certbot_mail erscheint admin_mail als certbot-Mail."""
    values = {
        "nginx_vhosts": "example.com",
        "admin_mail": "admin@example.com",
    }
    section = Nginx.doc(values)
    assert "Mail `admin@example.com`" in section


def test_doc_certbot_mode_defaults_to_live() -> None:
    """Ohne nginx_certbot_mode gilt 'live' wie in _validate()."""
    values = {"nginx_vhosts": "example.com", "admin_mail": "admin@example.com"}
    section = Nginx.doc(values)
    assert "Modus `live`" in section


def test_doc_missing_mail_marked_as_leer_default() -> None:
    """Fehlen beide Mail-Quellen, erscheint '(leer/Default)'."""
    values = {"nginx_vhosts": "example.com"}
    section = Nginx.doc(values)
    assert "Mail `(leer/Default)`" in section


def test_doc_rejects_missing_vhosts() -> None:
    """Ohne nginx_vhosts bricht doc() ab, analog zum Bash-Original."""
    with pytest.raises(ModuleError, match="kein vhost definiert"):
        Nginx.doc({})


def test_doc_never_leaks_secrets_from_unrelated_config_keys() -> None:
    """Kunstgeheimnis in fremden Schlüsseln erscheint nie in doc()."""
    values = {
        "nginx_vhosts": "example.com",
        "admin_mail": "admin@example.com",
        "relay_password": "KUNST-GEHEIMNIS-42",
        "totp_secret": "KUNST-GEHEIMNIS-42",
    }
    section = Nginx.doc(values)
    assert "KUNST-GEHEIMNIS-42" not in section
    assert "relay_password" not in section
    assert "totp_secret" not in section


# --- _test ---


def test_test_operation_reports_all_failures_when_nothing_runs() -> None:
    """Ohne laufenden Dienst/Listener meldet _test alle Teilprüfungen als Fehler."""
    mod = _make_nginx(operation="test")
    mod.SYSTEMCTL_BIN = "/bin/false"  # type: ignore[misc]
    mod.UFW_BIN = "/bin/false"  # type: ignore[misc]
    mod.CERTBOT_BIN = "/bin/false"  # type: ignore[misc]
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()
    mod.TEST_TCP_PORT = free_port  # type: ignore[misc]
    mod.TEST_TCP_TIMEOUT = 1.0  # type: ignore[misc]

    assert mod._test() == 1
