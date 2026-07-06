"""Unit-Tests für secure_base.modules.nginx."""

import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.nginx import Nginx, _hardening_content, _http_block_content


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
    return mod


# --- CONFIG ---


def test_nginx_config_declares_expected_keys_in_order() -> None:
    """CONFIG nennt operation, admin_mail und die nginx_-Schlüssel in Reihenfolge."""
    assert Nginx.CONFIG == [
        "operation",
        "admin_mail",
        "nginx_certbot_mail",
        "nginx_vhosts",
        "nginx_certbot_mode",
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
