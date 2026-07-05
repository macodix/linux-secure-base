"""Unit-Tests für lsb.modules.postfix."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from lsb.modules.postfix import (
    Postfix,
    _aliases_block_content,
    _debconf_content,
    _recipient_canonical_content,
    _sasl_passwd_content,
)
from pifos.errors import ModuleError
from pifos.ipc import LogLevel


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
