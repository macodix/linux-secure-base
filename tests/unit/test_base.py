"""Unit-Tests für secure_base.modules.base."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.base import (
    SYSCTL_PARAMS,
    Base,
    _modprobe_content,
    _sysctl_content,
)


def _make_base(
    fqdn: str = "server.example.com", timezone: str = "Europe/Berlin"
) -> Base:
    """Baut ein Base-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Base(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.timezone = timezone
    mod.force_overwrite = "no"
    mod.backup_run_dir = "/var/backup/secure-base/test-lauf"
    return mod


def _make_executable(tmp_path: Path, name: str, content: str) -> str:
    """Legt ein ausführbares Shell-Script an und liefert dessen Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{content}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


# --- CONFIG ---


def test_base_config_declares_operation_fqdn_timezone() -> None:
    """CONFIG nennt operation, fqdn, timezone und die Drift-Schutz-Schlüssel."""
    assert Base.CONFIG == [
        "operation",
        "fqdn",
        "timezone",
        "force_overwrite",
        "backup_run_dir",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültiger Rechnername und bekannte Zeitzone lösen keine Ausnahme aus."""
    mod = _make_base("server.example.com", "Europe/Berlin")
    mod._validate()


def test_validate_rejects_invalid_hostname() -> None:
    """Ein ungültiger Rechnername erzeugt ModuleError."""
    mod = _make_base("-invalid-.example.com", "Europe/Berlin")
    with pytest.raises(ModuleError, match="Ungültiger Rechnername"):
        mod._validate()


def test_validate_rejects_unknown_timezone() -> None:
    """Eine unbekannte Zeitzone erzeugt ModuleError."""
    mod = _make_base("server.example.com", "Nirgendwo/Erfunden")
    with pytest.raises(ModuleError, match="Unbekannte Zeitzone"):
        mod._validate()


# --- Inhaltsfunktionen ---


def test_sysctl_content_contains_all_params() -> None:
    """_sysctl_content enthält jeden Schlüssel/Wert aus SYSCTL_PARAMS."""
    content = _sysctl_content()
    for key, value in SYSCTL_PARAMS:
        assert f"{key} = {value}" in content


def test_modprobe_content_blacklists_usb_storage() -> None:
    """_modprobe_content sperrt usb-storage per install und blacklist."""
    content = _modprobe_content()
    assert "install usb-storage /bin/true" in content
    assert "blacklist usb-storage" in content


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_base("server.example.com", "Europe/Berlin")
    assert mod._check_value(["/bin/echo", "yes"], "yes", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_base("server.example.com", "Europe/Berlin")
    assert mod._check_value(["/bin/echo", "nein"], "ja", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_base("server.example.com", "Europe/Berlin")
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False


# --- _step_remove_sysctl_conf ---


def test_step_remove_sysctl_conf_removes_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entfernt die vorhandene sysctl-Datei und wendet die Systemwerte neu an."""
    mod = _make_base()
    conf = tmp_path / "sysctl.conf"
    conf.write_text("kernel.dmesg_restrict = 1\n", encoding="utf-8")
    monkeypatch.setattr(Base, "SYSCTL_CONF", str(conf))
    monkeypatch.setattr(Base, "SYSCTL_BIN", "/usr/bin/true")

    assert mod._step_remove_sysctl_conf() == 0
    assert not conf.exists()


def test_step_remove_sysctl_conf_idempotent_without_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Datei bereits, bleibt der Schritt erfolgreich (idempotent)."""
    mod = _make_base()
    monkeypatch.setattr(Base, "SYSCTL_CONF", str(tmp_path / "fehlt.conf"))

    assert mod._step_remove_sysctl_conf() == 0


def test_step_remove_sysctl_conf_fails_when_reapply_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt die Neuanwendung der Systemwerte fehl, liefert der Schritt 1."""
    mod = _make_base()
    conf = tmp_path / "sysctl.conf"
    conf.write_text("kernel.dmesg_restrict = 1\n", encoding="utf-8")
    monkeypatch.setattr(Base, "SYSCTL_CONF", str(conf))
    monkeypatch.setattr(Base, "SYSCTL_BIN", "/usr/bin/false")

    assert mod._step_remove_sysctl_conf() == 1
    assert not conf.exists()


# --- _step_remove_modprobe_conf ---


def test_step_remove_modprobe_conf_removes_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entfernt die vorhandene Modul-Sperrliste."""
    mod = _make_base()
    conf = tmp_path / "modprobe.conf"
    conf.write_text("blacklist usb-storage\n", encoding="utf-8")
    monkeypatch.setattr(Base, "MODPROBE_CONF", str(conf))

    assert mod._step_remove_modprobe_conf() == 0
    assert not conf.exists()


def test_step_remove_modprobe_conf_idempotent_without_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Datei bereits, bleibt der Schritt erfolgreich (idempotent)."""
    mod = _make_base()
    monkeypatch.setattr(Base, "MODPROBE_CONF", str(tmp_path / "fehlt.conf"))

    assert mod._step_remove_modprobe_conf() == 0


# --- _systemctl_is_enabled / _step_unmask_autofs ---


def test_systemctl_is_enabled_reads_stdout_despite_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Liest den Zustand aus stdout, auch wenn systemctl mit Fehlercode endet."""
    mod = _make_base()
    monkeypatch.setattr(
        Base,
        "SYSTEMCTL_BIN",
        _make_executable(tmp_path, "systemctl", "echo masked; exit 1"),
    )

    assert mod._systemctl_is_enabled("autofs") == "masked"


def test_systemctl_is_enabled_returns_empty_on_startup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Startet der Befehl nicht, liefert die Abfrage eine leere Zeichenkette."""
    mod = _make_base()
    monkeypatch.setattr(Base, "SYSTEMCTL_BIN", "/pfad/existiert/nicht")

    assert mod._systemctl_is_enabled("autofs") == ""


def test_step_unmask_autofs_unmasks_when_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist autofs maskiert, hebt der Schritt die Maskierung auf."""
    mod = _make_base()
    monkeypatch.setattr(
        Base,
        "SYSTEMCTL_BIN",
        _make_executable(
            tmp_path,
            "systemctl",
            'if [ "$1" = "is-enabled" ]; then echo masked; exit 1; fi\nexit 0',
        ),
    )

    assert mod._step_unmask_autofs() == 0


def test_step_unmask_autofs_skips_when_not_masked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist autofs nicht maskiert, überspringt der Schritt das Entmaskieren."""
    mod = _make_base()
    monkeypatch.setattr(
        Base,
        "SYSTEMCTL_BIN",
        _make_executable(tmp_path, "systemctl", "echo enabled; exit 0"),
    )

    assert mod._step_unmask_autofs() == 0


def test_step_unmask_autofs_fails_when_unmask_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt das Entmaskieren fehl, liefert der Schritt 1."""
    mod = _make_base()
    monkeypatch.setattr(
        Base,
        "SYSTEMCTL_BIN",
        _make_executable(
            tmp_path,
            "systemctl",
            'if [ "$1" = "is-enabled" ]; then echo masked; exit 1; fi\nexit 1',
        ),
    )

    assert mod._step_unmask_autofs() == 1


# --- _uninstall ---


def test_uninstall_runs_all_steps_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte erfolgreich: _uninstall liefert 0 und meldet keinen Fehlschlag."""
    mod = _make_base()
    mod.operation = "uninstall"
    monkeypatch.setattr(Base, "SYSCTL_CONF", str(tmp_path / "fehlt-sysctl.conf"))
    monkeypatch.setattr(Base, "MODPROBE_CONF", str(tmp_path / "fehlt-modprobe.conf"))
    monkeypatch.setattr(Base, "SYSTEMCTL_BIN", "/usr/bin/true")

    assert mod._uninstall() == 0


def test_uninstall_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Schlägt ein Schritt fehl, bricht _uninstall ab und liefert 1."""
    mod = _make_base()
    mod.operation = "uninstall"
    conf = tmp_path / "sysctl.conf"
    conf.write_text("kernel.dmesg_restrict = 1\n", encoding="utf-8")
    monkeypatch.setattr(Base, "SYSCTL_CONF", str(conf))
    monkeypatch.setattr(Base, "SYSCTL_BIN", "/usr/bin/false")

    assert mod._uninstall() == 1


# --- _test ---


def test_test_returns_success_without_any_action() -> None:
    """_test führt keine Aktion aus und liefert immer 0."""
    mod = _make_base()
    mod.operation = "test"

    assert mod._test() == 0


# --- doc ---


def test_doc_contains_title_values_and_file_path() -> None:
    """doc() enthält den Abschnittstitel, die Konfigurationswerte und Pfade."""
    output = Base.doc({"fqdn": "server.example.com", "timezone": "Europe/Berlin"})

    assert "## Grundkonfiguration" in output
    assert "server.example.com" in output
    assert "Europe/Berlin" in output
    assert Base.SYSCTL_CONF in output
    assert Base.MODPROBE_CONF in output


def test_doc_marks_missing_values_as_leer_default() -> None:
    """Fehlen Werte in values, erscheinen sie als '(leer/Default)'."""
    output = Base.doc({})

    assert "(leer/Default)" in output


def test_doc_never_leaks_secret_values() -> None:
    """Ein als Wert übergebenes Geheimnis erscheint nicht in der Ausgabe."""
    output = Base.doc(
        {
            "fqdn": "server.example.com",
            "timezone": "Europe/Berlin",
            "relay_password": "GEHEIM-X",
            "main_user_password": "GEHEIM-X",
            "restic_passphrase": "GEHEIM-X",
        }
    )

    assert "GEHEIM-X" not in output
