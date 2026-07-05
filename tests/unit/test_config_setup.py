"""Unit-Tests für lsb.config_setup."""

import stat
from pathlib import Path
from typing import ClassVar

import lsb.config_setup as config_setup
import pytest
from lsb.config_setup import (
    _flatten,
    _required_keys,
    _set_in_section,
    ensure_config,
    fill_missing,
    module_config,
)
from lsb.module_spec import ModuleSpec
from pifos.config.config import Config
from pifos.errors import ConfigError


class _FakeModuleCls:
    """Platzhalter für eine Modulklasse mit CONFIG-Deklaration."""

    CONFIG: ClassVar[list[str]] = ["operation", "fqdn", "timezone"]


_FAKE_SPEC = ModuleSpec("base", "Grundkonfiguration", _FakeModuleCls, optional=False)  # type: ignore[arg-type]
_FAKE_REGISTRY = [_FAKE_SPEC]

_EXAMPLE_CONTENT = (
    "[installer]\n"
    "logfile = /var/log/lsb/lsb-installer.log\n"
    "loglevel = INFO\n"
    "modules_enabled = base\n"
    "optional_enabled =\n"
    "\n"
    "[general]\n"
    "fqdn =\n"
    "admin_mail =\n"
    "\n"
    "[base]\n"
    "timezone = Europe/Berlin\n"
)


class _StubPrompter:
    """Ersetzt QuestionaryPrompter mit festen Antworten je Schlüssel."""

    def __init__(self, answers: dict[str, str]) -> None:
        self._answers = answers

    def text(self, message: str, default: str = "") -> str:
        for key, value in self._answers.items():
            if message.endswith(key):
                return value
        raise AssertionError(f"unerwartete Frage: {message!r}")


# --- _flatten ---


def test_flatten_merges_sections_and_top_level_values() -> None:
    """_flatten führt Abschnitte und abschnittslose Werte zusammen."""
    data: dict[str, object] = {
        "general": {"fqdn": "server.example.com"},
        "base": {"timezone": "Europe/Berlin"},
        "loose": "value",
    }
    assert _flatten(data) == {
        "fqdn": "server.example.com",
        "timezone": "Europe/Berlin",
        "loose": "value",
    }


# --- module_config ---


def test_module_config_contains_only_declared_keys_and_operation() -> None:
    """module_config nimmt genau die CONFIG-Schlüssel des Moduls plus operation."""
    config = Config()
    config.load_dict(
        {
            "general": {"fqdn": "server.example.com", "admin_mail": "a@example.com"},
            "base": {"timezone": "Europe/Berlin"},
        }
    )

    module_cfg = module_config(config, _FAKE_SPEC, "install")

    assert module_cfg.to_dict() == {
        "fqdn": "server.example.com",
        "timezone": "Europe/Berlin",
        "operation": "install",
    }


# --- _required_keys ---


def test_required_keys_excludes_operation() -> None:
    """_required_keys sammelt CONFIG-Schlüssel der Auswahl ohne operation."""
    assert _required_keys(_FAKE_REGISTRY) == {"fqdn", "timezone"}


def test_required_keys_excludes_optional_keys() -> None:
    """Als optional_keys erklärte Schlüssel erzwingen keine Abfrage."""
    spec = ModuleSpec(
        "base",
        "Grundkonfiguration",
        _FakeModuleCls,  # type: ignore[arg-type]
        optional=False,
        optional_keys=("timezone",),
    )
    assert _required_keys([spec]) == {"fqdn"}


def test_required_keys_ignores_unselected_modules() -> None:
    """Nicht ausgewählte Module erzwingen keine Abfrage ihrer Werte."""
    assert _required_keys([]) == set()


# --- _set_in_section ---


def test_set_in_section_updates_existing_key() -> None:
    """_set_in_section setzt den Wert im Abschnitt, der ihn bereits trägt."""
    data: dict[str, object] = {"general": {"fqdn": ""}, "base": {"timezone": "x"}}
    _set_in_section(data, "fqdn", "server.example.com")
    assert data["general"] == {"fqdn": "server.example.com"}


def test_set_in_section_missing_key_raises() -> None:
    """Kein Abschnitt mit dem Schlüssel erzeugt ConfigError."""
    with pytest.raises(ConfigError, match="in keinem Abschnitt"):
        _set_in_section({"general": {}}, "unbekannt", "wert")


# --- fill_missing ---


def test_fill_missing_prompts_only_empty_required_and_writes_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nur leere Pflichtwerte werden abgefragt und in die Datei zurückgeschrieben."""
    monkeypatch.setattr(
        config_setup,
        "QuestionaryPrompter",
        lambda: _StubPrompter({"fqdn": "server.example.com"}),
    )
    path = tmp_path / "lsb.conf"
    config = Config()
    config.load_dict(
        {
            "general": {"fqdn": "", "admin_mail": "a@example.com"},
            "base": {"timezone": "Europe/Berlin"},
        }
    )

    fill_missing(config, path, _FAKE_REGISTRY)

    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert config.to_dict()["general"] == {
        "fqdn": "server.example.com",
        "admin_mail": "a@example.com",
    }


def test_fill_missing_nothing_missing_skips_write(tmp_path: Path) -> None:
    """Sind alle Pflichtwerte gesetzt, entfällt das Zurückschreiben."""
    path = tmp_path / "lsb.conf"
    config = Config()
    config.load_dict(
        {
            "general": {"fqdn": "server.example.com"},
            "base": {"timezone": "Europe/Berlin"},
        }
    )

    fill_missing(config, path, _FAKE_REGISTRY)

    assert not path.exists()


# --- _example_path ---


def test_example_path_prefers_sibling_example(tmp_path: Path) -> None:
    """Eine Beispieldatei neben dem Zielpfad hat Vorrang vor der Paket-Vorlage."""
    path = tmp_path / "lsb.conf"
    sibling = tmp_path / "lsb.conf.example"
    sibling.write_text(_EXAMPLE_CONTENT, encoding="utf-8")

    assert config_setup._example_path(path) == sibling


def test_example_path_falls_back_to_package_example(tmp_path: Path) -> None:
    """Ohne Geschwister-Beispiel wird die mitgelieferte Paket-Vorlage verwendet."""
    path = tmp_path / "lsb.conf"

    assert config_setup._example_path(path) == config_setup._DEFAULT_EXAMPLE


# --- _seed_from_example ---


def test_seed_from_example_copies_template_with_mode_0600(tmp_path: Path) -> None:
    """Die Vorlage wird unverändert mit Rechten 0600 an den Zielpfad kopiert."""
    example = tmp_path / "lsb.conf.example"
    example.write_text(_EXAMPLE_CONTENT, encoding="utf-8")
    path = tmp_path / "lsb.conf"

    result = config_setup._seed_from_example(path)

    assert result is True
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text(encoding="utf-8") == _EXAMPLE_CONTENT


def test_seed_from_example_returns_false_without_any_template(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlen Geschwister- und Paket-Beispiel, liefert die Funktion False."""
    monkeypatch.setattr(
        config_setup, "_DEFAULT_EXAMPLE", tmp_path / "nirgendwo.example"
    )
    path = tmp_path / "lsb.conf"

    assert config_setup._seed_from_example(path) is False
    assert not path.exists()


# --- ensure_config ---


def test_ensure_config_loads_existing_file_without_seeding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existiert die Datei, wird sie geladen; die Vorlage wird nicht kopiert."""

    def _fail_if_called(path: Path) -> bool:
        raise AssertionError("sollte nicht aufgerufen werden")

    monkeypatch.setattr(config_setup, "_seed_from_example", _fail_if_called)
    path = tmp_path / "lsb.conf"
    path.write_text(
        "[general]\nfqdn = server.example.com\n\n[base]\ntimezone = Europe/Berlin\n",
        encoding="utf-8",
    )

    config = ensure_config(path)

    assert config is not None
    assert config.get_section("general") == {"fqdn": "server.example.com"}


def test_ensure_config_seeds_from_example_and_fills_only_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Konfiguration, wird die Vorlage kopiert; nur Leeres wird gefragt.

    Reproduziert den Servertest-Befund: [installer] muss danach vorhanden
    sein (sonst scheitert configure_logging), timezone hat bereits einen
    Vorgabewert und darf nicht erneut abgefragt werden. Die Abfrage läuft
    seit der Modulauswahl-Kopplung als eigener Schritt fill_missing nach
    ensure_config (wie in installer.main).
    """
    example = tmp_path / "vorlage.example"
    example.write_text(_EXAMPLE_CONTENT, encoding="utf-8")
    monkeypatch.setattr(config_setup, "_DEFAULT_EXAMPLE", example)
    monkeypatch.setattr(
        config_setup,
        "QuestionaryPrompter",
        lambda: _StubPrompter({"fqdn": "server.example.com"}),
    )
    path = tmp_path / "lsb.conf"

    config = ensure_config(path)
    assert config is not None
    fill_missing(config, path, _FAKE_REGISTRY)

    assert config is not None
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert config.get_section("installer") == {
        "logfile": "/var/log/lsb/lsb-installer.log",
        "loglevel": "INFO",
        "modules_enabled": "base",
        "optional_enabled": "",
    }
    assert config.get_section("general") == {
        "fqdn": "server.example.com",
        "admin_mail": "",
    }
    assert config.get_section("base") == {"timezone": "Europe/Berlin"}


def test_ensure_config_returns_none_if_seeding_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kann keine Vorlage gefunden werden, liefert ensure_config None."""
    monkeypatch.setattr(config_setup, "_seed_from_example", lambda path: False)
    path = tmp_path / "lsb.conf"

    assert ensure_config(path) is None


def test_ensure_config_propagates_configerror_from_seeding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein Fehler beim Kopieren der Vorlage wird als ConfigError durchgereicht."""

    def _raise(path: Path) -> bool:
        raise ConfigError("Vorlage kann nicht kopiert werden: kaputt")

    monkeypatch.setattr(config_setup, "_seed_from_example", _raise)
    path = tmp_path / "lsb.conf"

    with pytest.raises(ConfigError):
        ensure_config(path)
