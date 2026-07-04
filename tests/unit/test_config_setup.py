"""Unit-Tests für lsb.config_setup."""

import stat
from pathlib import Path
from typing import ClassVar

import lsb.config_setup as config_setup
import pytest
from lsb.config_setup import (
    _fill_missing,
    _flatten,
    _required_keys,
    _set_in_section,
    ensure_config,
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


class _StubPrompter:
    """Ersetzt QuestionaryPrompter mit festen Antworten je Schlüssel."""

    def __init__(self, answers: dict[str, str]) -> None:
        self._answers = answers

    def text(self, message: str, default: str = "") -> str:
        for key, value in self._answers.items():
            if message.endswith(key):
                return value
        raise AssertionError(f"unerwartete Frage: {message!r}")


class _StubConfigurator:
    """Ersetzt Configurator: keine echten Dialoge, feste Rückgabewerte."""

    last_modules: ClassVar[dict[str, type] | None] = None
    last_existing: ClassVar[dict[str, object] | None] = None

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def build_for_modules(
        self,
        modules: dict[str, type],
        existing: dict[str, object] | None = None,
    ) -> dict[str, object]:
        _StubConfigurator.last_modules = modules
        _StubConfigurator.last_existing = existing
        result: dict[str, object] = {}
        for name, prev in (existing or {}).items():
            section = dict(prev) if isinstance(prev, dict) else {}
            section["fqdn"] = "server.example.com"
            section["timezone"] = "Europe/Berlin"
            result[name] = section
        return result


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


def test_required_keys_excludes_operation(monkeypatch: pytest.MonkeyPatch) -> None:
    """_required_keys sammelt CONFIG-Schlüssel aller Module ohne operation."""
    monkeypatch.setattr(config_setup, "REGISTRY", _FAKE_REGISTRY)
    assert _required_keys() == {"fqdn", "timezone"}


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


# --- _fill_missing ---


def test_fill_missing_prompts_only_empty_required_and_writes_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nur leere Pflichtwerte werden abgefragt und in die Datei zurückgeschrieben."""
    monkeypatch.setattr(config_setup, "REGISTRY", _FAKE_REGISTRY)
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

    _fill_missing(config, path)

    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert config.to_dict()["general"] == {
        "fqdn": "server.example.com",
        "admin_mail": "a@example.com",
    }


def test_fill_missing_nothing_missing_skips_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sind alle Pflichtwerte gesetzt, entfällt das Zurückschreiben."""
    monkeypatch.setattr(config_setup, "REGISTRY", _FAKE_REGISTRY)
    path = tmp_path / "lsb.conf"
    config = Config()
    config.load_dict(
        {
            "general": {"fqdn": "server.example.com"},
            "base": {"timezone": "Europe/Berlin"},
        }
    )

    _fill_missing(config, path)

    assert not path.exists()


# --- _build_with_configurator ---


def test_build_with_configurator_writes_file_without_operation_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Die Datei entsteht mit Rechten 0600 und ohne den operation-Schlüssel."""
    monkeypatch.setattr(config_setup, "REGISTRY", _FAKE_REGISTRY)
    monkeypatch.setattr(config_setup, "Configurator", _StubConfigurator)
    path = tmp_path / "lsb.conf"

    result = config_setup._build_with_configurator(path)

    assert result is True
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    content = path.read_text(encoding="utf-8")
    assert "operation" not in content
    assert "fqdn = server.example.com" in content
    assert _StubConfigurator.last_existing == {"base": {"operation": ""}}


# --- ensure_config ---


def test_ensure_config_loads_existing_file_without_building(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existiert die Datei, wird sie geladen; der Konfigurator läuft nicht."""
    monkeypatch.setattr(config_setup, "REGISTRY", _FAKE_REGISTRY)

    def _fail_if_called(path: Path) -> bool:
        raise AssertionError("sollte nicht aufgerufen werden")

    monkeypatch.setattr(config_setup, "_build_with_configurator", _fail_if_called)
    path = tmp_path / "lsb.conf"
    path.write_text(
        "[general]\nfqdn = server.example.com\n\n[base]\ntimezone = Europe/Berlin\n",
        encoding="utf-8",
    )

    config = ensure_config(path)

    assert config is not None
    assert config.get_section("general") == {"fqdn": "server.example.com"}


def test_ensure_config_builds_when_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Datei, wird sie über den Konfigurator angelegt."""
    monkeypatch.setattr(config_setup, "REGISTRY", _FAKE_REGISTRY)
    path = tmp_path / "lsb.conf"

    def _fake_build(target: Path) -> bool:
        target.write_text(
            "[base]\nfqdn = server.example.com\ntimezone = Europe/Berlin\n",
            encoding="utf-8",
        )
        return True

    monkeypatch.setattr(config_setup, "_build_with_configurator", _fake_build)

    config = ensure_config(path)

    assert config is not None
    assert config.get_section("base") == {
        "fqdn": "server.example.com",
        "timezone": "Europe/Berlin",
    }


def test_ensure_config_returns_none_if_build_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scheitert der Aufbau, liefert ensure_config None."""
    monkeypatch.setattr(config_setup, "_build_with_configurator", lambda path: False)
    path = tmp_path / "lsb.conf"

    assert ensure_config(path) is None
