"""Unit-Tests für secure_base.selection."""

import pytest
import secure_base.selection as selection_module
from pifos.config.config import Config
from secure_base.module_spec import ModuleSpec
from secure_base.selection import _split, select_modules


class _DummyModuleCls:
    """Platzhalter für eine Modulklasse; select_modules liest sie nie."""


_MANDATORY_A = ModuleSpec("mandatory_a", "Pflicht A", _DummyModuleCls, optional=False)  # type: ignore[arg-type]
_OPTIONAL_B = ModuleSpec("optional_b", "Optional B", _DummyModuleCls, optional=True)  # type: ignore[arg-type]
_MANDATORY_C = ModuleSpec("mandatory_c", "Pflicht C", _DummyModuleCls, optional=False)  # type: ignore[arg-type]

_FAKE_REGISTRY = [_MANDATORY_A, _OPTIONAL_B, _MANDATORY_C]


def _config(modules_enabled: str, optional_enabled: str = "") -> Config:
    """Baut eine Config mit dem Abschnitt [installer]."""
    cfg = Config()
    cfg.load_dict(
        {
            "installer": {
                "modules_enabled": modules_enabled,
                "optional_enabled": optional_enabled,
            }
        }
    )
    return cfg


def test_split_ignores_empty_and_whitespace() -> None:
    """_split trimmt Einträge und verwirft leere."""
    assert _split(" a, b ,, c ") == ["a", "b", "c"]
    assert _split("") == []


def test_select_modules_named_returns_only_named_in_registry_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Benannte Module laufen unabhängig von der Konfiguration, in Reihenfolge."""
    monkeypatch.setattr(selection_module, "REGISTRY", _FAKE_REGISTRY)
    config = _config(modules_enabled="", optional_enabled="")

    result = select_modules(["mandatory_c", "mandatory_a"], False, config)

    assert [s.name for s in result] == ["mandatory_a", "mandatory_c"]


def test_select_modules_default_returns_enabled_mandatory_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ohne Angabe laufen nur die aktivierten Pflichtmodule."""
    monkeypatch.setattr(selection_module, "REGISTRY", _FAKE_REGISTRY)
    config = _config(modules_enabled="mandatory_a, mandatory_c")

    result = select_modules([], False, config)

    assert [s.name for s in result] == ["mandatory_a", "mandatory_c"]


def test_select_modules_excludes_disabled_mandatory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein nicht aktiviertes Pflichtmodul läuft nicht mit."""
    monkeypatch.setattr(selection_module, "REGISTRY", _FAKE_REGISTRY)
    config = _config(modules_enabled="mandatory_a")

    result = select_modules([], False, config)

    assert [s.name for s in result] == ["mandatory_a"]


def test_select_modules_with_optional_flag_adds_enabled_optional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Der Schalter -o ergänzt die aktivierten optionalen Module."""
    monkeypatch.setattr(selection_module, "REGISTRY", _FAKE_REGISTRY)
    config = _config(modules_enabled="mandatory_a", optional_enabled="optional_b")

    result = select_modules([], True, config)

    assert [s.name for s in result] == ["mandatory_a", "optional_b"]


def test_select_modules_without_optional_flag_excludes_optional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ohne den Schalter -o laufen aktivierte optionale Module nicht mit."""
    monkeypatch.setattr(selection_module, "REGISTRY", _FAKE_REGISTRY)
    config = _config(modules_enabled="mandatory_a", optional_enabled="optional_b")

    result = select_modules([], False, config)

    assert [s.name for s in result] == ["mandatory_a"]
