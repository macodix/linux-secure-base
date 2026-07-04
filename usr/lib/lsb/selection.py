"""Auswahllogik der auszuführenden Module."""

from typing import cast

from pifos.config.config import Config

from lsb.module_spec import ModuleSpec
from lsb.modules import REGISTRY


def _split(value: object) -> list[str]:
    """Zerlegt einen kommagetrennten ini-Wert in eine Liste.

    ini speichert Werte als Zeichenkette; die Aktivierungslisten stehen
    daher kommagetrennt in der Datei.

    Args:
        value: Kommagetrennte Zeichenkette oder leerer Wert.

    Returns:
        Liste der nicht-leeren, getrimmten Einträge.
    """
    return [item.strip() for item in str(value).split(",") if item.strip()]


def select_modules(
    named: list[str], with_optional: bool, config: Config
) -> list[ModuleSpec]:
    """Wählt die auszuführenden Module in fester Reihenfolge.

    Args:
        named: Ausdrücklich benannte Module; leer für die aktiven.
        with_optional: True, wenn optionale Module mitlaufen sollen.
        config: Geladene Konfiguration mit den Aktivierungslisten.

    Returns:
        Ausgewählte Registratureinträge in Ausführungsreihenfolge.
    """
    installer = cast(dict[str, object], config.get_section("installer"))
    enabled = set(_split(installer.get("modules_enabled", "")))
    optional_enabled = set(_split(installer.get("optional_enabled", "")))
    if named:
        wanted = set(named)
        return [s for s in REGISTRY if s.name in wanted]
    result: list[ModuleSpec] = []
    for spec in REGISTRY:
        if spec.optional:
            if with_optional and spec.name in optional_enabled:
                result.append(spec)
        elif spec.name in enabled:
            result.append(spec)
    return result
