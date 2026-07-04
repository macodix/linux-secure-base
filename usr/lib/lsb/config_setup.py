"""Konfiguration laden, fehlende Werte klären, Modulkonfiguration bauen."""

import logging
import os
from pathlib import Path

from pifos.config.config import Config
from pifos.configurator import Configurator, QuestionaryPrompter, write_config_data
from pifos.errors import ConfigError

from lsb.module_spec import ModuleSpec
from lsb.modules import REGISTRY

logger = logging.getLogger(__name__)


def _flatten(data: dict[str, object]) -> dict[str, object]:
    """Führt Abschnitte und oberste Werte zu einer flachen Zuordnung zusammen.

    Datei-weit eindeutige Schlüssel machen das Zusammenführen eindeutig
    (Plan 2.6).

    Args:
        data: Konfiguration als verschachteltes dict.

    Returns:
        Flache Zuordnung Schlüssel zu Wert.
    """
    flat: dict[str, object] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            flat.update(value)
        else:
            flat[key] = value
    return flat


def _required_keys() -> set[str]:
    """Sammelt die Pflichtschlüssel aller Module der Registratur.

    Pflicht ist jeder in einer Modul-CONFIG genannte Schlüssel außer
    operation; operation ist kein persistenter Wert, sondern wird vom
    Aufrufer je Lauf gesetzt (Plan Abschnitt 2.8).

    Returns:
        Vereinigung der Pflichtschlüssel über alle Registratureinträge.
    """
    required: set[str] = set()
    for spec in REGISTRY:
        required.update(k for k in spec.module_cls.CONFIG if k != "operation")
    return required


def _set_in_section(data: dict[str, object], key: str, value: str) -> None:
    """Setzt key im Abschnitt, in dem er bereits vorkommt.

    Args:
        data: Verschachtelte Konfiguration (Abschnitt → dict).
        key: Zu setzender Schlüssel.
        value: Neuer Wert.

    Raises:
        ConfigError: Wenn kein Abschnitt den Schlüssel bereits enthält.
    """
    for section in data.values():
        if isinstance(section, dict) and key in section:
            section[key] = value
            return
    raise ConfigError(f"Schlüssel {key!r} in keinem Abschnitt der Vorlage gefunden")


def _build_with_configurator(path: Path) -> bool:
    """Baut eine neue Konfiguration aus den Moduldeklarationen der Registratur.

    Fragt für jedes Modul dessen CONFIG-Werte ab und schreibt das Ergebnis
    nach path im ini-Format mit Rechten 0600, da die Datei später
    Geheimnisse aufnehmen kann. operation wird nicht abgefragt (kein
    persistenter Wert): als Platzhalter vorbelegt, damit build_for_modules
    nicht danach fragt, und vor dem Schreiben wieder entfernt.

    Args:
        path: Zielpfad der neuen Konfigurationsdatei.

    Returns:
        True, wenn die Konfiguration angelegt wurde.
    """
    configurator = Configurator()
    modules = {spec.name: spec.module_cls for spec in REGISTRY}
    placeholder: dict[str, object] = {spec.name: {"operation": ""} for spec in REGISTRY}
    data = configurator.build_for_modules(modules, placeholder)
    for section in data.values():
        if isinstance(section, dict):
            section.pop("operation", None)
    write_config_data(data, "ini", str(path))
    os.chmod(str(path), 0o600)
    return True


def _fill_missing(config: Config, path: Path) -> None:
    """Fragt leere Pflichtwerte ab und schreibt sie in path zurück.

    Eingaben laufen als Freitext ohne Maskierung (Plan Abschnitt 1.2);
    base kennt keine Geheimnisse. Ist nichts leer, entfällt das Schreiben.

    Args:
        config: Bereits geladene Konfiguration.
        path: Pfad der echten Konfigurationsdatei (Rückschreibeziel).
    """
    flat = _flatten(config.to_dict())
    missing = sorted(k for k in _required_keys() if not str(flat.get(k, "")).strip())
    if not missing:
        return

    prompter = QuestionaryPrompter()
    data = config.to_dict()
    for key in missing:
        value = prompter.text(f"Wert für {key}")
        _set_in_section(data, key, value)

    write_config_data(data, "ini", str(path), overwrite=True)
    os.chmod(str(path), 0o600)
    config.load_dict(data)


def ensure_config(path: Path) -> Config | None:
    """Lädt die Konfiguration und klärt fehlende Pflichtwerte.

    Fehlt die Datei, wird der Konfigurator geführt. Sind Pflichtwerte leer,
    werden sie dialogisch abgefragt und zurückgeschrieben.

    Args:
        path: Pfad der Konfigurationsdatei.

    Returns:
        Geladene Konfiguration oder None, wenn keine erzeugt werden konnte.
    """
    if not path.exists():
        logger.warning("Konfiguration fehlt: %s", path)
        if not _build_with_configurator(path):
            return None
    config = Config()
    config.load_file(str(path), "ini")
    _fill_missing(config, path)
    return config


def module_config(config: Config, spec: ModuleSpec, operation: str) -> Config:
    """Stellt die Konfiguration für ein Modul zusammen.

    Nimmt aus der flachen Zuordnung genau die in der Modul-CONFIG genannten
    Schlüssel und ergänzt die Betriebsart.

    Args:
        config: Vollständige geladene Konfiguration.
        spec: Registratureintrag des Moduls.
        operation: "install" oder "check".

    Returns:
        Config-Objekt mit den Modulwerten und dem Schlüssel "operation".
    """
    flat = _flatten(config.to_dict())
    keys = [k for k in spec.module_cls.CONFIG if k != "operation"]
    data = {k: flat[k] for k in keys if k in flat}
    data["operation"] = operation
    module_cfg = Config()
    module_cfg.load_dict(data)
    return module_cfg
