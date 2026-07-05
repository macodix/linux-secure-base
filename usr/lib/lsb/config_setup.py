"""Konfiguration laden, fehlende Werte klären, Modulkonfiguration bauen."""

import contextlib
import logging
import os
import shutil
import tempfile
from pathlib import Path

from pifos.config.config import Config
from pifos.configurator import QuestionaryPrompter, write_config_data
from pifos.errors import ConfigError

from lsb.module_spec import ModuleSpec

logger = logging.getLogger(__name__)

# Paket-Root, drei Verzeichnisebenen über dieser Datei (analog installer.py),
# und die mitgelieferte Vorlage als Rückfall, wenn keine Beispieldatei neben
# der Zieldatei liegt.
_PACKAGE_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_EXAMPLE = _PACKAGE_ROOT / "etc" / "lsb" / "lsb.conf.example"


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


def _required_keys(specs: list[ModuleSpec]) -> set[str]:
    """Sammelt die Pflichtschlüssel der ausgewählten Module.

    Pflicht ist jeder in einer Modul-CONFIG genannte Schlüssel außer
    operation und den je Registratureintrag als optional_keys erklärten
    Schlüsseln; operation ist kein persistenter Wert, sondern wird vom
    Aufrufer je Lauf gesetzt (Plan Abschnitt 2.8). Nicht ausgewählte
    Module (etwa ein deaktiviertes optionales Modul) erzwingen keine
    Abfrage ihrer Werte.

    Args:
        specs: Für diesen Lauf ausgewählte Registratureinträge.

    Returns:
        Vereinigung der Pflichtschlüssel über die ausgewählten Einträge.
    """
    required: set[str] = set()
    for spec in specs:
        skip = {"operation", *spec.optional_keys}
        required.update(k for k in spec.module_cls.CONFIG if k not in skip)
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


def _example_path(path: Path) -> Path:
    """Bestimmt die als Vorlage zu verwendende Beispieldatei.

    Bevorzugt eine Beispieldatei neben dem Zielpfad (<name>.example, z. B.
    lsb.conf.example neben lsb.conf); fehlt sie, wird die mitgelieferte
    Vorlage aus dem Paket verwendet.

    Args:
        path: Zielpfad der echten Konfigurationsdatei.

    Returns:
        Pfad der zu verwendenden Beispieldatei.
    """
    sibling = path.with_name(path.name + ".example")
    return sibling if sibling.exists() else _DEFAULT_EXAMPLE


def _seed_from_example(path: Path) -> bool:
    """Kopiert die Beispielvorlage atomar an den Zielpfad, mit Rechten 0600.

    Die Vorlage behält ihre Abschnitte ([installer], [general], [base],
    ...), Vorgabewerte (z. B. timezone) und Kommentare unangetastet;
    _fill_missing fragt danach nur die tatsächlich leeren Pflichtwerte ab.
    Der frühere Aufbau aus den Modul-CONFIG-Listen (Configurator.
    build_for_modules) erzeugte dagegen nur Modul-Abschnitte und ließ
    [installer]/[general] nie entstehen — configure_logging scheiterte
    danach an dem fehlenden Abschnitt [installer].

    Args:
        path: Zielpfad der neuen Konfigurationsdatei.

    Returns:
        True, wenn die Vorlage kopiert wurde; False, wenn keine
        Beispieldatei gefunden wurde.

    Raises:
        ConfigError: Bei einem Dateisystemfehler beim Kopieren.
    """
    example = _example_path(path)
    if not example.exists():
        logger.error("Keine Beispielvorlage gefunden: %s", example)
        return False

    try:
        fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    except OSError as exc:
        raise ConfigError(f"Vorlage kann nicht angelegt werden: {exc}") from exc
    os.close(fd)
    tmp_path = Path(tmp)
    success = False
    try:
        shutil.copyfile(str(example), tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(path))
        success = True
    except OSError as exc:
        raise ConfigError(f"Vorlage kann nicht kopiert werden: {exc}") from exc
    finally:
        if not success:
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
    return True


def fill_missing(config: Config, path: Path, specs: list[ModuleSpec]) -> None:
    """Fragt leere Pflichtwerte der ausgewählten Module ab.

    Eingaben laufen als Freitext ohne Maskierung (Plan Abschnitt 1.2).
    Ist nichts leer, entfällt das Schreiben; sonst wird die Datei mit
    Rechten 0600 zurückgeschrieben.

    Args:
        config: Bereits geladene Konfiguration.
        path: Pfad der echten Konfigurationsdatei (Rückschreibeziel).
        specs: Für diesen Lauf ausgewählte Registratureinträge.
    """
    flat = _flatten(config.to_dict())
    missing = sorted(
        k for k in _required_keys(specs) if not str(flat.get(k, "")).strip()
    )
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
    """Lädt die Konfiguration, bei Bedarf aus der Beispielvorlage.

    Fehlt die Datei, wird die mitgelieferte Beispielvorlage als
    Ausgangspunkt kopiert (Abschnitte, Vorgabewerte und Kommentare bleiben
    erhalten). Die Abfrage leerer Pflichtwerte übernimmt fill_missing,
    nachdem die Modulauswahl feststeht — nur ausgewählte Module erzwingen
    ihre Werte.

    Args:
        path: Pfad der Konfigurationsdatei.

    Returns:
        Geladene Konfiguration oder None, wenn keine erzeugt werden konnte.
    """
    if not path.exists():
        logger.warning("Konfiguration fehlt: %s", path)
        if not _seed_from_example(path):
            return None
    config = Config()
    config.load_file(str(path), "ini")
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
