"""Interaktiver Konfigurator für pifos-Konfigurationsdateien.

Erzeugt Konfigurationsdateien aus Moduldeklarationen, geht bestehende Dateien
Wert für Wert durch und legt beliebige Dateien frei an. Nutzbar als
Bibliotheks-Schnittstelle und über den Einstieg bin/pifos-config.
"""

import argparse
import contextlib
import importlib
import logging
import os
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

import questionary
from rich.console import Console

from pifos.actions._file_ops import backup_destination
from pifos.config.config import Config
from pifos.errors import ActionError, ConfigError
from pifos.module import Module

_FORMATS = ("ini", "json", "toml")

_LOGGER = logging.getLogger(__name__)
_LOGGER.addHandler(logging.NullHandler())


class Prompter(Protocol):
    """Abstrahiert die Dialogarten Text und Bestätigung."""

    def text(self, message: str, default: str = "") -> str:
        """Fragt einen Freitextwert ab.

        Args:
            message: Anzeigetext des Dialogs.
            default: Vorgabewert; bleibt sichtbar, wird nicht maskiert.

        Returns:
            Eingegebener Wert.
        """
        ...

    def confirm(self, message: str, default: bool = False) -> bool:
        """Fragt eine Ja/Nein-Entscheidung ab.

        Args:
            message: Anzeigetext des Dialogs.
            default: Vorbelegte Antwort.

        Returns:
            True bei Bestätigung, sonst False.
        """
        ...


class QuestionaryPrompter:
    """Standard-Prompter auf Basis von questionary.

    Erfasst Eingaben als Freitext ohne Maskierung. Ein abgebrochener Dialog
    (questionary liefert None) führt zu einem ConfigError.
    """

    def text(self, message: str, default: str = "") -> str:
        """Fragt einen Freitextwert über questionary.text ab."""
        answer = questionary.text(message, default=default).ask()
        if answer is None:
            raise ConfigError("Eingabe abgebrochen")
        return str(answer)

    def confirm(self, message: str, default: bool = False) -> bool:
        """Fragt eine Bestätigung über questionary.confirm ab."""
        answer = questionary.confirm(message, default=default).ask()
        if answer is None:
            raise ConfigError("Bestätigung abgebrochen")
        return bool(answer)


class Configurator:
    """Baut Konfigurationen im Dialog auf.

    Deckt drei Fälle ab: Erstellen aus Moduldeklarationen, Bearbeiten einer
    bestehenden Konfiguration und freies Erstellen. Die Dialoge laufen über einen
    Prompter, die Nutzerausgabe über eine rich.Console.
    """

    def __init__(
        self, prompter: Prompter | None = None, console: Console | None = None
    ) -> None:
        """Initialisiert den Konfigurator mit Prompter und Konsole.

        Args:
            prompter: Dialogquelle; ohne Angabe QuestionaryPrompter.
            console: Ausgabekonsole; ohne Angabe eine Standard-rich-Console.
        """
        self._prompter: Prompter = prompter or QuestionaryPrompter()
        self._console = console or Console()

    def build_for_module(
        self, module_cls: type[Module], existing: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Baut den Konfigurationsabschnitt eines Moduls aus dessen CONFIG.

        Vorhandene Werte aus existing werden übernommen, fehlende abgefragt.

        Args:
            module_cls: Modulklasse, deren CONFIG ausgewertet wird.
            existing: Bereits vorhandene Werte des Abschnitts oder None.

        Returns:
            Abschnitt als dict.
        """
        known = existing or {}
        section: dict[str, object] = {}
        self._console.rule(module_cls.__name__)
        for key in module_cls.CONFIG:
            if key in known:
                section[key] = known[key]
            else:
                section[key] = self._prompt_value(module_cls.__name__, key)
        return section

    def build_for_modules(
        self,
        modules: Sequence[type[Module]] | Mapping[str, type[Module]],
        existing: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """Baut eine Sammelkonfiguration mit einem Abschnitt je Modul.

        Args:
            modules: Folge von Modulklassen (Abschnittsname = Klassenname) oder
                Zuordnung Abschnittsname → Modulklasse.
            existing: Bereits vorhandene Konfiguration oder None.

        Returns:
            Konfiguration als dict mit einem Abschnitt je Modul.
        """
        known = existing or {}
        if isinstance(modules, Mapping):
            items = list(modules.items())
        else:
            items = [(cls.__name__, cls) for cls in modules]
        result: dict[str, object] = {}
        for name, cls in items:
            prev = known.get(name)
            prev_section = prev if isinstance(prev, dict) else None
            result[name] = self.build_for_module(cls, prev_section)
        return result

    def edit(self, data: dict[str, object]) -> dict[str, object]:
        """Geht eine bestehende Konfiguration durch und kann sie erweitern.

        Jeder vorhandene Wert ist die Vorgabe des Dialogs; eine leere Eingabe
        übernimmt ihn. Nach den Schlüsseln eines Abschnitts lassen sich weitere
        Schlüssel anlegen, nach allen Abschnitten weitere Abschnitte.

        Args:
            data: Bestehende Konfiguration.

        Returns:
            Angepasste Konfiguration als dict.
        """
        result: dict[str, object] = {}
        for name in sorted(data):
            value = data[name]
            if isinstance(value, dict):
                self._console.rule(name)
                section = self._edit_section(name, value)
                self._add_keys(name, section)
                result[name] = section
            else:
                result[name] = self._prompt_value("", name, default=str(value))
        self._add_sections(result)
        return result

    def build_free(
        self, existing: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Legt Abschnitte und Schlüssel/Werte frei an, ohne pifos-Bezug.

        Args:
            existing: Bereits vorhandene Konfiguration oder None.

        Returns:
            Aufgebaute Konfiguration als dict.
        """
        data: dict[str, object] = dict(existing) if existing else {}
        self._add_sections(data)
        return data

    def _edit_section(
        self, section_name: str, section: dict[str, object]
    ) -> dict[str, object]:
        """Fragt die vorhandenen Schlüssel eines Abschnitts mit Vorgabe ab."""
        result: dict[str, object] = {}
        for key in sorted(section):
            result[key] = self._prompt_value(
                section_name, key, default=str(section[key])
            )
        return result

    def _add_keys(self, section_name: str, section: dict[str, object]) -> None:
        """Bietet an, weitere Schlüssel/Wert-Paare im Abschnitt anzulegen."""
        while self._prompter.confirm(
            f"[{section_name}] weiteren Schlüssel anlegen?", default=False
        ):
            key = self._prompter.text("Schlüsselname").strip()
            if not key:
                break
            section[key] = self._prompt_value(section_name, key)

    def _add_sections(self, data: dict[str, object]) -> None:
        """Bietet an, weitere Abschnitte anzulegen."""
        while self._prompter.confirm("weiteren Abschnitt anlegen?", default=not data):
            name = self._prompter.text("Abschnittsname").strip()
            if not name:
                break
            prev = data.get(name)
            section: dict[str, object] = dict(prev) if isinstance(prev, dict) else {}
            self._add_keys(name, section)
            data[name] = section

    def _prompt_value(self, section_name: str, key: str, default: str = "") -> str:
        """Fragt einen einzelnen Wert als Freitext ab (keine Maskierung)."""
        label = f"{section_name}.{key}" if section_name else key
        return self._prompter.text(f"Wert für {label}", default=default)


def read_config_data(path: str, format: str) -> dict[str, object]:
    """Liest eine Konfigurationsdatei über die zentrale Config-Schnittstelle.

    Args:
        path: Pfad zur Datei.
        format: Dateiformat; erlaubte Werte: ini, json, toml.

    Returns:
        Konfiguration als dict.

    Raises:
        ConfigError: Bei unbekanntem Format oder Lesefehler.
    """
    cfg = Config()
    cfg.load_file(path, format)
    return cfg.to_dict()


def write_config_data(
    data: dict[str, object],
    format: str,
    path: str,
    *,
    overwrite: bool = False,
    backup_location: str | None = None,
) -> None:
    """Schreibt eine Konfiguration sicher in eine Datei.

    safe-mode: eine bestehende Zieldatei wird ohne overwrite nicht überschrieben.
    Vor dem Überschreiben entsteht eine Sicherung (backup_destination). Der neue
    Inhalt wird zuerst vollständig in eine Hilfsdatei geschrieben und dann in
    einem Schritt (os.replace) an die Stelle der Zieldatei gesetzt; die Zieldatei
    erhält die Rechte 0600.

    Args:
        data: Zu schreibende Konfiguration.
        format: Zielformat; erlaubte Werte: ini, json, toml.
        path: Zieldatei.
        overwrite: True, um eine bestehende Zieldatei zu ersetzen.
        backup_location: Verzeichnis für die Sicherung oder None.

    Raises:
        ConfigError: Bei unbekanntem Format, abschnittslosen Werten im ini-Format,
            verweigertem Überschreiben, Sicherungs- oder Schreibfehler.
    """
    if format not in _FORMATS:
        raise ConfigError(f"Unbekanntes Konfigurationsformat: {format!r}")
    if format == "ini":
        _reject_sectionless_for_ini(data)
    target = Path(path)
    exists = target.exists() or target.is_symlink()
    if exists and not overwrite:
        raise ConfigError(
            f"Zieldatei existiert bereits: {path!r}; overwrite erforderlich"
        )
    if exists:
        try:
            backup_destination(target, backup_location)
        except ActionError as e:
            raise ConfigError(f"Sicherung fehlgeschlagen: {e}") from e
    _write_via_temp(data, format, target)


def _reject_sectionless_for_ini(data: dict[str, object]) -> None:
    """Lehnt abschnittslose Werte ab, die IniConfig nicht ablegen kann.

    Das ini-Format kennt keinen Platz außerhalb eines Abschnitts; ein
    abschnittsloser Wert würde beim Schreiben stillschweigend verworfen.

    Raises:
        ConfigError: Wenn ein Wert der obersten Ebene kein dict ist.
    """
    for name, value in data.items():
        if not isinstance(value, dict):
            raise ConfigError(
                f"INI kann den abschnittslosen Wert {name!r} nicht ablegen;"
                " json oder toml verwenden"
            )


def _write_via_temp(data: dict[str, object], format: str, target: Path) -> None:
    """Schreibt in eine Hilfsdatei und ersetzt die Zieldatei in einem Schritt.

    Legt eine Hilfsdatei im Zielverzeichnis an, schreibt den Inhalt über die
    Formatklasse vollständig hinein, setzt die Rechte 0600 und tauscht die Datei
    per os.replace aus. Bei einem Fehler wird die Hilfsdatei entfernt.

    Raises:
        ConfigError: Bei einem Dateisystemfehler (generische Meldung ohne Pfad).
    """
    cfg = Config()
    cfg.load_dict(data)
    try:
        fd, tmp = tempfile.mkstemp(dir=str(target.parent))
    except OSError as exc:
        raise ConfigError("Hilfsdatei kann nicht angelegt werden") from exc
    os.close(fd)
    tmp_path = Path(tmp)
    success = False
    try:
        cfg.write_config(format, tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(target))
        success = True
    except OSError as exc:
        raise ConfigError("Konfigurationsdatei kann nicht geschrieben werden") from exc
    finally:
        if not success:
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)


def _load_module(spec: str) -> tuple[str, type[Module]]:
    """Importiert eine Modulklasse aus einem Importpfad.

    Args:
        spec: Importpfad als 'paket.modul:Klasse' oder 'paket.modul.Klasse'.

    Returns:
        Klassenname und Modulklasse.

    Raises:
        ConfigError: Bei ungültigem Pfad, Importfehler oder wenn die Klasse
            nicht von Module erbt.
    """
    if ":" in spec:
        mod_name, _, cls_name = spec.partition(":")
    else:
        mod_name, _, cls_name = spec.rpartition(".")
    if not mod_name or not cls_name:
        raise ConfigError(f"Ungültiger Modulpfad: {spec!r}")
    try:
        mod = importlib.import_module(mod_name)
        cls = getattr(mod, cls_name)
    except Exception as exc:
        raise ConfigError(f"Modul {spec!r} nicht ladbar") from exc
    if not (isinstance(cls, type) and issubclass(cls, Module)):
        raise ConfigError(f"{spec!r} ist keine Module-Unterklasse")
    return cls.__name__, cls


def _read_if_exists(path: str, format: str) -> dict[str, object] | None:
    """Liest eine Datei, falls sie existiert; sonst None."""
    return read_config_data(path, format) if Path(path).exists() else None


def _format_from_suffix(path: str) -> str | None:
    """Leitet das Konfigurationsformat aus der Dateiendung ab.

    Args:
        path: Zu prüfender Pfad.

    Returns:
        "ini", "json" oder "toml", wenn die Endung (unabhängig von
        Groß-/Kleinschreibung) einem bekannten Format entspricht; sonst None.
    """
    suffix = Path(path).suffix.lower().lstrip(".")
    return suffix if suffix in _FORMATS else None


def _resolve_format(explicit: str | None, path: str) -> str:
    """Löst das Format auf: explizit angegeben, sonst aus der Dateiendung.

    Args:
        explicit: Ausdrücklich angegebenes Format oder None.
        path: Pfad, dessen Endung als Rückfall dient.

    Returns:
        Aufgelöstes Format.

    Raises:
        ConfigError: Ohne explizites Format und ohne ableitbare Endung.
    """
    if explicit is not None:
        return explicit
    derived = _format_from_suffix(path)
    if derived is None:
        raise ConfigError(
            f"Kein Format angegeben und keine ableitbare Endung: {path!r}"
        )
    return derived


def _resolve_input_format(explicit: str | None, edit_path: str, fallback: str) -> str:
    """Löst das Format der --edit-Quelle auf.

    Reihenfolge: ausdrücklich angegebenes --input-format, sonst die Endung
    der Quelle, sonst das bereits aufgelöste Zielformat.

    Args:
        explicit: Ausdrücklich angegebenes --input-format oder None.
        edit_path: Pfad der --edit-Quelle.
        fallback: Bereits aufgelöstes Zielformat.

    Returns:
        Aufgelöstes Format der --edit-Quelle.
    """
    if explicit is not None:
        return explicit
    return _format_from_suffix(edit_path) or fallback


def main(args: argparse.Namespace) -> int:
    """Führt den Konfigurator nach den Kommandoargumenten aus.

    Die Zieldatei (args.target) ist bei --edit optional: ohne Angabe wird die
    --edit-Quelle an Ort und Stelle bearbeitet und nach der Sicherung ersetzt,
    ohne dass --overwrite nötig ist. Bei --module/--free ist die Zieldatei
    Pflicht. Das Zielformat wird, wenn nicht ausdrücklich mit --format
    angegeben, aus der Endung der Zieldatei abgeleitet; --input-format
    entsprechend aus der Endung der --edit-Quelle, sonst wie das Zielformat.

    Args:
        args: Ausgewertete Argumente (siehe bin/pifos-config).

    Returns:
        Exit-Code: 0 bei Erfolg, 1 bei einem gemeldeten Fehler (u. a. fehlende
        Zieldatei außerhalb von --edit oder ein nicht auflösbares Format).
    """
    try:
        if args.edit:
            in_place = args.target is None
            output_path = args.target or args.edit
        else:
            if args.target is None:
                raise ConfigError(
                    "Zieldatei erforderlich (nur bei --edit ohne Angabe optional)"
                )
            in_place = False
            output_path = args.target

        out_format = _resolve_format(args.format, output_path)
        configurator = Configurator()
        if args.free:
            data = configurator.build_free(_read_if_exists(output_path, out_format))
        elif args.edit:
            in_format = _resolve_input_format(args.input_format, args.edit, out_format)
            data = configurator.edit(read_config_data(args.edit, in_format))
        else:
            existing = _read_if_exists(output_path, out_format)
            modules = dict(_load_module(spec) for spec in args.module)
            data = configurator.build_for_modules(modules, existing)
        write_config_data(
            data,
            out_format,
            output_path,
            overwrite=args.overwrite or in_place,
            backup_location=args.backup_location,
        )
    except ConfigError as e:
        clean = str(e).translate(str.maketrans("\n\r\t", "   "))
        _LOGGER.error("Konfigurator-Fehler: %s", clean)
        return 1
    return 0
