"""Zentrale Config-Klasse für pifos.

Config ist die einheitliche Schnittstelle zwischen Konfigurationsquellen
und Modulen bzw. Aufrufer. Sie hält die Konfiguration intern als dict
und stellt Zugriffs- und Prüfmethoden bereit (KFG-01, KFG-02).
"""

import re
from typing import cast

from pifos.errors import ConfigError


class Config:
    """Zentrale Konfigurationsklasse; entkoppelt Formate von Verwendern.

    Hält die Konfiguration intern als dict[str, object]. Einfache Datentypen
    (str, int, float, bool, list, dict) sind pickelbar — Voraussetzung für
    die Übergabe an Modulprozesse via multiprocessing (STR-02).

    Inhaltliche Prüfung findet hier nicht statt (KFG-08); nur formale
    Musterprüfung über check_pattern.
    """

    # Reguläre Ausdrücke für check_pattern
    _PATTERN_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    _PATTERN_NUMBER = re.compile(r"^-?\d+(\.\d+)?$")
    _PATTERN_COMMA_SEP = re.compile(r"^[^,]+(,[^,]+)*$")

    def __init__(self) -> None:
        """Initialisiert eine leere Konfiguration."""
        self._data: dict[str, object] = {}
        self._raw: str = ""

    def load_dict(self, data: dict[str, object]) -> None:
        """Übernimmt die Konfiguration als dict.

        Args:
            data: Konfiguration als verschachteltes dict.
        """
        self._data = data

    def load_raw(self, raw: str) -> None:
        """Speichert den unzerlegten Inhalt ohne Zerlegung in _data.

        Args:
            raw: Konfigurationsinhalt als Zeichenkette.
        """
        self._raw = raw

    def load_file(self, path: str, format: str) -> None:
        """Liest eine Datei über die passende Formatklasse und übernimmt sie.

        Args:
            path: Pfad zur Konfigurationsdatei.
            format: Dateiformat; erlaubte Werte: ini, json, toml.

        Raises:
            ConfigError: Bei unbekanntem Format oder Lesefehler.
        """
        # Import innerhalb der Methode verhindert zirkuläre Importe
        # auf Modulebene (config/__init__.py importiert Config und Formatklassen).
        from pifos.config.ini_config import IniConfig
        from pifos.config.json_config import JsonConfig
        from pifos.config.toml_config import TomlConfig

        if format == "ini":
            fmt_ini = IniConfig(path)
            self._data = fmt_ini.to_dict()
            self._raw = fmt_ini.raw()
        elif format == "json":
            fmt_json = JsonConfig(path)
            self._data = fmt_json.to_dict()
            self._raw = fmt_json.raw()
        elif format == "toml":
            fmt_toml = TomlConfig(path)
            self._data = fmt_toml.to_dict()
            self._raw = fmt_toml.raw()
        else:
            raise ConfigError(f"Unbekanntes Konfigurationsformat: {format!r}")

    def get_value(self, key: str) -> object:
        """Liefert einen Einzelwert aus der Konfiguration.

        Args:
            key: Schlüssel des gesuchten Wertes.

        Returns:
            Wert zum Schlüssel.

        Raises:
            ConfigError: Wenn der Schlüssel nicht vorhanden ist.
        """
        try:
            return self._data[key]
        except KeyError as e:
            raise ConfigError(f"Konfigurationswert '{key}' nicht gefunden") from e

    def get_section(self, name: str) -> dict[str, object] | list[object]:
        """Liefert eine Sektion als dict oder list.

        Args:
            name: Name der Sektion.

        Returns:
            Sektion als dict oder list.

        Raises:
            ConfigError: Wenn der Schlüssel fehlt oder keine Sektion ist.
        """
        val = self.get_value(name)
        if isinstance(val, dict):
            return cast(dict[str, object], val)
        if isinstance(val, list):
            return cast(list[object], val)
        raise ConfigError(f"'{name}' ist keine Sektion (dict oder list)")

    def get_list(self, key: str, sort: bool = False) -> list[object]:
        """Liefert eine sortierte oder unsortierte Liste.

        Args:
            key: Schlüssel des Listenwertes.
            sort: True, um die Liste aufsteigend nach Zeichenkettendarstellung
                zu sortieren.

        Returns:
            Liste der Werte.

        Raises:
            ConfigError: Wenn der Schlüssel fehlt oder kein Listenwert ist.
        """
        val = self.get_value(key)
        if not isinstance(val, list):
            raise ConfigError(f"'{key}' ist kein Listenwert")
        result = cast(list[object], val)
        return sorted(result, key=str) if sort else result

    def check_pattern(self, pattern: str, value: object) -> bool:
        """Wendet ein formales Prüfmuster auf einen Wert an.

        Verfügbare Muster:
            exists: Wert ist nicht None.
            not_empty: Wert ist nicht None und nicht leer.
            is_number: Wert ist eine Zahl (int, float oder entsprechende str).
            is_list: Wert ist eine list.
            is_comma_separated: str-Wert ist kommasepariert.
            is_email: str-Wert ist syntaktisch eine E-Mail-Adresse.

        Args:
            pattern: Name des Prüfmusters.
            value: Zu prüfender Wert.

        Returns:
            True, wenn der Wert dem Muster entspricht.

        Raises:
            ConfigError: Bei unbekanntem Muster.
        """
        if pattern == "exists":
            return value is not None
        if pattern == "not_empty":
            return value is not None and bool(str(value))
        if pattern == "is_number":
            if isinstance(value, (int, float)):
                return True
            if isinstance(value, str):
                return bool(self._PATTERN_NUMBER.match(value))
            return False
        if pattern == "is_list":
            return isinstance(value, list)
        if pattern == "is_comma_separated":
            if not isinstance(value, str):
                return False
            return bool(self._PATTERN_COMMA_SEP.match(value))
        if pattern == "is_email":
            if not isinstance(value, str):
                return False
            return bool(self._PATTERN_EMAIL.match(value))
        raise ConfigError(f"Unbekanntes Prüfmuster: {pattern!r}")

    def to_dict(self) -> dict[str, object]:
        """Gibt den gesamten Konfigurationsinhalt als dict zurück.

        Liefert eine flache Kopie der internen Konfiguration, damit ein
        Aufrufer sie lesen kann, ohne den internen Zustand zu verändern.

        Returns:
            Konfiguration als dict.
        """
        return dict(self._data)

    def write_config(self, format: str, path: str) -> None:
        """Schreibt die aktuelle Konfiguration in eine Datei.

        Args:
            format: Zielformat; erlaubte Werte: ini, json, toml.
            path: Zielpfad der Konfigurationsdatei.

        Raises:
            ConfigError: Bei unbekanntem Format oder Schreibfehler.
        """
        from pifos.config.ini_config import IniConfig
        from pifos.config.json_config import JsonConfig
        from pifos.config.toml_config import TomlConfig

        if format == "ini":
            IniConfig.write_data(self._data, path)
        elif format == "json":
            JsonConfig.write_data(self._data, path)
        elif format == "toml":
            TomlConfig.write_data(self._data, path)
        else:
            raise ConfigError(f"Unbekanntes Konfigurationsformat: {format!r}")
