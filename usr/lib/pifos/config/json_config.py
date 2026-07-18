"""Formatklasse für JSON-Konfigurationsdateien.

Liest und schreibt JSON-Dateien über das json-Modul der Standardbibliothek.
Kein eval, kein pickle (SIC-17).
"""

import json
from typing import cast

from pifos.errors import ConfigError


class JsonConfig:
    """Adapter für JSON-Konfigurationsdateien.

    Liest eine JSON-Datei und liefert die Konfiguration als dict an Config.
    Schreibt über write_data zurück ins JSON-Format.

    Attributes:
        _path: Pfad zur geladenen Datei.
        _raw: Rohinhalt der Datei als Zeichenkette.
        _data: Geparste Konfiguration als dict.
    """

    def __init__(self, path: str) -> None:
        """Liest die JSON-Datei vom angegebenen Pfad.

        Args:
            path: Pfad zur JSON-Datei.

        Raises:
            ConfigError: Wenn die Datei nicht gelesen oder geparst werden kann,
                oder wenn der Inhalt kein JSON-Objekt ist.
        """
        self._path = path
        try:
            with open(path, encoding="utf-8") as fh:
                self._raw = fh.read()
            parsed = json.loads(self._raw)
        except OSError as e:
            raise ConfigError(f"JSON-Datei nicht lesbar: {path!r}: {e}") from e
        except json.JSONDecodeError as e:
            raise ConfigError(f"JSON-Datei ungültig: {path!r}: {e}") from e
        if not isinstance(parsed, dict):
            typ = type(parsed).__name__
            raise ConfigError(f"JSON-Konfiguration muss ein Objekt sein, nicht {typ!r}")
        self._data: dict[str, object] = cast(dict[str, object], parsed)

    def to_dict(self) -> dict[str, object]:
        """Gibt die Konfiguration als dict zurück.

        Returns:
            Geparste JSON-Konfiguration als dict.
        """
        return self._data

    def raw(self) -> str:
        """Gibt den Rohinhalt der Datei zurück.

        Returns:
            JSON-Dateiinhalt als Zeichenkette.
        """
        return self._raw

    @staticmethod
    def write_data(data: dict[str, object], path: str) -> None:
        """Schreibt ein dict als JSON-Datei.

        Args:
            data: Konfiguration als dict.
            path: Zielpfad der JSON-Datei.

        Raises:
            ConfigError: Wenn die Datei nicht geschrieben werden kann.
        """
        try:
            content = json.dumps(data, indent=2, ensure_ascii=False)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.write("\n")
        except OSError as e:
            raise ConfigError(f"JSON-Datei nicht schreibbar: {path!r}: {e}") from e
        except TypeError as e:
            raise ConfigError(f"Konfiguration nicht JSON-serialisierbar: {e}") from e
