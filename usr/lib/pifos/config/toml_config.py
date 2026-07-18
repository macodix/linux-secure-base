"""Formatklasse für TOML-Konfigurationsdateien.

Liest TOML-Dateien über tomllib (Standardbibliothek ab Python 3.11).
Schreibt über tomli-w (optionale mitgelieferte Bibliothek, erst bei Bedarf).
Kein eval, kein pickle (SIC-17).
"""

import tomllib
from typing import cast

from pifos.errors import ConfigError


class TomlConfig:
    """Adapter für TOML-Konfigurationsdateien.

    Liest eine TOML-Datei mit tomllib und liefert die Konfiguration als dict
    an Config. Schreibt über write_data mit tomli-w (optional, BRS-02).

    Attributes:
        _path: Pfad zur geladenen Datei.
        _raw: Rohinhalt der Datei als Zeichenkette.
        _data: Geparste Konfiguration als dict.
    """

    def __init__(self, path: str) -> None:
        """Liest die TOML-Datei vom angegebenen Pfad.

        Args:
            path: Pfad zur TOML-Datei.

        Raises:
            ConfigError: Wenn die Datei nicht gelesen oder geparst werden kann.
        """
        self._path = path
        try:
            with open(path, "rb") as fh:
                raw_bytes = fh.read()
            self._raw = raw_bytes.decode("utf-8")
            parsed = tomllib.loads(self._raw)
        except OSError as e:
            raise ConfigError(f"TOML-Datei nicht lesbar: {path!r}: {e}") from e
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"TOML-Datei ungültig: {path!r}: {e}") from e
        self._data: dict[str, object] = cast(dict[str, object], parsed)

    def to_dict(self) -> dict[str, object]:
        """Gibt die Konfiguration als dict zurück.

        Returns:
            Geparste TOML-Konfiguration als dict.
        """
        return self._data

    def raw(self) -> str:
        """Gibt den Rohinhalt der Datei zurück.

        Returns:
            TOML-Dateiinhalt als Zeichenkette.
        """
        return self._raw

    @staticmethod
    def write_data(data: dict[str, object], path: str) -> None:
        """Schreibt ein dict als TOML-Datei.

        Erfordert die optionale Bibliothek tomli-w. Sie wird erst bei Bedarf
        aktiviert (06_bereitstellung.md Kapitel 5).

        Args:
            data: Konfiguration als dict.
            path: Zielpfad der TOML-Datei.

        Raises:
            ConfigError: Wenn tomli-w nicht installiert ist oder die Datei
                nicht geschrieben werden kann.
        """
        try:
            import tomli_w
        except ImportError as e:
            raise ConfigError(
                "tomli-w ist nicht installiert; TOML-Schreiben nicht verfügbar"
            ) from e
        try:
            content: bytes = tomli_w.dumps(data).encode("utf-8")
            with open(path, "wb") as fh:
                fh.write(content)
        except OSError as e:
            raise ConfigError(f"TOML-Datei nicht schreibbar: {path!r}: {e}") from e
