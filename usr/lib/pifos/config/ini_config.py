"""Formatklasse für INI-Konfigurationsdateien.

Liest und schreibt INI-Dateien über configparser (Standardbibliothek).
Unterstützt Sektionen; Werte sind Zeichenketten (SIC-17).
"""

import configparser
import io

from pifos.errors import ConfigError


class IniConfig:
    """Adapter für INI-Konfigurationsdateien.

    Liest eine INI-Datei mit configparser und liefert die Konfiguration
    als dict[section -> dict[key -> value]] an Config. Schreibt über
    write_data zurück ins INI-Format.

    Attributes:
        _path: Pfad zur geladenen Datei.
        _parser: Interner configparser.RawConfigParser.
        _raw: Rohinhalt der Datei als Zeichenkette.
    """

    def __init__(self, path: str) -> None:
        """Liest die INI-Datei vom angegebenen Pfad.

        Args:
            path: Pfad zur INI-Datei.

        Raises:
            ConfigError: Wenn die Datei nicht gelesen werden kann.
        """
        self._path = path
        self._parser = configparser.RawConfigParser()
        try:
            with open(path, encoding="utf-8") as fh:
                self._raw = fh.read()
            self._parser.read_string(self._raw)
        except OSError as e:
            raise ConfigError(f"INI-Datei nicht lesbar: {path!r}: {e}") from e
        except configparser.Error as e:
            raise ConfigError(f"INI-Datei ungültig: {path!r}: {e}") from e

    def to_dict(self) -> dict[str, object]:
        """Gibt die Konfiguration als dict zurück.

        Die Schlüssel der obersten Ebene sind die Sektionsnamen.
        DEFAULT-Einträge erscheinen in jeder Sektion (configparser-Verhalten).

        Returns:
            Verschachteltes dict mit Sektionen als Schlüssel.
        """
        result: dict[str, object] = {}
        for section in self._parser.sections():
            result[section] = dict(self._parser[section])
        return result

    def raw(self) -> str:
        """Gibt den Rohinhalt der Datei zurück.

        Returns:
            INI-Dateiinhalt als Zeichenkette.
        """
        return self._raw

    @staticmethod
    def write_data(data: dict[str, object], path: str) -> None:
        """Schreibt ein dict als INI-Datei.

        Nur Sektionen mit dict-Werten werden geschrieben; andere Werte
        werden ignoriert. Alle Werte werden als Zeichenkette abgelegt.

        Args:
            data: Konfiguration als dict (Sektionen → dict von Schlüssel/Wert).
            path: Zielpfad der INI-Datei.

        Raises:
            ConfigError: Wenn die Datei nicht geschrieben werden kann.
        """
        parser = configparser.RawConfigParser()
        for section, values in data.items():
            if not isinstance(values, dict):
                continue
            parser.add_section(section)
            for key, val in values.items():
                parser.set(section, key, str(val))
        buf = io.StringIO()
        parser.write(buf)
        content = buf.getvalue()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        except OSError as e:
            raise ConfigError(f"INI-Datei nicht schreibbar: {path!r}: {e}") from e
