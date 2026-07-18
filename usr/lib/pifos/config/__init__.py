"""Konfigurationsunterpaket von pifos.

Stellt Config und die Formatklassen IniConfig, JsonConfig, TomlConfig bereit.
"""

from pifos.config.config import Config as Config
from pifos.config.ini_config import IniConfig as IniConfig
from pifos.config.json_config import JsonConfig as JsonConfig
from pifos.config.toml_config import TomlConfig as TomlConfig

__all__ = ["Config", "IniConfig", "JsonConfig", "TomlConfig"]
