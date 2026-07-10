"""Datenklasse für einen Eintrag der Modul-Registratur."""

from dataclasses import dataclass

from pifos.module import Module


@dataclass(frozen=True)
class ModuleSpec:
    """Ein Eintrag der Modul-Registratur.

    Attributes:
        name: Kurzname des Moduls, auch Schlüssel in der Konfiguration.
        label: Anzeige-Beschreibung für die Statusliste.
        module_cls: pifos-Modulklasse.
        optional: True für optionale Module (laufen mit, sobald sie in
            optional_enabled stehen).
        optional_keys: CONFIG-Schlüssel, die leer bleiben dürfen; sie
            werden vom Konfigurationsdialog nicht abgefragt.
    """

    name: str
    label: str
    module_cls: type[Module]
    optional: bool
    optional_keys: tuple[str, ...] = ()
