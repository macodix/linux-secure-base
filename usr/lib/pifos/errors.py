"""Ausnahmehierarchie für pifos.

Alle pifos-Ausnahmen leiten von PifosError ab. Aktionen erzeugen
ActionError, Module ModuleError, die Konfiguration ConfigError.
"""


class PifosError(Exception):
    """Gemeinsame Basisklasse für alle pifos-Ausnahmen."""


class ActionError(PifosError):
    """Ausnahme für Fehler in einer Aktion.

    Wird von Action.run() erzeugt und an das aufrufende Modul weitergegeben.
    """


class ModuleError(PifosError):
    """Ausnahme für Fehler in einem Modul.

    Wird von Modulen erzeugt und über IPC an den Aufrufer weitergereicht.
    """


class ConfigError(PifosError):
    """Ausnahme für Fehler bei der Konfiguration.

    Wird bei fehlenden oder formal ungültigen Konfigurationswerten erzeugt.
    """
