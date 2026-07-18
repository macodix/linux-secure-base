"""IPC-Nachrichtenformat für die Kommunikation zwischen Aufrufer und Modulprozess.

IpcMessage ist das einheitliche Nachrichtenformat für beide Richtungen.
MessageKind und LogLevel sind die Enums für Nachrichtenart und Logstufe.
"""

from dataclasses import dataclass
from enum import Enum


class MessageKind(Enum):
    """Nachrichtenart einer IpcMessage.

    COMMAND und REQUEST laufen vom Aufrufer zum Modul.
    LOG, MESSAGE, RESULT und EXCEPTION laufen vom Modul zum Aufrufer.
    """

    COMMAND = "COMMAND"
    LOG = "LOG"
    MESSAGE = "MESSAGE"
    REQUEST = "REQUEST"
    RESULT = "RESULT"
    EXCEPTION = "EXCEPTION"


class LogLevel(Enum):
    """Logstufen in aufsteigender Schwere.

    Entspricht den vier Stufen INFO, WARN, ERROR, CRITICAL (LOG-03).
    """

    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class IpcMessage:
    """Einheitliches Nachrichtenformat für die Pipe zwischen Aufrufer und Modul.

    Alle Felder außer level sind Pflichtfelder. level ist nur bei
    logging-relevanten Nachrichten (LOG, EXCEPTION) gesetzt.

    Attributes:
        kind: Art der Nachricht (Richtung und Semantik).
        level: Logstufe; None bei nicht-logging-relevanten Nachrichten.
        name: Befehlsname oder Meldungskennung.
        payload: Nutzdaten als einfacher Datentyp (SIC-09).
    """

    kind: MessageKind
    level: LogLevel | None
    name: str
    payload: object
