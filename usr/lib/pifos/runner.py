"""Einsprungfunktion des Modulprozesses.

module_runner ist das Ziel von multiprocessing.Process. Es instanziiert
das Modul, prüft die Konfiguration und führt die Befehlsschleife aus
(Kapitel 6 des Implementierungsplans).
"""

import contextlib
import traceback
from multiprocessing.connection import Connection
from typing import cast

from pifos.config.config import Config
from pifos.errors import ConfigError
from pifos.ipc import IpcMessage, LogLevel, MessageKind
from pifos.module import Module


def module_runner(
    module_cls: type[Module],
    config: Config | None,
    conn: Connection,
    loglevel: LogLevel,
) -> int:
    """Einsprungfunktion des Modulprozesses.

    Instanziiert module_cls, prüft die Konfiguration und tritt in die
    Befehlsschleife ein. Bildet COMMAND- und REQUEST-Nachrichten auf
    Modulmethoden ab. Leitet Ausnahmen als EXCEPTION-Meldungen an den
    Aufrufer weiter (Kapitel 8 des Implementierungsplans).

    Args:
        module_cls: Zu instanziierende Modulklasse.
        config: Konfigurationsobjekt oder None für Module ohne Konfiguration.
        conn: Pipe-Verbindung zum Aufrufer (Kindseite).
        loglevel: Logstufe, weitergegeben vom Aufrufer (LOG-05).

    Returns:
        Exitcode: 0 bei Erfolg, ungleich 0 bei Fehler (STR-05).
    """
    module = module_cls(conn=conn, loglevel=loglevel)
    exit_code = 0

    # Konfiguration prüfen und in Instanzvariablen ablegen (MOD-09)
    if config is not None:
        try:
            module.check_config(config)
        except ConfigError as e:
            _send_exception(conn, LogLevel.ERROR, e)
            conn.close()
            return 1

    # Befehlsschleife
    paused = False
    try:
        while True:
            msg = cast(IpcMessage, conn.recv())

            if msg.kind not in (MessageKind.COMMAND, MessageKind.REQUEST):
                continue

            if msg.name == "terminate":
                break

            if msg.name == "pause":
                paused = True
                conn.send(
                    IpcMessage(
                        kind=MessageKind.MESSAGE,
                        level=None,
                        name="paused",
                        payload=None,
                    )
                )
                # Warten auf resume oder terminate
                while paused:
                    inner = cast(IpcMessage, conn.recv())
                    if inner.name == "resume":
                        paused = False
                    elif inner.name == "terminate":
                        conn.close()
                        return exit_code
                continue

            if msg.name == "start":
                try:
                    exit_code = module.start()
                    conn.send(
                        IpcMessage(
                            kind=MessageKind.RESULT,
                            level=None,
                            name="start",
                            payload=exit_code,
                        )
                    )
                except Exception as exc:
                    _send_exception(conn, LogLevel.ERROR, exc)
                    exit_code = 1
                continue

            if msg.kind == MessageKind.REQUEST:
                # Angefordertes Attribut zurückliefern
                attr = str(msg.payload) if msg.payload is not None else ""
                payload: object = getattr(module, attr, None)
                conn.send(
                    IpcMessage(
                        kind=MessageKind.RESULT,
                        level=None,
                        name=msg.name,
                        payload=payload,
                    )
                )

    except EOFError:
        # Verbindung wurde vom Aufrufer geschlossen
        pass
    except Exception as exc:
        # Unerwartete Ausnahme; zuerst zustellen, dann beenden (EXC-03)
        with contextlib.suppress(Exception):
            _send_exception(conn, LogLevel.CRITICAL, exc)
        exit_code = 1
    finally:
        with contextlib.suppress(Exception):
            conn.close()

    return exit_code


def _send_exception(conn: Connection, level: LogLevel, exc: BaseException) -> None:
    """Überführt eine Ausnahme in eine EXCEPTION-IpcMessage und sendet sie.

    Args:
        conn: Ziel-Verbindung.
        level: Logstufe der Ausnahme (ERROR oder CRITICAL).
        exc: Die weiterzuleitende Ausnahme.
    """
    tb = traceback.format_exc()
    conn.send(
        IpcMessage(
            kind=MessageKind.EXCEPTION,
            level=level,
            name=type(exc).__name__,
            payload=f"{exc}\n{tb}",
        )
    )
