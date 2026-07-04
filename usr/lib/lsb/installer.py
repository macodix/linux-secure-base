"""Aufrufer des LSB-Installers auf Basis von PifosCaller."""

import argparse
import logging
import os
from pathlib import Path
from typing import cast

from pifos.caller import ModuleHandle, PifosCaller
from pifos.config.config import Config
from pifos.errors import ConfigError
from pifos.ipc import LogLevel, MessageKind

from lsb.config_setup import ensure_config, module_config
from lsb.module_spec import ModuleSpec
from lsb.selection import select_modules
from lsb.ui import StatusView

logger = logging.getLogger(__name__)

# Paket-Root, drei Verzeichnisebenen über dieser Datei
# (usr/lib/lsb/installer.py -> usr/lib/lsb -> usr/lib -> usr -> Root),
# analog zu _ROOT im Einstiegspunkt bin/lsb-installer. Verankert
# DEFAULT_CONF am Paket, unabhängig vom Arbeitsverzeichnis, aus dem
# lsb-installer aufgerufen wird.
_PACKAGE_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONF = _PACKAGE_ROOT / "etc" / "lsb" / "lsb.conf"


class LsbInstaller(PifosCaller):
    """Aufrufer, der die Härtungsmodule steuert und den Status anzeigt."""

    def __init__(self, view: StatusView) -> None:
        """Initialisiert den Aufrufer mit der Statusanzeige.

        Args:
            view: Bedienoberfläche für den Installationsstatus.
        """
        super().__init__()
        self.view = view
        self.failures = 0

    def run_module(self, spec: ModuleSpec, config: Config, operation: str) -> bool:
        """Führt ein Modul aus und aktualisiert die Statusanzeige.

        Args:
            spec: Registratureintrag des Moduls.
            config: Für das Modul zusammengestellte Konfiguration.
            operation: "install" oder "check".

        Returns:
            True bei Erfolg, sonst False.
        """
        self.view.set_running(spec.name)
        handle = self.start_module(spec.module_cls, config)
        self.send_command(handle, "start")
        result_code = self._drain(handle, spec.name)
        self.terminate_module(handle)
        self.check_module_exit(handle)
        ok = result_code == 0
        self.view.set_result(spec.name, ok)
        return ok

    def _drain(self, handle: ModuleHandle, name: str) -> int:
        """Nimmt Meldungen des Moduls an, bis das Ergebnis vorliegt.

        Args:
            handle: Handle des laufenden Modulprozesses.
            name: Modulname für Log- und Anzeigezeilen.

        Returns:
            Rückgabewert des Moduls; 1 bei einer gemeldeten Ausnahme.
        """
        while True:
            msg = self.receive_result(handle)
            if msg.kind is MessageKind.RESULT:
                return int(cast(int, msg.payload))
            if msg.kind is MessageKind.EXCEPTION:
                self.write_log(f"{name}: {msg.payload}", msg.level or LogLevel.ERROR)
                return 1
            level = msg.level or LogLevel.INFO
            self.write_log(f"{name}: {msg.payload}", level)
            self.view.set_status_line(name, str(msg.payload), level)

    def configure_logging(self) -> None:
        """Richtet die Logdatei aus dem Abschnitt [installer] ein.

        Überschreibt PifosCaller.configure_logging, weil die ini-Konfiguration
        ihre Werte in Abschnitten hält, die Basisklasse aber logfile und
        loglevel auf oberster Ebene liest. Die Werte werden aus [installer]
        auf die oberste Ebene gehoben; die Basisklasse legt die Logdatei
        dann mit den Rechten 0600 an.
        """
        if self.config is None:
            raise RuntimeError("Keine Konfiguration geladen.")
        section = cast(dict[str, object], self.config.get_section("installer"))
        data = self.config.to_dict()
        data["logfile"] = section["logfile"]
        data["loglevel"] = section["loglevel"]
        self.config.load_dict(data)
        super().configure_logging()

    def on_module_failure(self, handle: ModuleHandle, returncode: int) -> None:
        """Zählt einen Modulfehler für die Gesamtbilanz."""
        self.failures += 1

    def on_module_abort(self, handle: ModuleHandle) -> None:
        """Zählt einen erzwungenen Modulabbruch für die Gesamtbilanz."""
        self.failures += 1


def main(args: argparse.Namespace) -> int:
    """Führt den Installer nach den Argumenten aus.

    Args:
        args: Geparste Kommandozeilenargumente.

    Returns:
        0 bei Erfolg, 1 bei einem Modulfehler, 2 bei einem Aufruf ohne
        Systemrechte, mit fehlerhafter Auswahl oder ungültiger
        Konfiguration.
    """
    if os.geteuid() != 0:
        logger.error("lsb-installer benötigt Systemrechte (sudo).")
        return 2

    conf_path = Path(args.conf) if args.conf else DEFAULT_CONF
    try:
        config = ensure_config(conf_path)
        if config is None:
            return 2

        specs = select_modules(args.modules, args.optional, config)
        if not specs:
            logger.error("Keine Module ausgewählt.")
            return 2

        view = StatusView(specs)
        caller = LsbInstaller(view)
        caller.load_config(str(conf_path), "ini")
        caller.configure_logging()
    except ConfigError as exc:
        logger.error("Konfiguration ungültig: %s", exc)
        return 2

    with view.live():
        for spec in specs:
            module_cfg = module_config(config, spec, args.command)
            caller.run_module(spec, module_cfg, args.command)
    view.summary()
    return 1 if caller.failures else 0
