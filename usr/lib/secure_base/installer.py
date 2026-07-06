"""Aufrufer des LSB-Installers auf Basis von PifosCaller."""

import argparse
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import cast

from pifos.caller import ModuleHandle, PifosCaller
from pifos.config.config import Config
from pifos.errors import ConfigError
from pifos.ipc import LogLevel, MessageKind

from secure_base.config_setup import ensure_config, fill_missing, module_config
from secure_base.module_spec import ModuleSpec
from secure_base.modules.ufw import Ufw
from secure_base.selection import select_modules
from secure_base.ui import StatusView

logger = logging.getLogger(__name__)

# Paket-Root, drei Verzeichnisebenen über dieser Datei
# (usr/lib/secure_base/installer.py -> usr/lib/secure_base -> usr/lib -> usr -> Root),
# analog zu _ROOT im Einstiegspunkt bin/secure-base-installer. Verankert
# DEFAULT_CONF am Paket, unabhängig vom Arbeitsverzeichnis, aus dem
# secure-base-installer aufgerufen wird.
_PACKAGE_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONF = _PACKAGE_ROOT / "etc" / "secure-base" / "secure-base.conf"


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
        # Verzeichnis der Logdatei anlegen, bevor die Basisklasse die Datei
        # öffnet; sonst scheitert os.open an einem fehlenden /var/log/secure-base.
        Path(str(section["logfile"])).parent.mkdir(parents=True, exist_ok=True)
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


SENDMAIL_BIN = "/usr/sbin/sendmail"
REPORT_DIR = Path("/var/log/secure-base")


def _report_enabled(config: Config) -> bool:
    """Liest den Schalter install_report aus [installer]; Vorgabe: an."""
    try:
        section = cast(dict[str, object], config.get_section("installer"))
    except (ConfigError, KeyError):
        return True
    return str(section.get("install_report", "yes")).strip().lower() != "no"


def _build_install_report(
    host: str,
    results: list[tuple[str, bool]],
    skipped: list[str],
    stamp: str,
) -> tuple[str, str]:
    """Baut Betreff und Text des Installationsberichts.

    Reine Textmontage ohne Uhr und Dateizugriff (testbar); den
    Zeitstempel liefert der Aufrufer.

    Args:
        host: Rechnername des Zielsystems.
        results: (Modul-Label, Ergebnis) der gelaufenen Module.
        skipped: Labels der nach einem Abbruch nicht ausgeführten Module.
        stamp: Zeitangabe für Betreff und Kopfzeile.

    Returns:
        (Betreff, Berichtstext).
    """
    failed = [label for label, ok in results if not ok]
    if failed:
        subject = f"secure-base Installation {host} - ABGEBROCHEN ({stamp})"
        outcome = f"Ergebnis: abgebrochen bei {failed[0]}"
    else:
        subject = f"secure-base Installation {host} - {stamp}"
        outcome = "Ergebnis: alle Module erfolgreich"

    lines = [
        f"Installationslauf secure-base-installer auf {host}, {stamp}.",
        outcome,
        "",
    ]
    lines += [f"- {label}: {'OK' if ok else 'Fehler'}" for label, ok in results]
    lines += [f"- {label}: nicht ausgeführt" for label in skipped]
    return subject, "\n".join(lines) + "\n"


def _send_install_report(
    config: Config, results: list[tuple[str, bool]], skipped: list[str], host: str
) -> None:
    """Legt den Installationsbericht lokal ab und mailt ihn an admin_mail.

    Nachzügler des Bash-Berichts (sb_install_report), auf den Kern
    reduziert: Modulliste mit Ergebnis. Fail-soft — scheitert Ablage
    oder Versand, bleibt der Lauf-Exit-Code unverändert (WARN im Log).
    """
    if not _report_enabled(config) or not results:
        return
    try:
        general = cast(dict[str, object], config.get_section("general"))
        admin_mail = str(general.get("admin_mail", "") or "").strip()
    except (ConfigError, KeyError):
        admin_mail = ""

    stamp = time.strftime("%Y-%m-%d %H:%M")
    subject, body = _build_install_report(host, results, skipped, stamp)

    report_file = REPORT_DIR / time.strftime("install-bericht-%Y%m%d-%H%M%S.txt")
    try:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        report_file.write_text(body, encoding="utf-8")
        os.chmod(report_file, 0o600)
        logger.info("Installationsbericht abgelegt: %s", report_file)
    except OSError as exc:
        logger.warning("Installationsbericht nicht ablegbar: %s", exc)

    if not admin_mail:
        logger.warning("Kein admin_mail gesetzt — Bericht nur lokal.")
        return
    message = (
        f"To: {admin_mail}\n"
        f"Subject: {subject}\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        f"{body}"
    )
    try:
        result = subprocess.run(
            [SENDMAIL_BIN, "-t"],
            input=message.encode("utf-8"),
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Berichtsversand fehlgeschlagen: %s", exc)
        return
    if result.returncode == 0:
        logger.info("Installationsbericht an %s versendet.", admin_mail)
    else:
        logger.warning(
            "Berichtsversand an %s fehlgeschlagen (sendmail-Status %s).",
            admin_mail,
            result.returncode,
        )


def _offer_ufw_enable() -> None:
    """Bietet nach erfolgreichem ufw-Modul die Aktivierung der Firewall an.

    Wie im Bash-Vorgänger bleibt die Firewall nach dem Regelsetzen inaktiv;
    die Aktivierung erfolgt erst hier, am Ende des Installationslaufs, nach
    ausdrücklicher Zustimmung. Die Abfrage läuft über /dev/tty, damit sie
    auch bei umgeleiteter Standardein-/-ausgabe den Bediener erreicht; ohne
    interaktives Terminal unterbleibt die Aktivierung.
    """
    try:
        # Ausnahme SIM115: Das Öffnen muss außerhalb des with stehen, weil
        # ein fehlendes /dev/tty (kein Terminal) ein regulärer, getrennt
        # behandelter Fall ist; das with unten schließt die Datei sicher.
        tty_cm = open("/dev/tty", "r+", encoding="utf-8", errors="replace")  # noqa: SIM115
    except OSError:
        logger.info(
            "ufw: Firewall nicht aktiviert (kein interaktives Terminal) — "
            "manuell mit 'ufw enable' aktivieren."
        )
        return
    with tty_cm as tty:
        tty.write(
            "\nDie Firewall (ufw) ist konfiguriert, aber noch nicht aktiv.\n"
            "Das Aktivieren kann die laufende SSH-Verbindung unterbrechen —\n"
            "danach den Login in einer zweiten Sitzung prüfen; bei "
            "Problemen: ufw disable\n\n"
            "Firewall jetzt aktivieren? [j/N] "
        )
        tty.flush()
        answer = tty.readline().strip().lower()
        if answer in ("j", "ja", "y", "yes"):
            result = subprocess.run(
                [Ufw.UFW_BIN, "--force", "enable"], check=False, timeout=60
            )
            if result.returncode == 0:
                tty.write("Firewall aktiviert — Login in zweiter Sitzung prüfen.\n")
                logger.info("ufw: Firewall auf Anfrage aktiviert.")
            else:
                tty.write("Aktivierung fehlgeschlagen — Log prüfen.\n")
                logger.error("ufw: 'ufw --force enable' fehlgeschlagen.")
        else:
            tty.write("Firewall nicht aktiviert — später manuell: ufw enable\n")
            logger.info("ufw: Firewall nicht aktiviert (Entscheidung Bediener).")


def main(args: argparse.Namespace) -> int:
    """Führt den Installer nach den Argumenten aus.

    Args:
        args: Geparste Kommandozeilenargumente.

    Returns:
        0 bei Erfolg, 1 bei einem Modulfehler, 2 bei einem ändernden
        Aufruf ohne Systemrechte, mit fehlerhafter Auswahl oder
        ungültiger Konfiguration.
    """
    # Systemrechte nur für tatsächlich ändernde Läufe; check und test
    # sind rein lesend, der Trockenlauf führt nichts aus (wie der
    # Bash-Vorgänger).
    if (
        args.command in ("install", "uninstall")
        and not args.dry_run
        and os.geteuid() != 0
    ):
        logger.error(
            "secure-base-installer benötigt für %s Systemrechte (sudo).",
            args.command,
        )
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

        fill_missing(config, conf_path, specs)

        try:
            general = cast(dict[str, object], config.get_section("general"))
            host = str(general.get("fqdn", "") or "")
        except (ConfigError, KeyError):
            host = ""
        # uninstall nimmt in umgekehrter Reihenfolge zurück, was install
        # in Vorwärtsreihenfolge aufgebaut hat (wie der Bash-Vorgänger).
        run_specs = list(reversed(specs)) if args.command == "uninstall" else specs
        view = StatusView(run_specs, args.command, host)
        caller = LsbInstaller(view)
        caller.load_config(str(conf_path), "ini")
        try:
            caller.configure_logging()
        except OSError as exc:
            # Rein lesende Läufe ohne root dürfen an einer nicht
            # beschreibbaren Logdatei nicht scheitern.
            if args.command in ("install", "uninstall"):
                raise
            logger.warning("Logdatei nicht nutzbar (%s) — Lauf ohne Logdatei.", exc)
    except ConfigError as exc:
        logger.error("Konfiguration ungültig: %s", exc)
        return 2
    except OSError as exc:
        logger.error("Konfiguration nicht nutzbar: %s", exc)
        return 2

    ufw_ok = False
    results: list[tuple[str, bool]] = []
    with view.live():
        for spec in run_specs:
            # Trockenlauf: Module nur benennen, nichts starten (wie der
            # Bash-Vorgänger); Bericht und ufw-Abfrage entfallen unten.
            if args.dry_run:
                view.set_running(spec.name)
                view.set_status_line(
                    spec.name, "Trockenlauf — übersprungen", LogLevel.INFO
                )
                caller.write_log(
                    f"Trockenlauf — {spec.name} übersprungen", LogLevel.INFO
                )
                view.set_result(spec.name, True)
                continue
            module_cfg = module_config(config, spec, args.command)
            ok = caller.run_module(spec, module_cfg, args.command)
            results.append((spec.label, ok))
            if spec.name == "ufw" and ok:
                ufw_ok = True
            # install und uninstall ändern das System und bauen
            # aufeinander auf: nach einem Modul-Fehlschlag keine weiteren
            # Systemänderungen, Gesamtabbruch (wie der Bash-Vorgänger).
            # check und test sind rein lesend und laufen alles durch,
            # damit die Ergebnisliste vollständig ist.
            if not ok and args.command in ("install", "uninstall"):
                caller.write_log(
                    f"{args.command} abgebrochen bei {spec.name}", LogLevel.ERROR
                )
                break
    view.summary()
    if args.command == "install" and not args.dry_run:
        skipped = [s.label for s in run_specs[len(results) :]]
        _send_install_report(config, results, skipped, host)
    # Aktivierung nur nach vollständig erfolgreichem Installationslauf:
    # nach einem Abbruch wird erst behoben und neu gelaufen.
    if args.command == "install" and ufw_ok and not caller.failures:
        _offer_ufw_enable()
    return 1 if caller.failures else 0
