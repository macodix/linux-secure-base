"""Modul lynis — Härtungsprüfung des Systems.

Installiert lynis, legt ein Prüfskript unter /usr/local/sbin und einen
Cron-Eintrag für den regelmäßigen Audit-Lauf an. Betriebsart über den
Schlüssel operation.
"""

import re
import stat
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Ein Cron-Feld ist ein Wert (Zahl oder *) mit optionalem Bereich (-Zahl)
# und optionalem Schritt (/Zahl), kommagetrennt wiederholbar.
_CRON_FIELD_RE = re.compile(
    r"^(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?(,(\*|[0-9]+)(-[0-9]+)?(/[0-9]+)?)*$"
)

LYNIS_PACKAGES = ("lynis",)


def _pruef_script_content(berichte_dir: str) -> str:
    """Baut den Inhalt des Härtungsprüfskripts.

    Args:
        berichte_dir: Verzeichnis, unter dem die Berichte abgelegt werden.

    Returns:
        Vollständiger Skriptinhalt.
    """
    return (
        "#!/bin/bash\n"
        "# Von lsb/lynis verwaltet — nicht von Hand bearbeiten.\n"
        "set -euo pipefail\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "\n"
        f'BERICHTE="{berichte_dir}"\n'
        'mkdir -p "$BERICHTE"\n'
        "\n"
        "lynis audit system --quiet --no-colors \\\n"
        '    > "$BERICHTE/lynis-$(date +%F).txt" 2>&1\n'
        'cp /var/log/lynis-report.dat "$BERICHTE/lynis-report-$(date +%F).dat"\n'
    )


def _cron_content(schedule: str, pruef_script: str) -> str:
    """Baut den Inhalt des Cron-Eintrags.

    Args:
        schedule: Cron-Zeitplan (5 Felder).
        pruef_script: Pfad des aufzurufenden Prüfskripts.

    Returns:
        Vollständiger Inhalt der Cron-Datei.
    """
    return (
        "# Härtungsprüfung (lynis) — Zeitplan aus lynis_schedule (lsb.conf)\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        f"{schedule}  root  {pruef_script}\n"
    )


class Lynis(Module):
    """Härtungsprüfung des Systems über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = ["operation", "lynis_schedule"]

    # Programmpfade und Schreibziele als Klassenattribute (siehe base.py:
    # Testunterklasse ersetzt sie, ohne dieses Modul anzufassen).
    DPKG_QUERY_BIN: ClassVar[str] = "/usr/bin/dpkg-query"
    PRUEF_SCRIPT: ClassVar[str] = "/usr/local/sbin/secure-base-haertungspruefung.sh"
    CRON_FILE: ClassVar[str] = "/etc/cron.d/secure-base-haertung"
    BERICHTE_DIR: ClassVar[str] = "/var/lib/secure-base/haertung"

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    lynis_schedule: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem Cron-Zeitplan.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        return self._install()

    def _validate(self) -> None:
        """Prüft den Cron-Zeitplan und lehnt ungültige Werte ab.

        lynis_schedule geht in eine Cron-Datei. Deshalb prüft das Modul den
        Wert vor der Verwendung (konv-scripting-python.md Abschnitt 4.2):
        genau 5 Felder, jedes Feld nach dem strengen Cron-Feldmuster.

        Raises:
            ModuleError: Wenn lynis_schedule nicht aus genau 5 gültigen
                Cron-Feldern besteht.
        """
        fields = self.lynis_schedule.split()
        if len(fields) != 5:
            raise ModuleError(
                f"Cron-Zeitplan braucht 5 Felder"
                f" (Minute Stunde Tag Monat Wochentag): {self.lynis_schedule!r}"
            )
        for field in fields:
            if not _CRON_FIELD_RE.match(field):
                raise ModuleError(f"Ungültiges Cron-Feld: {field!r}")

    def _install(self) -> int:
        """Richtet Paket, Prüfskript und Cron-Eintrag ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, Action]] = [
            (
                "lynis installieren",
                self.APT_ACTION_CLS(packages=list(LYNIS_PACKAGES)),
            ),
            (
                "Berichtsverzeichnis anlegen",
                MakeDirAction(path=self.BERICHTE_DIR, mode=0o750, parents=True),
            ),
            (
                "Prüfskript schreiben",
                WriteFileAction(
                    dst=self.PRUEF_SCRIPT,
                    content=_pruef_script_content(self.BERICHTE_DIR),
                    mode=0o700,
                    overwrite=True,
                ),
            ),
            (
                "Cron-Eintrag schreiben",
                WriteFileAction(
                    dst=self.CRON_FILE,
                    content=_cron_content(self.lynis_schedule, self.PRUEF_SCRIPT),
                    mode=0o644,
                    overwrite=True,
                ),
            ),
        ]
        for label, action in steps:
            self.send_message(LogLevel.INFO, "lynis", label)
            if self.run_action(action) != 0:
                self.send_message(LogLevel.ERROR, "lynis", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _verify(self) -> int:
        """Gleicht die Wirkung der install-Schritte mit dem Soll ab.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_package_installed()
        ok &= self._check_mode(self.BERICHTE_DIR, 0o750, "Berichtsverzeichnis")
        ok &= self._check_file_content(
            self.PRUEF_SCRIPT, _pruef_script_content(self.BERICHTE_DIR), "Prüfskript"
        )
        ok &= self._check_mode(self.PRUEF_SCRIPT, 0o700, "Prüfskript")
        ok &= self._check_file_content(
            self.CRON_FILE,
            _cron_content(self.lynis_schedule, self.PRUEF_SCRIPT),
            "Cron-Eintrag",
        )
        ok &= self._check_mode(self.CRON_FILE, 0o644, "Cron-Eintrag")
        return 0 if ok else 1

    def _check_package_installed(self) -> bool:
        """Prüft, ob alle lynis-Pakete installiert sind.

        Returns:
            True, wenn jedes Paket als installiert gemeldet wird.
        """
        ok = True
        for package in LYNIS_PACKAGES:
            ok &= self._check_value(
                [self.DPKG_QUERY_BIN, "-W", "-f=${Status}", package],
                "install ok installed",
                f"Paket {package}",
            )
        return ok

    def _check_value(self, command: list[str], expected: str, label: str) -> bool:
        """Liest einen Wert über einen Befehl und vergleicht ihn mit dem Soll.

        Args:
            command: Befehl, dessen Ausgabe den Ist-Wert liefert.
            expected: Soll-Wert.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        action = SysCmdAction(command=command, timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "lynis", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "lynis", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "lynis", f"{label}: ist {current}, soll {expected}"
        )
        return False

    def _check_mode(self, path: str, expected_mode: int, label: str) -> bool:
        """Vergleicht die Rechte eines Pfads mit dem Soll.

        Args:
            path: Datei oder Verzeichnis.
            expected_mode: Erwartete Rechte.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        try:
            actual_mode = stat.S_IMODE(Path(path).stat().st_mode)
        except OSError:
            self.send_message(LogLevel.ERROR, "lynis", f"{label}: nicht lesbar")
            return False
        if actual_mode == expected_mode:
            self.send_message(
                LogLevel.INFO, "lynis", f"{label}: Rechte {oct(actual_mode)} — OK"
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "lynis",
            f"{label}: Rechte {oct(actual_mode)}, soll {oct(expected_mode)}",
        )
        return False

    def _check_file_content(self, path: str, expected: str, label: str) -> bool:
        """Vergleicht den Inhalt einer Datei mit dem Soll.

        Args:
            path: Zu prüfende Datei.
            expected: Erwarteter Inhalt.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        try:
            current = Path(path).read_text(encoding="utf-8")
        except OSError:
            self.send_message(LogLevel.ERROR, "lynis", f"{label}: nicht lesbar")
            return False
        if current == expected:
            self.send_message(LogLevel.INFO, "lynis", f"{label}: Inhalt stimmt — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "lynis", f"{label}: Inhalt weicht vom Soll ab"
        )
        return False
