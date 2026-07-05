"""Modul rkhunter — Schadsoftware-/Rootkit-Schutz.

Installiert das Paket rkhunter, härtet /etc/default/rkhunter (täglicher
Cron-Lauf, DB-Update, Report-Mail, apt-Hook) und den Mail-Absender in
/etc/rkhunter.conf, und initialisiert die Baseline-Datenbank. Betriebsart
über den Schlüssel operation. Kein eigener systemd-Dienst — der Lauf
erfolgt über /etc/cron.daily/rkhunter und einen apt-Hook.
"""

import re
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Zeichensatz für den Rechnernamen wie im Bash-Original (installer/lib/modules/
# rkhunter.sh): nur Buchstaben, Ziffern, Punkt und Bindestrich — keine
# RFC-1123-Strukturprüfung wie im Modul base.
_FQDN_RE = re.compile(r"[A-Za-z0-9.-]+")

# E-Mail-Zeichensatz wie im Modul monit (installer/lib/modules/monit.sh).
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+")


class Rkhunter(Module):
    """Schadsoftware-/Rootkit-Schutz über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = ["operation", "fqdn", "admin_mail"]

    # Programmpfade und Schreibziele als Klassenattribute statt Literale in
    # den Schritten (siehe Modul base für die Begründung); eine
    # Testunterklasse außerhalb dieses Moduls kann sie überschreiben.
    RKHUNTER_BIN: ClassVar[str] = "/usr/bin/rkhunter"
    RK_DEFAULT: ClassVar[str] = "/etc/default/rkhunter"
    RK_CONF: ClassVar[str] = "/etc/rkhunter.conf"
    RK_BASELINE: ClassVar[str] = "/var/lib/rkhunter/db/rkhunter.dat"

    # Zeitgrenze für die Baseline-Initialisierung (rkhunter --propupd hasht
    # eine größere Zahl von Systemdateien und kann mehrere Minuten dauern).
    PROPUPD_TIMEOUT: ClassVar[float] = 600.0

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    fqdn: str
    admin_mail: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem fqdn, nicht ableitbarem Absender
                oder ungültiger admin_mail.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        return self._install()

    def _validate(self) -> None:
        """Prüft fqdn und admin_mail und lehnt ungültige Werte ab.

        Beide Werte gehen in Dateiinhalte (REPORT_EMAIL, MAIL_CMD). Die
        Prüfung erfolgt vor der Verwendung (konv-scripting-python.md
        Abschnitt 4.2).

        Raises:
            ModuleError: Wenn fqdn unzulässige Zeichen enthält oder keine
                Domain besitzt, oder wenn admin_mail kein zulässiges
                E-Mail-Format hat.
        """
        if not _FQDN_RE.fullmatch(self.fqdn):
            raise ModuleError(f"Ungültiger Rechnername: {self.fqdn!r}")
        if not self._domain():
            raise ModuleError(
                f"Kein Absender ableitbar — Rechnername ohne Domain: {self.fqdn!r}"
            )
        if not _EMAIL_RE.fullmatch(self.admin_mail):
            raise ModuleError(f"Ungültige E-Mail-Adresse: {self.admin_mail!r}")

    def _domain(self) -> str:
        """Leitet die Domain aus fqdn ab (Teil nach dem ersten Punkt).

        Returns:
            Domain-Anteil, oder leer, wenn fqdn keinen Punkt enthält.
        """
        return self.fqdn.split(".", 1)[1] if "." in self.fqdn else ""

    def _mailfrom(self) -> str:
        """Baut den Absender der Report-Mail.

        Returns:
            Absender in der Form root@<domain>.
        """
        return f"root@{self._domain()}"

    def _mail_cmd(self) -> str:
        """Baut den Sollwert für MAIL_CMD in rkhunter.conf.

        ${HOST_NAME} ist eine rkhunter-interne Variable und bleibt literal
        erhalten.

        Returns:
            Vollständiger MAIL_CMD-Wert.
        """
        return (
            f"mail -r {self._mailfrom()} -s"
            ' "[rkhunter] Warnings found for ${HOST_NAME}"'
        )

    def _install(self) -> int:
        """Installiert das Paket und härtet die Konfiguration.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, Action]] = [
            (
                "Paket installieren",
                self.APT_ACTION_CLS(packages=["rkhunter"]),
            ),
            (
                "täglichen Lauf aktivieren",
                LineInFileAction(
                    path=self.RK_DEFAULT,
                    line='CRON_DAILY_RUN="yes"',
                    match=r"^CRON_DAILY_RUN=",
                ),
            ),
            (
                "DB-Update aktivieren",
                LineInFileAction(
                    path=self.RK_DEFAULT,
                    line='CRON_DB_UPDATE="yes"',
                    match=r"^CRON_DB_UPDATE=",
                ),
            ),
            (
                "DB-Update-Mail deaktivieren",
                LineInFileAction(
                    path=self.RK_DEFAULT,
                    line='DB_UPDATE_EMAIL="false"',
                    match=r"^DB_UPDATE_EMAIL=",
                ),
            ),
            (
                "Report-Empfänger setzen",
                LineInFileAction(
                    path=self.RK_DEFAULT,
                    line=f'REPORT_EMAIL="{self.admin_mail}"',
                    match=r"^REPORT_EMAIL=",
                ),
            ),
            (
                "apt-Hook aktivieren",
                LineInFileAction(
                    path=self.RK_DEFAULT,
                    line='APT_AUTOGEN="yes"',
                    match=r"^APT_AUTOGEN=",
                ),
            ),
            (
                "Mail-Absender setzen",
                LineInFileAction(
                    path=self.RK_CONF,
                    line=f"MAIL_CMD={self._mail_cmd()}",
                    match=r"^MAIL_CMD=",
                ),
            ),
        ]
        for label, action in steps:
            self.send_message(LogLevel.INFO, "rkhunter", label)
            if self.run_action(action) != 0:
                self.send_message(
                    LogLevel.ERROR, "rkhunter", f"fehlgeschlagen: {label}"
                )
                return 1
        return self._install_baseline()

    def _install_baseline(self) -> int:
        """Initialisiert die Baseline-Datenbank, falls noch keine vorhanden ist.

        Eine bereits vorhandene Baseline stammt aus einem früheren Lauf und
        bleibt unangetastet.

        Returns:
            0 bei Erfolg oder vorhandener Baseline, 1 bei Fehlschlag.
        """
        label = "Baseline initialisieren"
        if self._baseline_present():
            self.send_message(
                LogLevel.INFO, "rkhunter", f"{label}: bereits vorhanden — übersprungen"
            )
            self.send_message(
                LogLevel.WARN,
                "rkhunter",
                "übernommene Baseline bei Kompromittierungsverdacht nicht"
                " vertrauen — bei Bedarf manuell neu setzen (rkhunter --propupd)",
            )
            return 0
        self.send_message(LogLevel.INFO, "rkhunter", label)
        action = SysCmdAction(
            command=[self.RKHUNTER_BIN, "--propupd"], timeout=self.PROPUPD_TIMEOUT
        )
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "rkhunter", f"fehlgeschlagen: {label}")
            return 1
        return 0

    def _verify(self) -> int:
        """Gleicht die eigenen install-Wirkungen mit dem Soll ab.

        Prüft nur, ob die von diesem Modul gesetzten Werte wirken (kein
        System-Audit), läuft alle Prüfungen durch und sammelt das Ergebnis.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_setting(
            self.RK_DEFAULT, r'^CRON_DAILY_RUN="yes"$', "täglicher Lauf"
        )
        ok &= self._check_setting(
            self.RK_DEFAULT, r'^CRON_DB_UPDATE="yes"$', "DB-Update"
        )
        ok &= self._check_setting(
            self.RK_DEFAULT, r'^DB_UPDATE_EMAIL="false"$', "DB-Update-Mail"
        )
        ok &= self._check_setting(
            self.RK_DEFAULT,
            rf'^REPORT_EMAIL="{re.escape(self.admin_mail)}"$',
            "Report-Empfänger",
        )
        ok &= self._check_setting(self.RK_DEFAULT, r'^APT_AUTOGEN="yes"$', "apt-Hook")
        ok &= self._check_setting(
            self.RK_CONF,
            rf"^MAIL_CMD={re.escape(self._mail_cmd())}$",
            "Mail-Absender",
        )
        ok &= self._check_baseline()
        return 0 if ok else 1

    def _check_setting(self, path: str, pattern: str, label: str) -> bool:
        """Prüft, ob eine Datei eine auf pattern passende Zeile enthält.

        Args:
            path: Zu prüfende Datei.
            pattern: Regulärer Ausdruck für die Sollzeile.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Treffer, sonst False.
        """
        if self._file_has_line(path, pattern):
            self.send_message(LogLevel.INFO, "rkhunter", f"{label}: OK")
            return True
        self.send_message(
            LogLevel.ERROR, "rkhunter", f"{label}: nicht gesetzt ({path})"
        )
        return False

    def _file_has_line(self, path: str, pattern: str) -> bool:
        """Prüft, ob path eine auf pattern passende Zeile enthält.

        Args:
            path: Zu lesende Datei.
            pattern: Regulärer Ausdruck.

        Returns:
            True bei Treffer, False bei fehlender Datei oder ohne Treffer.
        """
        try:
            content = Path(path).read_text(encoding="utf-8")
        except OSError:
            return False
        return re.search(pattern, content, re.MULTILINE) is not None

    def _baseline_present(self) -> bool:
        """Prüft, ob die Baseline-Datenbank vorhanden und nicht leer ist.

        Returns:
            True, wenn RK_BASELINE existiert und eine Größe größer 0 hat.
        """
        try:
            return Path(self.RK_BASELINE).stat().st_size > 0
        except OSError:
            return False

    def _check_baseline(self) -> bool:
        """Prüft die Baseline-Datenbank und meldet das Ergebnis.

        Returns:
            True, wenn die Baseline vorhanden ist, sonst False.
        """
        if self._baseline_present():
            self.send_message(LogLevel.INFO, "rkhunter", "Baseline: vorhanden")
            return True
        self.send_message(
            LogLevel.ERROR, "rkhunter", f"Baseline fehlt oder leer ({self.RK_BASELINE})"
        )
        return False
