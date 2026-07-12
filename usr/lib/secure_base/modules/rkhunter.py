"""Modul rkhunter — Schadsoftware-/Rootkit-Schutz.

Installiert das Paket rkhunter, härtet /etc/default/rkhunter (täglicher
Cron-Lauf, DB-Update, Report-Mail, apt-Hook), setzt in /etc/rkhunter.conf
den Mail-Absender und trägt dort die Ausnahmen für bekannte Fehlalarme ein
(von systemd angelegte versteckte Dateien unter /etc, Shared-Memory-Segmente
von PostgreSQL unter /dev/shm), und initialisiert die Baseline-Datenbank.
Betriebsart über den Schlüssel operation (install, check, uninstall, test).
Kein eigener systemd-Dienst — der Lauf erfolgt über /etc/cron.daily/rkhunter
und einen apt-Hook.
"""

import contextlib
import re
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.errors import ActionError, ModuleError
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

    # Zeitgrenze für den Funktionstest (rkhunter --check liest eine
    # größere Zahl von Systemdateien und kann einige Minuten dauern).
    CHECK_TIMEOUT: ClassVar[float] = 300.0

    DPKG_QUERY_BIN: ClassVar[str] = "/usr/bin/dpkg-query"
    DPKG_QUERY_TIMEOUT: ClassVar[float] = 15.0

    # Bekannte Fehlalarme des täglichen Laufs, als Ausnahmen in rkhunter.conf.
    # Jeder Eintrag steht in einer eigenen Zeile; beide Schlüssel dürfen
    # mehrfach vorkommen. Ohne sie meldet rkhunter diese Dateien bei jedem
    # Lauf per Mail, und die Meldungen verdecken echte Funde.
    #
    # Versteckte Dateien (Punkt am Anfang), beide von systemd angelegt:
    # .resolv.conf.systemd-resolved.bak ist die Sicherung, die
    # systemd-resolved beim Übernehmen von /etc/resolv.conf hinterlässt;
    # .updated ist die Zeitstempel-Datei von systemd-update-done.service.
    ALLOWED_HIDDEN_FILES: ClassVar[tuple[str, ...]] = (
        "/etc/.resolv.conf.systemd-resolved.bak",
        "/etc/.updated",
    )
    # Shared-Memory-Segmente des PostgreSQL-Servers
    # (dynamic_shared_memory_type = posix, Vorgabe unter Debian/Ubuntu). Der
    # Zahlenteil des Namens ist zufällig und wechselt je Segment, deshalb ein
    # Muster statt fester Namen. Der Eintrag steht auch auf Systemen ohne
    # Datenbankserver: dort gibt es keine passenden Dateien, er bleibt wirkungslos.
    # S108 (Temp-Pfad) trifft hier nicht: der Wert wird nicht beschrieben oder
    # gelesen, er ist der Text einer rkhunter-Ausnahme.
    ALLOWED_DEV_FILES: ClassVar[tuple[str, ...]] = ("/dev/shm/PostgreSQL.*",)  # noqa: S108

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    fqdn: str
    admin_mail: str

    def start(self) -> int:
        """Führt Einrichtung, Abgleich, Rückbau oder Funktionstest aus.

        Die Betriebsart uninstall lässt _validate() bewusst aus: der
        Rückbau verwendet fqdn/admin_mail nicht und muss wie im
        Bash-Original auch bei ungültigen Werten durchlaufen (fail-safe).

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem fqdn, nicht ableitbarem Absender
                oder ungültiger admin_mail (außer bei uninstall).
        """
        if self.operation == "uninstall":
            return self._uninstall()
        self._validate()
        if self.operation == "check":
            return self._verify()
        if self.operation == "test":
            return self._test()
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

    @classmethod
    def _allow_entries(cls) -> list[tuple[str, str]]:
        """Liefert die Ausnahme-Einträge für rkhunter.conf.

        Returns:
            (Schlüssel, Wert)-Paare in Schreibreihenfolge.
        """
        entries = [("ALLOWHIDDENFILE", value) for value in cls.ALLOWED_HIDDEN_FILES]
        entries += [("ALLOWDEVFILE", value) for value in cls.ALLOWED_DEV_FILES]
        return entries

    @classmethod
    def _allow_pattern(cls, key: str, value: str) -> str:
        """Baut den Regex, der genau diesen Ausnahme-Eintrag trifft.

        Trifft den vollständigen Eintrag, nicht nur den Schlüssel: beide
        Schlüssel dürfen mehrfach vorkommen, ein Muster auf den Schlüssel
        allein würde fremde Einträge überschreiben.

        Args:
            key: Schlüssel des Eintrags (ALLOWHIDDENFILE, ALLOWDEVFILE).
            value: Wert des Eintrags.

        Returns:
            Regulärer Ausdruck für die Sollzeile.
        """
        return rf"^{re.escape(key)}={re.escape(value)}$"

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Markdown-Abschnitt für den Installationsbericht.

        Dokumentiert REPORT_EMAIL aus /etc/default/rkhunter sowie die
        Ausnahmen in /etc/rkhunter.conf; der Absender-Eintrag (MAIL_CMD)
        bleibt wie im Bash-Original (installer/lib/modules/rkhunter.sh)
        unerwähnt.

        SICHERHEIT: rkhunter kennt keine Geheimnisse; doc() liest aus
        values ausschließlich admin_mail.

        Args:
            values: Konfigurationswerte des Moduls (fqdn, admin_mail).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Schadsoftware-Schutz".
        """
        admin_mail = values.get("admin_mail") or "(leer/Default)"
        allow_block = "".join(
            f"  - `{key}={value}`\n" for key, value in cls._allow_entries()
        )
        return (
            "\n## Schadsoftware-Schutz\n\n"
            "**Pakete:** rkhunter\n\n"
            "**Dateien/Einstellungen:**\n\n"
            f"- `{cls.RK_DEFAULT}`:\n"
            "  - `CRON_DAILY_RUN=true`\n"
            "  - `CRON_DB_UPDATE=true`\n"
            f"  - `REPORT_EMAIL={admin_mail}`\n"
            f"- `{cls.RK_CONF}` (Ausnahmen für bekannte Fehlalarme):\n"
            f"{allow_block}"
            "\n**Timer/Cron:** täglicher Lauf via /etc/cron.daily/rkhunter;"
            " Baseline-DB wird bei apt-Update aktualisiert\n"
            "\n> Hinweis: Baseline-Datenbank wurde bei der Installation"
            " initialisiert. Die Ausnahmen decken Dateien ab, die systemd"
            " (versteckte Dateien unter /etc) und PostgreSQL"
            " (Shared-Memory-Segmente unter /dev/shm) im Normalbetrieb"
            " anlegen; ohne sie meldet jeder Lauf dieselben Fehlalarme und"
            " verdeckt damit echte Funde.\n"
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
        steps += [
            (
                f"Ausnahme eintragen: {key}={value}",
                LineInFileAction(
                    path=self.RK_CONF,
                    line=f"{key}={value}",
                    match=self._allow_pattern(key, value),
                ),
            )
            for key, value in self._allow_entries()
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

    def _uninstall(self) -> int:
        """Nimmt die install-Konfig-Eingriffe zurück und entfernt das Paket.

        Kein Dienst zu stoppen — rkhunter hat keinen eigenen
        systemd-Dienst. Die Baseline-Datenbank (RK_BASELINE) bleibt wie
        im Original unangetastet: sie kann aus einem früheren Lauf
        stammen und wird nicht durch uninstall entsorgt.

        Läuft schrittweise mit Abbruch beim ersten Fehler; jeder Schritt
        ist für sich idempotent (fehlende Zieldatei überspringt ihren
        Revert, eine bereits fehlende Zeile bleibt bei state="absent"
        unverändert).

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        if not self._revert_config(
            self.RK_DEFAULT,
            (
                ("täglichen Lauf zurücknehmen", r"^CRON_DAILY_RUN="),
                ("DB-Update zurücknehmen", r"^CRON_DB_UPDATE="),
                ("DB-Update-Mail zurücknehmen", r"^DB_UPDATE_EMAIL="),
                ("Report-Empfänger zurücknehmen", r"^REPORT_EMAIL="),
                ("apt-Hook zurücknehmen", r"^APT_AUTOGEN="),
            ),
        ):
            return 1
        conf_entries: tuple[tuple[str, str], ...] = (
            ("Mail-Absender zurücknehmen", r"^MAIL_CMD="),
            *(
                (
                    f"Ausnahme zurücknehmen: {key}={value}",
                    self._allow_pattern(key, value),
                )
                for key, value in self._allow_entries()
            ),
        )
        if not self._revert_config(self.RK_CONF, conf_entries):
            return 1
        return self._remove_package()

    def _revert_config(self, path: str, entries: tuple[tuple[str, str], ...]) -> bool:
        """Nimmt die genannten Einstellungen in path zurück.

        Fehlt path, gilt der Revert als bereits erledigt (idempotent) —
        entspricht dem Original, das den Revert je Datei nur bei
        Vorhandensein ausführt.

        Args:
            path: Zu bereinigende Konfigurationsdatei.
            entries: Folge aus (Meldungstext, Regex für die Sollzeile).
                line bleibt bei state="absent" mit gesetztem match ohne
                Wirkung und wird deshalb leer übergeben.

        Returns:
            True bei Erfolg oder wenn path nicht existiert, sonst False.
        """
        if not Path(path).exists():
            self.send_message(
                LogLevel.INFO, "rkhunter", f"{path} nicht vorhanden — kein Revert nötig"
            )
            return True
        for label, match in entries:
            self.send_message(LogLevel.INFO, "rkhunter", label)
            action = LineInFileAction(path=path, line="", match=match, state="absent")
            if self.run_action(action) != 0:
                self.send_message(
                    LogLevel.ERROR, "rkhunter", f"fehlgeschlagen: {label}"
                )
                return False
        return True

    def _remove_package(self) -> int:
        """Entfernt das Paket rkhunter ohne --purge (Baseline bleibt liegen).

        Returns:
            0 bei Erfolg, 1 bei Fehlschlag.
        """
        label = "Paket entfernen (ohne --purge)"
        self.send_message(LogLevel.INFO, "rkhunter", label)
        action = self.APT_ACTION_CLS(packages=["rkhunter"], state="absent")
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
        for key, value in self._allow_entries():
            ok &= self._check_setting(
                self.RK_CONF,
                self._allow_pattern(key, value),
                f"Ausnahme {key}={value}",
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

    def _test(self) -> int:
        """Führt den Funktionstest ohne Systemänderung aus.

        Prüft, ob das Paket rkhunter installiert ist, und führt bei
        vorhandenem Paket einen lesenden Scan aus (rkhunter --check --sk
        --nocolors --report-warnings-only), wie im Original. Läuft
        sammelnd durch — anders als _install/_uninstall kein Abbruch
        beim ersten Fehler.

        Returns:
            0 bei erfolgreichem Test, 1 bei Fehler.
        """
        ok = True
        ok &= self._check_package_installed()
        ok &= self._run_scan()
        return 0 if ok else 1

    def _check_package_installed(self) -> bool:
        """Prüft per dpkg-query, ob das Paket rkhunter installiert ist.

        Returns:
            True, wenn dpkg-query den Status "install ok installed" meldet.
        """
        action = SysCmdAction(
            command=[self.DPKG_QUERY_BIN, "-W", "-f=${Status}", "rkhunter"],
            timeout=self.DPKG_QUERY_TIMEOUT,
        )
        if self.run_action(action) == 0 and "install ok installed" in action.stdout:
            self.send_message(LogLevel.INFO, "rkhunter", "Paket rkhunter: installiert")
            return True
        self.send_message(
            LogLevel.ERROR, "rkhunter", "Paket rkhunter: nicht installiert"
        )
        return False

    def _run_scan(self) -> bool:
        """Führt den lesenden rkhunter-Scan aus und meldet das Ergebnis.

        Die Scan-Ausgabe geht zeilenweise als WARN ins Log (Audit-
        Lesbarkeit, wie im Original). Exit-Code 1 (rkhunter meldet
        Warnungen) gilt nicht als Testfehler — Warnungen direkt nach
        Erstinstallation sind manuell zu sichten, kein Hard-Fail. Nur ein
        anderer Exit-Code oder ein Startfehler zählt als Fehler.

        Returns:
            True bei Exit-Code 0 oder 1, sonst False.
        """
        self.send_message(
            LogLevel.INFO,
            "rkhunter",
            "Scan startet (lesend, kann einige Sekunden bis Minuten dauern)",
        )
        action = SysCmdAction(
            command=[
                self.RKHUNTER_BIN,
                "--check",
                "--sk",
                "--nocolors",
                "--report-warnings-only",
            ],
            timeout=self.CHECK_TIMEOUT,
        )
        with contextlib.suppress(ActionError):
            action.run()

        for line in action.stdout.splitlines():
            if line.strip():
                self.send_message(LogLevel.WARN, "rkhunter", line)

        if action.returncode == 0:
            self.send_message(LogLevel.INFO, "rkhunter", "Scan ohne Warnungen")
            return True
        if action.returncode == 1:
            self.send_message(
                LogLevel.WARN,
                "rkhunter",
                "Scan meldet Warnungen (siehe oben) — kein Testfehler. Warnungen"
                " direkt nach Erstinstallation manuell sichten, nicht ungeprüft"
                " als Fehlalarm abtun.",
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "rkhunter",
            f"Scan nicht ausführbar (Exit {action.returncode})",
        )
        return False
