"""Modul monit — Systemüberwachung.

Installiert Monit, setzt die globalen monitrc-Direktiven über die
Marker-Mechanik (BlockInFileAction) und legt die ausgewählten Checks unter
/etc/monit/conf.d/ als eigene Dateien an. Prüft die Konfiguration vor dem
(Neu-)Start, aktiviert und startet den Dienst. Alarm-Mail läuft über das
konfigurierte SMTP-Relay (Modul postfix). uninstall nimmt alle eigenen
Eingriffe zurück (konfig-unabhängig, alle KNOWN_CHECKS statt nur der
konfigurierten); test führt einen lesenden Funktionstest ohne
Systemänderung aus. Betriebsart über den Schlüssel operation.
"""

import re
import stat
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.block_in_file_action import BlockInFileAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# E-Mail-Muster wie im Bash-Original (require_monit_conf): kein Anspruch auf
# vollständige RFC-5322-Konformität, nur Schutz vor Werten, die in die
# monitrc-Direktiven gehen.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")

# Feste Liste aller vom Modul unterstützten Checks (Whitelist für monit_checks).
KNOWN_CHECKS: frozenset[str] = frozenset(
    {
        "system",
        "rootfs",
        "sshd",
        "postfix",
        "fail2ban",
        "ufw",
        "cron",
        "rkhunter",
        "restic",
    }
)

# Werte der monitrc-Einzelzeilen-Direktiven (Marker-Mechanik).
DAEMON_VALUE = "60 with start delay 60"
LOG_VALUE = "/var/log/monit.log"
MAILSERVER_VALUE = "localhost"

# (Marker, sprechender Direktiven-Name) je monitrc-Eingriff; gemeinsame
# Quelle für _install (Label/Blockinhalt) und _verify (Markerprüfung).
MONITRC_MARKERS: tuple[tuple[str, str], ...] = (
    ("monit-daemon", "set daemon"),
    ("monit-log", "set log"),
    ("monit-mailserver", "set mailserver"),
    ("monit-alert", "set alert"),
    ("monit-mail-format", "set mail-format"),
    ("monit-httpd", "set httpd"),
)

# Inhalt je conf.d-Check (ohne Markerzeilen — eigene, komplett überschriebene
# Datei je Check).
CHECK_CONTENT: dict[str, str] = {
    "system": (
        "check system $HOST\n"
        "    if loadavg (1min) > 4    then alert\n"
        "    if loadavg (5min) > 2    then alert\n"
        "    if memory usage > 90 %   then alert\n"
        "    if cpu usage (user) > 90 % for 5 cycles then alert\n"
    ),
    "rootfs": (
        "check filesystem rootfs with path /\n"
        "    if space usage > 85 % then alert\n"
        "    if inode usage > 85 % then alert\n"
    ),
    "sshd": (
        'check process sshd matching "sshd"\n'
        '    start program = "/bin/systemctl start ssh"\n'
        '    stop  program = "/bin/systemctl stop  ssh"\n'
        "    if 5 restarts within 5 cycles then alert\n"
    ),
    "postfix": (
        "check process postfix with pidfile /var/spool/postfix/pid/master.pid\n"
        '    start program = "/bin/systemctl start postfix"\n'
        '    stop  program = "/bin/systemctl stop  postfix"\n'
    ),
    "fail2ban": (
        "check process fail2ban with pidfile /var/run/fail2ban/fail2ban.pid\n"
        '    start program = "/bin/systemctl start fail2ban"\n'
        '    stop  program = "/bin/systemctl stop  fail2ban"\n'
    ),
    "ufw": (
        'check program ufw with path "/bin/systemctl is-active --quiet ufw"\n'
        "    if status != 0 then alert\n"
    ),
    "cron": (
        "check process crond with pidfile /var/run/crond.pid\n"
        '    start program = "/bin/systemctl start cron"\n'
        '    stop  program = "/bin/systemctl stop  cron"\n'
        "    if 5 restarts within 5 cycles then alert\n"
    ),
    "rkhunter": (
        "check file rkhunter with path /var/log/rkhunter.log\n"
        "    if mtime > 25 hours then alert\n"
    ),
    "restic": (
        "check file restic_backup with path /var/lib/secure-base/restic-last-success\n"
        "    if mtime > 26 hours then alert\n"
    ),
}


def _mail_format_block(mail_from: str) -> str:
    """Baut den Blockinhalt der monitrc-Direktive set mail-format.

    Args:
        mail_from: Absenderadresse der Alarm-Mails.

    Returns:
        Blockinhalt ohne Markerzeilen.
    """
    return (
        "set mail-format {\n"
        f"    from:    {mail_from}\n"
        "    subject: monit [$HOST] $EVENT - $SERVICE\n"
        "    message: $EVENT - $SERVICE auf $HOST ($DATE)\n"
        "             $DESCRIPTION\n"
        "}"
    )


def _httpd_block() -> str:
    """Baut den Blockinhalt der monitrc-Direktive set httpd.

    Returns:
        Blockinhalt ohne Markerzeilen.
    """
    return "set httpd port 2812 and\n    use address localhost\n    allow localhost"


class Monit(Module):
    """Systemüberwachung über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "admin_mail",
        "monit_mail_from",
        "monit_checks",
    ]

    # Programmpfade und Schreibziele als Klassenattribute (siehe base.py für
    # die Begründung: feste Vorgaben, per Testunterklasse umlenkbar).
    MONIT_BIN: ClassVar[str] = "/usr/bin/monit"
    DPKG_QUERY_BIN: ClassVar[str] = "/usr/bin/dpkg-query"
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"
    MAIL_BIN: ClassVar[str] = "/usr/bin/mail"
    MONITRC: ClassVar[str] = "/etc/monit/monitrc"
    CONFD: ClassVar[str] = "/etc/monit/conf.d"

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    admin_mail: str
    monit_mail_from: str
    monit_checks: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem admin_mail, monit_mail_from oder
                monit_checks.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        if self.operation == "uninstall":
            return self._uninstall()
        if self.operation == "test":
            return self._test()
        return self._install()

    def _validate(self) -> None:
        """Prüft admin_mail, monit_mail_from und monit_checks.

        Alle drei Werte gehen in monitrc-Direktiven bzw. Dateinamen unter
        CONFD. SysCmdAction hat bewusst keinen Optionsterminator, deshalb
        prüft das Modul die Werte vor der Verwendung
        (konv-scripting-python.md Abschnitt 4.2).

        Raises:
            ModuleError: Wenn admin_mail oder monit_mail_from keine gültige
                E-Mail-Adresse sind, monit_checks leer ist oder einen
                unbekannten Check-Namen enthält.
        """
        if not _EMAIL_RE.match(self.admin_mail):
            raise ModuleError(f"Ungültige admin_mail: {self.admin_mail!r}")
        if not _EMAIL_RE.match(self.monit_mail_from):
            raise ModuleError(f"Ungültige monit_mail_from: {self.monit_mail_from!r}")

        checks = self._parsed_checks()
        if not checks:
            raise ModuleError("monit_checks ist leer — mindestens ein Check erwartet")
        unknown = sorted(set(checks) - KNOWN_CHECKS)
        if unknown:
            raise ModuleError(
                f"monit_checks enthält unbekannte Werte: {unknown!r}"
                f" (erlaubt: {sorted(KNOWN_CHECKS)!r})"
            )

    def _parsed_checks(self) -> list[str]:
        """Zerlegt monit_checks in eine Liste von Check-Namen.

        Returns:
            Getrimmte, nicht-leere Check-Namen in der konfigurierten
            Reihenfolge.
        """
        return [c.strip() for c in self.monit_checks.split(",") if c.strip()]

    def _monitrc_edits(self) -> list[tuple[str, str, str]]:
        """Baut Label, Marker und Blockinhalt je monitrc-Eingriff.

        Returns:
            Liste aus (Label, Marker, Blockinhalt) in fester Reihenfolge
            gemäß MONITRC_MARKERS.
        """
        content_by_marker = {
            "monit-daemon": f"set daemon {DAEMON_VALUE}",
            "monit-log": f"set log {LOG_VALUE}",
            "monit-mailserver": f"set mailserver {MAILSERVER_VALUE}",
            "monit-alert": f"set alert {self.admin_mail}",
            "monit-mail-format": _mail_format_block(self.monit_mail_from),
            "monit-httpd": _httpd_block(),
        }
        return [
            (f"monitrc: {label} setzen", marker, content_by_marker[marker])
            for marker, label in MONITRC_MARKERS
        ]

    def _install(self) -> int:
        """Installiert Monit, setzt die Konfiguration und startet den Dienst.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, Action]] = [
            ("Paket installieren", self.APT_ACTION_CLS(packages=["monit"])),
        ]
        for label, marker, block in self._monitrc_edits():
            steps.append(
                (
                    label,
                    BlockInFileAction(path=self.MONITRC, block=block, marker=marker),
                )
            )
        for name in sorted(self._parsed_checks()):
            dst = str(Path(self.CONFD) / name)
            steps.append(
                (
                    f"Check {name} schreiben",
                    WriteFileAction(
                        dst=dst,
                        content=CHECK_CONTENT[name],
                        mode=0o644,
                        overwrite=True,
                        # kein safe_mode: eine .bak-Sicherung würde von
                        # monits Include-Glob mitgelesen (doppelter Check,
                        # monit -t schlägt fehl).
                        safe_mode=False,
                    ),
                )
            )
        steps += [
            (
                "Konfiguration prüfen (monit -t)",
                SysCmdAction(command=[self.MONIT_BIN, "-t"], timeout=30),
            ),
            (
                "Dienst aktivieren",
                self.SYSTEMD_ACTION_CLS(operation="enable", unit="monit", timeout=60),
            ),
            (
                "Dienst starten",
                self.SYSTEMD_ACTION_CLS(operation="start", unit="monit", timeout=60),
            ),
            (
                "Konfiguration neu einlesen (monit reload)",
                SysCmdAction(command=[self.MONIT_BIN, "reload"], timeout=30),
            ),
        ]

        for label, action in steps:
            self.send_message(LogLevel.INFO, "monit", label)
            if self.run_action(action) != 0:
                self.send_message(LogLevel.ERROR, "monit", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit dem Soll ab.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_value(
            [self.DPKG_QUERY_BIN, "-W", "-f=${Status}", "monit"],
            "install ok installed",
            "Paket monit",
        )
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", "monit"], "active", "Dienst aktiv"
        )
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-enabled", "monit"], "enabled", "Dienst enabled"
        )
        for marker, key_label in MONITRC_MARKERS:
            ok &= self._check_marker(marker, key_label)
        for name in sorted(self._parsed_checks()):
            dst = str(Path(self.CONFD) / name)
            ok &= self._check_file_mode(dst, 0o644, f"Check {name}")
        return 0 if ok else 1

    def _uninstall(self) -> int:
        """Nimmt die Installation zurück (Original: do_uninstall).

        Läuft konfig-unabhängig wie das Original: entfernt alle jemals
        verwalteten conf.d-Checks (KNOWN_CHECKS, nicht nur die aktuell
        konfigurierten monit_checks), nimmt sämtliche monitrc-Eingriffe über
        BlockInFileAction mit state="absent" zurück, deaktiviert den Dienst
        und entfernt zuletzt das Paket (ohne --purge, wie im Original).
        Idempotent — ein zweiter Lauf trifft auf bereits entfernte Dateien
        und Marker und bricht dafür nicht ab.

        Returns:
            0 bei Erfolg oder wenn das Paket bereits fehlt, sonst 1 beim
            ersten fehlgeschlagenen Schritt.
        """
        if not self._package_installed():
            self.send_message(
                LogLevel.INFO,
                "monit",
                "Paket monit nicht installiert — nichts zu tun",
            )
            return 0

        steps: list[tuple[str, Action]] = [
            (
                "Dienst stoppen",
                self.SYSTEMD_ACTION_CLS(operation="stop", unit="monit", timeout=60),
            ),
            (
                "Dienst deaktivieren",
                self.SYSTEMD_ACTION_CLS(operation="disable", unit="monit", timeout=60),
            ),
        ]
        for name in sorted(KNOWN_CHECKS):
            dst = Path(self.CONFD) / name
            if dst.exists():
                steps.append(
                    (
                        f"Check {name} entfernen",
                        # kein safe_mode: eine .bak-Sicherung in conf.d würde
                        # von monits Include-Glob mitgelesen (siehe _install).
                        DeleteFileAction(path=str(dst), safe_mode=False),
                    )
                )
        if Path(self.MONITRC).exists():
            for marker, key_label in MONITRC_MARKERS:
                steps.append(
                    (
                        f"monitrc: {key_label} zurücknehmen",
                        BlockInFileAction(
                            path=self.MONITRC,
                            block="",
                            marker=marker,
                            state="absent",
                        ),
                    )
                )
        steps.append(
            ("Paket entfernen", self.APT_ACTION_CLS(packages=["monit"], state="absent"))
        )

        for label, action in steps:
            self.send_message(LogLevel.INFO, "monit", label)
            if self.run_action(action) != 0:
                self.send_message(LogLevel.ERROR, "monit", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _test(self) -> int:
        """Führt einen lesenden Funktionstest ohne Systemänderung aus.

        Original: do_test. Prüft die Konfigurationssyntax (monit -t), ruft
        den Status über den lokalen httpd ab (monit status) und meldet, ob
        der mail-Befehl für die Alarm-Zustellung vorhanden ist. Sammelt alle
        Befunde, statt beim ersten Fehler abzubrechen (anders als
        _install/_uninstall).

        Returns:
            0, wenn das Paket installiert ist und beide Prüfungen (Syntax,
            Status) erfolgreich sind; sonst 1.
        """
        if not self._package_installed():
            self.send_message(
                LogLevel.ERROR,
                "monit",
                "Paket monit nicht installiert — kein Funktionstest möglich",
            )
            return 1

        ok = True
        ok &= self._run_diagnostic(
            [self.MONIT_BIN, "-t"], "monit -t", "Konfiguration syntaktisch gültig"
        )
        ok &= self._run_diagnostic(
            [self.MONIT_BIN, "status"], "monit status", "Dienst über httpd erreichbar"
        )
        if Path(self.MAIL_BIN).exists():
            self.send_message(
                LogLevel.INFO,
                "monit",
                f"{self.MAIL_BIN} vorhanden — Alarm-Zustellung möglich",
            )
        else:
            self.send_message(
                LogLevel.WARN,
                "monit",
                f"{self.MAIL_BIN} fehlt — Alarm-Mails würden nicht zugestellt"
                " (Modul postfix installiert mailutils)",
            )
        return 0 if ok else 1

    def _package_installed(self) -> bool:
        """Prüft, ob das Paket monit installiert ist.

        Returns:
            True, wenn dpkg-query den Status "install ok installed" meldet.
        """
        action = SysCmdAction(
            command=[self.DPKG_QUERY_BIN, "-W", "-f=${Status}", "monit"], timeout=15
        )
        if self.run_action(action) != 0:
            return False
        return action.stdout.strip() == "install ok installed"

    def _run_diagnostic(self, command: list[str], label: str, ok_note: str) -> bool:
        """Führt einen lesenden Diagnosebefehl aus und protokolliert jede Zeile.

        Args:
            command: Auszuführender Befehl.
            label: Bezeichner für die Zeilen-Meldungen und die Zusammenfassung.
            ok_note: Kurzbeschreibung für die Erfolgsmeldung.

        Returns:
            True bei Rückgabewert 0, sonst False.
        """
        action = SysCmdAction(command=command, timeout=30)
        rc = self.run_action(action)
        for line in action.stdout.splitlines():
            stripped = line.strip()
            if stripped:
                self.send_message(LogLevel.INFO, "monit", f"{label}: {stripped}")
        if rc == 0:
            self.send_message(LogLevel.INFO, "monit", f"test: '{label}' ok ({ok_note})")
            return True
        self.send_message(LogLevel.ERROR, "monit", f"test: '{label}' fehlgeschlagen")
        return False

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
            self.send_message(LogLevel.ERROR, "monit", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "monit", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "monit", f"{label}: ist {current}, soll {expected}"
        )
        return False

    def _check_marker(self, marker: str, key_label: str) -> bool:
        """Prüft, ob der BlockInFileAction-Marker in monitrc vorhanden ist.

        Args:
            marker: Marker-Name des Eingriffs.
            key_label: Sprechender Direktiven-Name für die Meldung.

        Returns:
            True, wenn die Begin-Markerzeile vorhanden ist, sonst False.
        """
        try:
            content = Path(self.MONITRC).read_text(encoding="utf-8")
        except OSError:
            self.send_message(
                LogLevel.ERROR,
                "monit",
                f"monitrc-Eingriff '{key_label}': {self.MONITRC} fehlt",
            )
            return False
        if f"# BEGIN {marker}" in content:
            self.send_message(
                LogLevel.INFO,
                "monit",
                f"monitrc-Eingriff '{key_label}': vorhanden — OK",
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "monit",
            f"monitrc-Eingriff '{key_label}': fehlt in {self.MONITRC}",
        )
        return False

    def _check_file_mode(self, path: str, mode: int, label: str) -> bool:
        """Prüft Existenz und Zugriffsrechte einer conf.d-Check-Datei.

        Args:
            path: Zu prüfender Dateipfad.
            mode: Erwartete Zugriffsrechte.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        try:
            actual = stat.S_IMODE(Path(path).stat().st_mode)
        except OSError:
            self.send_message(LogLevel.ERROR, "monit", f"{label}: {path} fehlt")
            return False
        if actual == mode:
            self.send_message(
                LogLevel.INFO, "monit", f"{label}: {path} Rechte {oct(actual)} — OK"
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "monit",
            f"{label}: {path} Rechte {oct(actual)}, soll {oct(mode)}",
        )
        return False
