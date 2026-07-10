"""Modul logging — Protokollierung und Auditing.

Härtet journald (persistentes Journal mit Größen-/Zeitgrenze), richtet
logwatch als täglichen Mail-Report ein, schreibt die logrotate-Konfig für
das secure-base-Logfile und aktiviert auditd mit sudo-Protokollierung und
Audit-Regeln nach konv-system.md Abschnitt 3.4. Betriebsart über den
Schlüssel operation.
"""

import re
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

_Step = Callable[[], int]

# fqdn-Zeichensatz für die Mailfrom-Ableitung (bewusst locker — die
# strenge Rechnername-Prüfung ist Aufgabe des Moduls base).
_FQDN_CHARS_RE = re.compile(r"^[A-Za-z0-9.-]+$")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# systemd-Größenmaß (journald SystemMaxUse), z. B. "500M", "1G".
_JOURNALD_SIZE_RE = re.compile(r"^[0-9]+[KMGT]?$")

# systemd-Zeitspanne (journald MaxRetentionSec), z. B. "4week", "3month".
_JOURNALD_RETENTION_RE = re.compile(r"^[0-9]+(s|min|h|day|week|month|year)$")

# Soll-Regeln nach konv-system.md Abschnitt 3.4 b (exakt); "-e 2" (Immutable)
# steht als letzte Regel.
AUDIT_RULES: tuple[str, ...] = (
    "-w /etc/passwd -p wa -k identity",
    "-w /etc/shadow -p wa -k identity",
    "-w /etc/group -p wa -k identity",
    "-w /var/log/lastlog -p wa -k logins",
    "-w /usr/bin/su -p x -k priv_esc",
    "-w /etc/sudoers -p wa -k scope",
    "-w /etc/sudoers.d -p wa -k scope",
    "-w /etc/ssh/sshd_config -p wa -k sshd",
    "-w /etc/pam.d -p wa -k pam",
    "-w /etc/ufw -p wa -k firewall",
    "-w /etc/audit -p wa -k auditconfig",
    "-e 2",
)


def _audit_rules_content() -> str:
    """Baut den Inhalt der Audit-Regeldatei."""
    return "".join(f"{rule}\n" for rule in AUDIT_RULES)


def _logrotate_content() -> str:
    """Baut den Inhalt der logrotate-Konfiguration für das secure-base-Logfile."""
    return (
        "/var/log/secure-base/secure-base.log {\n"
        "    weekly\n"
        "    size 5M\n"
        "    compress\n"
        "    rotate 8\n"
        "    missingok\n"
        "    notifempty\n"
        "    copytruncate\n"
        "}\n"
    )


def _sudolog_content() -> str:
    """Baut den Inhalt der sudo-Protokollierungs-Konfiguration."""
    return 'Defaults logfile="/var/log/sudo.log"\n'


def _doc_value(values: dict[str, str], key: str) -> str:
    """Liest einen Wert für den Installationsbericht aus values.

    doc() fragt hier ausschließlich fest benannte, unkritische Schlüssel ab
    (journald_max_use, journald_max_retention, admin_mail) — ein
    Allowlist-Mechanismus wie im Bash-Original (doc_val) ist deshalb hier
    nicht nötig.

    Args:
        values: Konfigurationswerte des Moduls.
        key: Abzufragender Schlüssel.

    Returns:
        Wert aus values, oder "(leer/Default)" wenn leer oder nicht gesetzt.
    """
    return values.get(key) or "(leer/Default)"


class Logging(Module):
    """Protokollierung und Auditing des Systems über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "fqdn",
        "admin_mail",
        "journald_max_use",
        "journald_max_retention",
    ]

    # Programmpfade und Schreibziele als Klassenattribute statt Literale in
    # den Schritten (Begründung wie im Referenzmodul base).
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"
    DPKG_BIN: ClassVar[str] = "/usr/bin/dpkg"
    JOURNALCTL_BIN: ClassVar[str] = "/usr/bin/journalctl"
    LOGWATCH_BIN: ClassVar[str] = "/usr/bin/logwatch"
    JOURNALD_CONF: ClassVar[str] = "/etc/systemd/journald.conf"
    LOGWATCH_CONF: ClassVar[str] = "/etc/logwatch/conf/logwatch.conf"
    JOURNAL_DIR: ClassVar[str] = "/var/log/journal"
    LOGROTATE_CONF: ClassVar[str] = "/etc/logrotate.d/secure-base"
    AUDIT_RULES_FILE: ClassVar[str] = "/etc/audit/rules.d/secure-base.rules"
    SUDOLOG_CONF: ClassVar[str] = "/etc/sudoers.d/secure-base-sudolog"

    # apt-/systemd-Aktionsklassen als Klassenattribute (Begründung wie im
    # Referenzmodul base): Testunterklasse kann sie im Testbaum umlenken.
    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Zeitgrenze für den probeweisen logwatch-Mailversand in _test (echter
    # Versand über das postfix-Relay, Klassenattribut wie im Referenzmodul
    # base testbar).
    LOGWATCH_TEST_TIMEOUT: ClassVar[float] = 60.0

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    fqdn: str
    admin_mail: str
    journald_max_use: str
    journald_max_retention: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigen Konfigurationswerten.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        if self.operation == "uninstall":
            return self._uninstall()
        if self.operation == "test":
            return self._test()
        return self._install()

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Markdown-Abschnitt für den Installationsbericht.

        SICHERHEIT: doc() liest ausschließlich die unten aufgeführten,
        unkritischen Schlüssel (journald_max_use, journald_max_retention,
        admin_mail) — keine Geheimnisse gehen in diesen Abschnitt ein.

        Args:
            values: Konfigurationswerte des Moduls (fqdn, admin_mail,
                journald_max_use, journald_max_retention, …).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Protokollierung und
            Auditing".
        """
        journald_max_use = _doc_value(values, "journald_max_use")
        journald_max_retention = _doc_value(values, "journald_max_retention")
        admin_mail = _doc_value(values, "admin_mail")
        return (
            "\n## Protokollierung und Auditing\n\n"
            "**Pakete:** logwatch, auditd\n\n"
            "\n**Dienste:** auditd (enabled, aktiv nach install)\n"
            "**Dateien/Einstellungen:**\n\n"
            f"- `{cls.JOURNALD_CONF}`:\n"
            "  - `Storage = persistent`\n"
            f"  - `SystemMaxUse = {journald_max_use}`\n"
            f"  - `MaxRetentionSec = {journald_max_retention}`\n"
            f"- `{cls.LOGWATCH_CONF}`:\n"
            f"  - `MailTo = {admin_mail}`\n"
            "  - `Detail = Med`\n"
            "  - `Service = All`\n"
            "  - `Output = mail`\n"
            f"- `{cls.LOGROTATE_CONF}`:\n"
            "  - `logrotate-Konfig für /var/log/secure-base/secure-base.log`\n"
            f"- `{cls.AUDIT_RULES_FILE}`:\n"
            "  - `-w /etc/sudoers -p wa -k scope`\n"
            "  - `-w /etc/sudoers.d -p wa -k scope`\n"
            "  - `-w /etc/passwd -p wa -k identity`\n"
            "  - `-w /etc/shadow -p wa -k identity`\n"
            "  - `-w /etc/group -p wa -k identity`\n"
            "  - `-w /var/log/lastlog -p wa -k logins`\n"
            "  - `-e 2 (Immutable — Regeländerungen ohne Reboot gesperrt)`\n"
            f"- `{cls.SUDOLOG_CONF}`:\n"
            '  - `Defaults logfile="/var/log/sudo.log"`\n'
            "\n**Timer/Cron:** logwatch: täglicher Lauf via "
            "/etc/cron.daily/00logwatch\n"
            "\n> Hinweis: systemd-journald wird nicht neu installiert "
            f"(Basis-Infrastruktur); persistentes Journal wird unter "
            f"{cls.JOURNAL_DIR} abgelegt. auditd-Regeln mit -e 2 (Immutable) "
            "greifen erst nach dem nächsten Reboot.\n"
        )

    def _validate(self) -> None:
        """Prüft alle Konfigurationswerte, die in Befehle oder Dateien gehen.

        Raises:
            ModuleError: Wenn fqdn keine Domain erkennen lässt oder
                unzulässige Zeichen enthält, admin_mail keine gültige
                Adresse ist, oder journald_max_use/journald_max_retention
                nicht dem jeweiligen systemd-Muster entsprechen.
        """
        if not _FQDN_CHARS_RE.match(self.fqdn):
            raise ModuleError(f"fqdn enthält unzulässige Zeichen: {self.fqdn!r}")
        if not self._mailfrom():
            raise ModuleError(f"Aus fqdn ist keine Domain ableitbar: {self.fqdn!r}")
        if not _EMAIL_RE.match(self.admin_mail):
            raise ModuleError(f"Ungültige admin_mail: {self.admin_mail!r}")
        if not _JOURNALD_SIZE_RE.match(self.journald_max_use):
            raise ModuleError(f"Ungültiges journald_max_use: {self.journald_max_use!r}")
        if not _JOURNALD_RETENTION_RE.match(self.journald_max_retention):
            raise ModuleError(
                f"Ungültiges journald_max_retention: {self.journald_max_retention!r}"
            )

    def _mailfrom(self) -> str:
        """Leitet den Logwatch-Absender root@<domain> aus fqdn ab.

        Returns:
            "root@<domain>", oder leer, wenn fqdn keinen Punkt enthält.
        """
        _, sep, domain = self.fqdn.partition(".")
        if not sep:
            return ""
        return f"root@{domain}"

    def _logwatch_directives(self, mailfrom: str) -> list[tuple[str, str]]:
        """Baut die Soll-Direktiven der logwatch-Konfiguration.

        Args:
            mailfrom: Absender-Adresse (Rückgabe von _mailfrom()).

        Returns:
            Liste aus (Schlüssel, Wert)-Paaren in fester Reihenfolge.
        """
        return [
            ("Output", "mail"),
            ("Format", "text"),
            ("Detail", "Med"),
            ("Range", "yesterday"),
            ("MailTo", self.admin_mail),
            ("MailFrom", mailfrom),
        ]

    def _install(self) -> int:
        """Richtet Protokollierung und Auditing ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        mailfrom = self._mailfrom()
        steps: list[tuple[str, Action]] = [
            (
                "journald Storage setzen",
                LineInFileAction(
                    path=self.JOURNALD_CONF,
                    line="Storage=persistent",
                    match=r"^#?\s*Storage\s*=",
                ),
            ),
            (
                "journald SystemMaxUse setzen",
                LineInFileAction(
                    path=self.JOURNALD_CONF,
                    line=f"SystemMaxUse={self.journald_max_use}",
                    match=r"^#?\s*SystemMaxUse\s*=",
                ),
            ),
            (
                "journald MaxRetentionSec setzen",
                LineInFileAction(
                    path=self.JOURNALD_CONF,
                    line=f"MaxRetentionSec={self.journald_max_retention}",
                    match=r"^#?\s*MaxRetentionSec\s*=",
                ),
            ),
            (
                "systemd-journald neu starten",
                self.SYSTEMD_ACTION_CLS(
                    operation="restart", unit="systemd-journald", timeout=30
                ),
            ),
            (
                "logwatch installieren",
                self.APT_ACTION_CLS(packages=["logwatch"]),
            ),
        ]
        if not Path(self.LOGWATCH_CONF).exists():
            steps.append(
                (
                    "logwatch-Konfig anlegen",
                    WriteFileAction(
                        dst=self.LOGWATCH_CONF,
                        content="",
                        mode=0o644,
                        overwrite=False,
                        safe_mode=False,
                    ),
                )
            )
        for key, value in self._logwatch_directives(mailfrom):
            steps.append(
                (
                    f"logwatch {key} setzen",
                    LineInFileAction(
                        path=self.LOGWATCH_CONF,
                        line=f"{key} = {value}",
                        match=rf"^\s*{key}\s*=",
                    ),
                )
            )
        steps += [
            (
                "logrotate-Konfig schreiben",
                WriteFileAction(
                    dst=self.LOGROTATE_CONF,
                    content=_logrotate_content(),
                    mode=0o644,
                    overwrite=True,
                    # kein safe_mode: eine .bak-Sicherung würde von
                    # logrotates Include-Glob mitgelesen (doppelter Eintrag).
                    safe_mode=False,
                ),
            ),
            (
                "sudo-Protokollierung einrichten",
                WriteFileAction(
                    dst=self.SUDOLOG_CONF,
                    content=_sudolog_content(),
                    mode=0o440,
                    overwrite=True,
                    safe_mode=False,
                ),
            ),
            (
                "auditd installieren",
                self.APT_ACTION_CLS(packages=["auditd"]),
            ),
            (
                "Audit-Regeln schreiben",
                WriteFileAction(
                    dst=self.AUDIT_RULES_FILE,
                    content=_audit_rules_content(),
                    mode=0o640,
                    overwrite=True,
                    safe_mode=False,
                ),
            ),
            (
                "auditd aktivieren",
                self.SYSTEMD_ACTION_CLS(operation="enable", unit="auditd", timeout=60),
            ),
            (
                "auditd starten",
                self.SYSTEMD_ACTION_CLS(operation="start", unit="auditd", timeout=60),
            ),
        ]
        for label, action in steps:
            self.send_message(LogLevel.INFO, "logging", label)
            if self.run_action(action) != 0:
                self.send_message(LogLevel.ERROR, "logging", f"fehlgeschlagen: {label}")
                return 1
            if label == "Audit-Regeln schreiben":
                self.send_message(
                    LogLevel.WARN,
                    "logging",
                    "Immutable (-e 2) gesetzt — neue Regeln greifen erst nach "
                    "einem Neustart.",
                )
        return 0

    def _uninstall(self) -> int:
        """Nimmt die eigenen Änderungen von _install zurück.

        systemd-journald bleibt bestehen (Basis-Infrastruktur) — nur die
        eigenen Direktiven werden zurückgenommen. logwatch und auditd
        werden nur entfernt, wenn sie installiert sind (wie im
        Bash-Original). /var/log/sudo.log bleibt als Datensicherung
        erhalten.

        Schrittliste mit Abbruch beim ersten Fehler (wie _install). Jeder
        Schritt ist idempotent: bereits Zurückgenommenes ist kein Fehler.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, _Step]] = [
            ("journald-Direktiven zurücknehmen", self._step_remove_journald),
            ("logwatch entfernen", self._step_remove_logwatch),
            ("logrotate-Konfig entfernen", self._step_remove_logrotate),
            ("Audit-Regeln entfernen", self._step_remove_audit_rules),
            ("sudo-Protokollierung entfernen", self._step_remove_sudolog),
            ("auditd entfernen", self._step_remove_auditd),
        ]
        for label, step in steps:
            self.send_message(LogLevel.INFO, "logging", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "logging", f"fehlgeschlagen: {label}")
                return 1
        self.send_message(
            LogLevel.WARN,
            "logging",
            "/var/log/sudo.log bleibt erhalten (Audit-Datensicherung) — bei Bedarf"
            " manuell entfernen.",
        )
        return 0

    def _step_remove_journald(self) -> int:
        """Nimmt die journald-Direktiven zurück und startet den Dienst neu.

        Returns:
            0 bei Erfolg oder wenn journald.conf bereits fehlt, sonst 1.
        """
        if not Path(self.JOURNALD_CONF).exists():
            self.send_message(
                LogLevel.INFO,
                "logging",
                f"{self.JOURNALD_CONF} nicht vorhanden — keine journald-Reverts nötig",
            )
            return 0
        for key in ("Storage", "SystemMaxUse", "MaxRetentionSec"):
            action = LineInFileAction(
                path=self.JOURNALD_CONF,
                line="",
                match=rf"^#?\s*{key}\s*=",
                state="absent",
            )
            if self.run_action(action) != 0:
                return 1
        return self.run_action(
            self.SYSTEMD_ACTION_CLS(
                operation="restart", unit="systemd-journald", timeout=30
            )
        )

    def _step_remove_logwatch(self) -> int:
        """Nimmt die logwatch-Konfiguration zurück und entfernt das Paket.

        logwatch hat keinen eigenen Dienst (Lauf via cron.daily) — kein
        Dienst-Stopp nötig.

        Returns:
            0 bei Erfolg oder wenn logwatch nicht installiert ist, sonst 1.
        """
        if not self._package_installed("logwatch"):
            self.send_message(
                LogLevel.INFO,
                "logging",
                "Paket logwatch nicht installiert — nichts zu entfernen",
            )
            return 0
        if Path(self.LOGWATCH_CONF).exists():
            for key, _ in self._logwatch_directives(""):
                action = LineInFileAction(
                    path=self.LOGWATCH_CONF,
                    line="",
                    match=rf"^\s*{key}\s*=",
                    state="absent",
                )
                if self.run_action(action) != 0:
                    return 1
        return self.run_action(
            self.APT_ACTION_CLS(packages=["logwatch"], state="absent")
        )

    def _step_remove_logrotate(self) -> int:
        """Entfernt die logrotate-Konfiguration für das secure-base-Logfile.

        Returns:
            0 bei Erfolg oder wenn die Datei bereits fehlt, sonst 1.
        """
        return self._remove_file_if_exists(self.LOGROTATE_CONF)

    def _step_remove_audit_rules(self) -> int:
        """Entfernt die Audit-Regeldatei.

        Returns:
            0 bei Erfolg oder wenn die Datei bereits fehlt, sonst 1.
        """
        return self._remove_file_if_exists(self.AUDIT_RULES_FILE)

    def _step_remove_sudolog(self) -> int:
        """Entfernt die sudo-Protokollierungs-Konfiguration.

        Returns:
            0 bei Erfolg oder wenn die Datei bereits fehlt, sonst 1.
        """
        return self._remove_file_if_exists(self.SUDOLOG_CONF)

    def _remove_file_if_exists(self, path: str) -> int:
        """Löscht path ohne Sicherung, falls vorhanden; idempotent.

        Args:
            path: Zu entfernende Datei.

        Returns:
            0 bei Erfolg oder wenn path bereits fehlt, sonst 1.
        """
        if not Path(path).exists():
            self.send_message(
                LogLevel.INFO, "logging", f"{path} nicht vorhanden — übersprungen"
            )
            return 0
        return self.run_action(DeleteFileAction(path=path, safe_mode=False))

    def _step_remove_auditd(self) -> int:
        """Stoppt, deaktiviert und entfernt auditd, sofern installiert.

        Returns:
            0 bei Erfolg oder wenn auditd nicht installiert ist, sonst 1.
        """
        if not self._package_installed("auditd"):
            self.send_message(
                LogLevel.INFO,
                "logging",
                "Paket auditd nicht installiert — nichts zu entfernen",
            )
            return 0
        if self.run_action(
            self.SYSTEMD_ACTION_CLS(operation="stop", unit="auditd", timeout=60)
        ):
            return 1
        if self.run_action(
            self.SYSTEMD_ACTION_CLS(operation="disable", unit="auditd", timeout=60)
        ):
            return 1
        return self.run_action(self.APT_ACTION_CLS(packages=["auditd"], state="absent"))

    def _package_installed(self, package: str) -> bool:
        """Prüft still über dpkg, ob package installiert ist.

        Dient als Vorbedingung für Rückbau-Schritte — anders als
        _check_installed erzeugt diese Methode keine Meldung, da sie kein
        Prüfergebnis, sondern nur eine Ablaufentscheidung liefert.

        Args:
            package: Paketname.

        Returns:
            True, wenn dpkg den Status "install ok installed" meldet.
        """
        action = SysCmdAction(command=[self.DPKG_BIN, "-s", package], timeout=15)
        try:
            action.run()
        except ActionError:
            return False
        return "Status: install ok installed" in action.stdout

    def _test(self) -> int:
        """Führt den Funktionstest ohne Systemänderung aus.

        Weist die journald-Persistenz nach und verschickt probeweise den
        logwatch-Report per Mail (echter Versand über das postfix-Relay).
        Sammelt beide Prüfungen; bricht nicht bei der ersten
        fehlgeschlagenen Prüfung ab.

        Returns:
            0, wenn beide Prüfungen erfolgreich waren, sonst 1.
        """
        ok = True
        ok &= self._test_journald_persistence()
        ok &= self._test_logwatch_report()
        return 0 if ok else 1

    def _test_journald_persistence(self) -> bool:
        """Weist die journald-Persistenz über journalctl --header nach.

        Returns:
            True bei erfolgreichem journalctl-Lauf und vorhandenem
            JOURNAL_DIR, sonst False.
        """
        action = SysCmdAction(command=[self.JOURNALCTL_BIN, "--header"], timeout=15)
        result = self.run_action(action)
        for line in action.stdout.splitlines():
            self.send_message(LogLevel.INFO, "logging", f"journald: {line}")
        if result == 0 and Path(self.JOURNAL_DIR).is_dir():
            self.send_message(
                LogLevel.INFO,
                "logging",
                f"journald-Persistenz nachgewiesen ({self.JOURNAL_DIR} vorhanden)",
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "logging",
            f"journald-Persistenz nicht nachweisbar (journalctl rc={result}, "
            f"{self.JOURNAL_DIR} "
            f"{'vorhanden' if Path(self.JOURNAL_DIR).is_dir() else 'fehlt'})",
        )
        return False

    def _test_logwatch_report(self) -> bool:
        """Verschickt den logwatch-Report probeweise per Mail.

        Returns:
            True, wenn logwatch installiert ist und der Versand gelang,
            sonst False.
        """
        if not self._check_installed("logwatch", "Paket logwatch"):
            return False
        action = SysCmdAction(
            command=[
                self.LOGWATCH_BIN,
                "--output",
                "mail",
                "--format",
                "text",
                "--range",
                "yesterday",
                "--detail",
                "Med",
            ],
            timeout=self.LOGWATCH_TEST_TIMEOUT,
        )
        result = self.run_action(action)
        for line in action.stdout.splitlines():
            self.send_message(LogLevel.INFO, "logging", f"logwatch: {line}")
        if result != 0:
            self.send_message(
                LogLevel.ERROR,
                "logging",
                f"logwatch-Mailversand fehlgeschlagen: {action.stderr.strip()}",
            )
            return False
        self.send_message(
            LogLevel.INFO,
            "logging",
            f"logwatch-Report abgesetzt — Eingang bei {self.admin_mail} prüfen",
        )
        return True

    def _verify(self) -> int:
        """Gleicht die eigenen install-Wirkungen mit dem Soll ab.

        Prüft nur, ob die Schritte aus _install gewirkt haben — kein
        allgemeiner System-Audit.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        mailfrom = self._mailfrom()
        ok = True
        ok &= self._check_file_line(
            self.JOURNALD_CONF, "Storage=persistent", "journald Storage"
        )
        ok &= self._check_file_line(
            self.JOURNALD_CONF,
            f"SystemMaxUse={self.journald_max_use}",
            "journald SystemMaxUse",
        )
        ok &= self._check_file_line(
            self.JOURNALD_CONF,
            f"MaxRetentionSec={self.journald_max_retention}",
            "journald MaxRetentionSec",
        )
        ok &= self._check_dir_exists(self.JOURNAL_DIR, "journald-Persistenzverzeichnis")
        ok &= self._check_installed("logwatch", "Paket logwatch")
        for key, value in self._logwatch_directives(mailfrom):
            ok &= self._check_file_line(
                self.LOGWATCH_CONF, f"{key} = {value}", f"logwatch {key}"
            )
        ok &= self._check_file_exists(self.LOGROTATE_CONF, "logrotate-Konfig")
        ok &= self._check_installed("auditd", "Paket auditd")
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", "--", "auditd"], "active", "auditd-Dienst"
        )
        for rule in AUDIT_RULES:
            ok &= self._check_file_line(
                self.AUDIT_RULES_FILE, rule, f"Audit-Regel {rule}"
            )
        ok &= self._check_file_line(
            self.SUDOLOG_CONF,
            'Defaults logfile="/var/log/sudo.log"',
            "sudo-Protokollierung",
        )
        return 0 if ok else 1

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
            self.send_message(LogLevel.ERROR, "logging", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "logging", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "logging", f"{label}: ist {current}, soll {expected}"
        )
        return False

    def _check_file_line(self, path: str, expected_line: str, label: str) -> bool:
        """Prüft, ob expected_line unverändert in der Datei path vorkommt.

        Args:
            path: Zu lesende Datei.
            expected_line: Erwartete Zeile (ohne Zeilenumbruch).
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn die Zeile vorkommt, sonst False.
        """
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError:
            self.send_message(
                LogLevel.ERROR, "logging", f"{label}: Datei nicht lesbar ({path})"
            )
            return False
        if expected_line in lines:
            self.send_message(LogLevel.INFO, "logging", f"{label}: gesetzt — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "logging", f"{label}: nicht gesetzt (soll: {expected_line})"
        )
        return False

    def _check_file_exists(self, path: str, label: str) -> bool:
        """Prüft, ob path als Datei existiert.

        Args:
            path: Zu prüfender Pfad.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn path eine Datei ist, sonst False.
        """
        if Path(path).is_file():
            self.send_message(LogLevel.INFO, "logging", f"{label}: vorhanden — OK")
            return True
        self.send_message(LogLevel.ERROR, "logging", f"{label}: fehlt ({path})")
        return False

    def _check_dir_exists(self, path: str, label: str) -> bool:
        """Prüft, ob path als Verzeichnis existiert.

        Args:
            path: Zu prüfender Pfad.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn path ein Verzeichnis ist, sonst False.
        """
        if Path(path).is_dir():
            self.send_message(LogLevel.INFO, "logging", f"{label}: vorhanden — OK")
            return True
        self.send_message(LogLevel.ERROR, "logging", f"{label}: fehlt ({path})")
        return False

    def _check_installed(self, package: str, label: str) -> bool:
        """Prüft über dpkg, ob package installiert ist.

        Args:
            package: Paketname.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn dpkg den Status "install ok installed" meldet.
        """
        action = SysCmdAction(command=[self.DPKG_BIN, "-s", package], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "logging", f"{label}: nicht installiert")
            return False
        if "Status: install ok installed" in action.stdout:
            self.send_message(LogLevel.INFO, "logging", f"{label}: installiert — OK")
            return True
        self.send_message(LogLevel.ERROR, "logging", f"{label}: nicht installiert")
        return False
