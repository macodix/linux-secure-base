"""Modul unattended — automatisierte Sicherheitsupdates.

Aktualisiert den Paketstand, installiert und härtet unattended-upgrades
(erlaubte Paketquellen, automatischer Reboot, Mail-Report) sowie zwei
gepinnte systemd-Timer-Overrides (apt-daily / apt-daily-upgrade), damit
der Upgrade-Lauf vor dem Reboot greift. Betriebsart über den Schlüssel
operation.

Die erlaubten Paketquellen sind der einzige distributionsabhängige Teil:
Ubuntu und Debian benennen ihre Archive verschieden, und die beiden Formate
sind nicht ineinander überführbar (siehe UBUNTU_ORIGINS_BLOCK und
DEBIAN_ORIGINS_BLOCK). Welcher Block gilt, entscheidet secure_base.distro.
"""

import contextlib
import re
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

from secure_base.distro import DEBIAN, OS_RELEASE_FILE, distro_id

# Kontrollierter PATH für apt-get-Aufrufe außerhalb der AptAction (SIC-06).
_CONTROLLED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

# Mail-Adresse nach demselben Muster wie das Bash-Original.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")

# Grobe Plausibilität einer HH:MM-Uhrzeit (24h, anchored).
_HHMM_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")

# Erlaubte Paketquellen unter Ubuntu. Die Kurzform Allowed-Origins vergleicht
# "Origin:Archiv"; unter Ubuntu trägt jedes Archiv den Codenamen als Suite
# (resolute, resolute-security, resolute-updates), die Kurzform trifft also.
# ${distro_id}/${distro_codename} sind wörtlicher apt.conf-Text, keine
# Python-Platzhalter — deshalb gewöhnliche Zeichenketten, keine f-strings.
UBUNTU_ORIGINS_BLOCK = (
    "Unattended-Upgrade::Allowed-Origins {\n"
    '    "${distro_id}:${distro_codename}";\n'
    '    "${distro_id}:${distro_codename}-security";\n'
    '    "${distro_id}:${distro_codename}-updates";\n'
    "};\n"
)

# Erlaubte Paketquellen unter Debian. Die Kurzform ist hier unbrauchbar: Debian
# führt als Suite "stable" bzw. "stable-security", nicht den Codenamen — der
# Vergleich träfe nichts, und der Server liefe ohne Sicherheitsupdates weiter,
# ohne Fehlermeldung. Origins-Pattern vergleicht stattdessen die Felder der
# Release-Dateien einzeln (belegt aus den Archiv-Release-Dateien: Hauptarchiv
# origin=Debian/label=Debian/codename=trixie, Sicherheitsarchiv
# label=Debian-Security/codename=trixie-security, Updates label=Debian/
# codename=trixie-updates).
DEBIAN_ORIGINS_BLOCK = (
    "Unattended-Upgrade::Origins-Pattern {\n"
    '    "origin=Debian,codename=${distro_codename},label=Debian";\n'
    '    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";\n'
    '    "origin=Debian,codename=${distro_codename}-updates,label=Debian";\n'
    "};\n"
)


def _uu_conf_content(
    admin_mail: str, auto_reboot: str, auto_reboot_time: str, origins_block: str
) -> str:
    """Baut den Inhalt von 50unattended-upgrades.

    Args:
        admin_mail: Empfänger des Fehlerberichts.
        auto_reboot: "true" oder "false".
        auto_reboot_time: Uhrzeit des automatischen Neustarts (HH:MM).
        origins_block: Block der erlaubten Paketquellen der Distribution.

    Returns:
        Vollständiger Dateiinhalt.
    """
    head = "# Von secure-base/unattended angelegt — nicht von Hand bearbeiten.\n"
    directives = (
        f'Unattended-Upgrade::Automatic-Reboot "{auto_reboot}";\n'
        f'Unattended-Upgrade::Automatic-Reboot-Time "{auto_reboot_time}";\n'
        f'Unattended-Upgrade::Mail "{admin_mail}";\n'
        'Unattended-Upgrade::MailReport "only-on-error";\n'
    )
    return head + origins_block + directives


def _periodic_conf_content() -> str:
    """Baut den Inhalt von 20auto-upgrades."""
    return (
        "# Von secure-base/unattended angelegt — nicht von Hand bearbeiten.\n"
        'APT::Periodic::Update-Package-Lists "1";\n'
        'APT::Periodic::Unattended-Upgrade "1";\n'
        'APT::Periodic::AutocleanInterval "7";\n'
    )


def _timer_override_content(hhmm: str) -> str:
    """Baut den Inhalt eines systemd-Timer-Drop-ins mit gepinnter Uhrzeit."""
    return (
        "# Von secure-base/unattended angelegt — nicht von Hand bearbeiten.\n"
        "[Timer]\n"
        "OnCalendar=\n"
        f"OnCalendar=*-*-* {hhmm}:00\n"
        "RandomizedDelaySec=0\n"
    )


def _doc_value(values: dict[str, str], key: str) -> str:
    """Liest einen Wert für den Installationsbericht aus values.

    doc() fragt hier ausschließlich die vier Reboot-/Zeitplan-Schlüssel ab
    (auto_reboot, auto_reboot_time, apt_daily_time, apt_daily_upgrade_time)
    — admin_mail und jedes Geheimnis werden nie über diesen Weg gelesen.

    Args:
        values: Konfigurationswerte des Moduls.
        key: Abzufragender Schlüssel.

    Returns:
        Wert aus values, oder "(leer/Default)" wenn leer oder nicht gesetzt.
    """
    return values.get(key) or "(leer/Default)"


class Unattended(Module):
    """Automatisierte Sicherheitsupdates über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "admin_mail",
        "auto_reboot",
        "auto_reboot_time",
        "apt_daily_time",
        "apt_daily_upgrade_time",
    ]

    # Programmpfade und Schreibziele als Klassenattribute (siehe base.py):
    # feste Vorgaben, im Auslieferungsbaum nie von außen überschrieben; eine
    # Testunterklasse kann sie außerhalb dieses Moduls umlenken.
    APT_GET_BIN: ClassVar[str] = "/usr/bin/apt-get"
    DPKG_BIN: ClassVar[str] = "/usr/bin/dpkg"
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"
    UNATTENDED_UPGRADE_BIN: ClassVar[str] = "/usr/bin/unattended-upgrade"
    UU_CONF: ClassVar[str] = "/etc/apt/apt.conf.d/50unattended-upgrades"
    PERIODIC_CONF: ClassVar[str] = "/etc/apt/apt.conf.d/20auto-upgrades"
    DAILY_DROPIN: ClassVar[str] = (
        "/etc/systemd/system/apt-daily.timer.d/secure-base.conf"
    )
    UPGRADE_DROPIN: ClassVar[str] = (
        "/etc/systemd/system/apt-daily-upgrade.timer.d/secure-base.conf"
    )
    REBOOT_REQUIRED_FILE: ClassVar[str] = "/var/run/reboot-required"
    REBOOT_REQUIRED_PKGS_FILE: ClassVar[str] = "/var/run/reboot-required.pkgs"
    # Quelle der Distributionskennung; wie die Pfade oben testumlenkbar.
    OS_RELEASE: ClassVar[str] = OS_RELEASE_FILE

    # Zeitgrenzen für die Betriebsart test (SIC-05); als Klassenattribute
    # testbar wie die Programmpfade oben.
    DRY_RUN_TIMEOUT: ClassVar[float] = 300.0
    LIST_TIMERS_TIMEOUT: ClassVar[float] = 15.0

    # apt-/systemd-Aktionsklassen ebenso als Klassenattribute; Vorgabe sind
    # immer die echten Aktionen (siehe base.py).
    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    admin_mail: str
    auto_reboot: str
    auto_reboot_time: str
    apt_daily_time: str
    apt_daily_upgrade_time: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültiger admin_mail, auto_reboot oder einer
                der drei Uhrzeiten.
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

        SICHERHEIT: liest ausschließlich die fünf unkritischen Schlüssel
        unten aus values; Geheimnisse erscheinen hier nie, auch wenn sie
        in values stünden.

        Args:
            values: Konfigurationswerte des Moduls (admin_mail,
                auto_reboot, auto_reboot_time, apt_daily_time,
                apt_daily_upgrade_time, …).

        Returns:
            Markdown-Abschnitt, beginnend mit
            "## Automatische Sicherheitsupdates".
        """
        admin_mail = _doc_value(values, "admin_mail")
        auto_reboot = _doc_value(values, "auto_reboot")
        auto_reboot_time = _doc_value(values, "auto_reboot_time")
        apt_daily_time = _doc_value(values, "apt_daily_time")
        apt_daily_upgrade_time = _doc_value(values, "apt_daily_upgrade_time")
        return (
            "\n## Automatische Sicherheitsupdates\n\n"
            "**Pakete:** unattended-upgrades\n\n"
            "**Dateien/Einstellungen:**\n\n"
            f"- `{cls.UU_CONF}`:\n"
            f"  - `Automatic-Reboot = {auto_reboot}`\n"
            f"  - `Automatic-Reboot-Time = {auto_reboot_time}`\n"
            f"  - `Mail = {admin_mail} (only-on-error)`\n"
            f"- `{cls.PERIODIC_CONF}`:\n"
            "  - `APT::Periodic::Update-Package-Lists = 1`\n"
            "  - `APT::Periodic::Unattended-Upgrade = 1`\n"
            f"- `{cls.DAILY_DROPIN}`:\n"
            f"  - `OnCalendar = {apt_daily_time}`\n"
            f"- `{cls.UPGRADE_DROPIN}`:\n"
            f"  - `OnCalendar = {apt_daily_upgrade_time}`\n"
            "\n**Timer/Cron:** apt-daily.timer und apt-daily-upgrade.timer"
            " (systemd) mit konfigurierten Uhrzeiten\n"
        )

    def _validate(self) -> None:
        """Prüft admin_mail, auto_reboot und die drei Uhrzeiten.

        Alle vier gehen in Systembefehle bzw. Dateiinhalte. SysCmdAction hat
        bewusst keinen Optionsterminator, deshalb prüft das Modul die Werte
        vor der Verwendung (konv-scripting-python.md Abschnitt 4.2).

        Raises:
            ModuleError: Wenn admin_mail keine gültige Mail-Adresse ist,
                auto_reboot nicht "yes"/"no" ist, oder eine Uhrzeit nicht
                dem Muster HH:MM entspricht.
        """
        if not _EMAIL_RE.match(self.admin_mail):
            raise ModuleError(f"Ungültige admin_mail-Adresse: {self.admin_mail!r}")
        if self.auto_reboot not in ("yes", "no"):
            raise ModuleError(
                f"auto_reboot muss 'yes' oder 'no' sein: {self.auto_reboot!r}"
            )
        for name, value in (
            ("auto_reboot_time", self.auto_reboot_time),
            ("apt_daily_time", self.apt_daily_time),
            ("apt_daily_upgrade_time", self.apt_daily_upgrade_time),
        ):
            if not _HHMM_RE.match(value):
                raise ModuleError(f"{name} ist keine gültige Uhrzeit HH:MM: {value!r}")
        if (
            not self.apt_daily_time
            < self.apt_daily_upgrade_time
            < self.auto_reboot_time
        ):
            self.send_message(
                LogLevel.WARN,
                "unattended",
                "Uhrzeiten nicht in Reihenfolge apt_daily_time < "
                "apt_daily_upgrade_time < auto_reboot_time — Updates könnten "
                "nach dem Reboot laufen.",
            )

    def _origins_block(self) -> str:
        """Liefert den Block der erlaubten Paketquellen der laufenden Distribution.

        Returns:
            DEBIAN_ORIGINS_BLOCK unter Debian, sonst UBUNTU_ORIGINS_BLOCK.

        Raises:
            ModuleError: Wenn die Distribution nicht unterstützt wird.
        """
        current = distro_id(self.OS_RELEASE)
        if current == DEBIAN:
            return DEBIAN_ORIGINS_BLOCK
        return UBUNTU_ORIGINS_BLOCK

    def _install(self) -> int:
        """Aktualisiert den Paketstand und richtet unattended-upgrades ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt oder wenn
            danach ein Neustart aussteht.

        Raises:
            ModuleError: Wenn die Distribution nicht unterstützt wird.
        """
        env = {
            "DEBIAN_FRONTEND": "noninteractive",
            "NEEDRESTART_SUSPEND": "1",
            "PATH": _CONTROLLED_PATH,
        }
        reboot_flag = "true" if self.auto_reboot == "yes" else "false"
        origins_block = self._origins_block()
        steps: list[tuple[str, Action]] = [
            (
                "Paketindex aktualisieren",
                SysCmdAction(
                    command=[self.APT_GET_BIN, "update"], timeout=120, env=env
                ),
            ),
            (
                "Vorhandene Updates einspielen",
                SysCmdAction(
                    command=[self.APT_GET_BIN, "-y", "upgrade"], timeout=900, env=env
                ),
            ),
            (
                "unattended-upgrades installieren",
                self.APT_ACTION_CLS(packages=["unattended-upgrades"]),
            ),
            (
                "50unattended-upgrades schreiben",
                WriteFileAction(
                    dst=self.UU_CONF,
                    content=_uu_conf_content(
                        self.admin_mail,
                        reboot_flag,
                        self.auto_reboot_time,
                        origins_block,
                    ),
                    mode=0o644,
                    overwrite=True,
                    # kein safe_mode: eine .bak-Sicherung würde von apts
                    # Include-Glob in apt.conf.d mitgelesen und dessen
                    # lexikalisch spätere Version die neue Datei überstimmen.
                    safe_mode=False,
                ),
            ),
            (
                "20auto-upgrades schreiben",
                WriteFileAction(
                    dst=self.PERIODIC_CONF,
                    content=_periodic_conf_content(),
                    mode=0o644,
                    overwrite=True,
                    # kein safe_mode: eine .bak-Sicherung würde von apts
                    # Include-Glob in apt.conf.d mitgelesen und dessen
                    # lexikalisch spätere Version die neue Datei überstimmen.
                    safe_mode=False,
                ),
            ),
            (
                "Verzeichnis für apt-daily-Override anlegen",
                MakeDirAction(
                    path=str(Path(self.DAILY_DROPIN).parent), mode=0o755, parents=True
                ),
            ),
            (
                "apt-daily-Override schreiben",
                WriteFileAction(
                    dst=self.DAILY_DROPIN,
                    content=_timer_override_content(self.apt_daily_time),
                    mode=0o644,
                    overwrite=True,
                    safe_mode=False,
                ),
            ),
            (
                "Verzeichnis für apt-daily-upgrade-Override anlegen",
                MakeDirAction(
                    path=str(Path(self.UPGRADE_DROPIN).parent),
                    mode=0o755,
                    parents=True,
                ),
            ),
            (
                "apt-daily-upgrade-Override schreiben",
                WriteFileAction(
                    dst=self.UPGRADE_DROPIN,
                    content=_timer_override_content(self.apt_daily_upgrade_time),
                    mode=0o644,
                    overwrite=True,
                    safe_mode=False,
                ),
            ),
            (
                "systemd neu laden",
                self.SYSTEMD_ACTION_CLS(operation="daemon-reload", timeout=60),
            ),
            (
                "apt-daily.timer neu starten",
                self.SYSTEMD_ACTION_CLS(
                    operation="restart", unit="apt-daily.timer", timeout=60
                ),
            ),
            (
                "apt-daily-upgrade.timer neu starten",
                self.SYSTEMD_ACTION_CLS(
                    operation="restart", unit="apt-daily-upgrade.timer", timeout=60
                ),
            ),
        ]
        for label, action in steps:
            self.send_message(LogLevel.INFO, "unattended", label)
            if self.run_action(action) != 0:
                self.send_message(
                    LogLevel.ERROR, "unattended", f"fehlgeschlagen: {label}"
                )
                return 1
        return self._check_reboot_required()

    def _check_reboot_required(self) -> int:
        """Meldet, falls das Upgrade neustartpflichtige Pakete aktualisiert hat.

        Returns:
            0, wenn kein Neustart aussteht, sonst 1.
        """
        flag = Path(self.REBOOT_REQUIRED_FILE)
        if not flag.exists():
            return 0
        self.send_message(
            LogLevel.WARN,
            "unattended",
            "Neustart erforderlich: Upgrade hat neustartpflichtige Pakete"
            " aktualisiert.",
        )
        pkgs = Path(self.REBOOT_REQUIRED_PKGS_FILE)
        if pkgs.exists():
            for line in sorted(pkgs.read_text().splitlines()):
                if line:
                    self.send_message(
                        LogLevel.INFO, "unattended", f"neustartpflichtig: {line}"
                    )
        return 1

    def _uninstall(self) -> int:
        """Baut die Einrichtung zurück: eigene Dateien, Timer-Overrides, Paket.

        apt-daily.timer und apt-daily-upgrade.timer selbst gehören zum
        Distro-Standard und werden nicht deaktiviert — nur die eigenen
        Drop-in-Overrides. 50unattended-upgrades und 20auto-upgrades werden
        von _install vollständig geschrieben (kein zeilenweises Patchen wie
        im Bash-Original), deshalb entfernt der Rückbau hier die ganze
        Datei statt einzelner Einstellungen. Läuft idempotent: bereits
        entfernte Dateien werden ohne Fehler übersprungen.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, Action]] = []
        any_dropin = False
        for label, path in (
            ("apt-daily-Override entfernen", self.DAILY_DROPIN),
            ("apt-daily-upgrade-Override entfernen", self.UPGRADE_DROPIN),
        ):
            if Path(path).exists():
                steps.append((label, DeleteFileAction(path=path, safe_mode=False)))
                any_dropin = True
        if any_dropin:
            steps += [
                (
                    "systemd neu laden",
                    self.SYSTEMD_ACTION_CLS(operation="daemon-reload", timeout=60),
                ),
                (
                    "apt-daily.timer neu starten",
                    self.SYSTEMD_ACTION_CLS(
                        operation="restart", unit="apt-daily.timer", timeout=60
                    ),
                ),
                (
                    "apt-daily-upgrade.timer neu starten",
                    self.SYSTEMD_ACTION_CLS(
                        operation="restart", unit="apt-daily-upgrade.timer", timeout=60
                    ),
                ),
            ]
        for label, path in (
            ("50unattended-upgrades entfernen", self.UU_CONF),
            ("20auto-upgrades entfernen", self.PERIODIC_CONF),
        ):
            if Path(path).exists():
                steps.append((label, DeleteFileAction(path=path, safe_mode=False)))
        if self._package_installed():
            steps.append(
                (
                    "Paket unattended-upgrades entfernen",
                    self.APT_ACTION_CLS(
                        packages=["unattended-upgrades"], state="absent"
                    ),
                )
            )
        else:
            self.send_message(
                LogLevel.INFO,
                "unattended",
                "Paket unattended-upgrades nicht installiert — nichts zu entfernen",
            )
        for label, action in steps:
            self.send_message(LogLevel.INFO, "unattended", label)
            if self.run_action(action) != 0:
                self.send_message(
                    LogLevel.ERROR, "unattended", f"fehlgeschlagen: {label}"
                )
                return 1
        self._cleanup_empty_dropin_dirs()
        return 0

    def _cleanup_empty_dropin_dirs(self) -> None:
        """Entfernt die Timer-Override-Verzeichnisse, wenn sie jetzt leer sind.

        Best-effort wie im Bash-Original (rmdir auf einem nicht-leeren oder
        nicht vorhandenen Verzeichnis schlägt fehl und wird ignoriert) —
        kein Abbruchkriterium für _uninstall.
        """
        for path in (self.DAILY_DROPIN, self.UPGRADE_DROPIN):
            with contextlib.suppress(OSError):
                Path(path).parent.rmdir()

    def _package_installed(self) -> bool:
        """Prüft per dpkg, ob unattended-upgrades installiert ist.

        Returns:
            True, wenn das Paket installiert ist, sonst False.
        """
        action = SysCmdAction(
            command=[self.DPKG_BIN, "-s", "unattended-upgrades"], timeout=15
        )
        return self.run_action(action) == 0

    def _test(self) -> int:
        """Weist die Funktionsfähigkeit nach, ohne das System zu ändern.

        Führt einen Trockenlauf von unattended-upgrade aus (simuliert nur;
        installiert nichts, rebootet nicht) und protokolliert nachrichtlich
        die nächsten geplanten Timer-Auslösungen. Sammelt beide Ergebnisse,
        ohne beim ersten Fehler abzubrechen; die Timer-Auflistung ist rein
        informativ und beeinflusst den Rückgabewert nicht (wie im
        Bash-Original).

        Returns:
            0, wenn der Trockenlauf erfolgreich war, sonst 1.
        """
        ok = self._test_dry_run()
        self._log_timers()
        return 0 if ok else 1

    def _test_dry_run(self) -> bool:
        """Weist per Trockenlauf nach, dass unattended-upgrade das Soll annimmt.

        Returns:
            True, wenn das Paket installiert ist und der Trockenlauf mit
            Returncode 0 endet, sonst False.
        """
        if not self._package_installed():
            self.send_message(
                LogLevel.ERROR,
                "unattended",
                "test: Paket unattended-upgrades nicht installiert — kein"
                " Funktionstest möglich",
            )
            return False
        self.send_message(
            LogLevel.INFO,
            "unattended",
            "test: unattended-upgrade --dry-run --debug (simuliert,"
            " installiert nichts, rebootet nicht)",
        )
        action = SysCmdAction(
            command=[self.UNATTENDED_UPGRADE_BIN, "--dry-run", "--debug"],
            timeout=self.DRY_RUN_TIMEOUT,
        )
        ok = self.run_action(action) == 0
        for line in (action.stdout + action.stderr).splitlines():
            if line:
                self.send_message(
                    LogLevel.INFO, "unattended", f"unattended-upgrade: {line}"
                )
        if ok:
            self.send_message(
                LogLevel.INFO,
                "unattended",
                "test: Trockenlauf erfolgreich — Konfiguration wird von"
                " unattended-upgrade akzeptiert",
            )
        else:
            self.send_message(
                LogLevel.ERROR,
                "unattended",
                "test: unattended-upgrade --dry-run fehlgeschlagen",
            )
        return ok

    def _log_timers(self) -> None:
        """Protokolliert die nächsten geplanten Auslösungen beider Timer.

        Rein informativ (wie im Bash-Original) — ein Fehler hier
        beeinflusst das Testergebnis nicht.
        """
        self.send_message(
            LogLevel.INFO, "unattended", "test: nächste geplante Timer-Auslösungen:"
        )
        action = SysCmdAction(
            command=[
                self.SYSTEMCTL_BIN,
                "list-timers",
                "apt-daily.timer",
                "apt-daily-upgrade.timer",
                "--no-pager",
            ],
            timeout=self.LIST_TIMERS_TIMEOUT,
        )
        if self.run_action(action) != 0:
            self.send_message(
                LogLevel.ERROR, "unattended", "test: list-timers nicht lesbar"
            )
            return
        for line in action.stdout.splitlines():
            if line:
                self.send_message(LogLevel.INFO, "unattended", f"list-timers: {line}")

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit dem Soll ab.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.

        Raises:
            ModuleError: Wenn die Distribution nicht unterstützt wird.
        """
        ok = True
        ok &= self._check_command_succeeds(
            [self.DPKG_BIN, "-s", "unattended-upgrades"],
            "Paket unattended-upgrades installiert",
        )
        reboot_flag = "true" if self.auto_reboot == "yes" else "false"
        ok &= self._check_file_content(
            self.UU_CONF,
            _uu_conf_content(
                self.admin_mail,
                reboot_flag,
                self.auto_reboot_time,
                self._origins_block(),
            ),
            "50unattended-upgrades",
        )
        ok &= self._check_file_content(
            self.PERIODIC_CONF, _periodic_conf_content(), "20auto-upgrades"
        )
        ok &= self._check_file_content(
            self.DAILY_DROPIN,
            _timer_override_content(self.apt_daily_time),
            "apt-daily-Override",
        )
        ok &= self._check_file_content(
            self.UPGRADE_DROPIN,
            _timer_override_content(self.apt_daily_upgrade_time),
            "apt-daily-upgrade-Override",
        )
        return 0 if ok else 1

    def _check_command_succeeds(self, command: list[str], label: str) -> bool:
        """Führt einen Befehl aus und wertet nur dessen Erfolg.

        Args:
            command: Auszuführender Befehl.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn der Befehl erfolgreich endet, sonst False.
        """
        action = SysCmdAction(command=command, timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "unattended", f"{label}: nicht erfüllt")
            return False
        self.send_message(LogLevel.INFO, "unattended", f"{label}: OK")
        return True

    def _check_file_content(self, path: str, expected: str, label: str) -> bool:
        """Vergleicht den Inhalt einer Datei mit dem Soll-Inhalt.

        Args:
            path: Zu lesende Datei.
            expected: Soll-Inhalt.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        try:
            current = Path(path).read_text()
        except OSError:
            self.send_message(LogLevel.ERROR, "unattended", f"{label}: nicht lesbar")
            return False
        if current == expected:
            self.send_message(LogLevel.INFO, "unattended", f"{label}: OK")
            return True
        self.send_message(
            LogLevel.ERROR, "unattended", f"{label}: Inhalt weicht vom Soll ab"
        )
        return False
