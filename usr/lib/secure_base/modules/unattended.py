"""Modul unattended — automatisierte Sicherheitsupdates.

Aktualisiert den Paketstand, installiert und härtet unattended-upgrades
(Allowed-Origins, automatischer Reboot, Mail-Report) sowie zwei
gepinnte systemd-Timer-Overrides (apt-daily / apt-daily-upgrade), damit
der Upgrade-Lauf vor dem Reboot greift. Betriebsart über den Schlüssel
operation.
"""

import re
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Kontrollierter PATH für apt-get-Aufrufe außerhalb der AptAction (SIC-06).
_CONTROLLED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

# Mail-Adresse nach demselben Muster wie das Bash-Original.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")

# Grobe Plausibilität einer HH:MM-Uhrzeit (24h, anchored).
_HHMM_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")

# Aktiver Allowed-Origins-Block. ${distro_id}/${distro_codename} sind
# woertlicher apt.conf-Text, keine Python-Platzhalter — deshalb als
# gewöhnliche Zeichenkette, nicht als f-string.
_ALLOWED_ORIGINS_BLOCK = (
    "Unattended-Upgrade::Allowed-Origins {\n"
    '    "${distro_id}:${distro_codename}";\n'
    '    "${distro_id}:${distro_codename}-security";\n'
    '    "${distro_id}:${distro_codename}-updates";\n'
    "};\n"
)


def _uu_conf_content(admin_mail: str, auto_reboot: str, auto_reboot_time: str) -> str:
    """Baut den Inhalt von 50unattended-upgrades."""
    head = "# Von secure-base/unattended angelegt — nicht von Hand bearbeiten.\n"
    directives = (
        f'Unattended-Upgrade::Automatic-Reboot "{auto_reboot}";\n'
        f'Unattended-Upgrade::Automatic-Reboot-Time "{auto_reboot_time}";\n'
        f'Unattended-Upgrade::Mail "{admin_mail}";\n'
        'Unattended-Upgrade::MailReport "only-on-error";\n'
    )
    return head + _ALLOWED_ORIGINS_BLOCK + directives


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
        return self._install()

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

    def _install(self) -> int:
        """Aktualisiert den Paketstand und richtet unattended-upgrades ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt oder wenn
            danach ein Neustart aussteht.
        """
        env = {
            "DEBIAN_FRONTEND": "noninteractive",
            "NEEDRESTART_SUSPEND": "1",
            "PATH": _CONTROLLED_PATH,
        }
        reboot_flag = "true" if self.auto_reboot == "yes" else "false"
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
                        self.admin_mail, reboot_flag, self.auto_reboot_time
                    ),
                    mode=0o644,
                    overwrite=True,
                ),
            ),
            (
                "20auto-upgrades schreiben",
                WriteFileAction(
                    dst=self.PERIODIC_CONF,
                    content=_periodic_conf_content(),
                    mode=0o644,
                    overwrite=True,
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

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit dem Soll ab.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_command_succeeds(
            [self.DPKG_BIN, "-s", "unattended-upgrades"],
            "Paket unattended-upgrades installiert",
        )
        reboot_flag = "true" if self.auto_reboot == "yes" else "false"
        ok &= self._check_file_content(
            self.UU_CONF,
            _uu_conf_content(self.admin_mail, reboot_flag, self.auto_reboot_time),
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
