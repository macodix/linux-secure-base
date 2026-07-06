"""Modul base — Grundkonfiguration des Systems.

Setzt Rechnername, Zeitzone, NTP, sysctl-Härtung, Kernel-Modul-Sperrliste,
autofs-Maskierung und AppArmor. Betriebsart über den Schlüssel operation.
"""

import re
from typing import ClassVar
from zoneinfo import available_timezones

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Rechnername nach RFC 1123: Labels aus a-z, 0-9 und Bindestrich, nicht am
# Rand; Gesamtlänge höchstens 253 Zeichen.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Kernel-Härtung nach konv-system.md Abschnitt 3.9.
SYSCTL_PARAMS = (
    ("kernel.randomize_va_space", "2"),
    ("kernel.kptr_restrict", "2"),
    ("kernel.dmesg_restrict", "1"),
    ("kernel.yama.ptrace_scope", "1"),
)


def _sysctl_content() -> str:
    """Baut den Inhalt der sysctl-Datei."""
    head = (
        "# Von secure-base/base angelegt — nicht von Hand bearbeiten.\n"
        "# Kernel-Härtung nach konv-system.md Abschnitt 3.9.\n"
    )
    body = "".join(f"{key} = {value}\n" for key, value in SYSCTL_PARAMS)
    return head + body


def _modprobe_content() -> str:
    """Baut den Inhalt der Kernel-Modul-Sperrliste."""
    return (
        "# Von secure-base/base angelegt — nicht von Hand bearbeiten.\n"
        "# USB-Storage-Sperre nach konv-system.md Abschnitt 3.1 c.\n"
        "install usb-storage /bin/true\n"
        "blacklist usb-storage\n"
    )


class Base(Module):
    """Grundkonfiguration des Systems über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = ["operation", "fqdn", "timezone"]

    # Programmpfade und Schreibziele als Klassenattribute statt Literale in
    # den Schritten: feste, sichere Vorgaben, die im Auslieferungsbaum nie
    # von außen (Umgebung, Konfiguration) überschrieben werden. Eine
    # Testunterklasse außerhalb dieses Moduls kann sie überschreiben, um
    # Systembefehle in einem echten Modul-Subprozess durch harmlose
    # Platzhalter zu ersetzen (Plan Abschnitt 2.12) — ohne dieses Modul
    # anzufassen und ohne jeden Laufzeit-Schalter in Produktionscode.
    HOSTNAMECTL: ClassVar[str] = "/usr/bin/hostnamectl"
    HOSTNAME_BIN: ClassVar[str] = "/usr/bin/hostname"
    TIMEDATECTL: ClassVar[str] = "/usr/bin/timedatectl"
    SYSCTL_BIN: ClassVar[str] = "/usr/sbin/sysctl"
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"
    SYSCTL_CONF: ClassVar[str] = "/etc/sysctl.d/60-secure-base.conf"
    MODPROBE_CONF: ClassVar[str] = "/etc/modprobe.d/secure-base-blacklist.conf"

    # AppArmor-Aktionsklassen ebenso als Klassenattribute; Vorgabe sind
    # immer die echten, härtenden Aktionen. Kein Laufzeit-Schalter kann sie
    # abschalten — eine Testunterklasse müsste sie im Testbaum gezielt auf
    # eine eigene Unterklasse von AptAction/SystemdServiceAction setzen.
    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    fqdn: str
    timezone: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem fqdn oder unbekannter timezone.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        return self._install()

    def _validate(self) -> None:
        """Prüft fqdn und timezone und lehnt ungültige Werte ab.

        Beide Werte gehen in Systembefehle. SysCmdAction hat bewusst keinen
        Optionsterminator, deshalb prüft das Modul die Werte vor der
        Verwendung (konv-scripting-python.md Abschnitt 4.2).

        Raises:
            ModuleError: Wenn fqdn kein gültiger Rechnername ist oder
                timezone nicht in der tzdata-Liste steht.
        """
        if not _HOSTNAME_RE.match(self.fqdn):
            raise ModuleError(f"Ungültiger Rechnername: {self.fqdn!r}")
        if self.timezone not in available_timezones():
            raise ModuleError(f"Unbekannte Zeitzone: {self.timezone!r}")

    def _install(self) -> int:
        """Richtet die Grundkonfiguration ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, Action]] = [
            (
                "Rechnername setzen",
                SysCmdAction(
                    command=[self.HOSTNAMECTL, "set-hostname", self.fqdn], timeout=30
                ),
            ),
            (
                "Zeitzone setzen",
                SysCmdAction(
                    command=[self.TIMEDATECTL, "set-timezone", self.timezone],
                    timeout=30,
                ),
            ),
            (
                "NTP aktivieren",
                SysCmdAction(command=[self.TIMEDATECTL, "set-ntp", "true"], timeout=30),
            ),
            (
                "sysctl schreiben",
                WriteFileAction(
                    dst=self.SYSCTL_CONF,
                    content=_sysctl_content(),
                    mode=0o644,
                    overwrite=True,
                ),
            ),
            (
                "sysctl anwenden",
                SysCmdAction(
                    command=[self.SYSCTL_BIN, "-p", self.SYSCTL_CONF], timeout=30
                ),
            ),
            (
                "Modul-Sperrliste schreiben",
                WriteFileAction(
                    dst=self.MODPROBE_CONF,
                    content=_modprobe_content(),
                    mode=0o644,
                    overwrite=True,
                ),
            ),
            (
                "autofs maskieren",
                SysCmdAction(
                    command=[self.SYSTEMCTL_BIN, "mask", "autofs"], timeout=30
                ),
            ),
            (
                "AppArmor installieren",
                self.APT_ACTION_CLS(packages=["apparmor", "apparmor-utils"]),
            ),
            (
                "AppArmor aktivieren",
                self.SYSTEMD_ACTION_CLS(
                    operation="enable", unit="apparmor", timeout=60
                ),
            ),
            (
                "AppArmor starten",
                self.SYSTEMD_ACTION_CLS(operation="start", unit="apparmor", timeout=60),
            ),
        ]
        for label, action in steps:
            self.send_message(LogLevel.INFO, "base", label)
            if self.run_action(action) != 0:
                self.send_message(LogLevel.ERROR, "base", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit dem Soll ab.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_value([self.HOSTNAME_BIN], self.fqdn, "Rechnername")
        ok &= self._check_value(
            [self.TIMEDATECTL, "show", "-p", "Timezone", "--value"],
            self.timezone,
            "Zeitzone",
        )
        ok &= self._check_value(
            [self.TIMEDATECTL, "show", "-p", "NTPSynchronized", "--value"],
            "yes",
            "NTP-Synchronisation",
        )
        for key, value in SYSCTL_PARAMS:
            ok &= self._check_value(
                [self.SYSCTL_BIN, "-n", key], value, f"sysctl {key}"
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
            self.send_message(LogLevel.ERROR, "base", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "base", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "base", f"{label}: ist {current}, soll {expected}"
        )
        return False
