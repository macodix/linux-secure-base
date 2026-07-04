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

SYSCTL_CONF = "/etc/sysctl.d/60-secure-base.conf"
MODPROBE_CONF = "/etc/modprobe.d/secure-base-blacklist.conf"

# Programmpfade als Konstanten (statt Literale in den Schritten), damit
# Tests die Systembefehle durch harmlose Platzhalter ersetzen können
# (Plan Abschnitt 2.12), ohne echte Systembefehle auszuführen.
HOSTNAMECTL = "/usr/bin/hostnamectl"
HOSTNAME_BIN = "/usr/bin/hostname"
TIMEDATECTL = "/usr/bin/timedatectl"
SYSCTL_BIN = "/usr/sbin/sysctl"
SYSTEMCTL_BIN = "/usr/bin/systemctl"

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
        "# Von lsb/base angelegt — nicht von Hand bearbeiten.\n"
        "# Kernel-Härtung nach konv-system.md Abschnitt 3.9.\n"
    )
    body = "".join(f"{key} = {value}\n" for key, value in SYSCTL_PARAMS)
    return head + body


def _modprobe_content() -> str:
    """Baut den Inhalt der Kernel-Modul-Sperrliste."""
    return (
        "# Von lsb/base angelegt — nicht von Hand bearbeiten.\n"
        "# USB-Storage-Sperre nach konv-system.md Abschnitt 3.1 c.\n"
        "install usb-storage /bin/true\n"
        "blacklist usb-storage\n"
    )


class Base(Module):
    """Grundkonfiguration des Systems über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = ["operation", "fqdn", "timezone"]

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
                    command=[HOSTNAMECTL, "set-hostname", self.fqdn], timeout=30
                ),
            ),
            (
                "Zeitzone setzen",
                SysCmdAction(
                    command=[TIMEDATECTL, "set-timezone", self.timezone], timeout=30
                ),
            ),
            (
                "NTP aktivieren",
                SysCmdAction(command=[TIMEDATECTL, "set-ntp", "true"], timeout=30),
            ),
            (
                "sysctl schreiben",
                WriteFileAction(
                    dst=SYSCTL_CONF,
                    content=_sysctl_content(),
                    mode=0o644,
                    overwrite=True,
                ),
            ),
            (
                "sysctl anwenden",
                SysCmdAction(command=[SYSCTL_BIN, "-p", SYSCTL_CONF], timeout=30),
            ),
            (
                "Modul-Sperrliste schreiben",
                WriteFileAction(
                    dst=MODPROBE_CONF,
                    content=_modprobe_content(),
                    mode=0o644,
                    overwrite=True,
                ),
            ),
            (
                "autofs maskieren",
                SysCmdAction(command=[SYSTEMCTL_BIN, "mask", "autofs"], timeout=30),
            ),
            (
                "AppArmor installieren",
                AptAction(packages=["apparmor", "apparmor-utils"]),
            ),
            (
                "AppArmor aktivieren",
                SystemdServiceAction(operation="enable", unit="apparmor", timeout=60),
            ),
            (
                "AppArmor starten",
                SystemdServiceAction(operation="start", unit="apparmor", timeout=60),
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
        ok &= self._check_value([HOSTNAME_BIN], self.fqdn, "Rechnername")
        ok &= self._check_value(
            [TIMEDATECTL, "show", "-p", "Timezone", "--value"],
            self.timezone,
            "Zeitzone",
        )
        ok &= self._check_value(
            [TIMEDATECTL, "show", "-p", "NTPSynchronized", "--value"],
            "yes",
            "NTP-Synchronisation",
        )
        for key, value in SYSCTL_PARAMS:
            ok &= self._check_value([SYSCTL_BIN, "-n", key], value, f"sysctl {key}")
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
