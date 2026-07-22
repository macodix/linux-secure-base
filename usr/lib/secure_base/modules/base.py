"""Modul base — Grundkonfiguration des Systems.

Setzt Rechnername, Zeitzone, NTP, sysctl-Härtung, Kernel-Modul-Sperrliste,
autofs-Maskierung und AppArmor. Betriebsart über den Schlüssel operation.
"""

import contextlib
import re
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar
from zoneinfo import available_timezones

from pifos.actions.apt_action import AptAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

from secure_base.managed_write import ManagedFile, ManagedWriteMixin

_Step = Callable[[], int]

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
        "# Von secure-base/base angelegt (wird bei erneutem Installer-Lauf"
        " überschrieben).\n"
        "# Kernel-Härtung nach konv-system.md Abschnitt 3.9.\n"
    )
    body = "".join(f"{key} = {value}\n" for key, value in SYSCTL_PARAMS)
    return head + body


def _modprobe_content() -> str:
    """Baut den Inhalt der Kernel-Modul-Sperrliste."""
    return (
        "# Von secure-base/base angelegt (wird bei erneutem Installer-Lauf"
        " überschrieben).\n"
        "# USB-Storage-Sperre nach konv-system.md Abschnitt 3.1 c.\n"
        "install usb-storage /bin/true\n"
        "blacklist usb-storage\n"
    )


def _content_lines(content: str) -> list[str]:
    """Filtert Kommentar- und Leerzeilen aus einem Dateiinhalt heraus.

    Args:
        content: Dateiinhalt, wie von _sysctl_content/_modprobe_content gebaut.

    Returns:
        Die reinen Einstellungszeilen ohne Kommentare/Leerzeilen.
    """
    return [line for line in content.splitlines() if line and not line.startswith("#")]


def _doc_file(path: str, lines: list[str]) -> str:
    """Baut einen Markdown-Dateieintrag mit eingerückten Einstellungszeilen.

    Args:
        path: Pfad der Datei.
        lines: Einstellungszeilen, die eingerückt unter dem Pfad erscheinen.

    Returns:
        Markdown-Textblock für diese Datei.
    """
    entry = f"- `{path}`:\n"
    entry += "".join(f"  - `{line}`\n" for line in lines)
    return entry


class Base(ManagedWriteMixin, Module):
    """Grundkonfiguration des Systems über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "fqdn",
        "timezone",
        "force_overwrite",
        "backup_run_dir",
    ]

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

    # Für AppArmor installierte Pakete — eigenes Klassenattribut, damit
    # _install und doc() dieselbe Liste verwenden (keine doppelte Pflege).
    APPARMOR_PACKAGES: ClassVar[tuple[str, ...]] = ("apparmor", "apparmor-utils")

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
        if self.operation == "preflight":
            return self.preflight_managed("base")
        if self.operation == "check":
            return self._verify()
        if self.operation == "uninstall":
            return self._uninstall()
        if self.operation == "test":
            return self._test()
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
        steps: list[tuple[str, _Step]] = [
            (
                "Rechnername setzen",
                lambda: self.run_action(
                    SysCmdAction(
                        command=[self.HOSTNAMECTL, "set-hostname", self.fqdn],
                        timeout=30,
                    )
                ),
            ),
            (
                "Zeitzone setzen",
                lambda: self.run_action(
                    SysCmdAction(
                        command=[self.TIMEDATECTL, "set-timezone", self.timezone],
                        timeout=30,
                    )
                ),
            ),
            (
                "NTP aktivieren",
                lambda: self.run_action(
                    SysCmdAction(
                        command=[self.TIMEDATECTL, "set-ntp", "true"], timeout=30
                    )
                ),
            ),
            ("sysctl schreiben", self._step_write_sysctl),
            (
                "sysctl anwenden",
                lambda: self.run_action(
                    SysCmdAction(
                        command=[self.SYSCTL_BIN, "-p", self.SYSCTL_CONF], timeout=30
                    )
                ),
            ),
            ("Modul-Sperrliste schreiben", self._step_write_modprobe),
            (
                "autofs maskieren",
                lambda: self.run_action(
                    SysCmdAction(
                        command=[self.SYSTEMCTL_BIN, "mask", "autofs"], timeout=30
                    )
                ),
            ),
            (
                "AppArmor installieren",
                lambda: self.run_action(
                    self.APT_ACTION_CLS(packages=list(self.APPARMOR_PACKAGES))
                ),
            ),
            (
                "AppArmor aktivieren",
                lambda: self.run_action(
                    self.SYSTEMD_ACTION_CLS(
                        operation="enable", unit="apparmor", timeout=60
                    )
                ),
            ),
            (
                "AppArmor starten",
                lambda: self.run_action(
                    self.SYSTEMD_ACTION_CLS(
                        operation="start", unit="apparmor", timeout=60
                    )
                ),
            ),
        ]
        for label, step in steps:
            self.send_message(LogLevel.INFO, "base", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "base", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _managed_files(self) -> list[ManagedFile]:
        """Deklariert sysctl- und modprobe-Drop-in als verwaltete Ziele."""
        return [
            ManagedFile(dst=self.SYSCTL_CONF, content=_sysctl_content(), mode=0o644),
            ManagedFile(
                dst=self.MODPROBE_CONF, content=_modprobe_content(), mode=0o644
            ),
        ]

    def _step_write_sysctl(self) -> int:
        """Schreibt die sysctl-Härtungsdatei (vollständig eigene Datei, 0644)."""
        return self.write_managed("base", self._managed_files()[0])

    def _step_write_modprobe(self) -> int:
        """Schreibt die Kernel-Modul-Sperrliste (vollständig eigene Datei, 0644)."""
        return self.write_managed("base", self._managed_files()[1])

    # --- uninstall ---

    def _uninstall(self) -> int:
        """Nimmt die eigenen Änderungen von _install zurück.

        Rechnername, Zeitzone und Paketstand bleiben unverändert (wie im
        Bash-Original: dort nur informativ ausgegeben, nicht revidiert).
        AppArmor bleibt installiert und aktiv — Basis-Infrastruktur, die
        das Original beim Rückbau bewusst nicht entfernt. Zurückgenommen
        werden nur die eigenen Dateien (sysctl-Härtung, Modul-Sperrliste)
        und die autofs-Maskierung.

        Schrittliste mit Abbruch beim ersten Fehler (wie _install). Jeder
        Schritt ist idempotent: bereits Zurückgenommenes ist kein Fehler.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        self.send_message(
            LogLevel.INFO,
            "base",
            "Rechnername, Zeitzone und Paketstand werden nicht zurückgesetzt",
        )
        steps: list[tuple[str, _Step]] = [
            ("sysctl-Härtung entfernen", self._step_remove_sysctl_conf),
            ("Modul-Sperrliste entfernen", self._step_remove_modprobe_conf),
            ("autofs-Maskierung aufheben", self._step_unmask_autofs),
        ]
        for label, step in steps:
            self.send_message(LogLevel.INFO, "base", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "base", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _step_remove_sysctl_conf(self) -> int:
        """Entfernt die sysctl-Härtungsdatei und wendet die Systemwerte neu an.

        Returns:
            0 bei Erfolg oder wenn die Datei bereits entfernt ist, sonst 1.
        """
        if not Path(self.SYSCTL_CONF).exists():
            self.send_message(
                LogLevel.INFO, "base", "sysctl-Härtungsdatei bereits entfernt"
            )
            return 0
        if self.run_action(DeleteFileAction(path=self.SYSCTL_CONF, safe_mode=False)):
            return 1
        return self.run_action(
            SysCmdAction(command=[self.SYSCTL_BIN, "--system"], timeout=30)
        )

    def _step_remove_modprobe_conf(self) -> int:
        """Entfernt die Kernel-Modul-Sperrliste.

        Returns:
            0 bei Erfolg oder wenn die Datei bereits entfernt ist, sonst 1.
        """
        if not Path(self.MODPROBE_CONF).exists():
            self.send_message(
                LogLevel.INFO, "base", "Modul-Sperrliste bereits entfernt"
            )
            return 0
        return self.run_action(
            DeleteFileAction(path=self.MODPROBE_CONF, safe_mode=False)
        )

    def _step_unmask_autofs(self) -> int:
        """Hebt die autofs-Maskierung auf, sofern sie aktuell gesetzt ist.

        systemctl is-enabled meldet den Zustand "masked" mit Returncode
        ungleich 0 — das ist die normale Zustandsauskunft, kein Fehler;
        deshalb direkter Aufruf statt run_action.

        Returns:
            0 bei Erfolg oder wenn autofs nicht maskiert ist, sonst 1.
        """
        state = self._systemctl_is_enabled("autofs")
        if state != "masked":
            self.send_message(
                LogLevel.INFO,
                "base",
                f"autofs nicht maskiert (ist: {state or 'unbekannt'})",
            )
            return 0
        return self.run_action(
            SysCmdAction(command=[self.SYSTEMCTL_BIN, "unmask", "autofs"], timeout=30)
        )

    def _systemctl_is_enabled(self, unit: str) -> str:
        """Liest den is-enabled-Zustand einer systemd-Einheit.

        Args:
            unit: Name der Einheit.

        Returns:
            Zustand laut systemctl (z. B. "masked", "disabled") oder eine
            leere Zeichenkette, wenn er nicht lesbar ist.
        """
        action = SysCmdAction(
            command=[self.SYSTEMCTL_BIN, "is-enabled", unit], timeout=15
        )
        with contextlib.suppress(ActionError):
            action.run()
        return action.stdout.strip()

    # --- check ---

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
        ok &= self.check_managed("base")
        return 0 if ok else 1

    # --- test ---

    def _test(self) -> int:
        """Funktionstest ohne jede Systemänderung.

        Das Bash-Original definiert für base keinen eigenständigen
        Funktionstest: Rechnername und Zeitzone sind statische
        Konfigurationswerte, deren Soll-Ist-Abgleich bereits _verify
        (Betriebsart check) leistet. _test meldet das und schließt ohne
        eigene Prüfung erfolgreich ab — keine Prüfungen zum Sammeln.

        Returns:
            0 (immer — keine eigene Prüfung definiert).
        """
        self.send_message(
            LogLevel.INFO,
            "base",
            "Kein eigenständiger Funktionstest für base definiert"
            " — check deckt den Soll-Ist-Abgleich ab",
        )
        return 0

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

    # --- doc ---

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Baut den Markdown-Abschnitt dieses Moduls für den Installationsbericht.

        Reine Textmontage: kein Dateizugriff, kein Prozessaufruf, keine
        Uhrzeitabfrage. Liest ausschließlich die für dieses Modul
        dokumentierten Konfigurationswerte fqdn und timezone aus values
        (Whitelist-Prinzip). Geheimniswerte (z. B. relay_password,
        main_user_password, restic_passphrase, TOTP-Werte) werden nie
        gelesen oder ausgegeben, selbst wenn sie in values stehen.

        Args:
            values: Konfigurationswerte des Laufs (Schlüssel wie in CONFIG).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Grundkonfiguration".
        """
        fqdn = values.get("fqdn", "") or "(leer/Default)"
        timezone = values.get("timezone", "") or "(leer/Default)"
        pakete = ", ".join(cls.APPARMOR_PACKAGES)
        sysctl_lines = _content_lines(_sysctl_content())
        modprobe_lines = _content_lines(_modprobe_content())

        return "".join(
            [
                "\n## Grundkonfiguration\n\n",
                f"**Hostname:** `{fqdn}`\n\n",
                f"**Zeitzone:** `{timezone}`\n\n",
                f"**Pakete:** {pakete}\n\n",
                "**Dateien/Einstellungen:**\n\n",
                _doc_file(cls.SYSCTL_CONF, sysctl_lines),
                _doc_file(cls.MODPROBE_CONF, modprobe_lines),
                "\n> Hinweis: NTP-Zeitsynchronisation via systemd-timesyncd"
                " aktiviert (timedatectl set-ntp true, konv-system.md"
                " Abschnitt 3.5 b). sysctl-Härtung nach konv-system.md"
                " Abschnitt 3.9. USB-Storage-Sperre nach konv-system.md"
                " Abschnitt 3.1 c. autofs maskiert (systemctl mask autofs,"
                " konv-system.md Abschnitt 3.1 d). AppArmor-Dienst aktiv"
                f" (konv-system.md Abschnitt 3.10 b): {pakete} installiert,"
                " Dienst enabled. Soll-Teilerfüllung mit Begründung"
                " (qm-richtlinien.md Kapitel 5): sshd hat kein"
                " mitgeliefertes AppArmor-Profil; seine Eindämmung erfolgt"
                " über den restriktiven Paketfilter (ufw) und die"
                " SSH-Härtung. Ein eigenes sshd-Profil wird bewusst nicht"
                " erstellt (Aussperr-Risiko).\n",
            ]
        )
