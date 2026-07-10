"""Modul fail2ban — Brute-Force-Schutz für SSH.

Installiert fail2ban, schützt die Konfiguration per jail.local-Kopie vor
Überschreiben bei Paket-Updates, setzt optional eine ignoreip-Whitelist
und aktiviert den Dienst. Betriebsart über den Schlüssel operation.
"""

import ipaddress
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.copy_file_action import CopyFileAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Loopback-Adressen, die im ignoreip-Wert immer erhalten bleiben.
IGNOREIP_LOOPBACK: tuple[str, ...] = ("127.0.0.1/8", "::1")


def _parse_ignoreip(raw: str) -> list[str]:
    """Zerlegt den ignoreip-Konfigurationswert in einzelne Tokens.

    Args:
        raw: Kommagetrennter Konfigurationswert; kann leer sein.

    Returns:
        Getrimmte, nicht-leere Tokens in Eingabereihenfolge.
    """
    return [tok.strip() for tok in raw.split(",") if tok.strip()]


def _effective_ignoreip(tokens: list[str]) -> str:
    """Baut den vollständigen ignoreip-Wert aus Loopback-Defaults und Tokens.

    Args:
        tokens: Zusätzliche IP-/CIDR-Tokens.

    Returns:
        Leerzeichengetrennter Wert für die ignoreip-Direktive.
    """
    return " ".join([*IGNOREIP_LOOPBACK, *tokens])


class Fail2ban(Module):
    """Brute-Force-Schutz für SSH über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = ["operation", "ignoreip"]

    # Programmpfade und Schreibziele als Klassenattribute statt Literale in
    # den Schritten (siehe Modul base): feste Vorgaben, die eine
    # Testunterklasse außerhalb dieses Moduls umlenken kann, ohne das Modul
    # anzufassen.
    JAIL_CONF: ClassVar[str] = "/etc/fail2ban/jail.conf"
    JAIL_LOCAL: ClassVar[str] = "/etc/fail2ban/jail.local"
    DPKG_QUERY: ClassVar[str] = "/usr/bin/dpkg-query"
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"
    FAIL2BAN_CLIENT: ClassVar[str] = "/usr/bin/fail2ban-client"

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    ignoreip: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem ignoreip-Eintrag.
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

        SICHERHEIT: values wird ausschließlich nach dem Schlüssel ignoreip
        abgefragt (kein Secret) — jeder andere Schlüssel in values bleibt
        unberücksichtigt und erscheint nicht in der Ausgabe.

        Args:
            values: Konfigurationswerte des Moduls (u. a. ignoreip).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Brute-Force-Schutz".
        """
        ignoreip = values.get("ignoreip") or "(leer/Default)"
        loopback = " ".join(IGNOREIP_LOOPBACK)
        return (
            "\n## Brute-Force-Schutz\n\n"
            "**Pakete:** fail2ban\n\n"
            "**Dateien/Einstellungen:**\n\n"
            f"- `{cls.JAIL_LOCAL}`:\n"
            "  - `Kopie von jail.conf (schützt Konfig gegen Updates)`\n"
            f"  - `ignoreip = {loopback} {ignoreip}`\n"
            "\n**Dienste:** fail2ban (enabled, aktiv nach install)\n"
            "\n> Hinweis: sshd-Jail ist in der Standardkonfiguration aktiv.\n"
        )

    def _validate(self) -> None:
        """Prüft jedes ignoreip-Token und lehnt ungültige Werte ab.

        ignoreip geht in eine Konfigurationsdatei und in Befehlsargumente.
        Die Prüfung mit dem ipaddress-Modul erfolgt vor jeder Verwendung
        (konv-scripting-python.md Abschnitt 4.2).

        Raises:
            ModuleError: Wenn ein Token keine gültige IPv4-/IPv6-Adresse
                oder kein gültiges CIDR-Netz ist.
        """
        for token in _parse_ignoreip(self.ignoreip):
            try:
                ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ModuleError(f"Ungültiger ignoreip-Eintrag: {token!r}") from exc

    def _install(self) -> int:
        """Installiert fail2ban und richtet die Konfiguration ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        tokens = _parse_ignoreip(self.ignoreip)
        steps: list[tuple[str, Action]] = [
            ("Paket installieren", self.APT_ACTION_CLS(packages=["fail2ban"])),
        ]

        if Path(self.JAIL_LOCAL).exists():
            self.send_message(
                LogLevel.INFO,
                "fail2ban",
                f"{self.JAIL_LOCAL} bereits vorhanden — Kopie übersprungen"
                " (hand-getunte jail.local wird nicht überschrieben)",
            )
        else:
            steps.append(
                (
                    "jail.local anlegen",
                    CopyFileAction(src=self.JAIL_CONF, dst=self.JAIL_LOCAL),
                )
            )

        if tokens:
            steps.append(
                (
                    "ignoreip-Whitelist setzen",
                    LineInFileAction(
                        path=self.JAIL_LOCAL,
                        line=f"ignoreip = {_effective_ignoreip(tokens)}",
                        match=r"^ignoreip\s*=",
                    ),
                )
            )
        else:
            self.send_message(
                LogLevel.INFO,
                "fail2ban",
                "ignoreip leer — keine Anpassung, es gilt der jail.local-Default",
            )

        steps.append(
            (
                "Dienst aktivieren",
                self.SYSTEMD_ACTION_CLS(
                    operation="enable", unit="fail2ban", timeout=60
                ),
            )
        )
        steps.append(
            (
                "Dienst starten",
                self.SYSTEMD_ACTION_CLS(operation="start", unit="fail2ban", timeout=60),
            )
        )

        for label, action in steps:
            self.send_message(LogLevel.INFO, "fail2ban", label)
            if self.run_action(action) != 0:
                self.send_message(
                    LogLevel.ERROR, "fail2ban", f"fehlgeschlagen: {label}"
                )
                return 1

        if tokens:
            self.send_message(
                LogLevel.INFO,
                "fail2ban",
                "aktiv mit ignoreip-Whitelist — Admin-IP vom Bannen ausgenommen",
            )
        else:
            self.send_message(
                LogLevel.WARN,
                "fail2ban",
                "aktiv ohne ignoreip-Whitelist — der sshd-Jail kann die eigene"
                " Admin-IP nach wiederholten Fehl-Logins sperren; ignoreip"
                " in der Konfiguration setzen",
            )
        return 0

    def _uninstall(self) -> int:
        """Nimmt die install-Eingriffe zurück und entfernt das Paket.

        Nach do_uninstall des Originals: ist das Paket nicht installiert,
        ist idempotent nichts zu tun. Sonst Dienst stoppen und deaktivieren,
        den ignoreip-Eingriff in jail.local zurücknehmen (die Datei selbst
        bleibt erhalten) und das Paket ohne --purge entfernen (Datenbank
        und Restkonfiguration bleiben liegen).

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        if not self._package_installed():
            self.send_message(
                LogLevel.INFO,
                "fail2ban",
                "Paket fail2ban nicht installiert — nichts zu tun",
            )
            return 0

        steps: list[tuple[str, Action]] = [
            (
                "Dienst stoppen",
                self.SYSTEMD_ACTION_CLS(operation="stop", unit="fail2ban", timeout=60),
            ),
            (
                "Dienst deaktivieren",
                self.SYSTEMD_ACTION_CLS(
                    operation="disable", unit="fail2ban", timeout=60
                ),
            ),
        ]
        if Path(self.JAIL_LOCAL).exists():
            steps.append(
                (
                    "ignoreip-Eingriff zurücknehmen",
                    LineInFileAction(
                        path=self.JAIL_LOCAL,
                        line="",
                        match=r"^ignoreip\s*=",
                        state="absent",
                    ),
                )
            )
        steps.append(
            (
                "Paket entfernen",
                self.APT_ACTION_CLS(packages=["fail2ban"], state="absent"),
            )
        )

        for label, action in steps:
            self.send_message(LogLevel.INFO, "fail2ban", label)
            if self.run_action(action) != 0:
                self.send_message(
                    LogLevel.ERROR, "fail2ban", f"fehlgeschlagen: {label}"
                )
                return 1
        return 0

    def _test(self) -> int:
        """Funktionstest ohne Systemänderung nach do_test des Originals.

        Prüft den Daemon per Ping und den sshd-Jail-Status; sammelt beide
        Ergebnisse, ohne beim ersten Fehler abzubrechen. Ohne installiertes
        Paket ist kein Test möglich.

        Returns:
            0 bei bestandenem Test, sonst 1.
        """
        if not self._package_installed():
            self.send_message(
                LogLevel.ERROR,
                "fail2ban",
                "Paket fail2ban nicht installiert — kein Funktionstest möglich",
            )
            return 1

        ok = True
        ok &= self._check_daemon_ping()
        ok &= self._check_jail_status_lines()
        return 0 if ok else 1

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit den eigenen install-Aktionen ab.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_package_installed()
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", "fail2ban"], "active", "Dienst aktiv"
        )
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-enabled", "fail2ban"],
            "enabled",
            "Dienst enabled",
        )
        ok &= self._check_jail_local_exists()

        tokens = _parse_ignoreip(self.ignoreip)
        if tokens:
            ok &= self._check_ignoreip_in_file(tokens)
            ok &= self._check_ignoreip_loaded(tokens)

        ok &= self._check_command_ok(
            [self.FAIL2BAN_CLIENT, "status", "sshd"], "sshd-Jail abfragbar"
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
            self.send_message(LogLevel.ERROR, "fail2ban", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "fail2ban", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "fail2ban", f"{label}: ist {current}, soll {expected}"
        )
        return False

    def _check_command_ok(self, command: list[str], label: str) -> bool:
        """Prüft, ob ein Befehl mit Exit-Code 0 durchläuft.

        Args:
            command: Auszuführender Befehl.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Exit-Code 0, sonst False.
        """
        action = SysCmdAction(command=command, timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "fail2ban", f"{label}: fehlgeschlagen")
            return False
        self.send_message(LogLevel.INFO, "fail2ban", f"{label}: OK")
        return True

    def _package_installed(self) -> bool:
        """Prüft per dpkg-query, ob das Paket fail2ban installiert ist.

        Ohne eigene Meldung — für uninstall/test, die den Fall je nach
        Kontext unterschiedlich vermelden (idempotenter Abbruch bzw. Fehler).

        Returns:
            True, wenn dpkg-query den Status "install ok installed" meldet.
        """
        action = SysCmdAction(
            command=[self.DPKG_QUERY, "-W", "-f=${Status}", "fail2ban"], timeout=15
        )
        return self.run_action(action) == 0 and "install ok installed" in action.stdout

    def _check_package_installed(self) -> bool:
        """Prüft per dpkg-query, ob das Paket fail2ban installiert ist.

        Returns:
            True, wenn dpkg-query den Status "install ok installed" meldet.
        """
        if self._package_installed():
            self.send_message(LogLevel.INFO, "fail2ban", "Paket fail2ban: installiert")
            return True
        self.send_message(
            LogLevel.ERROR, "fail2ban", "Paket fail2ban: nicht installiert"
        )
        return False

    def _check_daemon_ping(self) -> bool:
        """Prüft per fail2ban-client ping, ob der Daemon antwortet.

        Returns:
            True, wenn die Antwort "pong" enthält, sonst False.
        """
        action = SysCmdAction(command=[self.FAIL2BAN_CLIENT, "ping"], timeout=15)
        if self.run_action(action) == 0 and "pong" in action.stdout:
            self.send_message(LogLevel.INFO, "fail2ban", "Daemon-Ping: pong")
            return True
        self.send_message(
            LogLevel.ERROR, "fail2ban", "Daemon-Ping: keine Antwort (pong erwartet)"
        )
        return False

    def _check_jail_status_lines(self) -> bool:
        """Fragt den sshd-Jail-Status ab und protokolliert ihn zeilenweise.

        Returns:
            True, wenn der Status abfragbar ist, sonst False.
        """
        action = SysCmdAction(
            command=[self.FAIL2BAN_CLIENT, "status", "sshd"], timeout=15
        )
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "fail2ban", "sshd-Jail: nicht abfragbar")
            return False
        for line in action.stdout.splitlines():
            self.send_message(LogLevel.INFO, "fail2ban", f"sshd-Jail: {line}")
        return True

    def _check_jail_local_exists(self) -> bool:
        """Prüft, ob jail.local vorhanden ist.

        Returns:
            True, wenn die Datei existiert.
        """
        if Path(self.JAIL_LOCAL).exists():
            self.send_message(
                LogLevel.INFO, "fail2ban", f"{self.JAIL_LOCAL}: vorhanden"
            )
            return True
        self.send_message(LogLevel.ERROR, "fail2ban", f"{self.JAIL_LOCAL}: fehlt")
        return False

    def _check_ignoreip_in_file(self, tokens: list[str]) -> bool:
        """Prüft, ob jail.local die ignoreip-Zeile mit dem effektiven Wert enthält.

        Args:
            tokens: Zusätzliche IP-/CIDR-Tokens aus der Konfiguration.

        Returns:
            True, wenn eine passende ignoreip-Zeile gefunden wird.
        """
        expected = f"ignoreip = {_effective_ignoreip(tokens)}"
        try:
            content = Path(self.JAIL_LOCAL).read_text(encoding="utf-8")
        except OSError:
            self.send_message(
                LogLevel.ERROR, "fail2ban", f"{self.JAIL_LOCAL}: nicht lesbar"
            )
            return False
        if any(line.strip() == expected for line in content.splitlines()):
            self.send_message(LogLevel.INFO, "fail2ban", "ignoreip-Zeile: OK")
            return True
        self.send_message(
            LogLevel.ERROR, "fail2ban", "ignoreip-Zeile: nicht auf Soll-Wert gesetzt"
        )
        return False

    def _check_ignoreip_loaded(self, tokens: list[str]) -> bool:
        """Prüft, ob der laufende sshd-Jail alle ignoreip-Tokens geladen hat.

        Args:
            tokens: Zusätzliche IP-/CIDR-Tokens aus der Konfiguration.

        Returns:
            True, wenn jedes Token in der laufenden Konfiguration steht.
        """
        action = SysCmdAction(
            command=[self.FAIL2BAN_CLIENT, "get", "sshd", "ignoreip"], timeout=15
        )
        if self.run_action(action) != 0:
            self.send_message(
                LogLevel.ERROR, "fail2ban", "sshd-Jail: ignoreip nicht lesbar"
            )
            return False
        loaded = action.stdout
        missing = [tok for tok in tokens if tok not in loaded]
        if missing:
            self.send_message(
                LogLevel.ERROR,
                "fail2ban",
                f"sshd-Jail: ignoreip-Eintrag nicht geladen: {missing[0]!r}",
            )
            return False
        self.send_message(
            LogLevel.INFO, "fail2ban", "sshd-Jail: ignoreip-Einträge geladen"
        )
        return True
