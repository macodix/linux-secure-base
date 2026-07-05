"""Modul ufw — Firewall-Grundkonfiguration.

Installiert ufw, verwirft den bestehenden Regelsatz (deterministischer
Ausgangszustand), setzt die Default-Policies deny incoming/deny outgoing
und die aus der Konfiguration abgeleiteten Freigabe-Regeln. Aktiviert die
Firewall NICHT — das übernimmt der Installationslauf am Ende als eigene
Abfrage. Betriebsart über den Schlüssel operation.
"""

import re
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

_PORT_RE = re.compile(r"^[0-9]+$")


def _parse_port_list(raw: str, name: str) -> list[int]:
    """Zerlegt eine kommagetrennte Portliste und validiert jeden Eintrag.

    Args:
        raw: Kommagetrennte Portliste; eine leere Zeichenkette (nach
            Trimmen) ergibt eine leere Liste.
        name: Name des Konfigurationsschlüssels, für die Fehlermeldung.

    Returns:
        Sortierte Liste der Ports als int.

    Raises:
        ModuleError: Wenn ein Eintrag keine Ganzzahl im Bereich 1-65535 ist.
    """
    raw = raw.strip()
    if not raw:
        return []
    ports: list[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not _PORT_RE.match(token) or not (1 <= int(token) <= 65535):
            raise ModuleError(f"{name} enthält einen ungültigen Port: {token!r}")
        ports.append(int(token))
    return sorted(ports)


class Ufw(Module):
    """Firewall-Grundkonfiguration über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "allow_in_tcp",
        "allow_out_tcp",
        "allow_out_udp",
    ]

    # Programmpfad als Klassenattribut statt Literal in den Schritten
    # (siehe Modul base). Eine Testunterklasse kann ihn im Testbaum auf
    # einen harmlosen Platzhalter setzen, ohne dieses Modul anzufassen.
    UFW_BIN: ClassVar[str] = "/usr/sbin/ufw"

    # SSH-Verwaltungsport als Klassenattribut statt wiederholtem Literal;
    # feste Protokoll-Festlegung, kein umgebungsspezifischer Hardcode.
    SSH_PORT: ClassVar[int] = 22

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    allow_in_tcp: str
    allow_out_tcp: str
    allow_out_udp: str

    # Von _validate geparst und validiert; von _install und _verify genutzt.
    _in_tcp: list[int]
    _out_tcp: list[int]
    _out_udp: list[int]

    def start(self) -> int:
        """Führt Einrichtung oder Regelabgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem Port oder fehlendem SSH-Port unter
                den eingehenden TCP-Regeln.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        return self._install()

    def _validate(self) -> None:
        """Parst die drei Portlisten und sichert den SSH-Zugang ab.

        Raises:
            ModuleError: Bei ungültigem Port oder fehlendem SSH-Port unter
                den eingehenden TCP-Regeln.
        """
        self._in_tcp = _parse_port_list(self.allow_in_tcp, "allow_in_tcp")
        self._out_tcp = _parse_port_list(self.allow_out_tcp, "allow_out_tcp")
        self._out_udp = _parse_port_list(self.allow_out_udp, "allow_out_udp")
        self._require_ssh_port_or_die(self._in_tcp)

    def _require_ssh_port_or_die(self, in_tcp: list[int]) -> None:
        """Sichert den SSH-Verwaltungszugang gegen die Default-Deny-Policy ab.

        Ohne eingehendes SSH würde das Default-Deny den Verwaltungszugang
        kappen; nur bei install relevant, aber auch bei check geprüft, da
        beide Betriebsarten dieselbe Konfiguration validieren.

        Args:
            in_tcp: Geparste eingehende TCP-Ports.

        Raises:
            ModuleError: Wenn SSH_PORT nicht in in_tcp enthalten ist.
        """
        if self.SSH_PORT not in in_tcp:
            raise ModuleError(
                f"allow_in_tcp enthält keinen Port {self.SSH_PORT} —"
                " die Firewall würde den SSH-Verwaltungszugang aussperren."
            )

    def _install(self) -> int:
        """Setzt Paket, Ausgangszustand, Default-Policies und Regeln.

        Aktiviert die Firewall bewusst nicht (siehe Modul-Docstring).

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, Action]] = [
            ("Paket installieren", self.APT_ACTION_CLS(packages=["ufw"])),
            (
                "deterministischer Ausgangszustand (reset)",
                SysCmdAction(command=[self.UFW_BIN, "--force", "reset"], timeout=30),
            ),
            (
                "Default-Policy deny incoming",
                SysCmdAction(
                    command=[self.UFW_BIN, "default", "deny", "incoming"], timeout=15
                ),
            ),
            (
                "Default-Policy deny outgoing",
                SysCmdAction(
                    command=[self.UFW_BIN, "default", "deny", "outgoing"], timeout=15
                ),
            ),
        ]
        for port in self._in_tcp:
            steps.append(
                (
                    f"allow in {port}/tcp",
                    SysCmdAction(
                        command=[self.UFW_BIN, "allow", f"{port}/tcp"], timeout=15
                    ),
                )
            )
        for port in self._out_tcp:
            steps.append(
                (
                    f"allow out {port}/tcp",
                    SysCmdAction(
                        command=[self.UFW_BIN, "allow", "out", f"{port}/tcp"],
                        timeout=15,
                    ),
                )
            )
        for port in self._out_udp:
            steps.append(
                (
                    f"allow out {port}/udp",
                    SysCmdAction(
                        command=[self.UFW_BIN, "allow", "out", f"{port}/udp"],
                        timeout=15,
                    ),
                )
            )

        for label, action in steps:
            self.send_message(LogLevel.INFO, "ufw", label)
            if self.run_action(action) != 0:
                self.send_message(LogLevel.ERROR, "ufw", f"fehlgeschlagen: {label}")
                return 1
        self.send_message(
            LogLevel.INFO,
            "ufw",
            "Firewall-Regeln gesetzt. Die Firewall ist noch NICHT aktiv —"
            " Aktivierung am Ende der Installation oder manuell mit 'ufw enable'.",
        )
        return 0

    def _expected_rules(self) -> list[str]:
        """Baut die erwarteten `ufw show added`-Zeilen aus der Konfiguration.

        Returns:
            Sortierte Liste der erwarteten Regelzeilen.
        """
        rules: list[str] = []
        for port in self._in_tcp:
            rules.append(f"ufw allow {port}/tcp")
        for port in self._out_tcp:
            rules.append(f"ufw allow out {port}/tcp")
        for port in self._out_udp:
            rules.append(f"ufw allow out {port}/udp")
        return sorted(rules)

    def _verify(self) -> int:
        """Gleicht die gesetzten Regeln mit dem Soll aus der Konfiguration ab.

        Vergleicht `ufw show added` mit dem Soll; die Aktivierung der
        Firewall ist nicht Teil dieses Abgleichs (siehe Modul-Docstring).

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        action = SysCmdAction(command=[self.UFW_BIN, "show", "added"], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "ufw", "Regelsatz: nicht lesbar")
            return 1
        actual = sorted(
            line for line in action.stdout.splitlines() if line.startswith("ufw ")
        )
        expected = self._expected_rules()
        if actual == expected:
            self.send_message(
                LogLevel.INFO, "ufw", "Regelsatz: stimmt mit Konfiguration überein"
            )
            return 0
        self.send_message(
            LogLevel.ERROR,
            "ufw",
            "Regelsatz weicht ab — erwartet: "
            f"{' '.join(expected)}; vorhanden: {' '.join(actual)}",
        )
        return 1
