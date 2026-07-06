"""Modul ufw — Firewall-Grundkonfiguration.

Installiert ufw, verwirft den bestehenden Regelsatz (deterministischer
Ausgangszustand), setzt die Default-Policies deny incoming/deny outgoing
und die aus der Konfiguration abgeleiteten Freigabe-Regeln. Aktiviert die
Firewall NICHT — das übernimmt der Installationslauf am Ende als eigene
Abfrage. Betriebsart über den Schlüssel operation: install, check,
uninstall, test.
"""

import re
import socket
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
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


def _doc_ports(values: dict[str, str], key: str) -> list[str]:
    """Liest eine Portliste für den Installationsbericht aus values.

    Rein anzeigend: keine Gültigkeitsprüfung (die übernimmt _validate vor
    jeder Systemänderung), nur Trennen und Trimmen der Einträge.

    Args:
        values: Konfigurationswerte des Moduls.
        key: Abzufragender Schlüssel (allow_in_tcp, allow_out_tcp,
            allow_out_udp).

    Returns:
        Liste der Portangaben als Zeichenketten, ohne leere Einträge.
    """
    raw = values.get(key, "")
    return [token.strip() for token in raw.split(",") if token.strip()]


def _doc_list(items: list[str]) -> str:
    """Baut eine einfache Markdown-Aufzählung aus items.

    Args:
        items: Listenpunkte; eine leere Liste ergibt eine leere Zeichenkette.

    Returns:
        Eine Zeile "- <item>\\n" je Eintrag.
    """
    return "".join(f"- {item}\n" for item in items)


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
    DPKG_QUERY_BIN: ClassVar[str] = "/usr/bin/dpkg-query"
    NFT_BIN: ClassVar[str] = "/usr/sbin/nft"
    IPTABLES_BIN: ClassVar[str] = "/usr/sbin/iptables"

    # SSH-Verwaltungsport als Klassenattribut statt wiederholtem Literal;
    # feste Protokoll-Festlegung, kein umgebungsspezifischer Hardcode.
    SSH_PORT: ClassVar[int] = 22

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

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
        """Führt Einrichtung, Regelabgleich, Rückbau oder Test aus.

        uninstall lädt die Konfiguration bewusst nicht (fail-safe wie im
        Original): der Rückbau muss auch bei fehlender/defekter
        Portkonfiguration durchlaufen.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem Port oder fehlendem SSH-Port unter
                den eingehenden TCP-Regeln (nicht bei uninstall).
        """
        if self.operation == "uninstall":
            return self._uninstall()
        self._validate()
        if self.operation == "check":
            return self._verify()
        if self.operation == "test":
            return self._test()
        return self._install()

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Markdown-Abschnitt für den Installationsbericht.

        SICHERHEIT: doc() liest ausschließlich die drei Portlisten-
        Schlüssel; ufw verarbeitet keine Geheimnisse, andere Schlüssel in
        values bleiben unberücksichtigt.

        Args:
            values: Konfigurationswerte des Moduls (allow_in_tcp,
                allow_out_tcp, allow_out_udp, …).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Firewall".
        """
        in_tcp = _doc_ports(values, "allow_in_tcp")
        out_tcp = _doc_ports(values, "allow_out_tcp")
        out_udp = _doc_ports(values, "allow_out_udp")
        return (
            "\n## Firewall\n\n"
            "**Pakete:** ufw\n\n"
            "**Default-Policy:** deny incoming, deny outgoing\n\n"
            "**Eingehend TCP erlaubt:**\n"
            f"{_doc_list(in_tcp)}"
            "\n**Ausgehend TCP erlaubt:**\n"
            f"{_doc_list(out_tcp)}"
            "\n**Ausgehend UDP erlaubt:**\n"
            f"{_doc_list(out_udp)}"
            "\n**Dienste:** ufw (enabled, aktiv nach install)\n"
        )

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

    def _read_added_rules(self) -> list[str] | None:
        """Liest die aktuell gesetzten `ufw show added`-Regeln.

        Returns:
            Sortierte Liste der Regelzeilen, oder None, wenn der Befehl
            fehlschlägt.
        """
        action = SysCmdAction(command=[self.UFW_BIN, "show", "added"], timeout=15)
        if self.run_action(action) != 0:
            return None
        return sorted(
            line for line in action.stdout.splitlines() if line.startswith("ufw ")
        )

    def _verify(self) -> int:
        """Gleicht die gesetzten Regeln mit dem Soll aus der Konfiguration ab.

        Vergleicht `ufw show added` mit dem Soll; die Aktivierung der
        Firewall ist nicht Teil dieses Abgleichs (siehe Modul-Docstring).

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        actual = self._read_added_rules()
        if actual is None:
            self.send_message(LogLevel.ERROR, "ufw", "Regelsatz: nicht lesbar")
            return 1
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

    def _package_installed(self, package: str) -> bool:
        """Prüft über dpkg-query, ob ein Paket installiert ist.

        Args:
            package: Zu prüfender Paketname.

        Returns:
            True, wenn package installiert ist, sonst False (auch bei
            unbekanntem Paket oder fehlgeschlagenem Aufruf).
        """
        action = SysCmdAction(
            command=[self.DPKG_QUERY_BIN, "-W", "-f=${Status}", package],
            timeout=15,
        )
        if self.run_action(action) != 0:
            return False
        return "install ok installed" in action.stdout

    def _uninstall(self) -> int:
        """Deaktiviert die Firewall und entfernt das Paket ufw.

        Semantik nach do_uninstall des Originals: konfigunabhängiger,
        fail-safe Rückbau (keine Portlisten-Validierung), idempotent bei
        bereits entferntem Paket, ohne --purge (/etc/ufw/ bleibt liegen).
        Bricht beim ersten fehlgeschlagenen Schritt ab.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        if not self._package_installed("ufw"):
            self.send_message(
                LogLevel.INFO, "ufw", "Paket ufw nicht installiert — nichts zu tun"
            )
            return 0

        self.send_message(
            LogLevel.WARN,
            "ufw",
            "Firewall wird deaktiviert (ufw --force disable) — das System"
            " ist danach ungeschützt, bis eine andere Firewall aktiv ist.",
        )
        steps: list[tuple[str, Action]] = [
            (
                "Firewall deaktivieren (ufw --force disable)",
                SysCmdAction(command=[self.UFW_BIN, "--force", "disable"], timeout=15),
            ),
            (
                "Dienst deaktivieren",
                self.SYSTEMD_ACTION_CLS(operation="disable", unit="ufw", timeout=30),
            ),
            (
                "Dienst stoppen",
                self.SYSTEMD_ACTION_CLS(operation="stop", unit="ufw", timeout=30),
            ),
            (
                "Paket entfernen (ohne --purge)",
                self.APT_ACTION_CLS(packages=["ufw"], state="absent"),
            ),
        ]
        for label, action in steps:
            self.send_message(LogLevel.INFO, "ufw", label)
            if self.run_action(action) != 0:
                self.send_message(LogLevel.ERROR, "ufw", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _test_rules_match(self) -> bool:
        """Vergleicht den Regelsatz mit dem Soll, ohne bei Abweichung abzubrechen.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        actual = self._read_added_rules() or []
        expected = self._expected_rules()
        if actual == expected:
            self.send_message(
                LogLevel.INFO,
                "ufw",
                "test: Regelsatz stimmt mit Konfiguration überein",
            )
            return True
        self.send_message(
            LogLevel.ERROR, "ufw", "test: Regelsatz weicht von Konfiguration ab"
        )
        return False

    def _test_netfilter_chains(self) -> None:
        """Sucht ufw-Ketten im Netfilter-Regelwerk über nft oder iptables.

        Kein Hard-Fail: das Backend ist versionsabhängig variabel; fehlt
        der Nachweis, meldet die Methode das nur als INFO (wie im Original).
        """
        nft_action = SysCmdAction(command=[self.NFT_BIN, "list", "ruleset"], timeout=15)
        if self.run_action(nft_action) == 0 and "ufw" in nft_action.stdout:
            self.send_message(
                LogLevel.INFO,
                "ufw",
                "test: Netfilter-Regelwerk via nft vorhanden (ufw-Ketten)",
            )
            return
        iptables_action = SysCmdAction(command=[self.IPTABLES_BIN, "-S"], timeout=15)
        if self.run_action(iptables_action) == 0 and "ufw" in iptables_action.stdout:
            self.send_message(
                LogLevel.INFO,
                "ufw",
                "test: Netfilter-Regelwerk via iptables vorhanden (ufw-Ketten)",
            )
            return
        self.send_message(
            LogLevel.INFO,
            "ufw",
            "test: ufw-Ketten im Netfilter nicht eindeutig nachweisbar"
            " (Backend-Variabilität) — kein Hard-Fail",
        )

    def _test_ssh_reachable(self) -> bool:
        """Prüft testweise den TCP-Connect auf 127.0.0.1:SSH_PORT.

        localhost wird von ufw nicht gefiltert; der Test belegt nur, dass
        sshd lokal lauscht, nicht die Firewall-Regel selbst
        (sitzungsneutral, siehe do_test im Original).

        Returns:
            True bei erfolgreichem Connect, sonst False.
        """
        try:
            with socket.create_connection(("127.0.0.1", self.SSH_PORT), timeout=2):
                pass
        except OSError:
            self.send_message(
                LogLevel.ERROR,
                "ufw",
                f"test: TCP-Connect auf 127.0.0.1:{self.SSH_PORT} fehlgeschlagen",
            )
            return False
        self.send_message(
            LogLevel.INFO, "ufw", f"test: TCP-Connect auf 127.0.0.1:{self.SSH_PORT} ok"
        )
        return True

    def _test(self) -> int:
        """Funktionstest ohne Systemänderung nach do_test des Originals.

        Sammelnd: alle Prüfungen laufen unabhängig vom Ergebnis der
        vorherigen durch, kein Abbruch beim ersten Fehler.

        Returns:
            0, wenn alle Prüfungen bestanden sind, sonst 1.
        """
        ok = True
        ok &= self._test_rules_match()
        self._test_netfilter_chains()
        ok &= self._test_ssh_reachable()
        self.send_message(
            LogLevel.INFO,
            "ufw",
            "test: Firewall-Test (neue SSH-Verbindung von außen gegen"
            f" {self.SSH_PORT}/tcp) in zweiter Sitzung manuell verifizieren.",
        )
        return 0 if ok else 1
