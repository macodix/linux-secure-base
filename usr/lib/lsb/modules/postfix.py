"""Modul postfix — Mail-Versand als Satellite über einen externen SMTP-Relay.

Richtet Postfix als Satellite-System ein: main.cf-Direktiven für einen
authentifizierten SMTP-Relay, sasl_passwd-Zugangsdaten, Umschreiben aller
Empfänger auf eine Admin-Adresse (recipient_canonical) und Weiterleitung von
root-Mail über /etc/aliases. Betriebsart über den Schlüssel operation.
"""

import os
import re
import tempfile
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.block_in_file_action import BlockInFileAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.permissions_action import PermissionsAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# fqdn und relay_host: nur [A-Za-z0-9.-], wie im Bash-Original — beide Werte
# gehen in Kommandos (debconf, postconf-Direktiven) und main.cf-Inhalte.
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")
# admin_mail: einfache name@domain-Prüfung, wie im Bash-Original.
_MAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")
# relay_user steht als "user:password" in sasl_passwd — Doppelpunkt und
# Whitespace würden die Feldgrenze verschieben.
_RELAY_USER_RE = re.compile(r"^[^\s:]+$")
# relay_password steht als letztes Feld derselben Zeile — Whitespace/Newline
# würde die Zeile zerreißen. Der Wert selbst erscheint in keiner Meldung.
_RELAY_PASSWORD_RE = re.compile(r"^\S+$")

# Marker des /etc/aliases-Blocks für die root-Weiterleitung.
_ALIASES_MARKER = "aliases-root"


def _debconf_content(fqdn: str) -> str:
    """Baut die debconf-Selections für den unbeaufsichtigten Paketinstall.

    Setzt den Mailer-Typ auf Satellite mit leerem relayhost (das main.cf-
    Patchen danach trägt den echten Relay ein) und den mailname auf fqdn,
    damit apt-get install nicht interaktiv nach diesen Werten fragt.
    """
    return (
        "postfix postfix/main_mailer_type select Satellite system\n"
        f"postfix postfix/mailname string {fqdn}\n"
        "postfix postfix/relayhost string\n"
    )


def _sasl_passwd_content(
    relay_host: str, relay_port: str, relay_user: str, relay_password: str
) -> str:
    """Baut den Inhalt von sasl_passwd (Zugangsdaten für den SMTP-Relay).

    Das Ergebnis enthält relay_password im Klartext — nie protokollieren.
    """
    return f"[{relay_host}]:{relay_port} {relay_user}:{relay_password}\n"


def _recipient_canonical_content(admin_mail: str) -> str:
    """Baut den Inhalt von recipient_canonical: alle Empfänger auf admin_mail."""
    return f"/.+/   {admin_mail}\n"


def _aliases_block_content(admin_mail: str) -> str:
    """Baut den Blockinhalt für die root-Weiterleitung in /etc/aliases."""
    return f"postmaster: root\nroot:       {admin_mail}\n"


class Postfix(Module):
    """Postfix als Satellite gegen einen externen SMTP-Smarthost."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "fqdn",
        "admin_mail",
        "relay_host",
        "relay_port",
        "relay_user",
        "relay_password",
    ]

    PACKAGES: ClassVar[tuple[str, ...]] = (
        "ca-certificates",
        "libsasl2-modules",
        "mailutils",
        "postfix",
    )

    # Programmpfade und Schreibziele als Klassenattribute (siehe base.py):
    # feste Vorgaben, die eine Testunterklasse außerhalb dieses Moduls
    # überschreiben kann, ohne das Modul selbst anzufassen.
    DEBCONF_SET_SELECTIONS: ClassVar[str] = "/usr/bin/debconf-set-selections"
    POSTCONF_BIN: ClassVar[str] = "/usr/sbin/postconf"
    POSTMAP_BIN: ClassVar[str] = "/usr/sbin/postmap"
    NEWALIASES_BIN: ClassVar[str] = "/usr/bin/newaliases"
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"
    MAIN_CF: ClassVar[str] = "/etc/postfix/main.cf"
    SASL_PASSWD: ClassVar[str] = "/etc/postfix/sasl_passwd"  # noqa: S105 — Dateipfad, kein Geheimnis
    RECIPIENT_CANONICAL: ClassVar[str] = "/etc/postfix/recipient_canonical"
    ALIASES: ClassVar[str] = "/etc/aliases"
    CA_CERTIFICATES_FILE: ClassVar[str] = "/etc/ssl/certs/ca-certificates.crt"

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    fqdn: str
    admin_mail: str
    relay_host: str
    relay_port: str
    relay_user: str
    relay_password: str

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
        return self._install()

    def _validate(self) -> None:
        """Prüft alle Werte, die in Kommandos oder Dateiinhalte gehen.

        Raises:
            ModuleError: Wenn ein Wert vom erwarteten Format abweicht.
        """
        if not _HOST_RE.match(self.fqdn):
            raise ModuleError(f"Ungültiger Rechnername: {self.fqdn!r}")
        if not _MAIL_RE.match(self.admin_mail):
            raise ModuleError(f"Ungültige Admin-E-Mail-Adresse: {self.admin_mail!r}")
        if not _HOST_RE.match(self.relay_host):
            raise ModuleError(f"Ungültiger Relay-Host: {self.relay_host!r}")
        if not self.relay_port.isdigit() or not (1 <= int(self.relay_port) <= 65535):
            raise ModuleError(f"Ungültiger Relay-Port: {self.relay_port!r}")
        if not _RELAY_USER_RE.match(self.relay_user):
            raise ModuleError(f"Ungültiger Relay-Benutzer: {self.relay_user!r}")
        if not _RELAY_PASSWORD_RE.match(self.relay_password):
            raise ModuleError("Ungültiges Relay-Passwort")

    def _main_cf_settings(self) -> list[tuple[str, str]]:
        """Baut die geordnete Liste der main.cf-Direktiven für den Relay-Satz.

        Returns:
            Liste von (Schlüssel, Sollwert)-Paaren in fester Reihenfolge.
        """
        return [
            ("relayhost", f"[{self.relay_host}]:{self.relay_port}"),
            ("smtp_sasl_auth_enable", "yes"),
            ("smtp_sasl_password_maps", f"hash:{self.SASL_PASSWD}"),
            ("smtp_sasl_security_options", "noanonymous"),
            ("smtp_sasl_tls_security_options", "noanonymous"),
            ("smtp_tls_security_level", "encrypt"),
            ("smtp_tls_CAfile", self.CA_CERTIFICATES_FILE),
            ("smtp_tls_loglevel", "1"),
            ("inet_interfaces", "loopback-only"),
            ("mydestination", "$myhostname, localhost.$mydomain, localhost"),
            ("recipient_canonical_maps", f"regexp:{self.RECIPIENT_CANONICAL}"),
        ]

    def _install(self) -> int:
        """Richtet Postfix als Satellite gegen den konfigurierten Relay ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        fd, debconf_path = tempfile.mkstemp(prefix="lsb-postfix-debconf-")
        os.close(fd)
        try:
            steps: list[tuple[str, Action]] = [
                (
                    "debconf-Selections schreiben",
                    WriteFileAction(
                        dst=debconf_path,
                        content=_debconf_content(self.fqdn),
                        mode=0o600,
                        safe_mode=False,
                    ),
                ),
                (
                    "debconf-Antworten setzen",
                    SysCmdAction(
                        command=[self.DEBCONF_SET_SELECTIONS, debconf_path],
                        timeout=30,
                    ),
                ),
                (
                    "Pakete installieren",
                    self.APT_ACTION_CLS(packages=list(self.PACKAGES)),
                ),
            ]
            for key, value in self._main_cf_settings():
                steps.append(
                    (
                        f"main.cf {key} setzen",
                        LineInFileAction(
                            path=self.MAIN_CF,
                            line=f"{key} = {value}",
                            match=rf"^{re.escape(key)}\s*=",
                        ),
                    )
                )
            steps += [
                (
                    "sasl_passwd schreiben",
                    WriteFileAction(
                        dst=self.SASL_PASSWD,
                        content=_sasl_passwd_content(
                            self.relay_host,
                            self.relay_port,
                            self.relay_user,
                            self.relay_password,
                        ),
                        mode=0o600,
                        overwrite=True,
                    ),
                ),
                (
                    "sasl_passwd-Map bauen",
                    SysCmdAction(
                        command=[self.POSTMAP_BIN, self.SASL_PASSWD], timeout=30
                    ),
                ),
                (
                    "sasl_passwd.db-Rechte setzen",
                    PermissionsAction(path=f"{self.SASL_PASSWD}.db", mode=0o600),
                ),
                (
                    "recipient_canonical schreiben",
                    WriteFileAction(
                        dst=self.RECIPIENT_CANONICAL,
                        content=_recipient_canonical_content(self.admin_mail),
                        mode=0o644,
                        overwrite=True,
                    ),
                ),
                (
                    "recipient_canonical-Map bauen",
                    SysCmdAction(
                        command=[self.POSTMAP_BIN, self.RECIPIENT_CANONICAL],
                        timeout=30,
                    ),
                ),
                (
                    "/etc/aliases: root-Weiterleitung setzen",
                    BlockInFileAction(
                        path=self.ALIASES,
                        block=_aliases_block_content(self.admin_mail),
                        marker=_ALIASES_MARKER,
                    ),
                ),
                (
                    "aliases-Datenbank aktualisieren",
                    SysCmdAction(command=[self.NEWALIASES_BIN], timeout=30),
                ),
                (
                    "postfix aktivieren",
                    self.SYSTEMD_ACTION_CLS(
                        operation="enable", unit="postfix", timeout=60
                    ),
                ),
                (
                    "postfix starten",
                    self.SYSTEMD_ACTION_CLS(
                        operation="start", unit="postfix", timeout=60
                    ),
                ),
                (
                    "postfix neu laden",
                    self.SYSTEMD_ACTION_CLS(
                        operation="reload", unit="postfix", timeout=60
                    ),
                ),
            ]
            for label, action in steps:
                self.send_message(LogLevel.INFO, "postfix", label)
                if self.run_action(action) != 0:
                    self.send_message(
                        LogLevel.ERROR, "postfix", f"fehlgeschlagen: {label}"
                    )
                    return 1
            return 0
        finally:
            Path(debconf_path).unlink(missing_ok=True)

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit dem Soll der eigenen Installation ab.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        for key, value in self._main_cf_settings():
            ok &= self._check_value(
                [self.POSTCONF_BIN, "-nh", key], value, f"main.cf {key}"
            )
        ok &= self._check_file_mode(self.SASL_PASSWD, 0o600, "sasl_passwd-Rechte")
        ok &= self._check_file_exists(self.RECIPIENT_CANONICAL, "recipient_canonical")
        ok &= self._check_aliases_block()
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "show", "-p", "UnitFileState", "--value", "postfix"],
            "enabled",
            "postfix aktiviert",
        )
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "show", "-p", "ActiveState", "--value", "postfix"],
            "active",
            "postfix aktiv",
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
            self.send_message(LogLevel.ERROR, "postfix", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "postfix", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "postfix", f"{label}: ist {current}, soll {expected}"
        )
        return False

    def _check_file_mode(self, path: str, expected: int, label: str) -> bool:
        """Prüft die Rechte einer eigenen Datei gegen den Sollwert.

        Args:
            path: Zu prüfende Datei.
            expected: Sollrechte.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        try:
            mode = Path(path).stat().st_mode & 0o777
        except OSError:
            self.send_message(LogLevel.ERROR, "postfix", f"{label}: nicht lesbar")
            return False
        if mode == expected:
            self.send_message(LogLevel.INFO, "postfix", f"{label}: {oct(mode)} — OK")
            return True
        self.send_message(
            LogLevel.ERROR,
            "postfix",
            f"{label}: ist {oct(mode)}, soll {oct(expected)}",
        )
        return False

    def _check_file_exists(self, path: str, label: str) -> bool:
        """Prüft, ob eine eigene Datei vorhanden ist.

        Args:
            path: Zu prüfende Datei.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn die Datei existiert, sonst False.
        """
        if Path(path).exists():
            self.send_message(LogLevel.INFO, "postfix", f"{label}: OK")
            return True
        self.send_message(LogLevel.ERROR, "postfix", f"{label}: fehlt")
        return False

    def _check_aliases_block(self) -> bool:
        """Prüft, ob der root-Weiterleitungsblock in /etc/aliases steht.

        Returns:
            True, wenn beide Markerzeilen vorhanden sind, sonst False.
        """
        label = "/etc/aliases root-Weiterleitung"
        try:
            content = Path(self.ALIASES).read_text(encoding="utf-8")
        except OSError:
            self.send_message(LogLevel.ERROR, "postfix", f"{label}: nicht lesbar")
            return False
        begin = f"# BEGIN {_ALIASES_MARKER}"
        end = f"# END {_ALIASES_MARKER}"
        if begin in content and end in content:
            self.send_message(LogLevel.INFO, "postfix", f"{label}: OK")
            return True
        self.send_message(LogLevel.ERROR, "postfix", f"{label}: fehlt")
        return False
