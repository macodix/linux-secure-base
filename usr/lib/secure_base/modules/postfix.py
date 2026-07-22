"""Modul postfix — Mail-Versand als Satellite über einen externen SMTP-Relay.

Richtet Postfix als Satellite-System ein: main.cf-Direktiven für einen
authentifizierten SMTP-Relay, sasl_passwd-Zugangsdaten, Umschreiben aller
Empfänger auf eine Admin-Adresse (recipient_canonical) und Weiterleitung von
root-Mail über /etc/aliases. Betriebsart über den Schlüssel operation. Der
install-Schritt weist abschließend die Zustellfähigkeit über eine Testmail
nach — eine formal gültige main.cf liefert sonst keine Garantie, dass Mail
das System tatsächlich verlässt.
"""

import json
import os
import re
import secrets
import subprocess
import tempfile
import time
from collections.abc import Callable
from email.message import EmailMessage
from pathlib import Path
from typing import Any, ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.block_in_file_action import BlockInFileAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.permissions_action import PermissionsAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

from secure_base import mail_check
from secure_base.managed_write import ManagedFile, ManagedWriteMixin

_Step = Callable[[], int]

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


def _doc_value(values: dict[str, str], key: str) -> str:
    """Liest einen Wert für den Installationsbericht aus values.

    doc() fragt hier ausschließlich fest benannte, unkritische Schlüssel ab
    (relay_host, relay_port, admin_mail) — relay_password wird nie über
    diesen Weg gelesen, ein Allowlist-Mechanismus wie im Bash-Original
    (doc_val) ist deshalb hier nicht nötig.

    Args:
        values: Konfigurationswerte des Moduls.
        key: Abzufragender Schlüssel.

    Returns:
        Wert aus values, oder "(leer/Default)" wenn leer oder nicht gesetzt.
    """
    return values.get(key) or "(leer/Default)"


def _test_mail_content(fqdn: str, admin_mail: str, token: str) -> bytes:
    """Baut Kopf und Rumpf der Testmail für den Zustellungsnachweis.

    token identifiziert den Lauf in der Mail selbst (kein Geheimnis, dient
    nur der Nachvollziehbarkeit beim Admin). Der Betreff nennt den Zweck aus
    Empfängersicht (Prüfung des Mailversands), nicht die interne
    Verfahrensbezeichnung "Zustellungsnachweis". Über EmailMessage gebaut,
    damit der Betreff-Umlaut als RFC-2047-Encoded-Word im Kopf steht und der
    Rumpf quoted-printable-kodiert ist — beides ASCII auf der Leitung, sonst
    verlangt das Relay SMTPUTF8, das nicht jeder Relay anbietet.

    Returns:
        Die vollständige Mail (Kopf und Rumpf) als ASCII-sichere Bytes.
    """
    msg = EmailMessage()
    msg["Subject"] = f"secure-base {fqdn}: Testnachricht (Prüfung des Mailversands)"
    msg["To"] = admin_mail
    msg.set_content(
        f"Testnachricht des secure-base-Installers zur Prüfung des"
        f" Mailversands. Referenz: {token}.\n",
        cte="quoted-printable",
    )
    return msg.as_bytes()


class _SendMailAction(Action):
    """Sendet eine Mail über ein sendmail-kompatibles Programm.

    Modul-lokale Aktion: SysCmdAction unterstützt keine stdin-Eingabe, die
    sendmail zum Lesen von Kopf und Rumpf jedoch benötigt.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        command: Sendmail-Aufruf als Liste einzelner Elemente.
        content: Mailkopf und -rumpf (bereits serialisiert), über stdin.
        timeout: Zeitgrenze in Sekunden.
        stderr: Fehlerausgabe des Befehls nach run().
        returncode: Rückgabewert des Befehls nach run(); -1 vor der Ausführung.
    """

    PARAMS: ClassVar[list[str]] = ["command", "content", "timeout"]

    def __init__(self, command: list[str], content: bytes, timeout: float) -> None:
        """Initialisiert die Sendmail-Aktion.

        Args:
            command: Programmpfad und Argumente (SIC-04); die Empfänger stehen
                als Argument, nicht im Mailinhalt allein.
            content: Kopf und Rumpf der Mail (RFC-822-artig), bereits als
                Bytes serialisiert (z. B. über EmailMessage.as_bytes()), über
                stdin.
            timeout: Zeitgrenze in Sekunden (SIC-05).
        """
        super().__init__()
        self.command = command
        self.content = content
        self.timeout = timeout
        self.stderr: str = ""
        self.returncode: int = -1

    def run(self) -> str:
        """Führt den Sendmail-Aufruf aus und liefert den Ausführungsstatus.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei Timeout, Returncode != 0 oder Startfehler.
        """
        self.status = "running"
        try:
            result = subprocess.run(
                self.command,
                input=self.content,
                shell=False,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self.status = "failed"
            raise ActionError(
                f"Zeitgrenze ({self.timeout}s) überschritten: {self.command[0]!r}"
            ) from exc
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Befehl konnte nicht gestartet werden: {exc}") from exc
        self.stderr = result.stderr.decode("utf-8", errors="replace")
        self.returncode = result.returncode
        if self.returncode != 0:
            self.status = "failed"
            raise ActionError(
                f"Befehl {self.command[0]!r} endete mit Code {self.returncode};"
                f" stderr: {self.stderr.strip()!r}"
            )
        self.status = "finished"
        return self.status


class Postfix(ManagedWriteMixin, Module):
    """Postfix als Satellite gegen einen externen SMTP-Smarthost."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "fqdn",
        "admin_mail",
        "relay_host",
        "relay_port",
        "relay_user",
        "relay_password",
        "force_overwrite",
        "backup_run_dir",
    ]

    PACKAGES: ClassVar[tuple[str, ...]] = (
        "ca-certificates",
        "libsasl2-modules",
        "mailutils",
        "postfix",
    )

    # uninstall entfernt ca-certificates bewusst nicht mit — Distro-Basis,
    # von anderen Paketen mitgenutzt (Bash-Original: do_uninstall).
    UNINSTALL_PACKAGES: ClassVar[tuple[str, ...]] = (
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
    SENDMAIL_BIN: ClassVar[str] = "/usr/sbin/sendmail"
    POSTQUEUE_BIN: ClassVar[str] = "/usr/sbin/postqueue"
    MAIN_CF: ClassVar[str] = "/etc/postfix/main.cf"
    SASL_PASSWD: ClassVar[str] = "/etc/postfix/sasl_passwd"  # noqa: S105 — Dateipfad, kein Geheimnis
    RECIPIENT_CANONICAL: ClassVar[str] = "/etc/postfix/recipient_canonical"
    ALIASES: ClassVar[str] = "/etc/aliases"
    CA_CERTIFICATES_FILE: ClassVar[str] = "/etc/ssl/certs/ca-certificates.crt"
    MAIL_LOG: ClassVar[str] = "/var/log/mail.log"
    JOURNALCTL_BIN: ClassVar[str] = "/usr/bin/journalctl"

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction
    SEND_MAIL_ACTION_CLS: ClassVar[type[_SendMailAction]] = _SendMailAction

    # Zustellungsnachweis: Anzahl Versuche und Wartezeit je Versuch, bis die
    # Testmail die Queue verlassen haben muss. Als Klassenattribute testbar
    # (Tests setzen DELIVERY_CHECK_INTERVAL auf 0, keine echten Wartezeiten).
    DELIVERY_CHECK_ATTEMPTS: ClassVar[int] = 6
    DELIVERY_CHECK_INTERVAL: ClassVar[float] = 5.0

    # Zustellstatus im Mail-Log: eine leere Queue allein belegt keine
    # Zustellung (auch ein Bounce verlässt die Queue) — eigene, kleinere
    # Versuchs-/Wartekonstanten, falls der Logeintrag der Queue-Leerung
    # knapp nachläuft. Ebenfalls als Klassenattribute testbar.
    DELIVERY_LOG_CHECK_ATTEMPTS: ClassVar[int] = 3
    DELIVERY_LOG_CHECK_INTERVAL: ClassVar[float] = 2.0

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
        """Führt Einrichtung, Abgleich, Rückbau oder Funktionstest aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigen Konfigurationswerten.
        """
        self._validate()
        if self.operation == "preflight":
            return self.preflight_managed("postfix")
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

        SICHERHEIT: relay_password (und jedes andere Geheimnis) erscheint
        hier nie — weder Name noch Wert —, auch wenn es in values steht.
        doc() liest ausschließlich die unten aufgeführten, unkritischen
        Schlüssel; alles andere in values bleibt unberücksichtigt.

        Args:
            values: Konfigurationswerte des Moduls (fqdn, admin_mail,
                relay_host, relay_port, relay_user, relay_password, …).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Mail-Versand".
        """
        relay_host = _doc_value(values, "relay_host")
        relay_port = _doc_value(values, "relay_port")
        admin_mail = _doc_value(values, "admin_mail")
        return (
            "\n## Mail-Versand\n\n"
            f"**Pakete:** {', '.join(cls.PACKAGES)}\n\n"
            "**Dateien/Einstellungen:**\n\n"
            f"- `{cls.MAIN_CF}`:\n"
            f"  - `relayhost = [{relay_host}]:{relay_port}`\n"
            "  - `smtp_tls_security_level = encrypt`\n"
            "  - `inet_interfaces = loopback-only`\n"
            f"- `{cls.ALIASES}`:\n"
            f"  - `root: {admin_mail}`\n"
            "\n**Dienste:** postfix (enabled, aktiv nach install)\n"
            "\n> Hinweis: SMTP-Passwort wird nicht dokumentiert (Secret).\n"
        )

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
        fd, debconf_path = tempfile.mkstemp(prefix="secure-base-postfix-debconf-")
        os.close(fd)
        try:
            steps: list[tuple[str, _Step]] = [
                (
                    "debconf-Selections schreiben",
                    lambda: self.run_action(
                        WriteFileAction(
                            dst=debconf_path,
                            content=_debconf_content(self.fqdn),
                            mode=0o600,
                            safe_mode=False,
                        )
                    ),
                ),
                (
                    "debconf-Antworten setzen",
                    lambda: self.run_action(
                        SysCmdAction(
                            command=[self.DEBCONF_SET_SELECTIONS, debconf_path],
                            timeout=30,
                        )
                    ),
                ),
                (
                    "Pakete installieren",
                    lambda: self.run_action(
                        self.APT_ACTION_CLS(packages=list(self.PACKAGES))
                    ),
                ),
            ]
            for key, value in self._main_cf_settings():
                steps.append(
                    (f"main.cf {key} setzen", self._make_main_cf_step(key, value))
                )
            steps += [
                ("sasl_passwd schreiben", self._step_write_sasl_passwd),
                (
                    "sasl_passwd-Map bauen",
                    lambda: self.run_action(
                        SysCmdAction(
                            command=[self.POSTMAP_BIN, self.SASL_PASSWD], timeout=30
                        )
                    ),
                ),
                (
                    "sasl_passwd.db-Rechte setzen",
                    lambda: self.run_action(
                        PermissionsAction(path=f"{self.SASL_PASSWD}.db", mode=0o600)
                    ),
                ),
                (
                    "recipient_canonical schreiben",
                    self._step_write_recipient_canonical,
                ),
                (
                    "recipient_canonical-Map bauen",
                    lambda: self.run_action(
                        SysCmdAction(
                            command=[self.POSTMAP_BIN, self.RECIPIENT_CANONICAL],
                            timeout=30,
                        )
                    ),
                ),
                (
                    "/etc/aliases: root-Weiterleitung setzen",
                    self._step_aliases_block,
                ),
                (
                    "aliases-Datenbank aktualisieren",
                    lambda: self.run_action(
                        SysCmdAction(command=[self.NEWALIASES_BIN], timeout=30)
                    ),
                ),
                (
                    "postfix aktivieren",
                    lambda: self.run_action(
                        self.SYSTEMD_ACTION_CLS(
                            operation="enable", unit="postfix", timeout=60
                        )
                    ),
                ),
                (
                    "postfix starten",
                    lambda: self.run_action(
                        self.SYSTEMD_ACTION_CLS(
                            operation="start", unit="postfix", timeout=60
                        )
                    ),
                ),
                (
                    "postfix neu laden",
                    lambda: self.run_action(
                        self.SYSTEMD_ACTION_CLS(
                            operation="reload", unit="postfix", timeout=60
                        )
                    ),
                ),
            ]
            for label, step in steps:
                self.send_message(LogLevel.INFO, "postfix", label)
                if step() != 0:
                    self.send_message(
                        LogLevel.ERROR, "postfix", f"fehlgeschlagen: {label}"
                    )
                    return 1
            label = "Zustellung prüfen"
            self.send_message(LogLevel.INFO, "postfix", label)
            if self._check_delivery() != 0:
                self.send_message(LogLevel.ERROR, "postfix", f"fehlgeschlagen: {label}")
                return 1
            return 0
        finally:
            Path(debconf_path).unlink(missing_ok=True)

    def _managed_files(self) -> list[ManagedFile]:
        """Deklariert sasl_passwd und recipient_canonical als verwaltete Ziele.

        sasl_passwd enthält das Relay-Passwort im Klartext (secret=True) —
        bei einer Freigabe wird die alte Fassung nie in die
        Sicherungsablage kopiert.
        """
        return [
            ManagedFile(
                dst=self.SASL_PASSWD,
                content=_sasl_passwd_content(
                    self.relay_host,
                    self.relay_port,
                    self.relay_user,
                    self.relay_password,
                ),
                mode=0o600,
                secret=True,
            ),
            ManagedFile(
                dst=self.RECIPIENT_CANONICAL,
                content=_recipient_canonical_content(self.admin_mail),
                mode=0o644,
            ),
        ]

    def _step_write_sasl_passwd(self) -> int:
        """Schreibt sasl_passwd (Relay-Zugangsdaten, Geheimniswert, 0600)."""
        return self.write_managed("postfix", self._managed_files()[0])

    def _step_write_recipient_canonical(self) -> int:
        """Schreibt recipient_canonical (vollständig eigene Datei, 0644)."""
        return self.write_managed("postfix", self._managed_files()[1])

    def _make_main_cf_step(
        self, key: str, value: str, *, state: str = "present"
    ) -> _Step:
        """Baut einen main.cf-Direktiven-Schritt mit zentraler Sicherung.

        Sichert main.cf zentral vor der ersten Änderung im Lauf (je Datei
        und Lauf höchstens eine Sicherung, backup_before_edit ist
        idempotent) und setzt die Aktion auf safe_mode=False — vermeidet
        die .bak-Kaskade wiederholter Läufe.

        Args:
            key: main.cf-Schlüssel.
            value: Sollwert.
            state: "present" setzt die Direktive, "absent" entfernt sie.

        Returns:
            Ausführbarer Schritt, 0 bei Erfolg.
        """

        def step() -> int:
            if self.backup_before_edit("postfix", self.MAIN_CF) != 0:
                return 1
            return self.run_action(
                LineInFileAction(
                    path=self.MAIN_CF,
                    line=f"{key} = {value}",
                    match=rf"^{re.escape(key)}\s*=",
                    state=state,
                    safe_mode=False,
                )
            )

        return step

    def _step_aliases_block(self, *, state: str = "present") -> int:
        """Setzt oder entfernt den root-Weiterleitungsblock in /etc/aliases.

        Sichert /etc/aliases zentral vor der ersten Änderung im Lauf.

        Args:
            state: "present" setzt den Block, "absent" entfernt ihn.

        Returns:
            0 bei Erfolg, 1 bei Sicherungs- oder Aktionsfehler.
        """
        if self.backup_before_edit("postfix", self.ALIASES) != 0:
            return 1
        return self.run_action(
            BlockInFileAction(
                path=self.ALIASES,
                block=_aliases_block_content(self.admin_mail),
                marker=_ALIASES_MARKER,
                state=state,
                safe_mode=False,
            )
        )

    def _uninstall(self) -> int:
        """Nimmt genau die eigenen Änderungen der install-Betriebsart zurück.

        Bereits fehlende eigene Dateien oder Direktiven sind kein Fehler
        (Idempotenz) — der jeweilige Schritt entfällt dann und wird nur als
        INFO gemeldet. sasl_passwd (Geheimnisrest) wird ohne Sicherungskopie
        gelöscht, damit kein Klartext-Passwort als .bak liegen bleibt.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, _Step]] = [
            (
                "postfix stoppen",
                lambda: self.run_action(
                    self.SYSTEMD_ACTION_CLS(
                        operation="stop", unit="postfix", timeout=60
                    )
                ),
            ),
            (
                "postfix deaktivieren",
                lambda: self.run_action(
                    self.SYSTEMD_ACTION_CLS(
                        operation="disable", unit="postfix", timeout=60
                    )
                ),
            ),
        ]

        for path, label, safe_mode in (
            (self.SASL_PASSWD, "sasl_passwd entfernen", False),
            (f"{self.SASL_PASSWD}.db", "sasl_passwd.db entfernen", False),
            (self.RECIPIENT_CANONICAL, "recipient_canonical entfernen", True),
            (
                f"{self.RECIPIENT_CANONICAL}.db",
                "recipient_canonical.db entfernen",
                True,
            ),
        ):
            delete_step = self._delete_step(path, label, safe_mode=safe_mode)
            if delete_step is not None:
                delete_label, action = delete_step
                steps.append((delete_label, self._action_step(action)))

        if Path(self.MAIN_CF).exists():
            for key, value in self._main_cf_settings():
                steps.append(
                    (
                        f"main.cf {key} zurücknehmen",
                        self._make_main_cf_step(key, value, state="absent"),
                    )
                )
        else:
            self.send_message(LogLevel.INFO, "postfix", "main.cf: bereits entfernt")

        if Path(self.ALIASES).exists():
            steps.append(
                (
                    "/etc/aliases: root-Weiterleitung zurücknehmen",
                    lambda: self._step_aliases_block(state="absent"),
                )
            )
            steps.append(
                (
                    "aliases-Datenbank aktualisieren",
                    lambda: self.run_action(
                        SysCmdAction(command=[self.NEWALIASES_BIN], timeout=30)
                    ),
                )
            )
        else:
            self.send_message(
                LogLevel.INFO, "postfix", "/etc/aliases: bereits entfernt"
            )

        steps.append(
            (
                "Pakete entfernen",
                lambda: self.run_action(
                    self.APT_ACTION_CLS(
                        packages=list(self.UNINSTALL_PACKAGES), state="absent"
                    )
                ),
            )
        )

        for label, step in steps:
            self.send_message(LogLevel.INFO, "postfix", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "postfix", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _delete_step(
        self, path: str, label: str, *, safe_mode: bool
    ) -> tuple[str, Action] | None:
        """Baut einen Löschschritt für path, wenn die Datei vorhanden ist.

        Fehlt die Datei bereits, ist das kein Fehler (Idempotenz) — der
        Schritt entfällt, stattdessen ergeht eine INFO-Meldung.

        Args:
            path: Zu löschende Datei.
            label: Beschreibung für die Meldung.
            safe_mode: An DeleteFileAction durchgereicht; False bei
                Geheimnisresten (keine Sicherungskopie mit Klartext).

        Returns:
            (label, Action) wenn die Datei vorhanden ist, sonst None.
        """
        if not Path(path).exists():
            self.send_message(LogLevel.INFO, "postfix", f"{label}: bereits entfernt")
            return None
        return label, DeleteFileAction(path=path, safe_mode=safe_mode)

    def _action_step(self, action: Action) -> _Step:
        """Baut einen Schritt, der die gegebene Aktion ausführt.

        Args:
            action: Auszuführende Aktion.

        Returns:
            Ausführbarer Schritt, 0 bei Erfolg.
        """
        return lambda: self.run_action(action)

    def _test(self) -> int:
        """Weist die Zustellfähigkeit nach, ohne die Konfiguration zu ändern.

        Nutzt denselben Zustellungsnachweis wie der install-Schritt
        (_check_delivery) wieder — ein eigenständiges Duplikat des
        Testmail/Queue-Musters wäre Redundanz.

        Returns:
            0 bei nachgewiesener Zustellung, sonst 1.
        """
        label = "Funktionstest: Zustellung prüfen"
        self.send_message(LogLevel.INFO, "postfix", label)
        if self._check_delivery() != 0:
            self.send_message(LogLevel.ERROR, "postfix", f"fehlgeschlagen: {label}")
            return 1
        return 0

    def _check_delivery(self) -> int:
        """Weist die Zustellfähigkeit über eine Testmail nach.

        Sendet eine Testmail an admin_mail und fragt danach die Postfix-Queue
        ab, bis die Mail die Queue verlassen hat, ein Zustellfehler vermerkt
        ist (Fehlschlag) oder die Versuche ausgeschöpft sind (Fehlschlag).
        Eine leere Queue allein ist kein Zustellungsnachweis — eine
        unzustellbare Mail verlässt die Queue ebenso als Bounce. Erst danach
        wird der tatsächliche Zustellstatus im Mail-Log geprüft
        (_check_delivery_log).

        Returns:
            0 bei nachgewiesener Zustellung, sonst 1.
        """
        token = secrets.token_hex(8)
        anchor = mail_check.log_anchor()
        if not self._send_test_mail(token):
            return 1
        for attempt in range(1, self.DELIVERY_CHECK_ATTEMPTS + 1):
            entries = self._queue_entries()
            if entries is None:
                return 1
            if not entries:
                self.send_message(
                    LogLevel.INFO,
                    "postfix",
                    "Postfix-Queue leer — prüfe Zustellstatus im Mail-Log",
                )
                return self._check_delivery_log(anchor)
            reasons = self._deferred_reasons(entries)
            if reasons:
                self.send_message(
                    LogLevel.ERROR,
                    "postfix",
                    f"Testmail unzustellbar: {'; '.join(reasons)}",
                )
                return 1
            if attempt < self.DELIVERY_CHECK_ATTEMPTS:
                time.sleep(self.DELIVERY_CHECK_INTERVAL)
        self.send_message(
            LogLevel.ERROR, "postfix", "Testmail nach Wartezeit weiter in der Queue"
        )
        return 1

    def _check_delivery_log(self, anchor: str) -> int:
        """Weist den tatsächlichen Zustellstatus der Testmail im Mail-Log nach.

        Ausgelagert nach mail_check.check_delivery_log (gemeinsamer Helfer mit
        dem users-Modul); diese Methode baut daraus nur noch die passende
        Meldung. Ein fehlender Logeintrag oder ein unbekannter Status gilt als
        Fehlschlag (fail-closed) — kein stiller Erfolg aus einer leeren Queue.

        Args:
            anchor: Log-Anker aus mail_check.log_anchor.

        Returns:
            0 bei nachgewiesenem status=sent, sonst 1.
        """
        result = mail_check.check_delivery_log(
            recipient=self.admin_mail,
            anchor=anchor,
            mail_log=self.MAIL_LOG,
            journalctl_bin=self.JOURNALCTL_BIN,
            attempts=self.DELIVERY_LOG_CHECK_ATTEMPTS,
            interval=self.DELIVERY_LOG_CHECK_INTERVAL,
        )
        message = mail_check.format_result(result)
        if result.ok:
            self.send_message(
                LogLevel.INFO, "postfix", f"Testmail zugestellt — {message}"
            )
            return 0
        if result.status == "unknown":
            self.send_message(LogLevel.ERROR, "postfix", message)
        else:
            self.send_message(LogLevel.ERROR, "postfix", f"Testmail {message}")
        return 1

    def _send_test_mail(self, token: str) -> bool:
        """Sendet die Testmail über SENDMAIL_BIN.

        Args:
            token: Referenz in der Mail selbst (kein Geheimnis).

        Returns:
            True, wenn sendmail mit Returncode 0 endete, sonst False.
        """
        action = self.SEND_MAIL_ACTION_CLS(
            command=[self.SENDMAIL_BIN, self.admin_mail],
            content=_test_mail_content(self.fqdn, self.admin_mail, token),
            timeout=30,
        )
        if self.run_action(action) != 0:
            self.send_message(
                LogLevel.ERROR,
                "postfix",
                f"Testmail: sendmail fehlgeschlagen: {action.stderr.strip()}",
            )
            return False
        return True

    def _queue_entries(self) -> list[dict[str, Any]] | None:
        """Liest die Postfix-Queue strukturiert über POSTQUEUE_BIN -j.

        Any: JSON-Struktur von "postqueue -j" (variable Tiefe, kein festes
        Schema); nur einzelne Felder (recipients, delay_reason) werden gelesen.

        Returns:
            Liste der Queue-Einträge (leer, wenn die Queue leer ist), oder
            None, wenn die Abfrage selbst fehlschlug.
        """
        action = SysCmdAction(command=[self.POSTQUEUE_BIN, "-j"], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "postfix", "Postfix-Queue: nicht lesbar")
            return None
        entries: list[dict[str, Any]] = []
        for line in action.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                self.send_message(
                    LogLevel.ERROR, "postfix", "Postfix-Queue: Antwort nicht lesbar"
                )
                return None
        return entries

    def _deferred_reasons(self, entries: list[dict[str, Any]]) -> list[str]:
        """Sammelt die Zustellfehler-Gründe aller Empfänger in der Queue.

        Args:
            entries: Queue-Einträge aus _queue_entries.

        Returns:
            Liste der Zustellfehler-Gründe (leer, wenn keiner deferred ist).
        """
        reasons: list[str] = []
        for entry in entries:
            for recipient in entry.get("recipients", []):
                reason = recipient.get("delay_reason")
                if reason:
                    reasons.append(str(reason))
        return reasons

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
        ok &= self.check_managed("postfix")
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
