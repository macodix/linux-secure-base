"""Modul ssh — Härtung von sshd_config, TOTP-PAM, Login-Mail-Hook.

Härtet /etc/ssh/sshd_config, sperrt den PAM-Bypass über
@include common-auth in /etc/pam.d/sshd, hängt den TOTP-Eintrag
(pam_google_authenticator.so) an und richtet optional den
Login-Mail-Hook (login-mail-notification.sh via pam_exec) ein. Die
Pakete openssh-server und libpam-google-authenticator gelten als
Voraussetzung aus anderen Quellen (Basissystem bzw. Modul users) und
werden von diesem Modul weder installiert noch entfernt. Betriebsart
über den Schlüssel operation.
"""

import grp
import pwd
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from pifos.actions.block_in_file_action import BlockInFileAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Gruppe, deren Mitgliedschaft AllowGroups in sshd_config voraussetzt und
# gegen die die Aussperr-Schutz-Prüfung main_user abgleicht. Fest
# vorgegeben (kein Konfigurationswert), identisch mit Modul users
# (GROUP_NAME), das die Gruppe anlegt.
SSH_USERS_GROUP = "ssh-users"

# sshd_config-Direktiven, die install setzt und check über "sshd -T"
# abgleicht (Reihenfolge wie im Bash-Original). ChallengeResponseAuthentication
# steht bewusst nicht in dieser Liste — das ist ein deprecated-Alias, den
# "sshd -T" je nach OpenSSH-Version unter anderem Namen oder gar nicht
# aufführt; das Bash-Original prüft ihn deshalb ebenfalls nicht in do_check.
SSHD_SETTINGS: tuple[tuple[str, str], ...] = (
    ("PermitRootLogin", "no"),
    ("PasswordAuthentication", "no"),
    ("PermitEmptyPasswords", "no"),
    ("MaxAuthTries", "3"),
    ("LoginGraceTime", "60"),
    ("ClientAliveInterval", "300"),
    ("ClientAliveCountMax", "0"),
    ("PubkeyAuthentication", "yes"),
    ("AllowGroups", SSH_USERS_GROUP),
    ("UsePAM", "yes"),
    ("KbdInteractiveAuthentication", "yes"),
    ("AuthenticationMethods", "publickey,keyboard-interactive"),
)

# deprecated-Alias, nur über ssh_enable_challenge_response_auth gesteuert
# (siehe SSHD_SETTINGS-Kommentar).
CHALLENGE_RESPONSE_SETTING = "ChallengeResponseAuthentication"

PAM_GA_MARKER = "pam-google-authenticator"
LOGIN_MAIL_MARKER = "login-mail-notification"

# Benutzername nach den üblichen Login-Namensregeln (useradd/NAME_REGEX),
# wie in Modul users.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")
_YES_NO = frozenset({"yes", "no"})

_Step = Callable[[], int]


def _setting_match(key: str) -> str:
    """Baut das Erkennungsmuster für eine sshd_config-Direktive.

    Passt sowohl auf eine bereits gesetzte (auskommentierte oder aktive)
    Zeile mit diesem Direktivennamen.

    Args:
        key: Name der Direktive.

    Returns:
        Regulärer Ausdruck für LineInFileAction.match.
    """
    return rf"^\s*#?\s*{re.escape(key)}\b"


def _pam_ga_block() -> str:
    """Baut den PAM-Blockinhalt für den TOTP-Eintrag."""
    return "# Google Authenticator\nauth required pam_google_authenticator.so"


def _login_mail_pam_block(login_mail_script: str) -> str:
    """Baut den PAM-Blockinhalt für den Login-Mail-Hook.

    Args:
        login_mail_script: Pfad des Login-Mail-Skripts.

    Returns:
        Blockinhalt für BlockInFileAction.
    """
    return (
        "# secure-base Login-Mail-Benachrichtigung\n"
        f"session optional pam_exec.so seteuid {login_mail_script}"
    )


def _login_mail_script_content(admin_mail: str) -> str:
    """Baut den Inhalt von login-mail-notification.sh.

    Args:
        admin_mail: Empfängeradresse der Login-Benachrichtigung.

    Returns:
        Inhalt des Shell-Skripts, das über pam_exec (session open_session)
        als root aufgerufen wird.
    """
    return (
        "#!/bin/sh\n"
        "# Von lsb/ssh verwaltet — nicht von Hand bearbeiten.\n"
        "# Aufruf über pam_exec (session open_session) als root.\n"
        'if [ "$PAM_TYPE" = "open_session" ]; then\n'
        f'    ADMINMAIL="{admin_mail}"\n'
        '    TEXT="SSH-Login auf dem Server: $(hostname -f) '
        "\\nBenutzer: $PAM_USER \\nZeitpunkt: $(date) "
        '\\nClient-IP: $PAM_RHOST"\n'
        '    echo -e "$TEXT" | mail -s "SSH Login Info: $PAM_USER" '
        '"$ADMINMAIL"\n'
        "fi\n"
    )


def _parse_sshd_t(output: str) -> dict[str, str]:
    """Zerlegt die Ausgabe von "sshd -T" in Schlüssel/Wert-Paare.

    Args:
        output: Standardausgabe von "sshd -T".

    Returns:
        Zuordnung Direktivenname (kleingeschrieben) zu Wert.
    """
    result: dict[str, str] = {}
    for line in output.splitlines():
        key, sep, value = line.partition(" ")
        if sep:
            result[key.strip().lower()] = value.strip()
    return result


class Ssh(Module):
    """SSH-Härtung mit TOTP-PAM und optionalem Login-Mail-Hook."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "admin_mail",
        "main_user",
        "ssh_enable_login_mail",
        "ssh_enable_challenge_response_auth",
    ]

    # Programmpfade und Schreibziele als Klassenattribute (siehe base.py):
    # feste Vorgaben, im Auslieferungsbaum nie von außen überschrieben,
    # aber für eine Testunterklasse ersetzbar (Plan Abschnitt 2.12).
    SSHD_CONFIG: ClassVar[str] = "/etc/ssh/sshd_config"
    PAM_SSHD: ClassVar[str] = "/etc/pam.d/sshd"
    LOGIN_MAIL_SCRIPT: ClassVar[str] = "/etc/ssh/login-mail-notification.sh"
    SSHD_BIN: ClassVar[str] = "/usr/sbin/sshd"
    DPKG_QUERY_BIN: ClassVar[str] = "/usr/bin/dpkg-query"
    GETENT_BIN: ClassVar[str] = "/usr/bin/getent"
    ID_BIN: ClassVar[str] = "/usr/bin/id"

    # Erwarteter Eigentümer von LOGIN_MAIL_SCRIPT: root, weil pam_exec das
    # Skript als root aufruft (siehe Bash-Original, install -o root -g
    # root). Als Klassenattribut wie die Programmpfade — eine
    # Testunterklasse kann ihn umlenken, ohne Root-Rechte im Testlauf zu
    # brauchen.
    LOGIN_MAIL_OWNER: ClassVar[str] = "root"

    # systemd-Aktionsklasse als Klassenattribut wie base.py — für
    # Testumlenkung per Unterklasse. Kein APT_ACTION_CLS: dieses Modul
    # installiert keine Pakete (openssh-server und
    # libpam-google-authenticator sind Voraussetzung, keine Modulwirkung).
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    admin_mail: str
    main_user: str
    ssh_enable_login_mail: str
    ssh_enable_challenge_response_auth: str

    def start(self) -> int:
        """Führt Härtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem main_user, admin_mail oder einem
                der Ja/Nein-Schalter.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        return self._install()

    def _validate(self) -> None:
        """Prüft die Konfigurationswerte und lehnt ungültige ab.

        Alle Werte gehen in Systembefehle oder Dateiinhalte; SysCmdAction
        hat bewusst keinen Optionsterminator, deshalb prüft das Modul die
        Werte vor der Verwendung (konv-scripting-python.md Abschnitt 4.2).

        Raises:
            ModuleError: Bei ungültigem Benutzernamen, ungültiger
                admin_mail-Adresse oder einem Ja/Nein-Schalter außerhalb
                von yes/no.
        """
        if not _USERNAME_RE.match(self.main_user):
            raise ModuleError(f"Ungültiger Benutzername: {self.main_user!r}")
        if not _EMAIL_RE.match(self.admin_mail):
            raise ModuleError("Ungültige admin_mail-Adresse")
        if self.ssh_enable_login_mail not in _YES_NO:
            raise ModuleError(
                f"ssh_enable_login_mail muss yes oder no sein:"
                f" {self.ssh_enable_login_mail!r}"
            )
        if self.ssh_enable_challenge_response_auth not in _YES_NO:
            raise ModuleError(
                f"ssh_enable_challenge_response_auth muss yes oder no sein:"
                f" {self.ssh_enable_challenge_response_auth!r}"
            )

    # --- install ---

    def _install(self) -> int:
        """Härtet sshd_config und PAM, richtet optional den Login-Mail-Hook ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, _Step]] = [
            ("Paketvoraussetzungen prüfen", self._step_check_packages),
            (
                "Login-Voraussetzungen von main_user prüfen",
                self._step_check_user_login_artifacts,
            ),
            ("sshd_config härten", self._step_harden_sshd_config),
            ("PAM-Bypass-Schutz aktivieren", self._step_pam_bypass_protection),
            ("PAM-TOTP-Eintrag anhängen", self._step_pam_totp_entry),
            ("Login-Mail-Hook einrichten", self._step_login_mail_hook),
            (
                "sshd-Konfiguration validieren und neu laden",
                self._step_validate_and_reload,
            ),
        ]
        for label, step in steps:
            self.send_message(LogLevel.INFO, "ssh", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "ssh", f"fehlgeschlagen: {label}")
                return 1

        self.send_message(
            LogLevel.WARN,
            "ssh",
            "Vor dem Trennen dieser SSH-Sitzung in einer ZWEITEN Sitzung den"
            " Login (Public-Key + TOTP) verifizieren. Sonst Gefahr, sich"
            " auszusperren.",
        )
        return 0

    def _step_check_packages(self) -> int:
        """Prüft die Paketvoraussetzungen (Aussperr-Schutz).

        openssh-server und libpam-google-authenticator installiert dieses
        Modul nicht selbst — sie müssen aus anderer Quelle vorhanden sein.

        Returns:
            0, wenn beide Pakete installiert sind, sonst 1.
        """
        ok = self._check_package_installed("openssh-server")
        ok &= self._check_package_installed("libpam-google-authenticator")
        return 0 if ok else 1

    def _step_check_user_login_artifacts(self) -> int:
        """Prüft die Login-Voraussetzungen von main_user (Aussperr-Schutz).

        Verifiziert, dass main_user existiert, Mitglied von ssh-users ist
        und eine nicht-leere authorized_keys sowie
        google_authenticator-Datei besitzt — bevor die Härtung
        Passwort-Login abschaltet.

        Returns:
            0, wenn alle Voraussetzungen erfüllt sind, sonst 1.
        """
        if not self._user_exists(self.main_user):
            self.send_message(
                LogLevel.ERROR, "ssh", f"Benutzer {self.main_user} existiert nicht"
            )
            return 1
        ok = self._check_group_membership(self.main_user, SSH_USERS_GROUP)

        home = self._home_dir(self.main_user)
        if home is None:
            self.send_message(
                LogLevel.ERROR,
                "ssh",
                f"Home-Verzeichnis von {self.main_user} nicht ermittelbar",
            )
            return 1
        ok &= self._check_nonempty_file(
            Path(home) / ".ssh" / "authorized_keys", "authorized_keys"
        )
        ok &= self._check_nonempty_file(
            Path(home) / ".google_authenticator", "google_authenticator"
        )
        return 0 if ok else 1

    def _step_harden_sshd_config(self) -> int:
        """Setzt alle sshd_config-Direktiven aus SSHD_SETTINGS.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Setzen.
        """
        ok = True
        for key, value in SSHD_SETTINGS:
            ok &= self._apply_setting(key, value)
        if self.ssh_enable_challenge_response_auth == "yes":
            ok &= self._apply_setting(CHALLENGE_RESPONSE_SETTING, "yes")
        else:
            ok &= self._remove_setting(CHALLENGE_RESPONSE_SETTING)
        return 0 if ok else 1

    def _apply_setting(self, key: str, value: str) -> bool:
        """Setzt eine sshd_config-Direktive auf den Sollwert.

        Args:
            key: Name der Direktive.
            value: Sollwert.

        Returns:
            True bei Erfolg, sonst False.
        """
        action = LineInFileAction(
            path=self.SSHD_CONFIG, line=f"{key} {value}", match=_setting_match(key)
        )
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "ssh", f"sshd_config: {key} setzen")
            return False
        return True

    def _remove_setting(self, key: str) -> bool:
        """Entfernt eine sshd_config-Direktive vollständig.

        Args:
            key: Name der Direktive.

        Returns:
            True bei Erfolg, sonst False.
        """
        action = LineInFileAction(
            path=self.SSHD_CONFIG, line="", match=_setting_match(key), state="absent"
        )
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "ssh", f"sshd_config: {key} entfernen")
            return False
        return True

    def _step_pam_bypass_protection(self) -> int:
        """Kommentiert eine aktive @include common-auth aus und verifiziert.

        Ein stiller Erfolg (Zielzeile nicht gefunden, keine Änderung nötig)
        ist kein hinreichender Beleg für den gewünschten Endzustand —
        deshalb liest dieser Schritt die Datei danach erneut.

        Returns:
            0, wenn keine aktive Bypass-Zeile mehr vorhanden ist, sonst 1.
        """
        action = LineInFileAction(
            path=self.PAM_SSHD,
            line="# @include common-auth",
            match=r"^\s*#?\s*@include\s+common-auth\s*$",
        )
        if self.run_action(action) != 0:
            return 1
        if self._pam_bypass_active():
            self.send_message(
                LogLevel.ERROR,
                "ssh",
                "PAM-Bypass-Sperre fehlgeschlagen: @include common-auth"
                " weiterhin aktiv",
            )
            return 1
        return 0

    def _pam_bypass_active(self) -> bool:
        """Prüft, ob eine aktive @include common-auth-Zeile vorhanden ist.

        Returns:
            True, wenn eine aktive Bypass-Zeile gefunden wird.
        """
        content = Path(self.PAM_SSHD).read_text(encoding="utf-8")
        return (
            re.search(r"^\s*@include\s+common-auth\s*$", content, re.MULTILINE)
            is not None
        )

    def _step_pam_totp_entry(self) -> int:
        """Hängt den TOTP-PAM-Eintrag an /etc/pam.d/sshd an.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        action = BlockInFileAction(
            path=self.PAM_SSHD, block=_pam_ga_block(), marker=PAM_GA_MARKER
        )
        return self.run_action(action)

    def _step_login_mail_hook(self) -> int:
        """Richtet den Login-Mail-Hook ein, sofern nicht abgeschaltet.

        Returns:
            0 bei Erfolg oder wenn übersprungen, 1 bei Fehler.
        """
        if self.ssh_enable_login_mail == "no":
            self.send_message(
                LogLevel.INFO,
                "ssh",
                "Login-Mail-Hook übersprungen (ssh_enable_login_mail=no)",
            )
            return 0
        write_action = WriteFileAction(
            dst=self.LOGIN_MAIL_SCRIPT,
            content=_login_mail_script_content(self.admin_mail),
            mode=0o700,
            overwrite=True,
        )
        if self.run_action(write_action) != 0:
            return 1
        block_action = BlockInFileAction(
            path=self.PAM_SSHD,
            block=_login_mail_pam_block(self.LOGIN_MAIL_SCRIPT),
            marker=LOGIN_MAIL_MARKER,
        )
        return self.run_action(block_action)

    def _step_validate_and_reload(self) -> int:
        """Validiert sshd_config und lädt den Dienst neu (reload, kein restart).

        Returns:
            0 bei Erfolg, 1 bei Fehler. Bei ungültiger Konfiguration wird
            kein Reload ausgelöst.
        """
        if self.run_action(SysCmdAction([self.SSHD_BIN, "-t"], timeout=15)) != 0:
            return 1
        return self.run_action(
            self.SYSTEMD_ACTION_CLS(operation="reload", unit="ssh", timeout=30)
        )

    # --- check ---

    def _verify(self) -> int:
        """Gleicht die eigenen Härtungsmaßnahmen mit dem Soll ab.

        Prüft nur, ob die Aktionen dieses Moduls gewirkt haben — keine
        Prüfung von Paketstatus oder Benutzer-Voraussetzungen, die von
        anderen Modulen verantwortet werden.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_sshd_settings()
        ok &= self._check_pam_google_authenticator()
        ok &= self._check_pam_no_bypass()
        if self.ssh_enable_login_mail != "no":
            ok &= self._check_login_mail_script()
            ok &= self._check_login_mail_pam_line()
        return 0 if ok else 1

    def _check_sshd_settings(self) -> bool:
        """Gleicht die sshd_config-Direktiven über "sshd -T" ab.

        Ruft "sshd -T" einmalig auf und gleicht alle SSHD_SETTINGS gegen
        die geparste Ausgabe ab, statt den Befehl je Direktive erneut
        auszuführen.

        Returns:
            True, wenn alle SSHD_SETTINGS übereinstimmen.
        """
        action = SysCmdAction([self.SSHD_BIN, "-T"], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "ssh", "sshd -T nicht lesbar")
            return False

        current = _parse_sshd_t(action.stdout)
        ok = True
        for key, value in SSHD_SETTINGS:
            ist = current.get(key.lower())
            if ist == value.lower():
                self.send_message(LogLevel.INFO, "ssh", f"{key}: {ist} — OK")
            else:
                self.send_message(
                    LogLevel.ERROR, "ssh", f"{key}: ist {ist}, soll {value}"
                )
                ok = False
        return ok

    def _check_pam_google_authenticator(self) -> bool:
        """Prüft den aktiven pam_google_authenticator.so-Eintrag.

        Returns:
            True, wenn der Eintrag aktiv vorhanden ist.
        """
        content = Path(self.PAM_SSHD).read_text(encoding="utf-8")
        if re.search(
            r"^\s*auth\s+required\s+pam_google_authenticator\.so\s*$",
            content,
            re.MULTILINE,
        ):
            self.send_message(LogLevel.INFO, "ssh", "PAM-TOTP-Eintrag: OK")
            return True
        self.send_message(LogLevel.ERROR, "ssh", "PAM-TOTP-Eintrag fehlt")
        return False

    def _check_pam_no_bypass(self) -> bool:
        """Prüft, dass kein aktives @include common-auth mehr vorhanden ist.

        Returns:
            True, wenn keine aktive Bypass-Zeile mehr vorhanden ist.
        """
        if self._pam_bypass_active():
            self.send_message(
                LogLevel.ERROR,
                "ssh",
                "PAM-Bypass: @include common-auth weiterhin aktiv",
            )
            return False
        self.send_message(LogLevel.INFO, "ssh", "PAM-Bypass-Schutz: OK")
        return True

    def _check_login_mail_script(self) -> bool:
        """Prüft Existenz und Rechte von login-mail-notification.sh.

        Returns:
            True, wenn die Datei mit Rechten 0700 und Eigentümer
            LOGIN_MAIL_OWNER vorhanden ist.
        """
        return self._check_file_mode(
            Path(self.LOGIN_MAIL_SCRIPT), 0o700, self.LOGIN_MAIL_OWNER
        )

    def _check_login_mail_pam_line(self) -> bool:
        """Prüft die aktive pam_exec-session-Zeile für den Login-Mail-Hook.

        Returns:
            True, wenn eine passende session-Zeile aktiv vorhanden ist.
        """
        content = Path(self.PAM_SSHD).read_text(encoding="utf-8")
        pattern = rf"^\s*session\s+.*pam_exec\.so.*{re.escape(self.LOGIN_MAIL_SCRIPT)}"
        if re.search(pattern, content, re.MULTILINE):
            self.send_message(LogLevel.INFO, "ssh", "Login-Mail-PAM-Zeile: OK")
            return True
        self.send_message(LogLevel.ERROR, "ssh", "Login-Mail-PAM-Zeile fehlt")
        return False

    # --- Helfer ---

    def _check_package_installed(self, package: str) -> bool:
        """Prüft per dpkg-query, ob package installiert ist.

        Args:
            package: Paketname.

        Returns:
            True, wenn dpkg-query den Status "install ok installed" meldet.
        """
        action = SysCmdAction(
            command=[self.DPKG_QUERY_BIN, "-W", "-f=${Status}", package], timeout=15
        )
        if self.run_action(action) == 0 and "install ok installed" in action.stdout:
            self.send_message(LogLevel.INFO, "ssh", f"Paket {package}: installiert")
            return True
        self.send_message(LogLevel.ERROR, "ssh", f"Paket {package}: nicht installiert")
        return False

    def _user_exists(self, user: str) -> bool:
        """Prüft per getent passwd, ob user existiert.

        Args:
            user: Benutzername.

        Returns:
            True, wenn der Benutzer existiert.
        """
        action = SysCmdAction(command=[self.GETENT_BIN, "passwd", user], timeout=15)
        return self.run_action(action) == 0

    def _home_dir(self, user: str) -> str | None:
        """Ermittelt das Home-Verzeichnis von user über getent passwd.

        Args:
            user: Benutzername.

        Returns:
            Home-Verzeichnis, oder None, wenn nicht ermittelbar.
        """
        action = SysCmdAction(command=[self.GETENT_BIN, "passwd", user], timeout=15)
        if self.run_action(action) != 0:
            return None
        fields = action.stdout.strip().split(":")
        return fields[5] if len(fields) > 5 and fields[5] else None

    def _check_group_membership(self, user: str, group: str) -> bool:
        """Prüft, ob user Mitglied von group ist.

        Args:
            user: Benutzername.
            group: Gruppenname.

        Returns:
            True bei Mitgliedschaft.
        """
        action = SysCmdAction(command=[self.ID_BIN, "-nG", user], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(
                LogLevel.ERROR, "ssh", f"Gruppenzugehörigkeit von {user}: nicht lesbar"
            )
            return False
        if group in action.stdout.split():
            self.send_message(LogLevel.INFO, "ssh", f"{user} in Gruppe {group} — OK")
            return True
        self.send_message(LogLevel.ERROR, "ssh", f"{user} ist nicht in Gruppe {group}")
        return False

    def _check_nonempty_file(self, path: Path, label: str) -> bool:
        """Prüft, dass path als nicht-leere Datei existiert.

        Args:
            path: Zu prüfende Datei.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn path existiert und nicht leer ist.
        """
        try:
            size = path.stat().st_size
        except OSError:
            self.send_message(LogLevel.ERROR, "ssh", f"{label}: existiert nicht")
            return False
        if size > 0:
            self.send_message(LogLevel.INFO, "ssh", f"{label}: vorhanden — OK")
            return True
        self.send_message(LogLevel.ERROR, "ssh", f"{label}: ist leer")
        return False

    def _check_file_mode(self, path: Path, expected_mode: int, owner: str) -> bool:
        """Prüft exakte Rechte und Eigentümer:Gruppe (== owner:owner) von path.

        Args:
            path: Zu prüfender Pfad.
            expected_mode: Erwartete Rechte.
            owner: Erwarteter Eigentümer (Gruppe wird gleichnamig erwartet).

        Returns:
            True, wenn Rechte und Eigentümer exakt dem Soll entsprechen.
        """
        try:
            st = path.stat()
        except OSError:
            self.send_message(LogLevel.ERROR, "ssh", f"{path}: existiert nicht")
            return False
        mode = stat.S_IMODE(st.st_mode)
        owner_name = pwd.getpwuid(st.st_uid).pw_name
        group_name = grp.getgrgid(st.st_gid).gr_name
        ok = True
        if mode != expected_mode:
            self.send_message(
                LogLevel.ERROR,
                "ssh",
                f"{path}: Rechte {oct(mode)}, soll {oct(expected_mode)}",
            )
            ok = False
        if owner_name != owner or group_name != owner:
            self.send_message(
                LogLevel.ERROR,
                "ssh",
                f"{path}: Eigentümer {owner_name}:{group_name}, soll {owner}:{owner}",
            )
            ok = False
        if ok:
            self.send_message(LogLevel.INFO, "ssh", f"{path}: Rechte/Eigentümer — OK")
        return ok
