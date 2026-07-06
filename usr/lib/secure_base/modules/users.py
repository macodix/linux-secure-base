"""Modul users — Hauptbenutzer, ssh-users-Gruppe, TOTP.

Legt den Hauptbenutzer und die Gruppe ssh-users an, setzt dessen
Login-Passwort und SSH-Pubkey und richtet TOTP (google-authenticator)
ein. Setzt das root-Passwort NICHT — prüft es nur als Vorbedingung.
Betriebsart über den Schlüssel operation.
"""

import grp
import pwd
import re
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.permissions_action import PermissionsAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Benutzername nach den üblichen Login-Namensregeln (useradd/NAME_REGEX):
# a-z/_ am Anfang, danach a-z, 0-9, _ und -, Gesamtlänge höchstens 32 Zeichen.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# SSH-Pubkey-Zeile: bekannter Schlüsseltyp gefolgt von mindestens einem
# Leerzeichen/Tab vor dem Base64-Teil. Nur der Typ wird geprüft
# (Aussperr-Schutz vor einer leeren oder syntaktisch defekten Zeile) — der
# Schlüsselinhalt selbst bleibt Sache von sshd.
_PUBKEY_RE = re.compile(r"^(ssh-(rsa|ed25519|ecdsa)|ecdsa-sha2-nistp[0-9]+)[ \t]")

# Passwort-Hash-Werte, die "kein Passwort gesetzt" bedeuten
# (getent shadow, Feld 2): leer, gesperrt (!) oder deaktiviert (*).
_UNSET_HASHES = frozenset({"", "!", "*"})

_Step = Callable[[], int]


def _shadow_hash_from_line(line: str) -> str:
    """Extrahiert das Passwort-Hash-Feld aus einer getent-shadow-Zeile.

    Args:
        line: Ausgabe von `getent shadow <user>` (eine Zeile).

    Returns:
        Feld 2 (Passwort-Hash) oder Leerstring, wenn die Zeile kein
        zweites Feld hat.
    """
    fields = line.strip().split(":")
    return fields[1] if len(fields) > 1 else ""


def _is_password_set(hash_value: str) -> bool:
    """Prüft, ob ein shadow-Hash ein gesetztes Passwort bedeutet.

    Args:
        hash_value: Passwort-Hash-Feld aus getent shadow.

    Returns:
        True, wenn der Hash weder leer noch '!' noch '*' ist.
    """
    return hash_value not in _UNSET_HASHES


class _ChpasswdStdinAction(Action):
    """Setzt ein Login-Passwort über chpasswd, Übergabe nur per stdin.

    SysCmdAction unterstützt keine Standardeingabe für den Kindprozess
    (konv-scripting-python.md Abschnitt 4.4: Geheimnisse nie in
    Argumentliste oder Meldung). Diese modul-eigene Aktion reicht
    Benutzername und Passwort ausschließlich über die stdin-Pipe von
    chpasswd durch; beides taucht nie in argv, stdout, stderr-Auswertung
    oder einer ActionError-Meldung auf.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        user: Benutzername.
        password: Neues Login-Passwort (Klartext, nur für die stdin-Pipe).
        chpasswd_bin: Pfad zum chpasswd-Programm.
        timeout: Zeitgrenze in Sekunden.
        returncode: Rückgabewert von chpasswd nach run(); -1 vor der
            Ausführung.
    """

    PARAMS: ClassVar[list[str]] = ["user", "password", "chpasswd_bin", "timeout"]

    def __init__(
        self,
        user: str,
        password: str,
        chpasswd_bin: str,
        timeout: float = 30.0,
    ) -> None:
        """Initialisiert die Passwort-Setz-Aktion.

        Args:
            user: Benutzername.
            password: Neues Login-Passwort (Klartext).
            chpasswd_bin: Pfad zum chpasswd-Programm.
            timeout: Zeitgrenze in Sekunden für chpasswd (SIC-05).
        """
        super().__init__()
        self.user = user
        self.password = password
        self.chpasswd_bin = chpasswd_bin
        self.timeout = timeout
        self.returncode: int = -1

    def run(self) -> str:
        """Führt chpasswd aus und liefert den Ausführungsstatus.

        Das Format je Zeile ist "user:password"; chpasswd trennt am
        ersten Doppelpunkt, ein Doppelpunkt im Passwort selbst bleibt
        also unschädlich.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei Timeout, Returncode != 0 oder Startfehler.
                Die Meldung enthält nie das Passwort.
        """
        self.status = "running"
        stdin_data = f"{self.user}:{self.password}\n".encode()
        try:
            with subprocess.Popen(
                [self.chpasswd_bin],
                shell=False,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ) as proc:
                try:
                    proc.communicate(input=stdin_data, timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    self.returncode = (
                        proc.returncode if proc.returncode is not None else -1
                    )
                    self.status = "failed"
                    raise ActionError(
                        f"Zeitgrenze ({self.timeout}s) überschritten: chpasswd"
                    ) from None
                self.returncode = proc.returncode if proc.returncode is not None else -1
                if self.returncode != 0:
                    self.status = "failed"
                    raise ActionError(f"chpasswd endete mit Code {self.returncode}")
        except ActionError:
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"chpasswd konnte nicht gestartet werden: {exc}") from exc
        finally:
            stdin_data = b""

        self.status = "finished"
        return self.status


class Users(Module):
    """Hauptbenutzer, ssh-users-Gruppe und TOTP über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "main_user",
        "main_user_password",
        "main_user_pubkey",
    ]

    # Fachliche Konstanten: von außen nie überschreibbar, keine
    # umgebungsspezifischen Hardcodes (konv-scripting-python.md 4.4).
    GROUP_NAME: ClassVar[str] = "ssh-users"
    SHELL: ClassVar[str] = "/bin/bash"
    PKG_GOOGLE_AUTHENTICATOR: ClassVar[str] = "libpam-google-authenticator"
    CONTROLLED_PATH: ClassVar[str] = "/usr/sbin:/usr/bin:/sbin:/bin"

    # Programmpfade als Klassenattribute statt Literale in den Schritten
    # (siehe Begründung in base.py): feste Vorgaben, die eine
    # Testunterklasse außerhalb dieses Moduls überschreiben kann, um
    # Systembefehle in einem echten Modul-Subprozess durch harmlose
    # Platzhalter zu ersetzen — ohne dieses Modul anzufassen.
    GETENT_BIN: ClassVar[str] = "/usr/bin/getent"
    ID_BIN: ClassVar[str] = "/usr/bin/id"
    DPKG_BIN: ClassVar[str] = "/usr/bin/dpkg"
    GROUPADD_BIN: ClassVar[str] = "/usr/sbin/groupadd"
    USERADD_BIN: ClassVar[str] = "/usr/sbin/useradd"
    USERMOD_BIN: ClassVar[str] = "/usr/sbin/usermod"
    CHPASSWD_BIN: ClassVar[str] = "/usr/sbin/chpasswd"
    RUNUSER_BIN: ClassVar[str] = "/usr/sbin/runuser"
    GOOGLE_AUTHENTICATOR_BIN: ClassVar[str] = "/usr/bin/google-authenticator"

    # apt-Aktionsklasse als Klassenattribut wie base — für Testumlenkung
    # per Unterklasse (kein systemd-Bezug in diesem Modul).
    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    main_user: str
    main_user_password: str
    main_user_pubkey: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigem Benutzernamen oder Pubkey-Format.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        return self._install()

    def _validate(self) -> None:
        """Prüft Benutzername und Pubkey-Format und lehnt ungültige Werte ab.

        Beide Werte gehen in Systembefehle bzw. eine Datei. SysCmdAction hat
        bewusst keinen Optionsterminator, deshalb prüft das Modul die Werte
        vor der Verwendung (konv-scripting-python.md Abschnitt 4.2). Eine
        leere oder syntaktisch defekte Pubkey-Zeile darf nicht durchgehen —
        sonst landet der Hauptbenutzer unter SSH-Härtung ohne brauchbaren
        Pubkey (Aussperr-Schutz).

        Raises:
            ModuleError: Wenn main_user kein gültiger Benutzername ist,
                oder main_user_pubkey leer ist oder keinem bekannten
                Schlüsseltyp entspricht.
        """
        if not _USERNAME_RE.match(self.main_user):
            raise ModuleError(f"Ungültiger Benutzername: {self.main_user!r}")
        pubkey = self.main_user_pubkey.strip()
        if not pubkey:
            raise ModuleError(
                "Kein SSH-Pubkey für Hauptbenutzer konfiguriert (Aussperr-Schutz)"
            )
        if not _PUBKEY_RE.match(pubkey):
            raise ModuleError(
                f"Pubkey-Format unbekannt: {pubkey[:40]!r} (Aussperr-Schutz)"
            )

    # --- install ---

    def _install(self) -> int:
        """Richtet Hauptbenutzer, Gruppe, Passwort, Pubkey und TOTP ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, _Step]] = [
            ("root-Passwort-Vorbedingung prüfen", self._step_check_root_password),
            ("Paket installieren", self._step_install_package),
            ("Gruppe ssh-users anlegen", self._step_ensure_group),
            ("Hauptbenutzer anlegen", self._step_ensure_user),
            ("Mitgliedschaft in ssh-users sicherstellen", self._step_ensure_membership),
            ("Login-Shell setzen", self._step_ensure_shell),
            ("Passwort setzen", self._step_set_password),
            (".ssh-Verzeichnis anlegen", self._step_ssh_dir),
            ("SSH-Pubkey hinterlegen", self._step_authorized_keys),
            ("TOTP-Secret einrichten", self._step_totp),
        ]
        for label, step in steps:
            self.send_message(LogLevel.INFO, "users", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "users", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _step_check_root_password(self) -> int:
        """Prüft die Vorbedingung: root-Passwort ist bereits gesetzt.

        Das Modul setzt das root-Passwort bewusst NICHT — nur die Prüfung.

        Returns:
            0, wenn root ein gesetztes Passwort hat, sonst 1.
        """
        if self._shadow_password_set("root"):
            return 0
        self.send_message(LogLevel.ERROR, "users", "root-Passwort ist nicht gesetzt")
        return 1

    def _step_install_package(self) -> int:
        """Installiert libpam-google-authenticator.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        action = self.APT_ACTION_CLS(packages=[self.PKG_GOOGLE_AUTHENTICATOR])
        return self.run_action(action)

    def _step_ensure_group(self) -> int:
        """Legt die Gruppe ssh-users an; idempotent über groupadd -f.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        action = SysCmdAction(
            command=[self.GROUPADD_BIN, "-f", "--", self.GROUP_NAME], timeout=30
        )
        return self.run_action(action)

    def _step_ensure_user(self) -> int:
        """Legt den Hauptbenutzer an, wenn er noch nicht existiert.

        Returns:
            0 bei Erfolg oder wenn der Benutzer bereits existiert, 1 bei Fehler.
        """
        if self._user_exists(self.main_user):
            self.send_message(
                LogLevel.INFO,
                "users",
                f"Benutzer {self.main_user} existiert bereits — übersprungen",
            )
            return 0
        action = SysCmdAction(
            command=[
                self.USERADD_BIN,
                "-m",
                "-s",
                self.SHELL,
                "-G",
                self.GROUP_NAME,
                "--",
                self.main_user,
            ],
            timeout=30,
        )
        if self.run_action(action) != 0:
            return 1
        self.send_message(LogLevel.INFO, "users", f"Benutzer {self.main_user} angelegt")
        return 0

    def _step_ensure_membership(self) -> int:
        """Stellt die Mitgliedschaft in ssh-users sicher; idempotent.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        action = SysCmdAction(
            command=[
                self.USERMOD_BIN,
                "-a",
                "-G",
                self.GROUP_NAME,
                "--",
                self.main_user,
            ],
            timeout=30,
        )
        return self.run_action(action)

    def _step_ensure_shell(self) -> int:
        """Setzt die Login-Shell des Hauptbenutzers; idempotent.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        action = SysCmdAction(
            command=[self.USERMOD_BIN, "-s", self.SHELL, "--", self.main_user],
            timeout=30,
        )
        return self.run_action(action)

    def _step_set_password(self) -> int:
        """Setzt das Login-Passwort, wenn noch keins gesetzt ist.

        Returns:
            0 bei Erfolg oder wenn bereits gesetzt, 1 bei Fehler.
        """
        if self._shadow_password_set(self.main_user):
            self.send_message(
                LogLevel.INFO,
                "users",
                f"Passwort für {self.main_user} bereits gesetzt — übersprungen",
            )
            return 0
        if not self.main_user_password:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"Kein Passwort für {self.main_user} konfiguriert",
            )
            return 1
        action = _ChpasswdStdinAction(
            user=self.main_user,
            password=self.main_user_password,
            chpasswd_bin=self.CHPASSWD_BIN,
        )
        if self.run_action(action) != 0:
            return 1
        self.send_message(
            LogLevel.INFO, "users", f"Passwort für {self.main_user} gesetzt"
        )
        return 0

    def _step_ssh_dir(self) -> int:
        """Legt ~/.ssh an und setzt Rechte/Eigentümer defensiv.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        home = self._home_dir(self.main_user)
        if home is None:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"Home-Verzeichnis von {self.main_user} nicht ermittelbar",
            )
            return 1
        ssh_dir = str(Path(home) / ".ssh")
        if self.run_action(MakeDirAction(path=ssh_dir, mode=0o700)) != 0:
            return 1
        perm_action = PermissionsAction(
            path=ssh_dir, mode=0o700, owner=self.main_user, group=self.main_user
        )
        return self.run_action(perm_action)

    def _step_authorized_keys(self) -> int:
        """Hinterlegt den SSH-Pubkey in authorized_keys.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        home = self._home_dir(self.main_user)
        if home is None:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"Home-Verzeichnis von {self.main_user} nicht ermittelbar",
            )
            return 1
        authkeys = Path(home) / ".ssh" / "authorized_keys"
        pubkey = self.main_user_pubkey.strip()

        if authkeys.exists():
            try:
                existing = authkeys.read_text(encoding="utf-8")
            except OSError:
                self.send_message(LogLevel.ERROR, "users", f"{authkeys}: nicht lesbar")
                return 1
            if pubkey in existing.splitlines():
                self.send_message(
                    LogLevel.INFO,
                    "users",
                    f"Pubkey für {self.main_user} bereits hinterlegt — übersprungen",
                )
                return self._fix_authorized_keys_owner(authkeys)
            new_content = existing
            if new_content and not new_content.endswith("\n"):
                new_content += "\n"
            new_content += pubkey + "\n"
        else:
            new_content = pubkey + "\n"

        write_action = WriteFileAction(
            dst=str(authkeys),
            content=new_content,
            mode=0o600,
            overwrite=True,
            safe_mode=False,
        )
        if self.run_action(write_action) != 0:
            return 1
        if self._fix_authorized_keys_owner(authkeys) != 0:
            return 1
        self.send_message(
            LogLevel.INFO, "users", f"Pubkey für {self.main_user} hinterlegt"
        )
        return 0

    def _fix_authorized_keys_owner(self, authkeys: Path) -> int:
        """Setzt Eigentümer/Rechte von authorized_keys defensiv.

        Args:
            authkeys: Pfad der authorized_keys-Datei.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        action = PermissionsAction(
            path=str(authkeys), mode=0o600, owner=self.main_user, group=self.main_user
        )
        return self.run_action(action)

    def _step_totp(self) -> int:
        """Richtet TOTP (google-authenticator) für den Hauptbenutzer ein.

        Läuft nicht-interaktiv über Kommandozeilenoptionen; Secret, QR-Code
        und Notfall-Codes werden nie ausgegeben oder geloggt — die Meldung
        nennt nur den Ablageort der Secret-Datei.

        Returns:
            0 bei Erfolg oder wenn bereits eingerichtet, 1 bei Fehler.
        """
        home = self._home_dir(self.main_user)
        if home is None:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"Home-Verzeichnis von {self.main_user} nicht ermittelbar",
            )
            return 1
        ga_file = Path(home) / ".google_authenticator"
        if ga_file.exists() and ga_file.stat().st_size > 0:
            self.send_message(
                LogLevel.INFO,
                "users",
                f"TOTP-Secret für {self.main_user} bereits vorhanden — übersprungen",
            )
            return 0
        command = [
            self.RUNUSER_BIN,
            "-u",
            self.main_user,
            "--",
            self.GOOGLE_AUTHENTICATOR_BIN,
            "-t",
            "-d",
            "-f",
            "-C",
            "-q",
            "-Q",
            "NONE",
            "-r",
            "3",
            "-R",
            "30",
            "-W",
        ]
        env = {
            "PATH": self.CONTROLLED_PATH,
            "HOME": home,
            "USER": self.main_user,
            "LOGNAME": self.main_user,
        }
        action = SysCmdAction(command=command, timeout=60, env=env)
        if self.run_action(action) != 0:
            return 1
        self.send_message(
            LogLevel.INFO,
            "users",
            f"TOTP-Secret für {self.main_user} abgelegt unter {ga_file}",
        )
        return 0

    # --- check ---

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit dem Soll ab.

        Läuft alle Prüfungen durch und sammelt das Ergebnis. Existiert der
        Hauptbenutzer nicht, brechen die folgenden Pfad-Prüfungen sofort ab
        (sie lassen sich ohne Benutzer nicht auflösen).

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_package_installed(self.PKG_GOOGLE_AUTHENTICATOR)
        ok &= self._check_group_exists(self.GROUP_NAME)

        if not self._user_exists(self.main_user):
            self.send_message(
                LogLevel.ERROR, "users", f"Benutzer {self.main_user} existiert nicht"
            )
            return 1

        ok &= self._check_shell(self.main_user, self.SHELL)
        ok &= self._check_group_membership(self.main_user, self.GROUP_NAME)
        ok &= self._check_password_set(self.main_user)

        home = self._home_dir(self.main_user)
        if home is None:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"Home-Verzeichnis von {self.main_user} nicht ermittelbar",
            )
            return 1

        ok &= self._check_ssh_dir(home)
        ok &= self._check_authorized_keys(home)
        ok &= self._check_totp(home)
        return 0 if ok else 1

    def _check_package_installed(self, pkg: str) -> bool:
        """Prüft über dpkg, ob pkg installiert ist.

        Args:
            pkg: Paketname.

        Returns:
            True, wenn installiert.
        """
        action = SysCmdAction(command=[self.DPKG_BIN, "-s", pkg], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(
                LogLevel.ERROR, "users", f"Paket {pkg}: nicht installiert"
            )
            return False
        self.send_message(LogLevel.INFO, "users", f"Paket {pkg}: installiert — OK")
        return True

    def _check_group_exists(self, group: str) -> bool:
        """Prüft über getent, ob group existiert.

        Args:
            group: Gruppenname.

        Returns:
            True, wenn die Gruppe existiert.
        """
        action = SysCmdAction(command=[self.GETENT_BIN, "group", group], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(
                LogLevel.ERROR, "users", f"Gruppe {group}: existiert nicht"
            )
            return False
        self.send_message(LogLevel.INFO, "users", f"Gruppe {group}: existiert — OK")
        return True

    def _check_shell(self, user: str, shell: str) -> bool:
        """Prüft die Login-Shell von user gegen shell.

        Args:
            user: Benutzername.
            shell: Soll-Shell.

        Returns:
            True bei Übereinstimmung.
        """
        action = SysCmdAction(command=[self.GETENT_BIN, "passwd", user], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(
                LogLevel.ERROR, "users", f"{user}: passwd-Eintrag nicht lesbar"
            )
            return False
        fields = action.stdout.strip().split(":")
        current = fields[6] if len(fields) > 6 else ""
        if current == shell:
            self.send_message(
                LogLevel.INFO, "users", f"Login-Shell {user}: {current} — OK"
            )
            return True
        self.send_message(
            LogLevel.ERROR, "users", f"Login-Shell {user}: ist {current}, soll {shell}"
        )
        return False

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
                LogLevel.ERROR,
                "users",
                f"Gruppenzugehörigkeit von {user}: nicht lesbar",
            )
            return False
        if group in action.stdout.split():
            self.send_message(LogLevel.INFO, "users", f"{user} in Gruppe {group} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "users", f"{user} ist nicht in Gruppe {group}"
        )
        return False

    def _check_password_set(self, user: str) -> bool:
        """Prüft, ob user ein gesetztes Login-Passwort hat.

        Args:
            user: Benutzername.

        Returns:
            True, wenn ein Passwort gesetzt ist.
        """
        if self._shadow_password_set(user):
            self.send_message(
                LogLevel.INFO, "users", f"Login-Passwort {user}: gesetzt — OK"
            )
            return True
        self.send_message(
            LogLevel.ERROR, "users", f"{user} hat kein gesetztes Login-Passwort"
        )
        return False

    def _check_ssh_dir(self, home: str) -> bool:
        """Prüft Rechte/Eigentümer von ~/.ssh.

        Args:
            home: Home-Verzeichnis des Hauptbenutzers.

        Returns:
            True bei exaktem Soll-Zustand (0700, Eigentümer main_user).
        """
        return self._check_file_mode(Path(home) / ".ssh", 0o700, self.main_user)

    def _check_authorized_keys(self, home: str) -> bool:
        """Prüft Rechte, Eigentümer und Inhalt von ~/.ssh/authorized_keys.

        Args:
            home: Home-Verzeichnis des Hauptbenutzers.

        Returns:
            True bei exaktem Soll-Zustand (0600, Eigentümer main_user,
            nicht leer).
        """
        authkeys = Path(home) / ".ssh" / "authorized_keys"
        ok = self._check_file_mode(authkeys, 0o600, self.main_user)
        if ok and authkeys.stat().st_size == 0:
            self.send_message(LogLevel.ERROR, "users", f"{authkeys}: ist leer")
            ok = False
        return ok

    def _check_totp(self, home: str) -> bool:
        """Prüft Rechte, Eigentümer und Inhalt von ~/.google_authenticator.

        Args:
            home: Home-Verzeichnis des Hauptbenutzers.

        Returns:
            True bei Soll-Zustand (kein Gruppen-/Welt-Zugriff, Eigentümer
            main_user, nicht leer).
        """
        ga_file = Path(home) / ".google_authenticator"
        ok = self._check_owner_only_mode(ga_file, self.main_user)
        if ok and ga_file.stat().st_size == 0:
            self.send_message(LogLevel.ERROR, "users", f"{ga_file}: ist leer")
            ok = False
        return ok

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
            self.send_message(LogLevel.ERROR, "users", f"{path}: existiert nicht")
            return False
        mode = stat.S_IMODE(st.st_mode)
        owner_name = pwd.getpwuid(st.st_uid).pw_name
        group_name = grp.getgrgid(st.st_gid).gr_name
        ok = True
        if mode != expected_mode:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"{path}: Rechte {oct(mode)}, soll {oct(expected_mode)}",
            )
            ok = False
        if owner_name != owner or group_name != owner:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"{path}: Eigentümer {owner_name}:{group_name}, soll {owner}:{owner}",
            )
            ok = False
        if ok:
            self.send_message(LogLevel.INFO, "users", f"{path}: Rechte/Eigentümer — OK")
        return ok

    def _check_owner_only_mode(self, path: Path, owner: str) -> bool:
        """Prüft, dass Gruppe und andere keinen Zugriff auf path haben.

        Args:
            path: Zu prüfender Pfad.
            owner: Erwarteter Eigentümer (Gruppe wird gleichnamig erwartet).

        Returns:
            True, wenn Rechte keinen Gruppen-/Welt-Zugriff erlauben
            (Maske & 0o077 == 0) und der Eigentümer stimmt.
        """
        try:
            st = path.stat()
        except OSError:
            self.send_message(LogLevel.ERROR, "users", f"{path}: existiert nicht")
            return False
        mode = stat.S_IMODE(st.st_mode)
        owner_name = pwd.getpwuid(st.st_uid).pw_name
        group_name = grp.getgrgid(st.st_gid).gr_name
        ok = True
        if mode & 0o077:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"{path}: Rechte {oct(mode)} erlauben Gruppen-/Welt-Zugriff",
            )
            ok = False
        if owner_name != owner or group_name != owner:
            self.send_message(
                LogLevel.ERROR,
                "users",
                f"{path}: Eigentümer {owner_name}:{group_name}, soll {owner}:{owner}",
            )
            ok = False
        if ok:
            self.send_message(LogLevel.INFO, "users", f"{path}: Rechte/Eigentümer — OK")
        return ok

    # --- Helfer ---

    def _shadow_password_set(self, user: str) -> bool:
        """Prüft per getent shadow, ob user einen gesetzten Passwort-Hash hat.

        Args:
            user: Benutzername.

        Returns:
            True, wenn ein Passwort gesetzt ist; False auch, wenn der
            Shadow-Eintrag nicht gelesen werden kann.
        """
        action = SysCmdAction(command=[self.GETENT_BIN, "shadow", user], timeout=15)
        if self.run_action(action) != 0:
            return False
        return _is_password_set(_shadow_hash_from_line(action.stdout))

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
