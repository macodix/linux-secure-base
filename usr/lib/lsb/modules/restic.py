"""Modul restic — verschlüsselte Datensicherung auf ein externes SFTP-Ziel.

Installiert restic, initialisiert das Backup-Repository auf einem bereits
bestehenden SFTP-Ziel und legt Backup-Skript sowie täglichen Cron-Job an
(kein Modul-eigener Dienst). Betriebsart über den Schlüssel operation. Der
SFTP-Zugang (SSH-Schlüssel, Host-Alias in /root/.ssh/config, Autorisierung
beim Anbieter, Host-Key) ist Vorbedingung; dieses Modul richtet ihn nicht
ein, sondern prüft nur seine Erreichbarkeit.

Die Repo-Passphrase kommt ausschließlich aus der Konfiguration und landet
ausschließlich in der Passphrase-Datei (Rechte 0600) — nie in Meldungen,
Ausnahmen oder Befehlsargumenten.
"""

import os
import re
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from pifos.actions.apt_action import AptAction
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Rechnername: gleiches Muster wie lsb.modules.base — anchored, kein
# Whitespace/Metazeichen, da fqdn in Dateipfade und Skriptinhalt eingeht.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# E-Mail-Adresse: gleiches Muster wie im Bash-Original.
_MAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")

# SFTP-Host-Alias: muss mit einem alphanumerischen Zeichen beginnen (über das
# Bash-Original hinausgehende Verschärfung) — der Wert ist das letzte Element
# des sftp-Aufrufs; SysCmdAction hat keinen Optionsterminator, ein führendes
# "-" könnte sonst als Option statt als Hostname interpretiert werden.
_SFTP_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# SFTP-Zielpfad: absoluter Pfad ohne Whitespace/Sonderzeichen (gleiches
# Muster wie im Bash-Original); ein führendes "/" schließt "-" als
# Anfangszeichen bereits aus.
_SFTP_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")

_BACKUP_SCRIPT_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail

# Von lsb/restic angelegt — nicht von Hand bearbeiten.
# cron-Umgebung ist spartanisch — PATH explizit setzen.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RESTIC_REPO="{repo}"
RESTIC_PASS="{passphrase_file}"
ADMIN_MAIL="{admin_mail}"
LOGFILE="$(mktemp)"
trap 'rm -f "$LOGFILE"' EXIT

run() {{
    restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" backup \\
        /etc /home /var/log /root
    restic -r "$RESTIC_REPO" -p "$RESTIC_PASS" forget \\
        --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
}}

if ! run >"$LOGFILE" 2>&1; then
    mail -s "Backup FEHLGESCHLAGEN auf {fqdn}" "$ADMIN_MAIL" \\
        <"$LOGFILE"
    exit 1
fi

# Erfolgs-Sentinel für die monit-Frische-Überwachung (restic-Check).
mkdir -p {sentinel_dir} 2>/dev/null || true
touch {sentinel_file} 2>/dev/null || true
"""


def _backup_script_content(
    repo: str,
    admin_mail: str,
    fqdn: str,
    passphrase_file: str,
    sentinel_dir: str,
    sentinel_file: str,
) -> str:
    """Baut den Inhalt des Backup-Skripts.

    Args:
        repo: restic-Repo-URL (sftp:<alias>:<pfad>).
        admin_mail: Mail-Adresse für die Fehlermeldung.
        fqdn: Rechnername für den Mail-Betreff.
        passphrase_file: Pfad zur Passphrase-Datei (nicht ihr Inhalt).
        sentinel_dir: Verzeichnis des monit-Frische-Sentinels.
        sentinel_file: Datei des monit-Frische-Sentinels.

    Returns:
        Vollständiger Skriptinhalt.
    """
    return _BACKUP_SCRIPT_TEMPLATE.format(
        repo=repo,
        passphrase_file=passphrase_file,
        admin_mail=admin_mail,
        fqdn=fqdn,
        sentinel_dir=sentinel_dir,
        sentinel_file=sentinel_file,
    )


def _cron_content(backup_script: str) -> str:
    """Baut den Inhalt der Cron-Datei (täglich 02:30).

    Args:
        backup_script: Pfad zum Backup-Skript.

    Returns:
        Vollständiger Cron-Dateiinhalt.
    """
    return (
        "# Datensicherung (restic) - täglich um 02:30\n"
        "# Von lsb/restic angelegt — nicht von Hand bearbeiten.\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        f"30 2 * * *  root  {backup_script}\n"
    )


def _mkdir_batch_commands(path: str) -> list[str]:
    """Baut die sftp-Batch-Kommandos zum idempotenten Anlegen von path.

    Jede Pfadkomponente einzeln per "-mkdir" (führendes "-" ignoriert
    "existiert bereits"), zum Schluss "cd path" ohne "-" als Erfolgs-
    Verifikation.

    Args:
        path: Anzulegender absoluter Zielpfad.

    Returns:
        Liste der sftp-Batch-Kommandozeilen.
    """
    commands: list[str] = []
    acc = ""
    for part in path.split("/"):
        if not part:
            continue
        acc += f"/{part}"
        commands.append(f"-mkdir {acc}")
    commands.append(f"cd {path}")
    return commands


class Restic(Module):
    """Datensicherung mit restic auf ein externes SFTP-Ziel."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "fqdn",
        "admin_mail",
        "sftp_host_alias",
        "sftp_path",
        "restic_passphrase",
    ]

    # Programmpfade und Schreibziele als Klassenattribute (wie lsb.modules.base):
    # feste, sichere Vorgaben, die eine Testunterklasse gezielt umlenken kann,
    # ohne dieses Modul anzufassen und ohne Laufzeit-Schalter in Produktionscode.
    RESTIC_BIN: ClassVar[str] = "/usr/bin/restic"
    SFTP_BIN: ClassVar[str] = "/usr/bin/sftp"
    PASSPHRASE_FILE: ClassVar[str] = "/root/config/restic-passphrase"  # noqa: S105
    CONFIG_DIR: ClassVar[str] = "/root/config"
    BACKUP_SCRIPT_DIR: ClassVar[str] = "/usr/local/sbin"
    CRON_DIR: ClassVar[str] = "/etc/cron.d"
    SENTINEL_DIR: ClassVar[str] = "/var/lib/secure-base"
    SENTINEL_FILE: ClassVar[str] = "/var/lib/secure-base/restic-last-success"

    # apt-Aktionsklasse als Klassenattribut (wie lsb.modules.base) — für
    # Testumlenkung per Unterklasse. Kein SYSTEMD_ACTION_CLS: restic hat
    # keinen Modul-eigenen Dienst (cron = Distro-Default).
    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    fqdn: str
    admin_mail: str
    sftp_host_alias: str
    sftp_path: str
    restic_passphrase: str

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
        """Prüft alle Konfigurationswerte, bevor sie in Befehle oder Dateiinhalte gehen.

        SysCmdAction hat bewusst keinen Optionsterminator, deshalb prüft das
        Modul die Werte vor der Verwendung (konv-scripting-python.md
        Abschnitt 4.2). Die Passphrase selbst geht nie in einen
        Befehlsaufruf (nur ihr Dateipfad); geprüft wird hier nur, dass sie
        nicht leer ist.

        Raises:
            ModuleError: Wenn einer der Werte ungültig ist.
        """
        if not _HOSTNAME_RE.match(self.fqdn):
            raise ModuleError(f"Ungültiger Rechnername: {self.fqdn!r}")
        if not _MAIL_RE.match(self.admin_mail):
            raise ModuleError(f"Ungültige Mail-Adresse: {self.admin_mail!r}")
        if not _SFTP_ALIAS_RE.match(self.sftp_host_alias):
            raise ModuleError(f"Ungültiger SFTP-Host-Alias: {self.sftp_host_alias!r}")
        if not _SFTP_PATH_RE.match(self.sftp_path):
            raise ModuleError(f"Ungültiger SFTP-Zielpfad: {self.sftp_path!r}")
        if not self.restic_passphrase:
            raise ModuleError("restic_passphrase ist leer")

    def _repo_url(self) -> str:
        """Baut die restic-Repo-URL aus Host-Alias und Zielpfad."""
        return f"sftp:{self.sftp_host_alias}:{self.sftp_path}"

    def _backup_script_path(self) -> str:
        """Baut den Pfad des FQDN-benannten Backup-Skripts."""
        return f"{self.BACKUP_SCRIPT_DIR}/{self.fqdn}-backup.sh"

    def _cron_file_path(self) -> str:
        """Baut den Pfad der FQDN-benannten Cron-Datei."""
        return f"{self.CRON_DIR}/{self.fqdn}-backup"

    def _install(self) -> int:
        """Richtet Paket, Backup-Ziel, Passphrase, Skript und Cron-Job ein.

        Schrittliste mit Abbruch beim ersten Fehler (wie lsb.modules.base).
        Einzelne Schritte kapseln mehr als eine Aktion (z. B. bedingtes
        Überspringen bei bereits initialisiertem Repo); dafür ist jeder
        Schritt hier eine gebundene Methode statt einer einzelnen Action.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, Callable[[], int]]] = [
            ("Paket installieren", self._step_install_package),
            ("SFTP-Erreichbarkeit prüfen", self._step_check_sftp_reachable),
            ("Zielverzeichnis sicherstellen", self._step_ensure_remote_dir),
            ("Konfigurationsverzeichnis anlegen", self._step_ensure_config_dir),
            ("Passphrase-Datei schreiben", self._step_ensure_passphrase),
            ("Repo initialisieren", self._step_init_repo),
            ("Backup-Skript schreiben", self._step_write_backup_script),
            ("Cron-Datei schreiben", self._step_write_cron),
            ("Monit-Sentinel anlegen", self._step_write_sentinel),
        ]
        for label, step in steps:
            self.send_message(LogLevel.INFO, "restic", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "restic", f"fehlgeschlagen: {label}")
                return 1
        return 0

    def _step_install_package(self) -> int:
        """Installiert das Paket restic."""
        return self.run_action(self.APT_ACTION_CLS(packages=["restic"]))

    def _step_check_sftp_reachable(self) -> int:
        """Prüft die Erreichbarkeit des SFTP-Ziels (Vorbedingung, nie eingerichtet)."""
        return self._run_sftp_batch(["pwd"])

    def _step_ensure_remote_dir(self) -> int:
        """Legt das Zielverzeichnis am SFTP-Ziel idempotent an."""
        return self._run_sftp_batch(_mkdir_batch_commands(self.sftp_path))

    def _step_ensure_config_dir(self) -> int:
        """Legt das Konfigurationsverzeichnis (CONFIG_DIR) mit 0700 an."""
        return self.run_action(
            MakeDirAction(path=self.CONFIG_DIR, mode=0o700, parents=True)
        )

    def _step_ensure_passphrase(self) -> int:
        """Schreibt die Passphrase-Datei, sofern nötig — idempotent und verlustsicher.

        Fehlt die Datei, wird sie geschrieben. Existiert sie bereits mit dem
        gleichen Wert, wird nichts getan. Weicht der Wert ab, wird das
        Überschreiben abgelehnt, solange das bestehende Repo mit der
        aktuellen Datei erreichbar und entschlüsselbar ist oder das
        SFTP-Ziel gerade nicht erreichbar ist — sonst würde ein
        funktionierendes Repo verwaisen.

        Returns:
            0 bei Erfolg, 1 bei abgelehntem oder fehlgeschlagenem Schreiben.
        """
        passphrase_path = Path(self.PASSPHRASE_FILE)
        if not passphrase_path.exists():
            rc = self.run_action(
                WriteFileAction(
                    dst=self.PASSPHRASE_FILE,
                    content=f"{self.restic_passphrase}\n",
                    mode=0o600,
                    overwrite=False,
                )
            )
            if rc == 0:
                self.send_message(
                    LogLevel.INFO,
                    "restic",
                    f"Passphrase-Datei {self.PASSPHRASE_FILE} geschrieben",
                )
            return rc

        current = self._read_passphrase_file()
        if current is None:
            self.send_message(LogLevel.ERROR, "restic", "Passphrase-Datei nicht lesbar")
            return 1
        if current == self.restic_passphrase:
            self.send_message(
                LogLevel.INFO,
                "restic",
                "Passphrase-Datei bereits vorhanden und unverändert — übersprungen",
            )
            return 0

        if self._restic_cat_config_succeeds(self._repo_url()):
            self.send_message(
                LogLevel.ERROR,
                "restic",
                "Passphrase weicht von der bestehenden, funktionierenden"
                " Passphrase-Datei ab — Überschreiben abgelehnt",
            )
            return 1
        if self._run_sftp_batch(["pwd"]) != 0:
            self.send_message(
                LogLevel.ERROR,
                "restic",
                "SFTP-Ziel nicht erreichbar — Datei wird nicht überschrieben",
            )
            return 1
        self.send_message(
            LogLevel.WARN,
            "restic",
            "Passphrase-Datei weicht ab; Ziel erreichbar, Repo mit bestehender"
            " Passphrase nicht lesbar — Datei wird überschrieben",
        )
        return self.run_action(
            WriteFileAction(
                dst=self.PASSPHRASE_FILE,
                content=f"{self.restic_passphrase}\n",
                mode=0o600,
                overwrite=True,
            )
        )

    def _step_init_repo(self) -> int:
        """Initialisiert das Repo, sofern es nicht bereits initialisiert ist."""
        repo = self._repo_url()
        if self._restic_cat_config_succeeds(repo):
            self.send_message(
                LogLevel.INFO,
                "restic",
                f"Repo {repo} bereits initialisiert — übersprungen",
            )
            return 0
        return self.run_action(
            SysCmdAction(
                command=[
                    self.RESTIC_BIN,
                    "-r",
                    repo,
                    "-p",
                    self.PASSPHRASE_FILE,
                    "init",
                ],
                timeout=60.0,
            )
        )

    def _step_write_backup_script(self) -> int:
        """Schreibt das Backup-Skript (vollständig eigene Datei, 0700)."""
        content = _backup_script_content(
            repo=self._repo_url(),
            admin_mail=self.admin_mail,
            fqdn=self.fqdn,
            passphrase_file=self.PASSPHRASE_FILE,
            sentinel_dir=self.SENTINEL_DIR,
            sentinel_file=self.SENTINEL_FILE,
        )
        return self.run_action(
            WriteFileAction(
                dst=self._backup_script_path(),
                content=content,
                mode=0o700,
                overwrite=True,
            )
        )

    def _step_write_cron(self) -> int:
        """Schreibt die Cron-Datei (vollständig eigene Datei, 0644)."""
        content = _cron_content(self._backup_script_path())
        return self.run_action(
            WriteFileAction(
                dst=self._cron_file_path(), content=content, mode=0o644, overwrite=True
            )
        )

    def _step_write_sentinel(self) -> int:
        """Legt das Sentinel-Verzeichnis an und aktualisiert die Baseline-Datei."""
        rc = self.run_action(
            MakeDirAction(path=self.SENTINEL_DIR, mode=0o755, parents=True)
        )
        if rc != 0:
            return rc
        return self.run_action(
            WriteFileAction(
                dst=self.SENTINEL_FILE, content="", mode=0o644, overwrite=True
            )
        )

    def _read_passphrase_file(self) -> str | None:
        """Liest die bestehende Passphrase-Datei.

        Returns:
            Inhalt ohne abschließenden Zeilenumbruch, oder None bei Lesefehler.
        """
        try:
            return Path(self.PASSPHRASE_FILE).read_text(encoding="utf-8").rstrip("\n")
        except OSError:
            return None

    def _restic_cat_config_succeeds(self, repo: str) -> bool:
        """Prüft still, ob das Repo mit der aktuellen Passphrase-Datei lesbar ist.

        Args:
            repo: restic-Repo-URL.

        Returns:
            True, wenn "restic cat config" mit Rückgabewert 0 endet.
        """
        action = SysCmdAction(
            command=[
                self.RESTIC_BIN,
                "-r",
                repo,
                "-p",
                self.PASSPHRASE_FILE,
                "cat",
                "config",
            ],
            timeout=30.0,
        )
        return self.run_action(action) == 0

    def _run_sftp_batch(self, commands: list[str]) -> int:
        """Führt sftp-Batch-Kommandos über den konfigurierten Host-Alias aus.

        Die Kommandos gehen in eine Batch-Datei (sftp "-b"); SysCmdAction hat
        keine Stdin-Anbindung, daher hier eine Datei statt "-b -" (Abweichung
        vom Bash-Original, gleiche Wirkung).

        Args:
            commands: sftp-Batch-Kommandozeilen.

        Returns:
            0 bei Erfolg, 1 bei Fehler.
        """
        content = "\n".join(commands) + "\n"
        fd, batch_path = tempfile.mkstemp(prefix="lsb-restic-sftp-", suffix=".batch")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            action = SysCmdAction(
                command=[
                    self.SFTP_BIN,
                    "-o",
                    "BatchMode=yes",
                    "-b",
                    batch_path,
                    self.sftp_host_alias,
                ],
                timeout=30.0,
            )
            return self.run_action(action)
        finally:
            Path(batch_path).unlink(missing_ok=True)

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand der eigenen install-Wirkung mit dem Soll ab.

        Kein System-Audit: geprüft wird ausschließlich, ob die eigenen
        install-Aktionen gewirkt haben. Läuft alle Prüfungen durch und
        sammelt das Ergebnis (wie lsb.modules.base).

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_command_succeeds([self.RESTIC_BIN, "version"], "restic-Paket")
        ok &= self._check_file_mode(self.PASSPHRASE_FILE, 0o600, "Passphrase-Datei")
        ok &= self._check_file_mode(self._backup_script_path(), 0o700, "Backup-Skript")
        ok &= self._check_file_mode(self._cron_file_path(), 0o644, "Cron-Datei")
        ok &= self._check_command_succeeds(
            [
                self.RESTIC_BIN,
                "-r",
                self._repo_url(),
                "-p",
                self.PASSPHRASE_FILE,
                "check",
            ],
            "Repo-Integrität",
        )
        self.send_message(
            LogLevel.INFO,
            "restic",
            "append-only (SFTP-Backend): am Anbieter einzurichten,"
            " hier nicht automatisiert prüfbar",
        )
        return 0 if ok else 1

    def _check_command_succeeds(self, command: list[str], label: str) -> bool:
        """Führt einen Befehl aus und meldet, ob er erfolgreich endet.

        Args:
            command: Auszuführender Befehl.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Rückgabewert 0, sonst False.
        """
        action = SysCmdAction(command=command, timeout=30.0)
        if self.run_action(action) == 0:
            self.send_message(LogLevel.INFO, "restic", f"{label}: OK")
            return True
        self.send_message(LogLevel.ERROR, "restic", f"{label}: fehlgeschlagen")
        return False

    def _check_file_mode(self, path: str, expected_mode: int, label: str) -> bool:
        """Liest die Rechte einer Datei und vergleicht sie mit dem Soll.

        Öffnet path mit O_NOFOLLOW (kein Symlink-Folgen, TOCTOU-fest) und
        liest die Rechte über den Deskriptor.

        Args:
            path: Zu prüfende Datei.
            expected_mode: Soll-Rechte.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            self.send_message(LogLevel.ERROR, "restic", f"{label}: nicht lesbar")
            return False
        try:
            current = stat.S_IMODE(os.fstat(fd).st_mode)
        finally:
            os.close(fd)
        if current == expected_mode:
            self.send_message(LogLevel.INFO, "restic", f"{label}: {oct(current)} — OK")
            return True
        self.send_message(
            LogLevel.ERROR,
            "restic",
            f"{label}: ist {oct(current)}, soll {oct(expected_mode)}",
        )
        return False
