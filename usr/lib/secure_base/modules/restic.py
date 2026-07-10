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

import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from pifos.actions.apt_action import AptAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Rechnername: gleiches Muster wie secure_base.modules.base — anchored, kein
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

# Von secure-base/restic angelegt — nicht von Hand bearbeiten.
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
        "# Von secure-base/restic angelegt — nicht von Hand bearbeiten.\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        f"30 2 * * *  root  {backup_script}\n"
    )


def _doc_value(values: dict[str, str], key: str) -> str:
    """Liest einen Wert für den Installationsbericht aus values.

    doc() fragt hier ausschließlich fest benannte, unkritische Schlüssel ab
    (fqdn, sftp_host_alias, sftp_path) — restic_passphrase wird nie über
    diesen Weg gelesen, ein Allowlist-Mechanismus wie im Bash-Original
    (doc_val) ist deshalb hier nicht nötig.

    Args:
        values: Konfigurationswerte des Moduls.
        key: Abzufragender Schlüssel.

    Returns:
        Wert aus values, oder "(leer/Default)" wenn leer oder nicht gesetzt.
    """
    return values.get(key) or "(leer/Default)"


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

    # Programmpfade und Schreibziele als Klassenattribute (wie Modul base):
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

    # apt-Aktionsklasse als Klassenattribut (wie secure_base.modules.base) — für
    # Testumlenkung per Unterklasse. Kein SYSTEMD_ACTION_CLS: restic hat
    # keinen Modul-eigenen Dienst (cron = Distro-Default).
    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction

    # Für _uninstall/_test: Paketstatus- und mail-Verfügbarkeitsprüfung
    # (gleiches Muster wie secure_base.modules.monit/fail2ban).
    DPKG_QUERY_BIN: ClassVar[str] = "/usr/bin/dpkg-query"
    MAIL_BIN: ClassVar[str] = "/usr/bin/mail"

    # Zeitgrenzen für den Funktionstest (_test): Integritätsprüfung und
    # Probe-Restore können bei großen Repos deutlich länger laufen als die
    # übrigen, schnellen Lesebefehle (cat config, snapshots).
    TEST_SNAPSHOTS_TIMEOUT: ClassVar[float] = 30.0
    TEST_CHECK_TIMEOUT: ClassVar[float] = 300.0
    TEST_RESTORE_TIMEOUT: ClassVar[float] = 60.0

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
        if self.operation == "uninstall":
            return self._uninstall()
        if self.operation == "test":
            return self._test()
        return self._install()

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Markdown-Abschnitt für den Installationsbericht.

        SICHERHEIT: restic_passphrase erscheint hier nie — weder Name noch
        Wert —, auch wenn sie in values steht. doc() liest ausschließlich
        die unten aufgeführten, unkritischen Schlüssel; alles andere in
        values bleibt unberücksichtigt. Dokumentiert wird nur der
        Ablageort der Passphrase (PASSPHRASE_FILE), nie ihr Inhalt.

        Args:
            values: Konfigurationswerte des Moduls (fqdn, admin_mail,
                sftp_host_alias, sftp_path, restic_passphrase, …).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Datensicherung".
        """
        fqdn = _doc_value(values, "fqdn")
        sftp_host_alias = _doc_value(values, "sftp_host_alias")
        sftp_path = _doc_value(values, "sftp_path")
        return (
            "\n## Datensicherung\n\n"
            "**Pakete:** restic\n\n"
            "**Dateien/Einstellungen:**\n\n"
            f"- `{cls.PASSPHRASE_FILE}`:\n"
            "  - `Repo-Passphrase (0600 root:root)`\n"
            f"- `{cls.BACKUP_SCRIPT_DIR}/{fqdn}-backup.sh`:\n"
            "  - `Backup-Skript (täglicher Cron-Lauf)`\n"
            f"- `{cls.CRON_DIR}/{fqdn}-backup`:\n"
            "  - `Cron-Eintrag: restic backup + forget`\n"
            f"\n**SFTP-Ziel:** `{sftp_host_alias}:{sftp_path}`\n\n"
            f"\n**Timer/Cron:** täglicher Lauf via {cls.CRON_DIR}/{fqdn}-backup\n"
            "\n> Hinweis: Repo-Passphrase wird nicht dokumentiert (Secret)."
            " Forget-Politik: --keep-daily 7 --keep-weekly 4 --keep-monthly 6."
            " append-only (konv-system.md Abschnitt 3.8 b): am SFTP-Backend"
            " vom Anbieter serverseitig einzurichten — clientseitig nicht"
            " erzwingbar. Integritäts- und Restore-Test: Modul restic mit"
            ' operation "test" (konv-system.md Abschnitt 3.8 c).\n'
        )

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

        Schrittliste mit Abbruch beim ersten Fehler (wie secure_base.modules.base).
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
                    safe_mode=False,
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
                # kein safe_mode: eine .bak-Sicherung würde die
                # Repo-Passphrase im Klartext duplizieren.
                safe_mode=False,
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
                safe_mode=False,
            )
        )

    def _step_write_cron(self) -> int:
        """Schreibt die Cron-Datei (vollständig eigene Datei, 0644)."""
        content = _cron_content(self._backup_script_path())
        return self.run_action(
            WriteFileAction(
                dst=self._cron_file_path(),
                content=content,
                mode=0o644,
                overwrite=True,
                safe_mode=False,
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
                dst=self.SENTINEL_FILE,
                content="",
                mode=0o644,
                overwrite=True,
                safe_mode=False,
            )
        )

    # --- uninstall ---

    def _uninstall(self) -> int:
        """Entfernt die lokalen install-Artefakte (Original: do_uninstall).

        Das Backup-Repo auf dem SFTP-Server bleibt in jedem Fall
        unangetastet — es ist die eigentliche Datensicherung, kein
        install-Artefakt. Ebenso bleibt die Passphrase-Datei erhalten (wie
        im Original): ihr Wert wird für einen erneuten install oder einen
        manuellen Zugriff auf das Repo weiterhin gebraucht, ein Löschen
        wäre nicht rückholbar. Entfernt werden nur Cron-Datei,
        Backup-Skript und das Paket (ohne --purge).

        Schrittliste mit Abbruch beim ersten Fehler (wie _install); jeder
        Schritt ist idempotent.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, Callable[[], int]]] = [
            ("Cron-Datei entfernen", self._step_remove_cron),
            ("Backup-Skript entfernen", self._step_remove_backup_script),
            ("Paket entfernen", self._step_remove_package),
        ]
        for label, step in steps:
            self.send_message(LogLevel.INFO, "restic", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "restic", f"fehlgeschlagen: {label}")
                return 1
        self.send_message(
            LogLevel.INFO,
            "restic",
            f"Passphrase-Datei ({self.PASSPHRASE_FILE}), Backup-Repo und"
            " SFTP-Zugang (Vorbedingung) bleiben unverändert",
        )
        self.send_message(
            LogLevel.WARN,
            "restic",
            f"{self.PASSPHRASE_FILE} ist ein Klartext-Geheimnis und bleibt auf"
            " der Platte. Bei endgültiger Außerdienststellung oder Weitergabe"
            " der Maschine manuell löschen",
        )
        return 0

    def _step_remove_cron(self) -> int:
        """Entfernt die FQDN-benannte Cron-Datei, sofern vorhanden."""
        return self._remove_if_exists(self._cron_file_path(), "Cron-Datei")

    def _step_remove_backup_script(self) -> int:
        """Entfernt das FQDN-benannte Backup-Skript, sofern vorhanden."""
        return self._remove_if_exists(self._backup_script_path(), "Backup-Skript")

    def _remove_if_exists(self, path: str, label: str) -> int:
        """Entfernt path, sofern vorhanden — idempotent.

        Args:
            path: Zu entfernende Datei.
            label: Beschreibung für die Meldung.

        Returns:
            0 bei Erfolg oder wenn die Datei bereits fehlt, sonst 1.
        """
        if not Path(path).exists():
            self.send_message(
                LogLevel.INFO, "restic", f"{label} bereits entfernt: {path}"
            )
            return 0
        # kein safe_mode: vollständig eigene, generierte Datei (wie beim
        # Schreiben in _step_write_backup_script/_step_write_cron).
        return self.run_action(DeleteFileAction(path=path, safe_mode=False))

    def _step_remove_package(self) -> int:
        """Entfernt das Paket restic ohne --purge (Original: pkg_remove).

        apt-get remove auf ein nicht installiertes Paket endet bereits mit
        Rückgabewert 0 — ein vorheriger Installiert-Check entfällt.
        """
        return self.run_action(self.APT_ACTION_CLS(packages=["restic"], state="absent"))

    def _package_installed(self) -> bool:
        """Prüft per dpkg-query, ob das Paket restic installiert ist.

        Ohne eigene Meldung — für _test, das den Fall selbst vermeldet.

        Returns:
            True, wenn dpkg-query den Status "install ok installed" meldet.
        """
        action = SysCmdAction(
            command=[self.DPKG_QUERY_BIN, "-W", "-f=${Status}", "restic"], timeout=15
        )
        return self.run_action(action) == 0 and "install ok installed" in action.stdout

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
        fd, batch_path = tempfile.mkstemp(
            prefix="secure-base-restic-sftp-", suffix=".batch"
        )
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
        sammelt das Ergebnis (wie secure_base.modules.base).

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

    def _check_command_succeeds(
        self, command: list[str], label: str, timeout: float = 30.0
    ) -> bool:
        """Führt einen Befehl aus und meldet, ob er erfolgreich endet.

        Args:
            command: Auszuführender Befehl.
            label: Beschreibung für die Meldung.
            timeout: Zeitgrenze in Sekunden. Voreinstellung 30.0.

        Returns:
            True bei Rückgabewert 0, sonst False.
        """
        action = SysCmdAction(command=command, timeout=timeout)
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

    # --- test ---

    def _test(self) -> int:
        """Funktionstest ohne Systemänderung (Original: do_test).

        Prüft mail-Verfügbarkeit (nur Hinweis, kein Testfehler),
        SFTP-Erreichbarkeit, Repo-Entschlüsselbarkeit, Snapshot-Liste,
        Repo-Integrität (restic check) und — sofern ein Snapshot vorhanden
        ist — einen Probe-Restore. Sammelt alle Befunde, statt beim ersten
        Fehler abzubrechen (anders als _install/_uninstall); nur ohne
        installiertes Paket ist jede weitere Prüfung bedeutungslos und der
        Test bricht sofort ab (wie im Original).

        Returns:
            0, wenn alle Prüfungen erfolgreich waren, sonst 1.
        """
        if not self._package_installed():
            self.send_message(
                LogLevel.ERROR,
                "restic",
                "Paket restic nicht installiert — kein Funktionstest möglich",
            )
            return 1

        self._check_mail_available()

        repo = self._repo_url()
        ok = True
        ok &= self._check_sftp_reachable()
        ok &= self._check_repo_decryptable(repo)
        ok &= self._check_command_succeeds(
            [self.RESTIC_BIN, "-r", repo, "-p", self.PASSPHRASE_FILE, "snapshots"],
            "Snapshot-Liste",
            timeout=self.TEST_SNAPSHOTS_TIMEOUT,
        )
        ok &= self._check_command_succeeds(
            [self.RESTIC_BIN, "-r", repo, "-p", self.PASSPHRASE_FILE, "check"],
            "Repo-Integrität",
            timeout=self.TEST_CHECK_TIMEOUT,
        )
        ok &= self._check_probe_restore(repo)
        return 0 if ok else 1

    def _check_mail_available(self) -> None:
        """Meldet, ob der mail-Befehl vorhanden ist (Fehlermail des Backup-Skripts).

        Nur ein Hinweis — ein fehlender mail-Befehl zählt nicht als
        Testfehler (wie im Original).
        """
        if Path(self.MAIL_BIN).exists():
            self.send_message(LogLevel.INFO, "restic", "mail-Befehl vorhanden")
            return
        self.send_message(
            LogLevel.WARN,
            "restic",
            "mail-Befehl fehlt — Fehlermail des Backup-Skripts würde nicht"
            " zugestellt; postfix-Modul vorab laufen lassen",
        )

    def _check_sftp_reachable(self) -> bool:
        """Prüft die SFTP-Erreichbarkeit über den konfigurierten Host-Alias.

        Returns:
            True, wenn das SFTP-Ziel erreichbar ist, sonst False.
        """
        if self._run_sftp_batch(["pwd"]) == 0:
            self.send_message(LogLevel.INFO, "restic", "SFTP-Ziel erreichbar")
            return True
        self.send_message(
            LogLevel.ERROR,
            "restic",
            f"SFTP-Ziel über Alias {self.sftp_host_alias!r} nicht erreichbar",
        )
        return False

    def _check_repo_decryptable(self, repo: str) -> bool:
        """Prüft, ob das Repo initialisiert und mit der Passphrase lesbar ist.

        Args:
            repo: restic-Repo-URL.

        Returns:
            True, wenn "restic cat config" erfolgreich endet, sonst False.
        """
        if self._restic_cat_config_succeeds(repo):
            self.send_message(
                LogLevel.INFO,
                "restic",
                f"Repo {repo}: initialisiert und mit der Passphrase entschlüsselbar",
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "restic",
            f"Repo {repo}: nicht initialisiert/erreichbar oder Passphrase falsch",
        )
        return False

    def _check_probe_restore(self, repo: str) -> bool:
        """Restauriert probeweise eine kleine Datei aus dem jüngsten Snapshot.

        Ohne Snapshot ist kein Wiederherstellungstest möglich — das gilt
        nicht als Fehler (frisch initialisiertes Repo, wie im Original).

        Args:
            repo: restic-Repo-URL.

        Returns:
            True, wenn kein Snapshot vorhanden ist oder der Probe-Restore
            gelingt; sonst False.
        """
        snapshot_id = self._latest_snapshot_id(repo)
        if snapshot_id is None:
            self.send_message(
                LogLevel.INFO,
                "restic",
                "kein Snapshot vorhanden — Probe-Restore übersprungen",
            )
            return True

        restore_dir = Path(tempfile.mkdtemp(prefix="secure-base-restic-restore-"))
        try:
            action = SysCmdAction(
                command=[
                    self.RESTIC_BIN,
                    "-r",
                    repo,
                    "-p",
                    self.PASSPHRASE_FILE,
                    "restore",
                    snapshot_id,
                    "--include",
                    "/etc/hostname",
                    "--target",
                    str(restore_dir),
                ],
                timeout=self.TEST_RESTORE_TIMEOUT,
            )
            if self.run_action(action) == 0:
                self.send_message(
                    LogLevel.INFO,
                    "restic",
                    f"Probe-Restore aus Snapshot {snapshot_id} erfolgreich",
                )
                return True
            self.send_message(
                LogLevel.ERROR,
                "restic",
                f"Probe-Restore aus Snapshot {snapshot_id} fehlgeschlagen",
            )
            return False
        finally:
            shutil.rmtree(restore_dir, ignore_errors=True)

    def _latest_snapshot_id(self, repo: str) -> str | None:
        """Liest die ID des jüngsten Snapshots über "restic snapshots --json --last".

        Args:
            repo: restic-Repo-URL.

        Returns:
            Snapshot-ID, oder None wenn kein Snapshot vorhanden ist oder die
            Abfrage fehlschlägt.
        """
        action = SysCmdAction(
            command=[
                self.RESTIC_BIN,
                "-r",
                repo,
                "-p",
                self.PASSPHRASE_FILE,
                "snapshots",
                "--json",
                "--last",
            ],
            timeout=self.TEST_SNAPSHOTS_TIMEOUT,
        )
        if self.run_action(action) != 0:
            return None
        try:
            snapshots = json.loads(action.stdout)
        except json.JSONDecodeError:
            return None
        if not snapshots:
            return None
        snapshot_id = snapshots[0].get("id")
        return str(snapshot_id) if snapshot_id else None
