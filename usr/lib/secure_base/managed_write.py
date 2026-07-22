"""Soll-Ist-Vergleich und zentrale Sicherungsablage für Installer-Schreibziele.

Setzt den Plan installer-drift-schutz um: Vor jedem Schreiben einer
vollständig generierten Datei wird die vorhandene Datei mit dem Soll-Inhalt
verglichen. Identisch → nichts tun; abweichend → Konflikt (Überschreiben nur
mit ausdrücklicher Freigabe je Lauf); fehlt → schreiben. Es wird kein
Zustand auf dem Server abgelegt — der Vergleich läuft vollständig im
Speicher.

Sicherungen liegen zentral unter einem Lauf-Verzeichnis
(/var/backup/secure-base/<JJJJ-MM-TT-HHMMSS>/), gespiegelt unter dem vollen
Pfad der Zieldatei; je Datei und Lauf entsteht höchstens eine Sicherung.
Überschrieben wird nur nach nachweislich erfolgreicher Sicherung. Dateien
mit Geheimniswert werden nie in die Sicherungsablage kopiert (secret=True);
bei Freigabe wird ihre alte Fassung ersatzlos verworfen, mit Hinweis.

Meldungen nennen ausschließlich Pfad und Grund — Dateiinhalte oder
Unterschiede werden nie ausgegeben.
"""

import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from pifos.actions.write_file_action import WriteFileAction
from pifos.ipc import LogLevel

# Wurzel der zentralen Sicherungsablage. /var/backup ist das
# Sammelverzeichnis lokaler Sicherungen (0700 root) und liegt im
# restic-Sicherungsumfang.
BACKUP_BASE = "/var/backup/secure-base"

# Freigabe-Hinweis, einheitlich in allen Konflikt-Meldungen.
_FORCE_HINT = "Überschreiben nur mit --force-overwrite"


@dataclass(frozen=True)
class ManagedFile:
    """Ein vollständig generiertes Schreibziel des Installers.

    Attributes:
        dst: Absoluter Pfad der Zieldatei.
        content: Soll-Inhalt; None, wenn er im aktuellen Zustand nicht
            bestimmbar ist (Ziel wird in der Sammel-Prüfung übersprungen).
        mode: Rechte der Zieldatei.
        secret: True für Dateien mit Geheimniswert — sie werden nie in
            die Sicherungsablage kopiert.
    """

    dst: str
    content: str | None
    mode: int
    secret: bool = False


def _read_text(path: Path) -> str | None:
    """Liest eine Datei symlink-sicher als UTF-8-Text.

    Args:
        path: Zu lesende Datei.

    Returns:
        Dateiinhalt, oder None, wenn die Datei nicht lesbar oder kein
        gültiges UTF-8 ist (gilt beim Vergleich als abweichend).
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            return fh.read().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def managed_state(mf: ManagedFile) -> str:
    """Bestimmt den Zustand eines Schreibziels gegenüber dem Soll.

    Args:
        mf: Schreibziel mit Soll-Inhalt (content darf nicht None sein).

    Returns:
        "fehlt", "identisch" oder "abweichend".
    """
    path = Path(mf.dst)
    if not path.exists() and not path.is_symlink():
        return "fehlt"
    ist = _read_text(path)
    if ist is not None and ist == mf.content:
        return "identisch"
    return "abweichend"


class ManagedWriteMixin:
    """Mixin für Module: Soll-Ist-Vergleich, Sammel-Prüfung, Sicherung.

    Erwartet vom Modul (über CONFIG gesetzt): force_overwrite
    ("yes"/"no") und backup_run_dir (Lauf-Verzeichnis der zentralen
    Sicherungsablage, vom Installer je Lauf vergeben), außerdem die
    Module-Schnittstelle send_message/run_action.

    Module überschreiben _managed_files() und nutzen write_managed()
    an ihren Schreibstellen, backup_before_edit() vor zeilenweisen
    Änderungen sowie preflight_managed()/check_managed() in den
    Betriebsarten preflight und check.
    """

    # Von check_config gesetzt (CONFIG der nutzenden Module).
    force_overwrite: str
    backup_run_dir: str

    def _managed_files(self) -> list[ManagedFile]:
        """Deklariert die vollständig generierten Schreibziele des Moduls.

        Returns:
            Schreibziele mit Soll-Inhalt; Vorgabe: keine.
        """
        return []

    @property
    def _force(self) -> bool:
        """True, wenn der Lauf das Überschreiben freigegeben hat."""
        return str(getattr(self, "force_overwrite", "no")).lower() == "yes"

    def preflight_managed(self, name: str) -> int:
        """Sammel-Prüfung: meldet alle vom Soll abweichenden Ziele.

        Ändert nichts. Ziele mit content=None werden übersprungen (ihr
        Zustand hängt von einem späteren Schritt ab und ist gesondert
        geregelt).

        Args:
            name: Meldungskennung (Modulname).

        Returns:
            0 ohne Konflikte oder mit Freigabe, sonst 1.
        """
        conflicts = 0
        for mf in self._managed_files():
            if mf.content is None:
                continue
            state = managed_state(mf)
            if state != "abweichend":
                continue
            if self._force:
                self.send_message(  # type: ignore[attr-defined]
                    LogLevel.WARN,
                    name,
                    f"{mf.dst} weicht vom Soll ab — wird in diesem Lauf"
                    " überschrieben (Freigabe erteilt)",
                )
            else:
                conflicts += 1
                self.send_message(  # type: ignore[attr-defined]
                    LogLevel.ERROR,
                    name,
                    f"{mf.dst} weicht vom Soll ab — {_FORCE_HINT}",
                )
        return 1 if conflicts else 0

    def check_managed(self, name: str) -> bool:
        """Soll-Ist-Abgleich aller Ziele für die Betriebsart check.

        Args:
            name: Meldungskennung (Modulname).

        Returns:
            True, wenn alle bestimmbaren Ziele dem Soll entsprechen.
        """
        ok = True
        for mf in self._managed_files():
            if mf.content is None:
                continue
            state = managed_state(mf)
            if state == "identisch":
                self.send_message(  # type: ignore[attr-defined]
                    LogLevel.INFO, name, f"{mf.dst}: entspricht dem Soll"
                )
            else:
                ok = False
                grund = "fehlt" if state == "fehlt" else "weicht vom Soll ab"
                self.send_message(  # type: ignore[attr-defined]
                    LogLevel.ERROR, name, f"{mf.dst}: {grund}"
                )
        return ok

    def write_managed(self, name: str, mf: ManagedFile, adopt: bool = False) -> int:
        """Schreibt ein Ziel nach der Entscheidungsregel des Plans.

        Args:
            name: Meldungskennung (Modulname).
            mf: Schreibziel; content darf nicht None sein.
            adopt: True, wenn eine vorgefundene Datei die unberührte
                Paket-Vorgabe ist und ohne Freigabe ersetzt werden darf
                (Erstübernahme, mit Sicherung).

        Returns:
            0 bei Erfolg oder übersprungenem Ziel, 1 bei Konflikt oder
            Fehler.
        """
        if mf.content is None:
            self.send_message(  # type: ignore[attr-defined]
                LogLevel.ERROR, name, f"{mf.dst}: Soll-Inhalt nicht bestimmbar"
            )
            return 1
        state = managed_state(mf)
        if state == "identisch":
            self.send_message(  # type: ignore[attr-defined]
                LogLevel.INFO, name, f"{mf.dst}: unverändert — übersprungen"
            )
            return 0
        if state == "abweichend":
            if not (self._force or adopt):
                self.send_message(  # type: ignore[attr-defined]
                    LogLevel.ERROR,
                    name,
                    f"{mf.dst} weicht vom Soll ab — {_FORCE_HINT}",
                )
                return 1
            if mf.secret:
                # Nie in die Sicherungsablage kopieren; alte Fassung wird
                # ersatzlos verworfen (Plan Kap. 2.7).
                self.send_message(  # type: ignore[attr-defined]
                    LogLevel.WARN,
                    name,
                    f"{mf.dst}: wird überschrieben; alte Fassung wird nicht"
                    " gesichert (Datei mit Geheimniswert)",
                )
            elif not self._backup_to_run_dir(name, Path(mf.dst)):
                # Ohne gelungene Sicherung wird nicht überschrieben.
                return 1
            else:
                self.send_message(  # type: ignore[attr-defined]
                    LogLevel.WARN,
                    name,
                    f"{mf.dst}: wird überschrieben; Sicherung unter"
                    f" {self.backup_run_dir}",
                )
        rc = self.run_action(  # type: ignore[attr-defined]
            WriteFileAction(
                dst=mf.dst,
                content=mf.content,
                mode=mf.mode,
                overwrite=True,
                # Die Sicherung ist bereits zentral erfolgt (oder entfällt
                # bewusst) — keine .bak neben der Zieldatei.
                safe_mode=False,
            )
        )
        return int(rc)

    def backup_before_edit(self, name: str, path: str) -> int:
        """Sichert eine Datei vor zeilenweisen Änderungen — einmal je Lauf.

        Für Dateien, die der Installer nur punktuell ändert (z. B.
        sshd_config): Die Sicherung übernimmt der Installer zentral,
        die einzelnen Aktionen laufen danach ohne eigene Sicherung.

        Args:
            name: Meldungskennung (Modulname).
            path: Zu sichernde Datei.

        Returns:
            0 bei Erfolg oder wenn keine Sicherung nötig ist, sonst 1.
        """
        backed_up: set[str] = getattr(self, "_managed_backed_up", set())
        if path in backed_up:
            return 0
        target = Path(path)
        if not target.exists():
            return 0
        if not self._backup_to_run_dir(name, target):
            return 1
        backed_up.add(path)
        self._managed_backed_up = backed_up
        return 0

    def _backup_to_run_dir(self, name: str, src: Path) -> bool:
        """Kopiert eine Datei in das Lauf-Verzeichnis der Sicherungsablage.

        Ablage unter dem vollen Pfad der Zieldatei (z. B.
        <lauf>/etc/ssh/sshd_config); je Datei und Lauf höchstens eine
        Sicherung (Aufrufer prüfen den Zustand vorher). Verzeichnisse
        entstehen mit 0700, die Kopie mit den Rechten des Originals.

        Args:
            name: Meldungskennung (Modulname).
            src: Zu sichernde Datei.

        Returns:
            True bei nachweislich gelungener Sicherung.
        """
        run_dir = Path(self.backup_run_dir)
        dst = run_dir / src.relative_to("/")
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            # Verzeichniskette vom Ziel bis einschließlich Lauf-Verzeichnis
            # auf 0700 halten (darüber schützt /var/backup selbst, 0700 root).
            probe = dst.parent
            stop = run_dir.parent
            while probe != stop and probe != probe.parent:
                os.chmod(probe, 0o700)
                probe = probe.parent
            shutil.copy2(src, dst)
            src_stat = src.stat()
            os.chmod(dst, stat.S_IMODE(src_stat.st_mode))
            if dst.stat().st_size != src_stat.st_size:
                raise OSError("Sicherung unvollständig (Größe weicht ab)")
        except OSError as exc:
            self.send_message(  # type: ignore[attr-defined]
                LogLevel.ERROR,
                name,
                f"Sicherung von {src} nach {dst} fehlgeschlagen ({exc}) —"
                " Datei wird nicht überschrieben",
            )
            return False
        return True
