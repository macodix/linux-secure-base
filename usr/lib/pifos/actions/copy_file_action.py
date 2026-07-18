"""Datei-Kopier-Aktion mit safe-mode für pifos.

Setzt AKT-06, AKT-07 (safe-mode und einstellbarer Sicherungsort)
sowie SIC-13, SIC-14, SIC-15 (Rechte, Pfadprüfung, TOCTOU) um.
"""

import os
import shutil
import stat
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions import _file_ops
from pifos.errors import ActionError


class CopyFileAction(Action):
    """Kopiert eine Datei von einer Quelle zu einem Ziel.

    Im safe-mode (Voreinstellung) wird eine bestehende Zieldatei ohne
    explizite Freigabe (overwrite=True) nicht überschrieben. Bei gesetzter
    Freigabe wird die Zieldatei vorher gesichert (AKT-06). Der Sicherungsort
    ist einstellbar (AKT-07). Die Sicherung weitet die Zugriffsrechte nicht
    aus (SIC-13); der Sicherungspfad wird geprüft (SIC-14); Prüfung und
    Schreiben sind gegen Symlink-Manipulation und TOCTOU abgesichert (SIC-15).

    Attributes:
        PARAMS: Parameternamen der Aktion.
        src: Quelldatei-Pfad.
        dst: Zieldatei-Pfad.
        safe_mode: Schützt bestehende Zieldatei; Voreinstellung True.
        backup_location: Verzeichnis für die Sicherung oder None (dann
            gleiches Verzeichnis wie Zieldatei).
        overwrite: Erlaubt das Überschreiben einer bestehenden Zieldatei
            im safe-mode; Sicherung wird angelegt. Voreinstellung False.

    Example:
        action = CopyFileAction("/etc/hosts", "/tmp/hosts.bak",
                                safe_mode=False)
        action.run()
    """

    PARAMS: ClassVar[list[str]] = [
        "src",
        "dst",
        "safe_mode",
        "backup_location",
        "overwrite",
    ]

    def __init__(
        self,
        src: str,
        dst: str,
        safe_mode: bool = True,
        backup_location: str | None = None,
        overwrite: bool = False,
    ) -> None:
        """Initialisiert die Datei-Kopier-Aktion.

        Args:
            src: Quelldatei-Pfad.
            dst: Zieldatei-Pfad.
            safe_mode: Bei True wird eine bestehende Zieldatei geschützt.
                Ist overwrite ebenfalls True, wird sie vor dem Überschreiben
                gesichert (AKT-06).
            backup_location: Verzeichnis für die Sicherungsdatei; None legt
                die Sicherung im Verzeichnis der Zieldatei ab (AKT-07).
            overwrite: Gibt das Überschreiben einer bestehenden Zieldatei
                explizit frei. Nur wirksam, wenn safe_mode=True.
        """
        super().__init__()
        self.src = src
        self.dst = dst
        self.safe_mode = safe_mode
        self.backup_location = backup_location
        self.overwrite = overwrite

    def run(self) -> str:
        """Kopiert die Quelldatei zur Zieldatei und liefert den Ausführungsstatus.

        Bei safe_mode=True und vorhandener Zieldatei ohne overwrite=True
        wird ActionError erzeugt. Mit overwrite=True wird die Zieldatei
        vorher gesichert. Das Kopieren erfolgt über eine Temp-Datei und
        einen atomaren Austausch.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei fehlendem safe-mode-Schutz, Sicherungsfehler
                oder Kopierfehler.
        """
        self.status = "running"
        try:
            src_path = Path(self.src)
            dst_path = Path(self.dst)

            if not src_path.exists():
                self.status = "failed"
                raise ActionError(f"Quelldatei nicht gefunden: {self.src!r}")

            if self.safe_mode and dst_path.exists():
                if not self.overwrite:
                    self.status = "failed"
                    raise ActionError(
                        f"Zieldatei vorhanden, Überschreiben nicht freigegeben:"
                        f" {self.dst!r}"
                    )
                _file_ops.backup_destination(dst_path, self.backup_location)

            self._copy(src_path, dst_path)
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler beim Kopieren: {exc}") from exc

        self.status = "finished"
        return self.status

    def _copy(self, src_path: Path, dst_path: Path) -> None:
        """Kopiert src_path nach dst_path über eine Temp-Datei (atomar).

        Übernimmt die Rechte der Quelldatei; Schreiben und Austausch
        laufen über _file_ops.atomic_write.

        Args:
            src_path: Quelldatei.
            dst_path: Zieldatei.

        Raises:
            ActionError: Bei Temp-Datei-, Kopier- oder Umbenennungsfehler.
        """
        src_mode = stat.S_IMODE(os.lstat(src_path).st_mode)
        try:
            with open(src_path, "rb") as src_file:
                _file_ops.atomic_write(
                    dst_path, src_mode, lambda f: shutil.copyfileobj(src_file, f)
                )
        except OSError as exc:
            raise ActionError(f"Fehler beim Kopieren: {exc}") from exc
