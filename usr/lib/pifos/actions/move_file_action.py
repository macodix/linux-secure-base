"""Datei-Verschiebe-Aktion mit safe-mode für pifos.

Setzt AKT-06, AKT-07 (safe-mode und einstellbarer Sicherungsort)
sowie SIC-13, SIC-14, SIC-15 (Rechte, Pfadprüfung, TOCTOU) um.
"""

import errno
import os
import shutil
import stat
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions import _file_ops
from pifos.errors import ActionError


class MoveFileAction(Action):
    """Verschiebt eine Datei von einer Quelle zu einem Ziel.

    Im safe-mode (Voreinstellung) wird eine bestehende Zieldatei ohne
    explizite Freigabe (overwrite=True) nicht überschrieben. Bei gesetzter
    Freigabe wird die Zieldatei vorher gesichert (AKT-06). Der Sicherungsort
    ist einstellbar (AKT-07).

    Innerhalb desselben Dateisystems erfolgt das Verschieben atomar über
    os.replace. Über Dateisystemgrenzen hinweg (EXDEV) wird stattdessen
    über eine Temp-Datei im Zielverzeichnis kopiert — Rechte der Quelle
    werden übernommen — und die Quelle danach entfernt.

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
        action = MoveFileAction("/var/tmp/upload.bin", "/srv/data/upload.bin")
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
        """Initialisiert die Datei-Verschiebe-Aktion.

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
        """Verschiebt die Quelldatei zur Zieldatei und liefert den Status.

        Bei safe_mode=True und vorhandener Zieldatei ohne overwrite=True
        wird ActionError erzeugt. Mit overwrite=True wird die Zieldatei
        vorher gesichert.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei fehlender Quelldatei, fehlendem safe-mode-
                Schutz, Sicherungsfehler oder Fehler beim Verschieben.
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

            self._move(src_path, dst_path)
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler beim Verschieben: {exc}") from exc

        self.status = "finished"
        return self.status

    def _move(self, src_path: Path, dst_path: Path) -> None:
        """Verschiebt src_path nach dst_path.

        Versucht zunächst os.replace (atomar innerhalb desselben
        Dateisystems). Schlägt das mit EXDEV fehl (Dateisystemgrenze),
        wird stattdessen über eine Temp-Datei kopiert und die Quelle
        anschließend entfernt.

        Args:
            src_path: Quelldatei.
            dst_path: Zieldatei.

        Raises:
            ActionError: Bei Kopier-, Entfernungs- oder Umbenennungsfehler.
        """
        try:
            os.replace(str(src_path), str(dst_path))
            return
        except OSError as exc:
            if exc.errno != errno.EXDEV:
                raise ActionError(f"Fehler beim Verschieben: {exc}") from exc

        src_mode = stat.S_IMODE(os.lstat(src_path).st_mode)
        try:
            with open(src_path, "rb") as src_file:
                _file_ops.atomic_write(
                    dst_path, src_mode, lambda f: shutil.copyfileobj(src_file, f)
                )
            os.remove(str(src_path))
        except OSError as exc:
            raise ActionError(f"Fehler beim Verschieben: {exc}") from exc
