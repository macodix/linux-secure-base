"""Datei-Schreib-Aktion mit safe-mode für pifos.

Setzt AKT-06, AKT-07 (safe-mode und einstellbarer Sicherungsort)
sowie SIC-13, SIC-14, SIC-15 (Rechte, Pfadprüfung, TOCTOU) um.
"""

import os
import stat
from pathlib import Path
from typing import IO, ClassVar

from pifos.action import Action
from pifos.actions import _file_ops
from pifos.errors import ActionError


class WriteFileAction(Action):
    """Schreibt Inhalt in eine Zieldatei.

    Im safe-mode (Voreinstellung) wird eine bestehende Zieldatei ohne
    explizite Freigabe (overwrite=True) nicht überschrieben. Bei gesetzter
    Freigabe wird die Zieldatei vorher gesichert (AKT-06). Der Sicherungsort
    ist einstellbar (AKT-07). Das Schreiben erfolgt atomar über eine
    Temp-Datei im Zielverzeichnis und os.replace.

    mode legt die Rechte der Zieldatei fest; Voreinstellung ist 0o600.
    Wird mode nicht ausdrücklich übergeben (None) und die Zieldatei
    existiert bereits, übernimmt die Aktion deren bestehende Rechte statt
    des Default-Werts — ein ausdrücklich übergebenes mode hat stets
    Vorrang, auch wenn die Zieldatei existiert.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        dst: Zieldatei-Pfad.
        content: Zu schreibender Inhalt.
        mode: Zieldatei-Rechte oder None (siehe Klassenbeschreibung).
        safe_mode: Schützt bestehende Zieldatei; Voreinstellung True.
        backup_location: Verzeichnis für die Sicherung oder None (dann
            gleiches Verzeichnis wie Zieldatei).
        overwrite: Erlaubt das Überschreiben einer bestehenden Zieldatei
            im safe-mode; Sicherung wird angelegt. Voreinstellung False.

    Example:
        action = WriteFileAction("/etc/motd", "Willkommen\\n", mode=0o644)
        action.run()
    """

    PARAMS: ClassVar[list[str]] = [
        "dst",
        "content",
        "mode",
        "safe_mode",
        "backup_location",
        "overwrite",
    ]

    def __init__(
        self,
        dst: str,
        content: str,
        mode: int | None = None,
        safe_mode: bool = True,
        backup_location: str | None = None,
        overwrite: bool = False,
    ) -> None:
        """Initialisiert die Datei-Schreib-Aktion.

        Args:
            dst: Zieldatei-Pfad.
            content: Zu schreibender Inhalt.
            mode: Zieldatei-Rechte; None übernimmt bei bestehender
                Zieldatei deren Rechte, sonst 0o600 (Voreinstellung).
            safe_mode: Bei True wird eine bestehende Zieldatei geschützt.
                Ist overwrite ebenfalls True, wird sie vor dem Überschreiben
                gesichert (AKT-06).
            backup_location: Verzeichnis für die Sicherungsdatei; None legt
                die Sicherung im Verzeichnis der Zieldatei ab (AKT-07).
            overwrite: Gibt das Überschreiben einer bestehenden Zieldatei
                explizit frei. Nur wirksam, wenn safe_mode=True.
        """
        super().__init__()
        self.dst = dst
        self.content = content
        self.mode = mode
        self.safe_mode = safe_mode
        self.backup_location = backup_location
        self.overwrite = overwrite

    def run(self) -> str:
        """Schreibt content in die Zieldatei und liefert den Ausführungsstatus.

        Bei safe_mode=True und vorhandener Zieldatei ohne overwrite=True
        wird ActionError erzeugt. Mit overwrite=True wird die Zieldatei
        vorher gesichert. Das Schreiben erfolgt über eine Temp-Datei und
        einen atomaren Austausch.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei fehlendem safe-mode-Schutz, Sicherungsfehler
                oder Schreibfehler.
        """
        self.status = "running"
        try:
            dst_path = Path(self.dst)
            exists = dst_path.exists()

            if self.safe_mode and exists and not self.overwrite:
                self.status = "failed"
                raise ActionError(
                    f"Zieldatei vorhanden, Überschreiben nicht freigegeben:"
                    f" {self.dst!r}"
                )

            effective_mode = self._effective_mode(dst_path, exists)

            if self.safe_mode and exists and self.overwrite:
                _file_ops.backup_destination(dst_path, self.backup_location)

            self._write(dst_path, effective_mode)
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler beim Schreiben: {exc}") from exc

        self.status = "finished"
        return self.status

    def _effective_mode(self, dst_path: Path, exists: bool) -> int:
        """Ermittelt die beim Schreiben zu setzenden Rechte.

        Ein ausdrücklich übergebenes mode hat Vorrang. Fehlt mode und die
        Zieldatei existiert, werden deren bestehende Rechte übernommen;
        sonst gilt 0o600.

        Args:
            dst_path: Zieldatei.
            exists: True, wenn die Zieldatei bereits existiert.

        Die Rechte werden über einen O_NOFOLLOW-Deskriptor ermittelt
        (SIC-15): Ist dst_path ein Symlink, schlägt das Öffnen fehl
        (ELOOP), statt die Rechte des Symlinks (typischerweise 0o777)
        zu übernehmen und damit beim Schreiben auszuweiten (SIC-13).

        Returns:
            Zu setzende Rechte.

        Raises:
            OSError: Wenn die bestehende Zieldatei nicht geöffnet werden
                kann — u. a. wenn sie ein Symlink ist (ELOOP).
        """
        if self.mode is not None:
            return self.mode
        if exists:
            fd = os.open(str(dst_path), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                return stat.S_IMODE(os.fstat(fd).st_mode)
            finally:
                os.close(fd)
        return 0o600

    def _write(self, dst_path: Path, mode: int) -> None:
        """Schreibt content atomar in dst_path mit den gegebenen Rechten.

        Args:
            dst_path: Zieldatei.
            mode: Zu setzende Rechte.

        Raises:
            ActionError: Bei Temp-Datei-, Schreib- oder Umbenennungsfehler.
        """
        content_bytes = self.content.encode("utf-8")

        def writer(f: IO[bytes]) -> None:
            f.write(content_bytes)

        try:
            _file_ops.atomic_write(dst_path, mode, writer)
        except OSError as exc:
            raise ActionError(f"Fehler beim Schreiben: {exc}") from exc
