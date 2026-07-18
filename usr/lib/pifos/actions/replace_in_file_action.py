"""Suchen-und-Ersetzen-Aktion mit safe-mode für pifos.

Setzt AKT-06, AKT-07 (safe-mode und einstellbarer Sicherungsort)
sowie SIC-13, SIC-14, SIC-15 (Rechte, Pfadprüfung, TOCTOU) um.
"""

import os
import re
import stat
from pathlib import Path
from typing import IO, ClassVar

from pifos.action import Action
from pifos.actions import _file_ops
from pifos.errors import ActionError


class ReplaceInFileAction(Action):
    """Ersetzt Fundstellen eines regulären Ausdrucks im Inhalt einer Textdatei.

    Die Zieldatei muss existieren, sonst wird ActionError erzeugt — die
    Aktion legt keine Datei an. pattern wird als regulärer Ausdruck über
    den gesamten Dateiinhalt angewendet (nicht zeilenweise), replacement
    ist der Ersetzungstext (Rückverweise wie \\1 sind zulässig). count
    begrenzt die Anzahl ersetzter Fundstellen; 0 ersetzt alle.

    Ergibt sich keine Fundstelle, bleibt die Datei unverändert und der
    Status wird dennoch finished. Ist eine Änderung nötig, wird die
    Zieldatei vor dem Schreiben nach safe-mode-Muster gesichert (AKT-06,
    AKT-07). Das Schreiben erfolgt atomar über eine Temp-Datei im
    Zielverzeichnis und os.replace; die bestehenden Dateirechte bleiben
    erhalten.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        path: Pfad der Textdatei.
        pattern: Regulärer Ausdruck (Suchmuster).
        replacement: Ersetzungstext.
        count: Maximale Anzahl Ersetzungen; 0 ersetzt alle Fundstellen.
        safe_mode: Sichert die Datei vor einer Änderung; Voreinstellung
            True.
        backup_location: Verzeichnis für die Sicherung oder None (dann
            gleiches Verzeichnis wie die Zieldatei).

    Example:
        action = ReplaceInFileAction(
            "/etc/motd", r"Version \\d+\\.\\d+", "Version 2.0"
        )
        action.run()
    """

    PARAMS: ClassVar[list[str]] = [
        "path",
        "pattern",
        "replacement",
        "count",
        "safe_mode",
        "backup_location",
    ]

    def __init__(
        self,
        path: str,
        pattern: str,
        replacement: str,
        count: int = 0,
        safe_mode: bool = True,
        backup_location: str | None = None,
    ) -> None:
        """Initialisiert die Suchen-und-Ersetzen-Aktion.

        Args:
            path: Pfad der Textdatei. Muss existieren.
            pattern: Regulärer Ausdruck (Suchmuster).
            replacement: Ersetzungstext.
            count: Maximale Anzahl Ersetzungen; 0 ersetzt alle
                Fundstellen (Voreinstellung).
            safe_mode: Sichert die Datei vor einer nötigen Änderung
                (AKT-06). Voreinstellung True.
            backup_location: Verzeichnis für die Sicherungsdatei; None
                legt die Sicherung im Verzeichnis der Zieldatei ab
                (AKT-07).
        """
        super().__init__()
        self.path = path
        self.pattern = pattern
        self.replacement = replacement
        self.count = count
        self.safe_mode = safe_mode
        self.backup_location = backup_location

    def run(self) -> str:
        """Ersetzt die Fundstellen und liefert den Ausführungsstatus.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei fehlender Zieldatei, Sicherungsfehler oder
                Schreibfehler.
        """
        self.status = "running"
        try:
            path = Path(self.path)
            if not path.exists():
                self.status = "failed"
                raise ActionError(f"Datei nicht gefunden: {self.path!r}")

            orig_mode = stat.S_IMODE(os.lstat(path).st_mode)
            text = _file_ops.read_text_no_follow(path)

            new_text, num_subs = re.subn(
                self.pattern, self.replacement, text, count=self.count
            )

            if num_subs == 0:
                self.status = "finished"
                return self.status

            if self.safe_mode:
                _file_ops.backup_destination(path, self.backup_location)

            self._write(path, orig_mode, new_text)
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler: {exc}") from exc

        self.status = "finished"
        return self.status

    def _write(self, path: Path, mode: int, new_text: str) -> None:
        """Schreibt new_text atomar nach path mit den gegebenen Rechten.

        Args:
            path: Zieldatei.
            mode: Zu setzende Rechte (bestehende Rechte der Datei).
            new_text: Zu schreibender Dateiinhalt.

        Raises:
            ActionError: Bei Temp-Datei-, Schreib- oder Umbenennungsfehler.
        """
        content = new_text.encode("utf-8")

        def writer(f: IO[bytes]) -> None:
            f.write(content)

        try:
            _file_ops.atomic_write(path, mode, writer)
        except OSError as exc:
            raise ActionError(f"Fehler beim Schreiben: {exc}") from exc
