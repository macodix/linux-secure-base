"""Block-in-Datei-Aktion mit safe-mode für pifos.

Verwaltet einen markierten Textblock in einer Textdatei. Setzt AKT-06,
AKT-07 (safe-mode und einstellbarer Sicherungsort) sowie SIC-13,
SIC-14, SIC-15 (Rechte, Pfadprüfung, TOCTOU) um.
"""

import os
import stat
from pathlib import Path
from typing import IO, ClassVar

from pifos.action import Action
from pifos.actions import _file_ops
from pifos.errors import ActionError


class BlockInFileAction(Action):
    """Stellt einen markierten Textblock in einer Datei sicher oder entfernt ihn.

    Der Block wird von zwei Markerzeilen eingerahmt, die aus marker und
    comment_char gebildet werden: "<comment_char> BEGIN <marker>" und
    "<comment_char> END <marker>". Die Zieldatei muss existieren, sonst
    wird ActionError erzeugt — die Aktion legt keine Datei an.

    state="present": Sind beide Markerzeilen vorhanden, wird der
    eingerahmte Inhalt bei Abweichung durch block ersetzt. Fehlen die
    Markerzeilen (oder ist nur eine vorhanden), wird der Block mit einer
    Leerzeile davor am Dateiende angefügt.

    state="absent": Sind beide Markerzeilen vorhanden, werden sie samt
    eingerahmtem Inhalt entfernt. Eine unmittelbar vor der Begin-
    Markerzeile stehende Leerzeile (der beim Anfügen eingefügte Trenner)
    wird dabei ebenfalls entfernt, sofern vorhanden — damit ein
    present/absent-Rundlauf den ursprünglichen Inhalt wiederherstellt.
    Ohne vollständige Markerung entfällt die Änderung.

    Ist eine Änderung nötig, wird die Zieldatei vor dem Schreiben nach
    safe-mode-Muster gesichert (AKT-06, AKT-07); ist keine Änderung
    nötig, entfällt die Sicherung und der Status wird dennoch finished.
    Das Schreiben erfolgt atomar über eine Temp-Datei im Zielverzeichnis
    und os.replace; die bestehenden Dateirechte bleiben erhalten.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        path: Pfad der Textdatei.
        block: Blockinhalt ohne Markerzeilen.
        marker: Name des Blocks; bildet zusammen mit comment_char die
            Markerzeilen.
        comment_char: Kommentarzeichen der Markerzeilen; Voreinstellung
            "#".
        state: "present" oder "absent"; Voreinstellung "present".
        safe_mode: Sichert die Datei vor einer Änderung; Voreinstellung
            True.
        backup_location: Verzeichnis für die Sicherung oder None (dann
            gleiches Verzeichnis wie die Zieldatei).

    Example:
        action = BlockInFileAction(
            "/etc/hosts",
            "127.0.0.1 intern.example\\n",
            marker="pifos-hosts",
        )
        action.run()
    """

    PARAMS: ClassVar[list[str]] = [
        "path",
        "block",
        "marker",
        "comment_char",
        "state",
        "safe_mode",
        "backup_location",
    ]

    def __init__(
        self,
        path: str,
        block: str,
        marker: str,
        comment_char: str = "#",
        state: str = "present",
        safe_mode: bool = True,
        backup_location: str | None = None,
    ) -> None:
        """Initialisiert die Block-in-Datei-Aktion.

        Args:
            path: Pfad der Textdatei. Muss existieren.
            block: Blockinhalt ohne Markerzeilen.
            marker: Name des Blocks; bildet zusammen mit comment_char die
                Begin-/End-Markerzeilen.
            comment_char: Kommentarzeichen der Markerzeilen. Voreinstellung
                "#".
            state: "present" stellt den Block sicher, "absent" entfernt
                ihn. Voreinstellung "present".
            safe_mode: Sichert die Datei vor einer nötigen Änderung
                (AKT-06). Voreinstellung True.
            backup_location: Verzeichnis für die Sicherungsdatei; None
                legt die Sicherung im Verzeichnis der Zieldatei ab
                (AKT-07).
        """
        super().__init__()
        self.path = path
        self.block = block
        self.marker = marker
        self.comment_char = comment_char
        self.state = state
        self.safe_mode = safe_mode
        self.backup_location = backup_location

    def run(self) -> str:
        """Stellt den Block sicher oder entfernt ihn; liefert den Status.

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
            lines = _file_ops.read_lines_no_follow(path)
            begin_marker = f"{self.comment_char} BEGIN {self.marker}"
            end_marker = f"{self.comment_char} END {self.marker}"

            if self.state == "absent":
                new_lines, changed = self._apply_absent(lines, begin_marker, end_marker)
            else:
                new_lines, changed = self._apply_present(
                    lines, begin_marker, end_marker
                )

            if not changed:
                self.status = "finished"
                return self.status

            if self.safe_mode:
                _file_ops.backup_destination(path, self.backup_location)

            self._write(path, orig_mode, new_lines)
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler: {exc}") from exc

        self.status = "finished"
        return self.status

    def _find_markers(
        self, lines: list[str], begin_marker: str, end_marker: str
    ) -> tuple[int, int] | None:
        """Sucht die Begin-/End-Markerzeilen in lines.

        Args:
            lines: Zeilen der Datei.
            begin_marker: Text der Begin-Markerzeile (ohne Zeilenumbruch).
            end_marker: Text der End-Markerzeile (ohne Zeilenumbruch).

        Returns:
            Tupel (begin_index, end_index), wenn beide Markerzeilen in
            dieser Reihenfolge vorhanden sind; sonst None.
        """
        begin_idx: int | None = None
        end_idx: int | None = None
        for i, raw in enumerate(lines):
            content = raw.rstrip("\n")
            if begin_idx is None and content == begin_marker:
                begin_idx = i
            elif begin_idx is not None and end_idx is None and content == end_marker:
                end_idx = i
                break
        if begin_idx is not None and end_idx is not None:
            return begin_idx, end_idx
        return None

    def _block_lines(self, begin_marker: str, end_marker: str) -> list[str]:
        """Baut die Zeilen des Blocks samt Markerzeilen.

        Args:
            begin_marker: Text der Begin-Markerzeile.
            end_marker: Text der End-Markerzeile.

        Returns:
            Zeilenliste: Begin-Marker, Blockinhalt, End-Marker.
        """
        result = [begin_marker + "\n"]
        result.extend(f"{line}\n" for line in self.block.splitlines())
        result.append(end_marker + "\n")
        return result

    def _apply_present(
        self, lines: list[str], begin_marker: str, end_marker: str
    ) -> tuple[list[str], bool]:
        """Stellt sicher, dass der Block mit aktuellem Inhalt vorhanden ist.

        Args:
            lines: Aktuelle Zeilen der Datei.
            begin_marker: Text der Begin-Markerzeile.
            end_marker: Text der End-Markerzeile.

        Returns:
            Neue Zeilenliste und ob sich etwas geändert hat.
        """
        found = self._find_markers(lines, begin_marker, end_marker)
        desired_body = [f"{line}\n" for line in self.block.splitlines()]

        if found is not None:
            begin_idx, end_idx = found
            current_body = lines[begin_idx + 1 : end_idx]
            if current_body == desired_body:
                return lines, False
            new_lines = lines[: begin_idx + 1] + desired_body + lines[end_idx:]
            return new_lines, True

        new_lines = list(lines)
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        if new_lines:
            new_lines.append("\n")
        new_lines.extend(self._block_lines(begin_marker, end_marker))
        return new_lines, True

    def _apply_absent(
        self, lines: list[str], begin_marker: str, end_marker: str
    ) -> tuple[list[str], bool]:
        """Entfernt den Block samt Markerzeilen, falls vorhanden.

        Eine unmittelbar vor der Begin-Markerzeile stehende Leerzeile wird
        zusammen mit dem Block entfernt (Trenner-Leerzeile, die
        _apply_present beim Anfügen einfügt) — sonst wäre die Aktion im
        present/absent-Rundlauf nicht idempotent, da sich diese Leerzeile
        bei wiederholten Zyklen aufsummieren würde. Eine inhaltlich
        gefüllte Zeile vor dem Block bleibt unangetastet.

        Args:
            lines: Aktuelle Zeilen der Datei.
            begin_marker: Text der Begin-Markerzeile.
            end_marker: Text der End-Markerzeile.

        Returns:
            Neue Zeilenliste und ob sich etwas geändert hat.
        """
        found = self._find_markers(lines, begin_marker, end_marker)
        if found is None:
            return lines, False
        begin_idx, end_idx = found
        remove_start = begin_idx
        if begin_idx > 0 and lines[begin_idx - 1].rstrip("\n") == "":
            remove_start = begin_idx - 1
        new_lines = lines[:remove_start] + lines[end_idx + 1 :]
        return new_lines, True

    def _write(self, path: Path, mode: int, new_lines: list[str]) -> None:
        """Schreibt new_lines atomar nach path mit den gegebenen Rechten.

        Args:
            path: Zieldatei.
            mode: Zu setzende Rechte (bestehende Rechte der Datei).
            new_lines: Zu schreibende Zeilen.

        Raises:
            ActionError: Bei Temp-Datei-, Schreib- oder Umbenennungsfehler.
        """
        content = "".join(new_lines).encode("utf-8")

        def writer(f: IO[bytes]) -> None:
            f.write(content)

        try:
            _file_ops.atomic_write(path, mode, writer)
        except OSError as exc:
            raise ActionError(f"Fehler beim Schreiben: {exc}") from exc
