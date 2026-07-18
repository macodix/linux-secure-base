"""Zeilen-in-Datei-Aktion mit safe-mode für pifos.

Stellt sicher, dass eine Zeile in einer Textdatei vorhanden ist oder
fehlt. Setzt AKT-06, AKT-07 (safe-mode und einstellbarer Sicherungsort)
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


class LineInFileAction(Action):
    """Stellt eine Zeile in einer Textdatei sicher oder entfernt sie.

    Die Zieldatei muss existieren, sonst wird ActionError erzeugt — die
    Aktion legt keine Datei an. Über match kann ein regulärer Ausdruck
    angegeben werden; trifft er auf eine Zeile zu, gilt diese als
    passend. Ohne match zählt der exakte Vergleich mit line.

    state="present": Trifft match bzw. line auf eine vorhandene Zeile zu,
    wird nur diese erste Fundstelle bei Abweichung durch line ersetzt;
    mehrere Treffer bleiben bis auf die erste Fundstelle unverändert.
    Ohne Treffer wird line am Dateiende angefügt.

    state="absent": Alle auf match bzw. line passenden Zeilen werden
    entfernt.

    Ist eine Änderung nötig, wird die Zieldatei vor dem Schreiben nach
    safe-mode-Muster gesichert (AKT-06, AKT-07); ist keine Änderung
    nötig, entfällt die Sicherung und der Status wird dennoch finished.
    Das Schreiben erfolgt atomar über eine Temp-Datei im Zielverzeichnis
    und os.replace; die bestehenden Dateirechte bleiben erhalten.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        path: Pfad der Textdatei.
        line: Sollzeile (ohne Zeilenumbruch).
        match: Regulärer Ausdruck zur Erkennung der Zielzeile oder None
            (dann exakter Vergleich mit line).
        state: "present" oder "absent"; Voreinstellung "present".
        safe_mode: Sichert die Datei vor einer Änderung; Voreinstellung
            True.
        backup_location: Verzeichnis für die Sicherung oder None (dann
            gleiches Verzeichnis wie die Zieldatei).

    Example:
        action = LineInFileAction(
            "/etc/ssh/sshd_config",
            "PermitRootLogin no",
            match=r"^#?\\s*PermitRootLogin\\b",
        )
        action.run()
    """

    PARAMS: ClassVar[list[str]] = [
        "path",
        "line",
        "match",
        "state",
        "safe_mode",
        "backup_location",
    ]

    def __init__(
        self,
        path: str,
        line: str,
        match: str | None = None,
        state: str = "present",
        safe_mode: bool = True,
        backup_location: str | None = None,
    ) -> None:
        """Initialisiert die Zeilen-in-Datei-Aktion.

        Args:
            path: Pfad der Textdatei. Muss existieren.
            line: Sollzeile (ohne Zeilenumbruch).
            match: Regulärer Ausdruck zur Erkennung der Zielzeile; None
                verwendet den exakten Vergleich mit line.
            state: "present" stellt die Zeile sicher, "absent" entfernt
                passende Zeilen. Voreinstellung "present".
            safe_mode: Sichert die Datei vor einer nötigen Änderung
                (AKT-06). Voreinstellung True.
            backup_location: Verzeichnis für die Sicherungsdatei; None
                legt die Sicherung im Verzeichnis der Zieldatei ab
                (AKT-07).
        """
        super().__init__()
        self.path = path
        self.line = line
        self.match = match
        self.state = state
        self.safe_mode = safe_mode
        self.backup_location = backup_location

    def run(self) -> str:
        """Stellt die Zeile sicher oder entfernt sie; liefert den Status.

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
            match_re = re.compile(self.match) if self.match is not None else None

            if self.state == "absent":
                new_lines, changed = self._apply_absent(lines, match_re)
            else:
                new_lines, changed = self._apply_present(lines, match_re)

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

    def _line_matches(self, raw_line: str, match_re: re.Pattern[str] | None) -> bool:
        """Prüft, ob raw_line die Zielzeile ist.

        Args:
            raw_line: Zeile inklusive Zeilenumbruch.
            match_re: Kompilierter Ausdruck oder None für exakten Vergleich.

        Returns:
            True, wenn raw_line auf match_re passt bzw. mit line übereinstimmt.
        """
        content = raw_line.rstrip("\n")
        if match_re is not None:
            return match_re.search(content) is not None
        return content == self.line.rstrip("\n")

    def _apply_present(
        self, lines: list[str], match_re: re.Pattern[str] | None
    ) -> tuple[list[str], bool]:
        """Stellt sicher, dass die Sollzeile vorhanden ist.

        Args:
            lines: Aktuelle Zeilen der Datei.
            match_re: Kompilierter Ausdruck oder None.

        Returns:
            Neue Zeilenliste und ob sich etwas geändert hat.
        """
        target = self.line if self.line.endswith("\n") else self.line + "\n"
        for i, raw in enumerate(lines):
            if self._line_matches(raw, match_re):
                if raw == target:
                    return lines, False
                new_lines = list(lines)
                new_lines[i] = target
                return new_lines, True

        new_lines = list(lines)
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.append(target)
        return new_lines, True

    def _apply_absent(
        self, lines: list[str], match_re: re.Pattern[str] | None
    ) -> tuple[list[str], bool]:
        """Entfernt alle passenden Zeilen.

        Args:
            lines: Aktuelle Zeilen der Datei.
            match_re: Kompilierter Ausdruck oder None.

        Returns:
            Neue Zeilenliste und ob sich etwas geändert hat.
        """
        new_lines = [raw for raw in lines if not self._line_matches(raw, match_re)]
        return new_lines, len(new_lines) != len(lines)

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
