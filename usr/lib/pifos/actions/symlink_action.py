"""Symlink-Anlege-Aktion für pifos.

Setzt SIC-11/SIC-15 sinngemäß für Symlinks um: atomarer Austausch über
Temp-Symlink und os.replace, unvorhersagbarer Temp-Name über secrets.
"""

import contextlib
import os
import secrets
import stat
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.errors import ActionError

_MAX_SYMLINK_ATTEMPTS = 100


def _create_symlink_atomic(link_dir: Path, link_name: str, target: str) -> None:
    """Legt target als Symlink unter link_dir/link_name atomar an.

    Erstellt zunächst einen Symlink unter einem unvorhersagbaren
    temporären Namen im selben Verzeichnis (kryptografisch sicherer
    Zufall über secrets, SIC-15) und tauscht ihn per os.replace gegen
    link_name aus — auch wenn dort bereits ein Eintrag liegt. Unmittelbar
    vor dem Austausch wird per os.lstat erneut geprüft, dass link_name
    noch ein Symlink ist (Recheck); ist er es nicht mehr (zwischenzeitlich
    durch eine reguläre Datei ersetzt) oder fehlt er, wird abgebrochen.
    Das verengt das Zeitfenster einer möglichen Ersetzung durch Dritte,
    schließt es aber nicht vollständig — os.replace selbst kennt kein
    „nur ersetzen, wenn Symlink" (siehe Klassen-Docstring). Kollidiert
    der temporäre Name (praktisch ausgeschlossen), wird mit neuem Namen
    erneut versucht, bis zu _MAX_SYMLINK_ATTEMPTS Mal. Schlägt der Recheck
    oder der Austausch selbst fehl, wird der bereits angelegte temporäre
    Symlink entfernt, statt liegen zu bleiben.

    Args:
        link_dir: Verzeichnis, in dem der Symlink liegt/entstehen soll.
        link_name: Dateiname des Symlinks (ohne Verzeichnisanteil).
        target: Ziel, auf das der Symlink zeigen soll.

    Raises:
        ActionError: Wenn nach allen Versuchen kein temporärer Symlink
            angelegt werden konnte, oder wenn der Recheck unmittelbar vor
            dem Austausch zeigt, dass link_name kein Symlink mehr ist.
        OSError: Bei sonstigem Anlege- oder Austauschfehler; der
            temporäre Symlink wird zuvor entfernt.
    """
    for _ in range(_MAX_SYMLINK_ATTEMPTS):
        tmp_path = link_dir / f".{link_name}.tmp-{secrets.token_hex(8)}"
        try:
            os.symlink(target, str(tmp_path))
        except FileExistsError:
            continue

        final_path = link_dir / link_name
        try:
            current_stat = os.lstat(str(final_path))
        except OSError as exc:
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise ActionError(
                f"Zielpfad für Symlink-Austausch nicht mehr vorhanden:"
                f" {link_name!r}: {exc}"
            ) from exc
        if not stat.S_ISLNK(current_stat.st_mode):
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise ActionError(
                f"Zielpfad ist zwischenzeitlich kein Symlink mehr,"
                f" Austausch abgebrochen: {link_name!r}"
            )

        try:
            os.replace(str(tmp_path), str(final_path))
        except OSError:
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise
        return

    raise ActionError(
        f"Temporärer Symlink konnte nach {_MAX_SYMLINK_ATTEMPTS} Versuchen"
        f" nicht angelegt werden: {link_name!r}"
    )


class SymlinkAction(Action):
    """Legt einen Symlink an, der auf target zeigt.

    target muss nicht existieren — ein toter Symlink (Ziel fehlt) ist
    zulässig und wird nicht geprüft; das entspricht dem Grundsatz, dass
    Aktionen Parameter nicht inhaltlich prüfen.

    Existiert am link_path bereits ein Eintrag, wird ohne overwrite=True
    ActionError erzeugt (safe-mode-Gedanke wie bei den anderen Datei-
    Aktionen). Mit overwrite=True wird nur ein vorhandener Symlink
    ersetzt — über einen temporären Symlink und os.replace, mit einem
    Recheck (os.lstat) unmittelbar vor dem Austausch, siehe
    _create_symlink_atomic. Ein Verzeichnis am link_path wird dabei nie
    ersetzt: os.replace lehnt das Ersetzen eines Verzeichnisses durch
    einen Nicht-Verzeichnis-Eintrag auf Betriebssystemebene ab (kein
    Zeitfenster, kein Restrisiko). Eine reguläre Datei am link_path soll
    ebenfalls nie ersetzt werden — dieser Schutz beruht jedoch auf der
    Vorprüfung (is_symlink) und dem Recheck unmittelbar vor os.replace,
    nicht auf einer Betriebssystem-Garantie wie bei Verzeichnissen: ein
    Wettlauf mit einem gleichzeitigen dritten Prozess, der die Datei
    genau im letzten Moment durch einen Symlink ersetzt, ist theoretisch
    weiterhin möglich (TOCTOU, kein absoluter Schutz). Erkennt die
    Vorprüfung oder der Recheck eine reguläre Datei bzw. ein Verzeichnis,
    wird ActionError erzeugt, auch mit overwrite=True.

    Für einen Symlink gibt es keine Sicherung (safe-mode-Backup): ein
    Symlink hat keinen eigenen Inhalt, der gesichert werden könnte — nur
    ein Ziel-Pfad als Zeichenkette. Ein Rückbau ist über einen erneuten
    SymlinkAction-Aufruf mit dem vorherigen target möglich.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        link_path: Pfad des anzulegenden Symlinks.
        target: Ziel, auf das der Symlink zeigen soll.
        overwrite: Erlaubt das Ersetzen eines bestehenden Symlinks an
            link_path. Voreinstellung False.

    Example:
        action = SymlinkAction("/etc/pifos/config.ini", "config.d/prod.ini")
        action.run()
    """

    PARAMS: ClassVar[list[str]] = ["link_path", "target", "overwrite"]

    def __init__(
        self,
        link_path: str,
        target: str,
        overwrite: bool = False,
    ) -> None:
        """Initialisiert die Symlink-Anlege-Aktion.

        Args:
            link_path: Pfad des anzulegenden Symlinks.
            target: Ziel, auf das der Symlink zeigen soll. Muss nicht
                existieren (toter Link zulässig).
            overwrite: Erlaubt das Ersetzen eines bestehenden Symlinks an
                link_path; eine bestehende reguläre Datei oder ein
                Verzeichnis wird dadurch nicht ersetzt. Voreinstellung
                False.
        """
        super().__init__()
        self.link_path = link_path
        self.target = target
        self.overwrite = overwrite

    def run(self) -> str:
        """Legt den Symlink an und liefert den Ausführungsstatus.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei vorhandenem Eintrag ohne overwrite=True,
                bei einer bestehenden Datei/einem Verzeichnis am
                link_path (auch mit overwrite=True) oder bei Anlege-
                bzw. Austauschfehler.
        """
        self.status = "running"
        try:
            link_path = Path(self.link_path)
            is_symlink = link_path.is_symlink()
            exists = is_symlink or link_path.exists()

            if exists:
                if not self.overwrite:
                    self.status = "failed"
                    raise ActionError(
                        f"Pfad vorhanden, Überschreiben nicht freigegeben:"
                        f" {self.link_path!r}"
                    )
                if not is_symlink:
                    self.status = "failed"
                    raise ActionError(
                        f"Pfad ist eine Datei oder ein Verzeichnis, wird"
                        f" nie ersetzt: {self.link_path!r}"
                    )
                _create_symlink_atomic(link_path.parent, link_path.name, self.target)
            else:
                os.symlink(self.target, str(link_path))
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Fehler beim Anlegen des Symlinks: {exc}") from exc

        self.status = "finished"
        return self.status
