"""Datei-Lösch-Aktion mit safe-mode für pifos.

Setzt AKT-06, AKT-07 (safe-mode und einstellbarer Sicherungsort)
sowie SIC-13, SIC-14, SIC-15 (Rechte, Pfadprüfung, TOCTOU) um.
"""

import os
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions import _file_ops
from pifos.errors import ActionError


class DeleteFileAction(Action):
    """Löscht eine Datei.

    Im safe-mode (Voreinstellung) wird die Datei vor dem Löschen gesichert
    (AKT-06, _file_ops.backup_destination, Sicherungsname mit Zeitstempel);
    der Sicherungsort ist einstellbar (AKT-07). Mit safe_mode=False entfällt
    die Sicherung, die Datei wird ohne Sicherung gelöscht — safe-mode ist
    hier bewusst abschaltbar, nicht nur per overwrite-Freigabe wie bei den
    Kopier-/Schreib-Aktionen.

    Ist path ein Symlink, wirkt das Löschen (os.remove) nur auf den
    Symlink selbst, nie auf sein Ziel — das Ziel bleibt unangetastet.
    Im safe-mode kann ein Symlink jedoch nicht gesichert werden:
    backup_destination öffnet die zu sichernde Datei mit O_NOFOLLOW
    (SIC-15), was bei einem Symlink als path mit ELOOP fehlschlägt: die
    Aktion bricht dann mit ActionError ab, ohne etwas zu löschen. Mit
    safe_mode=False wird ein Symlink dagegen ohne Weiteres entfernt (nur
    der Link, nicht sein Ziel). Ein bestehender, auch defekter (Ziel
    fehlt) Symlink gilt als vorhandene Datei im Sinne dieser Aktion.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        path: Zu löschende Datei.
        safe_mode: Sichert die Datei vor dem Löschen; Voreinstellung True.
        backup_location: Verzeichnis für die Sicherung oder None (dann
            gleiches Verzeichnis wie die Datei).

    Example:
        action = DeleteFileAction("/var/tmp/upload.bin", safe_mode=False)
        action.run()
    """

    PARAMS: ClassVar[list[str]] = ["path", "safe_mode", "backup_location"]

    def __init__(
        self,
        path: str,
        safe_mode: bool = True,
        backup_location: str | None = None,
    ) -> None:
        """Initialisiert die Datei-Lösch-Aktion.

        Args:
            path: Zu löschende Datei.
            safe_mode: Bei True wird die Datei vor dem Löschen gesichert
                (AKT-06). Bei False entfällt die Sicherung; safe-mode ist
                hier vollständig abschaltbar. Voreinstellung True.
            backup_location: Verzeichnis für die Sicherungsdatei; None
                legt die Sicherung im Verzeichnis der zu löschenden Datei
                ab (AKT-07).
        """
        super().__init__()
        self.path = path
        self.safe_mode = safe_mode
        self.backup_location = backup_location

    def run(self) -> str:
        """Löscht die Datei und liefert den Ausführungsstatus.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei fehlender Datei, Sicherungsfehler (u. a. bei
                einem Symlink als path im safe-mode, siehe Klassen-
                Docstring) oder Löschfehler.
        """
        self.status = "running"
        try:
            path = Path(self.path)
            if not path.exists() and not path.is_symlink():
                self.status = "failed"
                raise ActionError(f"Datei nicht gefunden: {self.path!r}")

            if self.safe_mode:
                _file_ops.backup_destination(path, self.backup_location)

            os.remove(str(path))
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler beim Löschen: {exc}") from exc

        self.status = "finished"
        return self.status
