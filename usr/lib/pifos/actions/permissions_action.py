"""Rechte- und Eigentümer-Aktion für pifos.

Setzt SIC-13, SIC-15 um: kein Folgen von Symlinks bei Eigentümer- und
Rechteänderung, TOCTOU-fest über einen einzigen O_NOFOLLOW-Deskriptor.
"""

import grp
import os
import pwd
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.errors import ActionError


class PermissionsAction(Action):
    """Setzt Rechte und/oder Eigentümer eines bestehenden Dateisystemobjekts.

    Gilt für Dateien und Verzeichnisse gleichermaßen. Mindestens einer von
    mode, owner, group muss gesetzt sein, sonst wird ActionError erzeugt.
    owner und group akzeptieren einen Namen (Auflösung über pwd/grp) oder
    direkt eine numerische UID/GID; ein unbekannter Name erzeugt
    ActionError.

    path wird einmalig mit O_NOFOLLOW geöffnet (SIC-15); Eigentümer- und
    Rechteänderung laufen beide über denselben Deskriptor (os.fchown,
    os.fchmod) statt über den Namen. Damit ist zwischen der Existenz-
    prüfung und der eigentlichen Änderung kein Zeitfenster mehr offen, in
    dem der Eintrag durch einen Symlink ersetzt und die Änderung so auf
    ein anderes Ziel umgelenkt werden könnte (TOCTOU). Ist path selbst
    ein Symlink, schlägt das Öffnen mit ELOOP fehl und die Aktion bricht
    mit ActionError ab, ohne etwas zu ändern (fail-closed) — os.chmod/
    os.chown würden dem Symlink sonst folgen und sein Ziel treffen.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        path: Datei oder Verzeichnis, dessen Rechte/Eigentümer geändert
            werden.
        mode: Neue Rechte oder None (unverändert).
        owner: Neuer Eigentümer (Name oder UID) oder None (unverändert).
        group: Neue Gruppe (Name oder GID) oder None (unverändert).

    Example:
        action = PermissionsAction("/etc/pifos/config.ini", mode=0o600,
                                    owner="root", group="root")
        action.run()
    """

    PARAMS: ClassVar[list[str]] = ["path", "mode", "owner", "group"]

    def __init__(
        self,
        path: str,
        mode: int | None = None,
        owner: str | int | None = None,
        group: str | int | None = None,
    ) -> None:
        """Initialisiert die Rechte- und Eigentümer-Aktion.

        Args:
            path: Datei oder Verzeichnis, dessen Rechte/Eigentümer
                geändert werden. Muss existieren.
            mode: Neue Rechte oder None (unverändert).
            owner: Neuer Eigentümer als Name (Auflösung über pwd) oder
                UID, oder None (unverändert).
            group: Neue Gruppe als Name (Auflösung über grp) oder GID,
                oder None (unverändert).
        """
        super().__init__()
        self.path = path
        self.mode = mode
        self.owner = owner
        self.group = group

    def run(self) -> str:
        """Setzt Rechte und/oder Eigentümer und liefert den Status.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Wenn weder mode noch owner noch group gesetzt
                ist, bei fehlendem path, unbekanntem Benutzer-/Gruppen-
                namen, wenn path (u. a. weil es ein Symlink ist) nicht
                ohne Symlink-Folgen geöffnet werden kann, oder bei
                sonstigem Fehler.
        """
        self.status = "running"
        try:
            if self.mode is None and self.owner is None and self.group is None:
                self.status = "failed"
                raise ActionError(
                    "Mindestens einer von mode, owner, group muss gesetzt sein"
                )

            path = Path(self.path)
            if not path.exists() and not path.is_symlink():
                self.status = "failed"
                raise ActionError(f"Pfad nicht gefunden: {self.path!r}")

            try:
                fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as exc:
                self.status = "failed"
                raise ActionError(
                    f"Pfad kann nicht ohne Symlink-Folgen geöffnet werden"
                    f" (path ist evtl. ein Symlink): {self.path!r}: {exc}"
                ) from exc

            try:
                if self.owner is not None or self.group is not None:
                    uid = (
                        self._resolve_uid(self.owner) if self.owner is not None else -1
                    )
                    gid = (
                        self._resolve_gid(self.group) if self.group is not None else -1
                    )
                    os.fchown(fd, uid, gid)

                if self.mode is not None:
                    os.fchmod(fd, self.mode)
            finally:
                os.close(fd)
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler bei der Rechteänderung: {exc}") from exc

        self.status = "finished"
        return self.status

    def _resolve_uid(self, owner: str | int) -> int:
        """Löst owner zu einer UID auf.

        Args:
            owner: Benutzername oder UID.

        Returns:
            UID.

        Raises:
            ActionError: Bei unbekanntem Benutzernamen.
        """
        if isinstance(owner, int):
            return owner
        try:
            return pwd.getpwnam(owner).pw_uid
        except KeyError as exc:
            raise ActionError(f"Unbekannter Benutzer: {owner!r}") from exc

    def _resolve_gid(self, group: str | int) -> int:
        """Löst group zu einer GID auf.

        Args:
            group: Gruppenname oder GID.

        Returns:
            GID.

        Raises:
            ActionError: Bei unbekanntem Gruppennamen.
        """
        if isinstance(group, int):
            return group
        try:
            return grp.getgrnam(group).gr_gid
        except KeyError as exc:
            raise ActionError(f"Unbekannte Gruppe: {group!r}") from exc
