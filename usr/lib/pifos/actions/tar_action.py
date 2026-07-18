"""Tar-Archiv-Erstellungs-Aktion mit safe-mode für pifos.

Setzt AKT-06, AKT-07 (safe-mode und einstellbarer Sicherungsort)
sowie SIC-13, SIC-14, SIC-15 (Rechte, Pfadprüfung, TOCTOU) um.
"""

import tarfile
from pathlib import Path
from typing import IO, ClassVar

from pifos.action import Action
from pifos.actions import _file_ops
from pifos.errors import ActionError


class TarAction(Action):
    """Packt eine Liste von Pfaden in ein tar-Archiv.

    Jede Quelle in sources (Datei oder Verzeichnis, rekursiv) wird unter
    ihrem Basisnamen ins Archiv aufgenommen. compression bestimmt die
    Komprimierung ("gz" oder None für unkomprimiert). Alle Quellen müssen
    existieren.

    Im safe-mode (Voreinstellung) wird ein bestehendes Zielarchiv ohne
    explizite Freigabe (overwrite=True) nicht überschrieben. Bei gesetzter
    Freigabe wird es vorher gesichert (AKT-06); der Sicherungsort ist
    einstellbar (AKT-07). Das Archiv wird atomar über eine Temp-Datei im
    Zielverzeichnis und os.replace erstellt; die Rechte sind restriktiv
    (Voreinstellung 0o600, über mode übersteuerbar).

    Attributes:
        PARAMS: Parameternamen der Aktion.
        sources: Zu packende Pfade.
        dst: Pfad des Zielarchivs.
        compression: "gz" oder None; Voreinstellung "gz".
        mode: Rechte des Zielarchivs; Voreinstellung 0o600.
        safe_mode: Schützt ein bestehendes Zielarchiv; Voreinstellung True.
        backup_location: Verzeichnis für die Sicherung oder None (dann
            gleiches Verzeichnis wie das Zielarchiv).
        overwrite: Erlaubt das Überschreiben eines bestehenden Zielarchivs
            im safe-mode; Sicherung wird angelegt. Voreinstellung False.

    Example:
        action = TarAction(["/etc/ssh"], "/var/backups/ssh.tar.gz")
        action.run()
    """

    PARAMS: ClassVar[list[str]] = [
        "sources",
        "dst",
        "compression",
        "mode",
        "safe_mode",
        "backup_location",
        "overwrite",
    ]

    def __init__(
        self,
        sources: list[str],
        dst: str,
        compression: str | None = "gz",
        mode: int = 0o600,
        safe_mode: bool = True,
        backup_location: str | None = None,
        overwrite: bool = False,
    ) -> None:
        """Initialisiert die Tar-Archiv-Erstellungs-Aktion.

        Args:
            sources: Zu packende Pfade (Dateien oder Verzeichnisse).
            dst: Pfad des Zielarchivs.
            compression: "gz" für gzip-Komprimierung, None für
                unkomprimiert. Voreinstellung "gz".
            mode: Rechte des Zielarchivs. Voreinstellung 0o600.
            safe_mode: Bei True wird ein bestehendes Zielarchiv geschützt.
                Ist overwrite ebenfalls True, wird es vor dem Überschreiben
                gesichert (AKT-06).
            backup_location: Verzeichnis für die Sicherungsdatei; None legt
                die Sicherung im Verzeichnis des Zielarchivs ab (AKT-07).
            overwrite: Gibt das Überschreiben eines bestehenden Zielarchivs
                explizit frei. Nur wirksam, wenn safe_mode=True.
        """
        super().__init__()
        self.sources = sources
        self.dst = dst
        self.compression = compression
        self.mode = mode
        self.safe_mode = safe_mode
        self.backup_location = backup_location
        self.overwrite = overwrite

    def run(self) -> str:
        """Erstellt das Archiv und liefert den Ausführungsstatus.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei fehlender Quelle, fehlendem safe-mode-Schutz,
                Sicherungsfehler oder Fehler beim Packen.
        """
        self.status = "running"
        try:
            dst_path = Path(self.dst)

            for source in self.sources:
                if not Path(source).exists():
                    self.status = "failed"
                    raise ActionError(f"Quelle nicht gefunden: {source!r}")

            if self.safe_mode and dst_path.exists():
                if not self.overwrite:
                    self.status = "failed"
                    raise ActionError(
                        f"Zielarchiv vorhanden, Überschreiben nicht freigegeben:"
                        f" {self.dst!r}"
                    )
                _file_ops.backup_destination(dst_path, self.backup_location)

            self._create(dst_path)
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler beim Packen: {exc}") from exc

        self.status = "finished"
        return self.status

    def _open_tar(self, f: IO[bytes]) -> tarfile.TarFile:
        """Öffnet das tar-Archiv auf f im Schreibmodus.

        compression="gz" komprimiert, jeder andere Wert (auch None)
        erstellt ein unkomprimiertes Archiv. Zwei feste Modus-Literale
        statt einer zusammengesetzten Zeichenkette, damit mypy den
        tarfile-Overload eindeutig auflösen kann.

        Args:
            f: Offenes, schreibbares Dateiobjekt der Temp-Datei.

        Returns:
            Geöffnetes TarFile-Objekt.
        """
        if self.compression == "gz":
            return tarfile.open(fileobj=f, mode="w:gz")
        return tarfile.open(fileobj=f, mode="w:")

    def _create(self, dst_path: Path) -> None:
        """Erstellt das Archiv atomar über eine Temp-Datei.

        tarfile.TarError wird als OSError weitergereicht, damit
        _file_ops.atomic_write die Temp-Datei auch bei Packungsfehlern
        (nicht nur bei reinen I/O-Fehlern) zuverlässig entfernt.

        Args:
            dst_path: Zielarchiv.

        Raises:
            ActionError: Bei Temp-Datei-, Packungs- oder Umbenennungsfehler.
        """

        def writer(f: IO[bytes]) -> None:
            try:
                with self._open_tar(f) as tar:
                    for source in self.sources:
                        source_path = Path(source)
                        tar.add(str(source_path), arcname=source_path.name)
            except tarfile.TarError as exc:
                raise OSError(str(exc)) from exc

        try:
            _file_ops.atomic_write(dst_path, self.mode, writer)
        except OSError as exc:
            raise ActionError(f"Fehler beim Packen: {exc}") from exc
