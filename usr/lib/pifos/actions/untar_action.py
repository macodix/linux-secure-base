"""Tar-Archiv-Extraktions-Aktion für pifos.

Setzt SIC-13, SIC-14, SIC-15 sinngemäß für die Extraktion um:
ausschließlich über tarfile mit dem Extraktionsfilter "data" (PEP 706),
der Pfadausbruch, absolute Pfade, Symlink-Angriffe und Rechteausweitung
beim Entpacken abwehrt.
"""

import tarfile
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.errors import ActionError


class UntarAction(Action):
    """Entpackt ein tar-Archiv in ein bestehendes Zielverzeichnis.

    Die Komprimierung (gzip oder unkomprimiert) wird automatisch erkannt
    (tarfile-Lesemodus "r:*"). Das Zielverzeichnis muss existieren, die
    Aktion legt es nicht an.

    Die Extraktion läuft ausschließlich über tarfile.extractall mit dem
    Extraktionsfilter filter="data" (PEP 706, verfügbar ab Python 3.12).
    Der Filter weist absolute Pfade, Pfadausbruch aus dem Zielverzeichnis,
    Gerätedateien, Symlink-Angriffe auf Pfade außerhalb des Ziels und eine
    Rechteausweitung zurück und bricht die Extraktion mit einem Fehler ab.

    Ohne overwrite=True (Voreinstellung) wird vor der Extraktion geprüft,
    ob eine Archiv-Datei (kein Verzeichnis) im Zielverzeichnis bereits
    existiert; trifft das zu, wird ActionError erzeugt und nichts entpackt.
    Mit overwrite=True werden bestehende Dateien überschrieben. Es wird
    keine Sicherung einzelner Dateien angelegt (kein safe-mode-Backup).

    Gegen Dekompressionsangriffe (z. B. gzip-Bomben, Massen an Mitgliedern)
    prüft die Aktion vor der Extraktion die Mitgliederzahl gegen
    max_members und die Summe der unkomprimierten Größen (member.size)
    gegen max_total_size; eine Überschreitung erzeugt ActionError ohne
    Extraktion.

    Attributes:
        PARAMS: Parameternamen der Aktion.
        src: Pfad des Archivs.
        dst_dir: Zielverzeichnis; muss existieren.
        overwrite: Erlaubt das Überschreiben bestehender Dateien im
            Zielverzeichnis. Voreinstellung False.
        max_members: Maximale Anzahl Mitglieder im Archiv. Voreinstellung
            10000.
        max_total_size: Maximale Summe der unkomprimierten Mitglieder-
            größen in Bytes. Voreinstellung 1 GiB (1073741824).

    Example:
        action = UntarAction("/var/backups/ssh.tar.gz", "/restore/ssh")
        action.run()
    """

    PARAMS: ClassVar[list[str]] = [
        "src",
        "dst_dir",
        "overwrite",
        "max_members",
        "max_total_size",
    ]

    def __init__(
        self,
        src: str,
        dst_dir: str,
        overwrite: bool = False,
        max_members: int = 10_000,
        max_total_size: int = 1024**3,
    ) -> None:
        """Initialisiert die Tar-Archiv-Extraktions-Aktion.

        Args:
            src: Pfad des zu entpackenden Archivs.
            dst_dir: Zielverzeichnis. Muss existieren.
            overwrite: Erlaubt das Überschreiben bestehender Dateien im
                Zielverzeichnis. Voreinstellung False.
            max_members: Maximale Anzahl Mitglieder im Archiv, gegen
                Massen-Mitglieder-Angriffe. Voreinstellung 10000.
            max_total_size: Maximale Summe der unkomprimierten
                Mitgliedergrößen in Bytes, gegen Dekompressionsangriffe
                (z. B. gzip-Bomben). Voreinstellung 1 GiB (1073741824).
        """
        super().__init__()
        self.src = src
        self.dst_dir = dst_dir
        self.overwrite = overwrite
        self.max_members = max_members
        self.max_total_size = max_total_size

    def run(self) -> str:
        """Entpackt das Archiv und liefert den Ausführungsstatus.

        Returns:
            Aktueller Status nach der Ausführung ("finished" oder "failed").

        Raises:
            ActionError: Bei fehlendem Archiv, fehlendem Zielverzeichnis,
                Überschreitung von max_members oder max_total_size,
                Dateikollision ohne overwrite=True oder Extraktionsfehler
                (u. a. bei Verstoß gegen den Extraktionsfilter "data").
        """
        self.status = "running"
        try:
            src_path = Path(self.src)
            dst_path = Path(self.dst_dir)

            if not src_path.exists():
                self.status = "failed"
                raise ActionError(f"Archiv nicht gefunden: {self.src!r}")
            if not dst_path.is_dir():
                self.status = "failed"
                raise ActionError(f"Zielverzeichnis nicht gefunden: {self.dst_dir!r}")

            self._extract(src_path, dst_path)
        except ActionError:
            if self.status != "failed":
                self.status = "failed"
            raise
        except OSError as exc:
            self.status = "failed"
            raise ActionError(f"Dateifehler beim Entpacken: {exc}") from exc
        except tarfile.TarError as exc:
            self.status = "failed"
            raise ActionError(f"Fehler beim Entpacken: {exc}") from exc

        self.status = "finished"
        return self.status

    def _check_limits(self, members: list[tarfile.TarInfo]) -> None:
        """Prüft Mitgliederzahl und Gesamtgröße gegen die konfigurierten Grenzen.

        Schützt vor Dekompressionsangriffen (z. B. gzip-Bomben) und
        Massen-Mitglieder-Angriffen, indem vor der Extraktion abgebrochen
        wird statt während einer bereits laufenden Extraktion.

        Args:
            members: Mitglieder des Archivs (tar.getmembers()).

        Raises:
            ActionError: Bei Überschreitung von max_members oder
                max_total_size.
        """
        if len(members) > self.max_members:
            raise ActionError(
                f"Archiv enthält zu viele Mitglieder: {len(members)}"
                f" > max_members={self.max_members}"
            )
        total_size = sum(member.size for member in members)
        if total_size > self.max_total_size:
            raise ActionError(
                f"Unkomprimierte Archivgröße zu groß: {total_size} Bytes"
                f" > max_total_size={self.max_total_size} Bytes"
            )

    def _extract(self, src_path: Path, dst_path: Path) -> None:
        """Prüft Grenzen und Kollisionen, entpackt das Archiv mit filter="data".

        Args:
            src_path: Archiv.
            dst_path: Zielverzeichnis.

        Raises:
            ActionError: Bei Überschreitung von max_members/max_total_size
                oder bei Dateikollision ohne overwrite=True.
            tarfile.TarError: Bei Verstoß gegen den Extraktionsfilter oder
                sonstigem Extraktionsfehler.
        """
        with tarfile.open(str(src_path), mode="r:*") as tar:
            members = tar.getmembers()
            self._check_limits(members)
            if not self.overwrite:
                collisions = [
                    member.name
                    for member in members
                    if not member.isdir()
                    and (
                        (dst_path / member.name).exists()
                        or (dst_path / member.name).is_symlink()
                    )
                ]
                if collisions:
                    raise ActionError(f"Zieldateien bereits vorhanden: {collisions!r}")
            tar.extractall(path=str(dst_path), filter="data")
