"""Gemeinsame Dateioperationen für Aktionen (SIC-13, SIC-14, SIC-15).

Interne Hilfsfunktionen für atomares Schreiben, Sicherung vor dem
Überschreiben und symlink-sicheres Lesen. Genutzt von den Aktionsmodulen aus
pifos.actions und vom Konfigurator (configurator.py).
"""

import contextlib
import os
import stat
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import IO, TextIO

from pifos.errors import ActionError

_MAX_BACKUP_ATTEMPTS = 100


def fd_copy(src_fd: int, dst_fd: int) -> None:
    """Kopiert Inhalt von src_fd nach dst_fd in 64-KiB-Blöcken.

    Args:
        src_fd: Quelldeskriptor (lesend geöffnet).
        dst_fd: Zieldeskriptor (schreibend geöffnet).

    Raises:
        OSError: Bei Lese- oder Schreibfehler.
    """
    while True:
        chunk = os.read(src_fd, 65536)
        if not chunk:
            break
        os.write(dst_fd, chunk)


def _open_no_follow(path: Path) -> TextIO:
    """Öffnet eine Textdatei lesend, ohne Symlinks zu folgen (SIC-15).

    Args:
        path: Zu öffnende Datei.

    Returns:
        Geöffnetes Textdateiobjekt (encoding="utf-8"); vom Aufrufer über
        einen Kontextmanager zu schließen.

    Raises:
        OSError: Bei Öffnungsfehler, insbesondere ELOOP bei Symlinks.
    """
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    return os.fdopen(fd, encoding="utf-8")


def read_lines_no_follow(path: Path) -> list[str]:
    """Liest eine Textdatei zeilenweise, ohne Symlinks zu folgen (SIC-15).

    Args:
        path: Zu lesende Datei.

    Returns:
        Zeilen der Datei einschließlich Zeilenumbruch (wie str.readlines()).

    Raises:
        OSError: Bei Öffnungs- oder Lesefehler.
    """
    with _open_no_follow(path) as f:
        return f.readlines()


def read_text_no_follow(path: Path) -> str:
    """Liest eine Textdatei vollständig, ohne Symlinks zu folgen (SIC-15).

    Args:
        path: Zu lesende Datei.

    Returns:
        Vollständiger Dateiinhalt.

    Raises:
        OSError: Bei Öffnungs- oder Lesefehler.
    """
    with _open_no_follow(path) as f:
        return f.read()


def atomic_write(
    dst_path: Path, mode: int, writer: Callable[[IO[bytes]], None]
) -> None:
    """Schreibt eine Datei atomar über eine Temp-Datei im Zielverzeichnis.

    Legt eine Temp-Datei im Verzeichnis von dst_path an, ruft writer mit
    dem offenen, schreibbaren Dateiobjekt auf, setzt die übergebenen Rechte
    und tauscht die Datei atomar aus (os.replace). Bei Fehler wird die
    Temp-Datei entfernt.

    Args:
        dst_path: Zieldatei.
        mode: Zu setzende Rechte der Zieldatei.
        writer: Callback, das den Inhalt in die offene Temp-Datei schreibt.

    Raises:
        OSError: Bei Temp-Datei-, Schreib- oder Umbenennungsfehler.
    """
    dst_dir = dst_path.parent
    tmp_fd, tmp_str = tempfile.mkstemp(dir=str(dst_dir))
    tmp_path = Path(tmp_str)
    fd_owned_by_fdopen = False
    try:
        with os.fdopen(tmp_fd, "wb") as tmp_file:
            fd_owned_by_fdopen = True
            writer(tmp_file)
        os.chmod(tmp_str, mode)
        os.replace(tmp_str, str(dst_path))
    except OSError:
        if not fd_owned_by_fdopen:
            with contextlib.suppress(OSError):
                os.close(tmp_fd)
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise


def _create_backup_file(
    backup_dir: Path, dst_name: str, timestamp: str, mode: int, src_fd: int
) -> tuple[Path, int]:
    """Legt die Sicherungsdatei exklusiv an, mit Zeitstempel im Namen.

    Der Name ist "<dst_name>.bak-<timestamp>". Kollidiert er (O_EXCL
    meldet EEXIST — z. B. zwei Sicherungen derselben Datei innerhalb
    derselben Sekunde), wird ein numerischer Zusatz "-1", "-2", ...
    angehängt, bis zu _MAX_BACKUP_ATTEMPTS Versuchen. O_EXCL bleibt dabei
    die einzige Existenzprüfung; es erfolgt keine vorherige exists()-
    Prüfung (TOCTOU, SIC-15).

    Args:
        backup_dir: Zielverzeichnis der Sicherung.
        dst_name: Name der zu sichernden Datei.
        timestamp: Zeitstempel im Format YYYY-MM-DD-HHMMSS.
        mode: Rechte der Sicherungsdatei (Original-Rechte, SIC-13).
        src_fd: Offener Deskriptor der Originaldatei; wird bei Fehler
            geschlossen.

    Returns:
        Pfad und offener Schreib-Deskriptor der angelegten Sicherungsdatei.

    Raises:
        ActionError: Bei Anlegefehler oder wenn die Sicherungsdatei nach
            allen Versuchen nicht angelegt werden kann (Namenskollisionen).
    """
    for attempt in range(_MAX_BACKUP_ATTEMPTS):
        suffix = "" if attempt == 0 else f"-{attempt}"
        backup_path = backup_dir / f"{dst_name}.bak-{timestamp}{suffix}"
        try:
            bak_fd = os.open(
                str(backup_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                mode,
            )
        except FileExistsError:
            continue
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.close(src_fd)
            raise ActionError(
                f"Sicherungsdatei kann nicht angelegt werden"
                f" {str(backup_path)!r}: {exc}"
            ) from exc
        return backup_path, bak_fd

    with contextlib.suppress(OSError):
        os.close(src_fd)
    raise ActionError(
        f"Sicherungsdatei konnte nach {_MAX_BACKUP_ATTEMPTS} Versuchen nicht"
        f" angelegt werden (Namenskollisionen): {dst_name!r}"
    )


def backup_destination(dst_path: Path, backup_location: str | None) -> None:
    """Sichert dst_path vor dem Überschreiben.

    Öffnet die Zieldatei mit O_NOFOLLOW (SIC-15), legt die Sicherung
    exklusiv mit denselben Rechten an (SIC-13) und schreibt den Inhalt
    per Dateideskriptor (SIC-15). Der Sicherungsort wird geprüft (SIC-14).
    Der Sicherungsname trägt einen Zeitstempel (lokale Zeit)
    "<name>.bak-<YYYY-MM-DD-HHMMSS>", bei Kollision innerhalb derselben
    Sekunde mit numerischem Zusatz ("-1", "-2", ...), siehe
    _create_backup_file.

    Args:
        dst_path: Zu sichernde Zieldatei.
        backup_location: Verzeichnis für die Sicherung oder None (dann
            gleiches Verzeichnis wie dst_path).

    Raises:
        ActionError: Bei ungültigem Sicherungsort, Rechteproblem,
            Symlink-Erkennung, Namenskollision nach allen Versuchen oder
            Schreibfehler.
    """
    # Sicherungsort prüfen (SIC-14)
    if backup_location is not None:
        backup_dir = Path(backup_location).resolve()
        if not backup_dir.is_dir():
            raise ActionError(
                f"Sicherungsort ist kein Verzeichnis: {backup_location!r}"
            )
    else:
        backup_dir = dst_path.resolve().parent

    # Rechte der Originaldatei (SIC-13: nicht ausweiten)
    try:
        orig_mode = stat.S_IMODE(os.lstat(dst_path).st_mode)
    except OSError as exc:
        raise ActionError(f"Rechte der Zieldatei nicht lesbar: {exc}") from exc

    # Bestehende Zieldatei mit O_NOFOLLOW öffnen — erkennt Symlink-
    # Substitution zwischen Prüfung und Öffnen (SIC-15)
    try:
        src_fd = os.open(str(dst_path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ActionError(f"Zieldatei für Sicherung nicht lesbar: {exc}") from exc

    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    backup_path, bak_fd = _create_backup_file(
        backup_dir, dst_path.name, timestamp, orig_mode, src_fd
    )

    copy_error: OSError | None = None
    try:
        fd_copy(src_fd, bak_fd)
    except OSError as exc:
        copy_error = exc
    finally:
        with contextlib.suppress(OSError):
            os.close(bak_fd)
        with contextlib.suppress(OSError):
            os.close(src_fd)
        if copy_error is not None:
            with contextlib.suppress(OSError):
                backup_path.unlink(missing_ok=True)

    if copy_error is not None:
        raise ActionError(
            f"Fehler beim Schreiben der Sicherung: {copy_error}"
        ) from copy_error
