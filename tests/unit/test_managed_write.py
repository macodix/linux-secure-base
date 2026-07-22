"""Tests für managed_write — Soll-Ist-Vergleich und zentrale Sicherung."""

import stat
from pathlib import Path
from typing import ClassVar, cast
from unittest.mock import MagicMock

from pifos.ipc import LogLevel
from pifos.module import Module
from secure_base.managed_write import ManagedFile, ManagedWriteMixin, managed_state


class _Mod(ManagedWriteMixin, Module):
    """Minimales Modul für die Mixin-Tests."""

    CONFIG: ClassVar[list[str]] = []

    def __init__(self, files: list[ManagedFile], run_dir: str, force: bool) -> None:
        super().__init__(conn=MagicMock(), loglevel=LogLevel.INFO)
        self._files = files
        self.backup_run_dir = run_dir
        self.force_overwrite = "yes" if force else "no"

    def start(self) -> int:
        return 0

    def _managed_files(self) -> list[ManagedFile]:
        return self._files


def _messages(mod: _Mod) -> list[str]:
    """Sammelt die Meldungstexte des Moduls."""
    conn = cast(MagicMock, mod._conn)
    return [str(c.args[0].payload) for c in conn.send.call_args_list]


def _make(
    tmp_path: Path, content: str | None, mode: int = 0o644, **kwargs: object
) -> tuple[_Mod, ManagedFile]:
    """Baut Modul und ein Ziel unter tmp_path."""
    mf = ManagedFile(
        dst=str(tmp_path / "ziel" / "datei.conf"),
        content=content,
        mode=mode,
        secret=bool(kwargs.get("secret", False)),
    )
    mod = _Mod(
        [mf], str(tmp_path / "sicherung" / "lauf-1"), bool(kwargs.get("force", False))
    )
    return mod, mf


# --- managed_state ---


def test_managed_state_missing_identical_deviating(tmp_path: Path) -> None:
    """Die drei Zustände fehlt/identisch/abweichend werden erkannt."""
    mf = ManagedFile(dst=str(tmp_path / "d"), content="soll\n", mode=0o644)
    assert managed_state(mf) == "fehlt"
    Path(mf.dst).write_text("soll\n", encoding="utf-8")
    assert managed_state(mf) == "identisch"
    Path(mf.dst).write_text("von hand geändert\n", encoding="utf-8")
    assert managed_state(mf) == "abweichend"


def test_managed_state_symlink_counts_as_deviating(tmp_path: Path) -> None:
    """Ein Symlink am Zielpfad gilt als abweichend (symlink-sicheres Lesen)."""
    real = tmp_path / "echt"
    real.write_text("soll\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real)
    mf = ManagedFile(dst=str(link), content="soll\n", mode=0o644)
    assert managed_state(mf) == "abweichend"


# --- write_managed ---


def test_write_managed_creates_missing_file_with_mode(tmp_path: Path) -> None:
    """Fehlendes Ziel wird mit dem deklarierten Modus geschrieben."""
    mod, mf = _make(tmp_path, "soll\n", mode=0o600)
    Path(mf.dst).parent.mkdir(parents=True)
    assert mod.write_managed("test", mf) == 0
    assert Path(mf.dst).read_text(encoding="utf-8") == "soll\n"
    assert stat.S_IMODE(Path(mf.dst).stat().st_mode) == 0o600


def test_write_managed_skips_identical_without_backup(tmp_path: Path) -> None:
    """Identischer Inhalt: kein Schreiben, keine Sicherung, Meldung je Datei."""
    mod, mf = _make(tmp_path, "soll\n")
    Path(mf.dst).parent.mkdir(parents=True)
    Path(mf.dst).write_text("soll\n", encoding="utf-8")
    before = Path(mf.dst).stat().st_mtime_ns
    assert mod.write_managed("test", mf) == 0
    assert Path(mf.dst).stat().st_mtime_ns == before
    assert not Path(mod.backup_run_dir).exists()
    assert any("unverändert — übersprungen" in m for m in _messages(mod))


def test_write_managed_conflict_without_force(tmp_path: Path) -> None:
    """Abweichender Inhalt ohne Freigabe: Konflikt, Datei bleibt unangetastet."""
    mod, mf = _make(tmp_path, "soll\n")
    Path(mf.dst).parent.mkdir(parents=True)
    Path(mf.dst).write_text("von hand\n", encoding="utf-8")
    assert mod.write_managed("test", mf) == 1
    assert Path(mf.dst).read_text(encoding="utf-8") == "von hand\n"
    assert not Path(mod.backup_run_dir).exists()
    assert any("--force-overwrite" in m for m in _messages(mod))


def test_write_managed_force_backs_up_then_overwrites(tmp_path: Path) -> None:
    """Freigabe: Original landet unter vollem Pfad in der Ablage, Ziel wird ersetzt."""
    mod, mf = _make(tmp_path, "soll\n", force=True)
    Path(mf.dst).parent.mkdir(parents=True)
    Path(mf.dst).write_text("von hand\n", encoding="utf-8")
    assert mod.write_managed("test", mf) == 0
    assert Path(mf.dst).read_text(encoding="utf-8") == "soll\n"
    backup = Path(mod.backup_run_dir) / Path(mf.dst).relative_to("/")
    assert backup.read_text(encoding="utf-8") == "von hand\n"


def test_write_managed_secret_is_never_backed_up(tmp_path: Path) -> None:
    """Geheimnis-Ziel: Überschreiben mit Freigabe, aber keine Kopie in der Ablage."""
    mod, mf = _make(tmp_path, "soll\n", secret=True, force=True)
    Path(mf.dst).parent.mkdir(parents=True)
    Path(mf.dst).write_text("altes passwort\n", encoding="utf-8")
    assert mod.write_managed("test", mf) == 0
    assert Path(mf.dst).read_text(encoding="utf-8") == "soll\n"
    assert not Path(mod.backup_run_dir).exists()
    assert any("nicht" in m and "gesichert" in m for m in _messages(mod))


def test_write_managed_failed_backup_blocks_overwrite(tmp_path: Path) -> None:
    """Scheitert die Sicherung, wird nicht überschrieben (Abbruch)."""
    mod, mf = _make(tmp_path, "soll\n", force=True)
    Path(mf.dst).parent.mkdir(parents=True)
    Path(mf.dst).write_text("von hand\n", encoding="utf-8")
    # Ablage-Wurzel als Datei blockiert das Anlegen der Verzeichniskette.
    Path(mod.backup_run_dir).parent.mkdir(parents=True)
    Path(mod.backup_run_dir).write_text("blockiert", encoding="utf-8")
    assert mod.write_managed("test", mf) == 1
    assert Path(mf.dst).read_text(encoding="utf-8") == "von hand\n"
    assert any("nicht überschrieben" in m for m in _messages(mod))


# --- backup_before_edit ---


def test_backup_before_edit_backs_up_once_per_run(tmp_path: Path) -> None:
    """Je Datei und Lauf höchstens eine Sicherung."""
    mod, _ = _make(tmp_path, "soll\n")
    ziel = tmp_path / "etc-datei"
    ziel.write_text("original\n", encoding="utf-8")
    assert mod.backup_before_edit("test", str(ziel)) == 0
    ziel.write_text("erste änderung\n", encoding="utf-8")
    assert mod.backup_before_edit("test", str(ziel)) == 0
    backup = Path(mod.backup_run_dir) / ziel.relative_to("/")
    assert backup.read_text(encoding="utf-8") == "original\n"


def test_backup_before_edit_skips_missing_file(tmp_path: Path) -> None:
    """Eine fehlende Datei braucht keine Sicherung."""
    mod, _ = _make(tmp_path, "soll\n")
    assert mod.backup_before_edit("test", str(tmp_path / "fehlt")) == 0
    assert not Path(mod.backup_run_dir).exists()


# --- preflight_managed / check_managed ---


def test_preflight_reports_conflicts_collected(tmp_path: Path) -> None:
    """Abweichung ohne Freigabe: Rückgabe 1 und Konflikt-Meldung."""
    mod, mf = _make(tmp_path, "soll\n")
    Path(mf.dst).parent.mkdir(parents=True)
    Path(mf.dst).write_text("von hand\n", encoding="utf-8")
    assert mod.preflight_managed("test") == 1
    assert any("weicht vom Soll ab" in m for m in _messages(mod))
    # Nichts wurde geändert.
    assert Path(mf.dst).read_text(encoding="utf-8") == "von hand\n"


def test_preflight_with_force_warns_but_passes(tmp_path: Path) -> None:
    """Mit Freigabe wird die Abweichung gemeldet, der Lauf aber nicht blockiert."""
    mod, mf = _make(tmp_path, "soll\n", force=True)
    Path(mf.dst).parent.mkdir(parents=True)
    Path(mf.dst).write_text("von hand\n", encoding="utf-8")
    assert mod.preflight_managed("test") == 0
    assert any("Freigabe erteilt" in m for m in _messages(mod))


def test_preflight_skips_undeterminable_targets(tmp_path: Path) -> None:
    """Ziele ohne bestimmbaren Soll-Inhalt (content=None) blockieren nicht."""
    mf = ManagedFile(dst=str(tmp_path / "x"), content=None, mode=0o644)
    mod = _Mod([mf], str(tmp_path / "lauf"), force=False)
    assert mod.preflight_managed("test") == 0


def test_check_managed_reports_states(tmp_path: Path) -> None:
    """check meldet identisch als OK, fehlt und abweichend als Befund."""
    mod, mf = _make(tmp_path, "soll\n")
    assert mod.check_managed("test") is False  # fehlt
    Path(mf.dst).parent.mkdir(parents=True)
    Path(mf.dst).write_text("soll\n", encoding="utf-8")
    assert mod.check_managed("test") is True
    Path(mf.dst).write_text("anders\n", encoding="utf-8")
    assert mod.check_managed("test") is False
    # Meldungen nennen nie Dateiinhalte.
    assert not any("anders" in m for m in _messages(mod))
