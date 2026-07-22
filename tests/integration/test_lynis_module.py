"""Integrationstest für secure_base.modules.lynis.

Startet Lynis.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn), siehe test_base_module.py für die Begründung.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.lynis import Lynis


class _NoOpAptAction(AptAction):
    """Ersetzt AptAction für Tests: läuft immer erfolgreich durch, ohne apt-get."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Lynis, MagicMock]:
    """Baut ein Lynis-Modul mit harmlosen Platzhaltern für Schreibziele/Paket."""
    monkeypatch.setattr(Lynis, "PRUEF_SCRIPT", str(tmp_path / "pruef.sh"))
    monkeypatch.setattr(Lynis, "CRON_FILE", str(tmp_path / "cron"))
    monkeypatch.setattr(Lynis, "BERICHTE_DIR", str(tmp_path / "berichte"))
    monkeypatch.setattr(Lynis, "APT_ACTION_CLS", _NoOpAptAction)

    conn = MagicMock()
    mod = Lynis(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.lynis_schedule = "0 4 1 * *"
    return mod, conn


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, keine Fehlermeldung."""
    mod, conn = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "Cron-Eintrag schreiben" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    berichte_dir = tmp_path / "berichte"
    pruef_script = tmp_path / "pruef.sh"
    cron_file = tmp_path / "cron"
    assert berichte_dir.is_dir()
    assert pruef_script.exists()
    assert cron_file.exists()


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    # Berichteverzeichnis existiert bereits als Datei statt als Verzeichnis:
    # MakeDirAction scheitert am zweiten Schritt.
    (tmp_path / "berichte").write_text("keine Datei erwartet", encoding="utf-8")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Berichtsverzeichnis anlegen" in messages
    assert "Prüfskript schreiben" not in messages


def test_install_rejects_invalid_schedule_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiger Cron-Zeitplan bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.lynis_schedule = "unsinn"

    with pytest.raises(ModuleError, match="braucht 5 Felder"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_confirms_after_successful_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check bestätigt einen zuvor erfolgreichen install-Lauf."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    fake_dpkg_query = tmp_path / "dpkg-query-fake"
    fake_dpkg_query.write_text(
        "#!/bin/sh\nprintf 'install ok installed'\n", encoding="utf-8"
    )
    fake_dpkg_query.chmod(0o755)
    monkeypatch.setattr(Lynis, "DPKG_QUERY_BIN", str(fake_dpkg_query))
    conn.reset_mock()
    mod.operation = "check"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert not any("soll" in str(m) for m in messages)


def test_check_reports_mismatch_when_nothing_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne vorherigen install-Lauf meldet check jede Abweichung."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Lynis, "DPKG_QUERY_BIN", "/usr/bin/false")
    mod.operation = "check"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("Paket lynis" in str(m) for m in messages)
    assert any("Berichtsverzeichnis" in str(m) for m in messages)


class _NoOpAptRemoveAction(_NoOpAptAction):
    """Ersetzt AptAction für uninstall-Tests: merkt sich den gewünschten Zustand."""

    last_state: str | None = None

    def run(self) -> str:
        _NoOpAptRemoveAction.last_state = self.state
        self.status = "finished"
        return self.status


def test_uninstall_removes_cron_and_script_but_keeps_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall entfernt Cron-Eintrag und Prüfskript, lässt Berichte stehen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Lynis, "APT_ACTION_CLS", _NoOpAptRemoveAction)
    assert mod.start() == 0
    berichte_dir = tmp_path / "berichte"
    bericht = berichte_dir / "lynis-2026-07-05.txt"
    bericht.write_text("Prüfnachweis", encoding="utf-8")
    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    assert not (tmp_path / "cron").exists()
    assert not (tmp_path / "pruef.sh").exists()
    assert bericht.exists()
    assert _NoOpAptRemoveAction.last_state == "absent"
    messages = _sent_messages(conn)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_uninstall_without_prior_install_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall ohne vorherigen install-Lauf meldet keinen Fehler."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Lynis, "APT_ACTION_CLS", _NoOpAptRemoveAction)
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("übersprungen" in str(m) for m in messages)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_test_operation_succeeds_after_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """test bestätigt einen zuvor erfolgreichen install-Lauf, ohne ihn zu ändern."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    fake_dpkg_query = tmp_path / "dpkg-query-fake"
    fake_dpkg_query.write_text(
        "#!/bin/sh\nprintf 'install ok installed'\n", encoding="utf-8"
    )
    fake_dpkg_query.chmod(0o755)
    monkeypatch.setattr(Lynis, "DPKG_QUERY_BIN", str(fake_dpkg_query))
    monkeypatch.setattr(Lynis, "LYNIS_BIN", "/bin/echo")
    monkeypatch.setattr(Lynis, "BASH_BIN", "/bin/bash")
    pruef_script = tmp_path / "pruef.sh"
    pruef_before = pruef_script.read_text(encoding="utf-8")
    conn.reset_mock()
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    assert pruef_script.read_text(encoding="utf-8") == pruef_before
    messages = _sent_messages(conn)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_test_operation_reports_missing_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """test meldet ohne installiertes Paket einen Fehler, ohne abzubrechen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Lynis, "DPKG_QUERY_BIN", "/usr/bin/false")
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("Paket lynis" in str(m) for m in messages)
    # Sammelnd statt abbrechend: die nachfolgende Prüfung lief trotz des
    # ersten Fehlschlags noch mit.
    assert any("Prüfskript-Selbsttest" in str(m) for m in messages)


# --- Drift-Schutz ---


def test_install_second_run_without_change_writes_nothing_new(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter install-Lauf ohne Abweichung schreibt keine der Dateien neu."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    conn.reset_mock()

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any(
        f"{mod.PRUEF_SCRIPT}: unverändert — übersprungen" in str(m) for m in messages
    )
    assert any(
        f"{mod.CRON_FILE}: unverändert — übersprungen" in str(m) for m in messages
    )


def test_install_rejects_manually_changed_pruef_script_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein von Hand geändertes Prüfskript bricht install ohne Freigabe ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    Path(mod.PRUEF_SCRIPT).write_text("#!/bin/bash\necho geändert\n", encoding="utf-8")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any(f"{mod.PRUEF_SCRIPT} weicht vom Soll ab" in str(m) for m in messages)
    assert (
        Path(mod.PRUEF_SCRIPT).read_text(encoding="utf-8")
        == "#!/bin/bash\necho geändert\n"
    )
