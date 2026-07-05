"""Integrationstest für lsb.modules.lynis.

Startet Lynis.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn), siehe test_base_module.py für die Begründung.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from lsb.modules.lynis import Lynis
from pifos.actions.apt_action import AptAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel


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
