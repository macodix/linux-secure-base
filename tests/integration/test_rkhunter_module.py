"""Integrationstest für lsb.modules.rkhunter.

Startet Rkhunter.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn) — Begründung siehe test_base_module.py. Die
System-/Paketaktionen werden durch harmlose Platzhalter ersetzt; die
Dateiaktionen (LineInFileAction) laufen echt gegen Dateien unter tmp_path.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from lsb.modules.rkhunter import Rkhunter
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
) -> tuple[Rkhunter, MagicMock]:
    """Baut ein Rkhunter-Modul mit harmlosen Platzhaltern für Paket/Systembefehl.

    Die Zieldateien für /etc/default/rkhunter und /etc/rkhunter.conf werden
    unter tmp_path mit einem minimalen Bestand vorbelegt — LineInFileAction
    verlangt eine vorhandene Datei.
    """
    rk_default = tmp_path / "default_rkhunter"
    rk_default.write_text("# vom Paket rkhunter mitgeliefert\n", encoding="utf-8")
    rk_conf = tmp_path / "rkhunter.conf"
    rk_conf.write_text("# vom Paket rkhunter mitgeliefert\n", encoding="utf-8")

    monkeypatch.setattr(Rkhunter, "RK_DEFAULT", str(rk_default))
    monkeypatch.setattr(Rkhunter, "RK_CONF", str(rk_conf))
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(tmp_path / "rkhunter.dat"))
    monkeypatch.setattr(Rkhunter, "RKHUNTER_BIN", "/usr/bin/true")
    monkeypatch.setattr(Rkhunter, "APT_ACTION_CLS", _NoOpAptAction)

    conn = MagicMock()
    mod = Rkhunter(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = "srv001.example.com"
    mod.admin_mail = "admin@example.com"
    return mod, conn


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, Dateien gehärtet."""
    mod, conn = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "Baseline initialisieren" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)

    default_content = Path(mod.RK_DEFAULT).read_text(encoding="utf-8")
    assert 'CRON_DAILY_RUN="yes"' in default_content
    assert 'CRON_DB_UPDATE="yes"' in default_content
    assert 'DB_UPDATE_EMAIL="false"' in default_content
    assert 'REPORT_EMAIL="admin@example.com"' in default_content
    assert 'APT_AUTOGEN="yes"' in default_content

    conf_content = Path(mod.RK_CONF).read_text(encoding="utf-8")
    assert "MAIL_CMD=mail -r root@example.com" in conf_content
    assert "${HOST_NAME}" in conf_content


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Rkhunter, "RK_DEFAULT", str(tmp_path / "fehlt-nicht-angelegt"))

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: täglichen Lauf aktivieren" in messages
    assert "Mail-Absender setzen" not in messages
    assert "Baseline initialisieren" not in messages


def test_install_rejects_invalid_fqdn_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiger Rechnername bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.fqdn = "-invalid-"

    with pytest.raises(ModuleError, match="Kein Absender ableitbar"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check meldet fehlende Einstellungen und fehlende Baseline."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"
    # Die Stub-Dateien enthalten keine der gesuchten Zeilen, Baseline fehlt.

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any(
        "täglicher Lauf" in str(m) and "nicht gesetzt" in str(m) for m in messages
    )
    assert any("Baseline fehlt" in str(m) for m in messages)


def test_check_passes_after_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nach erfolgreichem install meldet check keine Abweichung."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    # Baseline vorab ablegen: der Platzhalter RKHUNTER_BIN (/usr/bin/true)
    # legt beim install keine echte Baseline an.
    Path(mod.RK_BASELINE).write_text("baseline-inhalt\n", encoding="utf-8")

    install_result = mod.start()
    assert install_result == 0

    mod.operation = "check"
    check_result = mod.start()

    assert check_result == 0
    messages = _sent_messages(conn)
    assert not any("nicht gesetzt" in str(m) for m in messages)
    assert not any("Baseline fehlt" in str(m) for m in messages)
