"""Integrationstest für secure_base.modules.logging.

Startet Logging.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn) — Begründung analog test_base_module.py: ein
Spawn-Subprozess teilt keinen Zustand mit dem Testprozess, sodass ein
monkeypatch der Systembefehl-Konstanten dort nicht ankäme. Der direkte
Aufruf ersetzt die Systembefehle durch harmlose Platzhalter und prüft
Ablauf, Meldungen und Rückgabewert. Die Aktionen selbst sind bereits in
pifos getestet.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.logging import Logging


class _NoOpAptAction(AptAction):
    """Ersetzt AptAction für Tests: läuft immer erfolgreich durch, ohne apt-get."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


class _NoOpSystemdAction(SystemdServiceAction):
    """Ersetzt SystemdServiceAction für Tests: läuft immer erfolgreich durch."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Logging, MagicMock]:
    """Baut ein Logging-Modul mit harmlosen Platzhaltern für alle Zielpfade."""
    journald_conf = tmp_path / "journald.conf"
    journald_conf.write_text("#Storage=auto\n#SystemMaxUse=\n", encoding="utf-8")

    monkeypatch.setattr(Logging, "JOURNALD_CONF", str(journald_conf))
    monkeypatch.setattr(Logging, "LOGWATCH_CONF", str(tmp_path / "logwatch.conf"))
    monkeypatch.setattr(Logging, "JOURNAL_DIR", str(tmp_path / "journal"))
    monkeypatch.setattr(Logging, "LOGROTATE_CONF", str(tmp_path / "logrotate.conf"))
    monkeypatch.setattr(Logging, "AUDIT_RULES_FILE", str(tmp_path / "audit-rules.conf"))
    monkeypatch.setattr(Logging, "SUDOLOG_CONF", str(tmp_path / "sudolog.conf"))
    monkeypatch.setattr(Logging, "SYSTEMCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Logging, "DPKG_BIN", "/usr/bin/true")
    monkeypatch.setattr(Logging, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Logging, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)

    conn = MagicMock()
    mod = Logging(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = "server.example.com"
    mod.admin_mail = "admin@example.com"
    mod.journald_max_use = "1G"
    mod.journald_max_retention = "3month"
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
    assert "auditd starten" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert Path(Logging.JOURNALD_CONF).read_text(encoding="utf-8").splitlines() == [
        "Storage=persistent",
        "SystemMaxUse=1G",
        "MaxRetentionSec=3month",
    ]
    assert Path(Logging.LOGWATCH_CONF).exists()
    logwatch_lines = Path(Logging.LOGWATCH_CONF).read_text(encoding="utf-8")
    assert "MailTo = admin@example.com" in logwatch_lines
    assert "MailFrom = root@example.com" in logwatch_lines
    assert Path(Logging.LOGROTATE_CONF).exists()
    assert Path(Logging.AUDIT_RULES_FILE).exists()
    assert Path(Logging.SUDOLOG_CONF).exists()


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Logging, "JOURNALD_CONF", str(tmp_path / "fehlt.conf"))

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: journald Storage setzen" in messages
    assert "logwatch installieren" not in messages


def test_install_rejects_invalid_admin_mail_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein ungültiges admin_mail bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.admin_mail = "ungueltig"

    with pytest.raises(ModuleError, match="Ungültige admin_mail"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check vergleicht Ist- und Soll-Werte und meldet Abweichungen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"
    # Kein install-Lauf: keine der Zieldateien existiert, JOURNAL_DIR fehlt,
    # /usr/bin/true liefert keine passende Ausgabe für den Dienststatus.

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any(
        "journald Storage" in str(m) and "nicht gesetzt" in str(m) for m in messages
    )
