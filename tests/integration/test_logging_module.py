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
    # Reale Zielpfade (/usr/local/sbin, /etc/cron.daily) sind ohne Systemrechte
    # nicht beschreibbar — im Test auf tmp_path umgelenkt. Der mitgelieferte
    # logwatch-Cron wird als Platzhalterdatei vorbelegt: PermissionsAction
    # verlangt ein vorhandenes Ziel.
    stock_cron = tmp_path / "00logwatch"
    stock_cron.write_text("#!/bin/bash\n", encoding="utf-8")
    stock_cron.chmod(0o755)
    monkeypatch.setattr(Logging, "STOCK_CRON", str(stock_cron))
    monkeypatch.setattr(
        Logging, "REPORT_SCRIPT", str(tmp_path / "secure-base-logwatch.sh")
    )
    monkeypatch.setattr(Logging, "REPORT_CRON", str(tmp_path / "secure-base-logwatch"))
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


def _make_fake_dpkg(tmp_path: Path, installed: bool) -> str:
    """Baut ein ausführbares Fake-dpkg für die Paketstatus-Abfrage."""
    script = tmp_path / "fake-dpkg-uninstall"
    if installed:
        body = "printf 'Status: install ok installed\\n'\nexit 0\n"
    else:
        body = "printf 'Status: deinstall ok config-files\\n'\nexit 1\n"
    script.write_text(f"#!/bin/sh\n{body}")
    script.chmod(0o755)
    return str(script)


# --- Betriebsart uninstall ---


def test_uninstall_skips_absent_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne vorherigen install-Lauf überspringt uninstall alle Schritte (rc 0)."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "uninstall"
    # DPKG_BIN=/usr/bin/true (aus _make_module) meldet keinen Installationsstatus
    # — logwatch/auditd gelten als nicht installiert.

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("nicht installiert" in str(m) for m in messages)
    assert any("nicht vorhanden — übersprungen" in str(m) for m in messages)
    assert any("/var/log/sudo.log bleibt erhalten" in str(m) for m in messages)


def test_uninstall_removes_all_present_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vorhandene eigene Dateien und Pakete werden vollständig zurückgebaut."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "uninstall"
    monkeypatch.setattr(Logging, "DPKG_BIN", _make_fake_dpkg(tmp_path, installed=True))

    Path(Logging.JOURNALD_CONF).write_text(
        "Storage=persistent\nSystemMaxUse=1G\nMaxRetentionSec=3month\n",
        encoding="utf-8",
    )
    Path(Logging.LOGWATCH_CONF).write_text(
        "Output = mail\nMailTo = admin@example.com\n", encoding="utf-8"
    )
    Path(Logging.LOGROTATE_CONF).write_text("Inhalt\n", encoding="utf-8")
    Path(Logging.AUDIT_RULES_FILE).write_text("-e 2\n", encoding="utf-8")
    Path(Logging.SUDOLOG_CONF).write_text(
        'Defaults logfile="/var/log/sudo.log"\n', encoding="utf-8"
    )

    result = mod.start()

    assert result == 0
    assert Path(Logging.JOURNALD_CONF).read_text(encoding="utf-8") == ""
    assert not Path(Logging.LOGROTATE_CONF).exists()
    assert not Path(Logging.AUDIT_RULES_FILE).exists()
    assert not Path(Logging.SUDOLOG_CONF).exists()
    messages = _sent_messages(conn)
    assert "logwatch entfernen" in messages
    assert "auditd entfernen" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_uninstall_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "uninstall"
    # JOURNALD_CONF zeigt auf ein Verzeichnis statt einer Datei: exists()
    # ist True, das Lesen als Textdatei schlägt jedoch fehl.
    monkeypatch.setattr(Logging, "JOURNALD_CONF", str(tmp_path))

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: journald-Direktiven zurücknehmen" in messages
    assert "logwatch entfernen" not in messages


# --- Betriebsart test ---


def test_test_all_checks_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Beide Funktionstests (journald, logwatch) laufen erfolgreich durch."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "test"
    Path(Logging.JOURNAL_DIR).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Logging, "JOURNALCTL_BIN", "/bin/true")
    monkeypatch.setattr(Logging, "DPKG_BIN", _make_fake_dpkg(tmp_path, installed=True))
    logwatch_script = tmp_path / "fake-logwatch"
    logwatch_script.write_text("#!/bin/sh\nprintf 'Report OK\\n'\nexit 0\n")
    logwatch_script.chmod(0o755)
    monkeypatch.setattr(Logging, "LOGWATCH_BIN", str(logwatch_script))

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("journald-Persistenz nachgewiesen" in str(m) for m in messages)
    assert any("logwatch-Report abgesetzt" in str(m) for m in messages)


def test_test_reports_missing_journal_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt JOURNAL_DIR, meldet der journald-Test einen Fehlschlag ohne Abbruch."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "test"
    # JOURNAL_DIR wird bewusst nicht angelegt.
    monkeypatch.setattr(Logging, "JOURNALCTL_BIN", "/bin/true")
    monkeypatch.setattr(Logging, "DPKG_BIN", _make_fake_dpkg(tmp_path, installed=True))
    logwatch_script = tmp_path / "fake-logwatch"
    logwatch_script.write_text("#!/bin/sh\nprintf 'Report OK\\n'\nexit 0\n")
    logwatch_script.chmod(0o755)
    monkeypatch.setattr(Logging, "LOGWATCH_BIN", str(logwatch_script))

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("journald-Persistenz nicht nachweisbar" in str(m) for m in messages)
    # Der zweite Test läuft trotz des ersten Fehlschlags (sammelnd, kein Abbruch).
    assert any("logwatch-Report abgesetzt" in str(m) for m in messages)


def test_test_reports_logwatch_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt logwatch, meldet der Test einen Fehlschlag ohne Mailversand."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "test"
    Path(Logging.JOURNAL_DIR).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(Logging, "JOURNALCTL_BIN", "/bin/true")
    monkeypatch.setattr(Logging, "DPKG_BIN", _make_fake_dpkg(tmp_path, installed=False))

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("journald-Persistenz nachgewiesen" in str(m) for m in messages)
    assert not any("logwatch-Report abgesetzt" in str(m) for m in messages)
