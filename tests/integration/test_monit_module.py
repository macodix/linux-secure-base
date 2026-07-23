"""Integrationstest für secure_base.modules.monit.

Startet Monit.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn) — Begründung siehe test_base_module.py. Der
direkte Aufruf im Testprozess ersetzt die Systembefehle durch harmlose
Platzhalter (Plan Abschnitt 2.12) und prüft Ablauf, Meldungen und
Rückgabewert von Monit. Die Aktionen selbst sind bereits in pifos getestet.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.monit import Monit


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


class _FailingSystemdAction(SystemdServiceAction):
    """Ersetzt SystemdServiceAction für Tests: scheitert immer."""

    def run(self) -> str:
        self.status = "failed"
        raise ActionError("stub: systemd-Aktion fehlgeschlagen")


def _write_dpkg_stub(path: Path, output: str, returncode: int = 0) -> str:
    """Schreibt ein ausführbares Stub-Skript als dpkg-query-Ersatz.

    Args:
        path: Zielpfad des Stub-Skripts.
        output: Stdout-Ausgabe des Stubs.
        returncode: Rückgabewert des Stubs.

    Returns:
        Pfad des Stub-Skripts als Zeichenkette.
    """
    path.write_text(f"#!/bin/sh\nprintf '%s' '{output}'\nexit {returncode}\n")
    path.chmod(0o755)
    return str(path)


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Monit, MagicMock]:
    """Baut ein Monit-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monitrc = tmp_path / "monitrc"
    monitrc.write_text("# vorhandene monitrc (von apt angelegt)\n")
    confd = tmp_path / "conf.d"
    confd.mkdir()

    monkeypatch.setattr(Monit, "MONIT_BIN", "/usr/bin/true")
    monkeypatch.setattr(Monit, "SYSTEMCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Monit, "MONITRC", str(monitrc))
    monkeypatch.setattr(Monit, "CONFD", str(confd))
    monkeypatch.setattr(Monit, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Monit, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)

    conn = MagicMock()
    mod = Monit(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = "admin@example.com"
    mod.monit_mail_from = "monit@example.com"
    mod.monit_checks = "system,rootfs"
    mod.force_overwrite = "no"
    mod.backup_run_dir = str(tmp_path / "backup-lauf")
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
    assert "Konfiguration neu einlesen (monit reload)" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)
    assert (Path(Monit.CONFD) / "system").exists()
    assert (Path(Monit.CONFD) / "rootfs").exists()
    monitrc_content = Path(Monit.MONITRC).read_text()
    assert "# BEGIN monit-alert" in monitrc_content
    assert "set alert admin@example.com but not on { instance }" in monitrc_content


def test_install_writes_only_configured_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nur die in monit_checks genannten Checks werden angelegt."""
    mod, _conn = _make_module(tmp_path, monkeypatch)
    mod.monit_checks = "sshd"

    result = mod.start()

    assert result == 0
    assert (Path(Monit.CONFD) / "sshd").exists()
    assert not (Path(Monit.CONFD) / "system").exists()


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Monit, "MONIT_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Konfiguration prüfen (monit -t)" in messages
    assert "Dienst aktivieren" not in messages


def test_install_rejects_invalid_admin_mail_before_any_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine ungültige admin_mail bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.admin_mail = "ungueltig"

    with pytest.raises(ModuleError, match="Ungültige admin_mail"):
        mod.start()

    assert conn.send.call_args_list == []


def test_install_twice_writes_no_backup_files_in_confd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter install-Lauf legt keine .bak-Sicherung in conf.d an.

    Sonst würde die Sicherung von monits Include-Glob mitgelesen (doppelter
    Check) und der anschließende monit -t-Lauf fehlschlagen (Regressionstest
    zum Servertest-Befund).
    """
    mod, _conn = _make_module(tmp_path, monkeypatch)

    assert mod.start() == 0
    assert mod.start() == 0

    confd_entries = sorted(p.name for p in Path(Monit.CONFD).iterdir())
    assert confd_entries == ["rootfs", "system"]


def test_install_second_run_skips_unchanged_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter install-Lauf ohne Änderung überspringt die Check-Dateien."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    check_file = Path(Monit.CONFD) / "system"
    before = check_file.stat().st_mtime_ns
    conn.reset_mock()

    result = mod.start()

    assert result == 0
    assert check_file.stat().st_mtime_ns == before
    messages = _sent_messages(conn)
    assert f"{check_file}: unverändert — übersprungen" in messages


def test_install_conflict_without_force_blocks_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine von Hand geänderte Check-Datei bleibt ohne Freigabe unangetastet."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    check_file = Path(Monit.CONFD) / "system"
    check_file.write_text("von hand geändert\n", encoding="utf-8")
    conn.reset_mock()

    result = mod.start()

    assert result == 1
    assert check_file.read_text(encoding="utf-8") == "von hand geändert\n"
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Check system schreiben" in messages


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check vergleicht Ist- und Soll-Werte und meldet Abweichungen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"
    # /usr/bin/true liefert keine Ausgabe; weicht daher von jedem Soll-Wert ab.
    # monitrc-Marker und conf.d-Dateien fehlen ebenfalls (kein install-Lauf).

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("Dienst aktiv" in str(m) and "soll" in str(m) for m in messages)
    assert any("set daemon" in str(m) and "fehlt" in str(m) for m in messages)


def test_check_confirms_markers_and_files_after_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nach install bestätigt check die monitrc-Marker und conf.d-Dateirechte.

    Paket- und Dienststatus bleiben trotzdem als Abweichung gemeldet, da der
    Platzhalter /usr/bin/true keine der erwarteten Ausgaben (z. B. "active")
    liefert — das ist hier unerheblich, geprüft wird nur die eigene Wirkung
    der install-Schritte (Marker, Dateirechte).
    """
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    conn.reset_mock()

    mod.operation = "check"
    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("monitrc-Eingriff 'set alert': vorhanden" in str(m) for m in messages)
    assert any("Check system:" in str(m) and "OK" in str(m) for m in messages)


# --- Betriebsart uninstall ---


def test_uninstall_skips_when_package_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist das Paket monit nicht installiert, meldet uninstall Erfolg ohne Schritte."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Monit,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "unknown", returncode=1),
    )
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "Paket monit nicht installiert — nichts zu tun" in messages
    assert "Paket entfernen" not in messages


def test_uninstall_removes_all_known_checks_and_monitrc_markers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall entfernt alle KNOWN_CHECKS (nicht nur monit_checks) und alle Marker."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0  # install: legt system, rootfs und die sechs Marker an

    # Eine nicht (mehr) konfigurierte Check-Datei simuliert einen älteren
    # Lauf mit anderer monit_checks-Auswahl — muss ebenfalls entfernt werden.
    (Path(Monit.CONFD) / "sshd").write_text('check process sshd matching "sshd"\n')

    monkeypatch.setattr(
        Monit,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    assert list(Path(Monit.CONFD).iterdir()) == []
    assert "BEGIN" not in Path(Monit.MONITRC).read_text()
    messages = _sent_messages(conn)
    assert "Paket entfernen" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_uninstall_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    monkeypatch.setattr(
        Monit,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    monkeypatch.setattr(Monit, "SYSTEMD_ACTION_CLS", _FailingSystemdAction)
    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Dienst stoppen" in messages
    assert "Paket entfernen" not in messages
    assert (Path(Monit.CONFD) / "system").exists()


def test_uninstall_twice_stays_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter uninstall-Lauf trifft auf bereits entfernte Dateien/Marker."""
    mod, _conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    monkeypatch.setattr(
        Monit,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    mod.operation = "uninstall"

    assert mod.start() == 0
    assert mod.start() == 0


# --- Betriebsart test ---


def test_test_reports_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Sind Paket, Syntax und Status in Ordnung, liefert test 0."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Monit,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    monkeypatch.setattr(Monit, "MAIL_BIN", "/usr/bin/true")
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("monit -t" in str(m) and "ok" in str(m) for m in messages)
    assert any("monit status" in str(m) and "ok" in str(m) for m in messages)
    assert any("vorhanden" in str(m) for m in messages)


def test_test_collects_both_diagnostics_without_aborting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """test sammelt beide Befunde, statt beim ersten Fehler abzubrechen."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Monit,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    monkeypatch.setattr(Monit, "MONIT_BIN", "/usr/bin/false")
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("monit -t" in str(m) and "fehlgeschlagen" in str(m) for m in messages)
    assert any(
        "monit status" in str(m) and "fehlgeschlagen" in str(m) for m in messages
    )


def test_test_fails_when_package_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt das Paket monit, meldet test einen Fehler ohne Diagnosebefehle."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Monit,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "unknown", returncode=1),
    )
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "Paket monit nicht installiert — kein Funktionstest möglich" in messages


def test_test_warns_when_mail_binary_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt der mail-Befehl, warnt test, ohne den Rückgabewert zu verschlechtern."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(
        Monit,
        "DPKG_QUERY_BIN",
        _write_dpkg_stub(tmp_path / "dpkg-query", "install ok installed"),
    )
    monkeypatch.setattr(Monit, "MAIL_BIN", str(tmp_path / "mail-fehlt"))
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("fehlt" in str(m) and "Alarm-Mails" in str(m) for m in messages)
