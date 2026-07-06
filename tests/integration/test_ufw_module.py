"""Integrationstest für secure_base.modules.ufw.

Startet Ufw.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn); Begründung siehe test_base_module.py. Die
Systembefehle laufen über harmlose Platzhalter oder — für den
Regelabgleich (check/test) und die Paketprüfung (uninstall) — über
kleine Fake-Skripte, die die jeweilige Ausgabe nachbilden.
"""

import contextlib
import socket
import stat
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.ufw import Ufw


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


def _make_executable(path: Path, content: str) -> str:
    """Legt ein ausführbares Shell-Skript an und liefert seinen Pfad."""
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def _make_module(monkeypatch: pytest.MonkeyPatch) -> tuple[Ufw, MagicMock]:
    """Baut ein Ufw-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(Ufw, "UFW_BIN", "/usr/bin/true")
    monkeypatch.setattr(Ufw, "APT_ACTION_CLS", _NoOpAptAction)

    conn = MagicMock()
    mod = Ufw(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.allow_in_tcp = "22"
    mod.allow_out_tcp = "443,80"
    mod.allow_out_udp = "53"
    return mod, conn


def _make_uninstall_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, installed: bool
) -> tuple[Ufw, MagicMock]:
    """Baut ein Ufw-Modul für uninstall mit gefaktem dpkg-query-Ergebnis."""
    mod, conn = _make_module(monkeypatch)
    mod.operation = "uninstall"
    monkeypatch.setattr(Ufw, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)
    status = "install ok installed" if installed else "unknown ok not-installed"
    fake_dpkg_query = _make_executable(
        tmp_path / "fake_dpkg_query",
        f"#!/bin/sh\necho '{status}'\nexit 0\n",
    )
    monkeypatch.setattr(Ufw, "DPKG_QUERY_BIN", fake_dpkg_query)
    return mod, conn


def _make_test_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Ufw, MagicMock]:
    """Baut ein Ufw-Modul für die Betriebsart test mit harmlosen Platzhaltern."""
    mod, conn = _make_module(monkeypatch)
    mod.operation = "test"
    monkeypatch.setattr(Ufw, "NFT_BIN", "/usr/bin/false")
    monkeypatch.setattr(Ufw, "IPTABLES_BIN", "/usr/bin/false")
    return mod, conn


@contextlib.contextmanager
def _listening_port() -> Iterator[int]:
    """Öffnet einen lokalen TCP-Listener auf 127.0.0.1 und liefert dessen Port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        yield srv.getsockname()[1]


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def test_install_all_steps_succeed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, keine Fehlermeldung."""
    mod, conn = _make_module(monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("NICHT aktiv" in str(m) for m in messages)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_install_stops_at_first_failed_step(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(monkeypatch)
    monkeypatch.setattr(Ufw, "UFW_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: deterministischer Ausgangszustand (reset)" in messages
    assert "Default-Policy deny incoming" not in messages


def test_install_rejects_invalid_port_before_any_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein ungültiger Port bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(monkeypatch)
    mod.allow_in_tcp = "22,70000"

    with pytest.raises(ModuleError, match="ungültigen Port"):
        mod.start()

    assert conn.send.call_args_list == []


def test_install_rejects_missing_ssh_port_before_any_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein fehlender SSH-Port bricht vor dem ersten Schritt ab."""
    mod, conn = _make_module(monkeypatch)
    mod.allow_in_tcp = "80"

    with pytest.raises(ModuleError, match="SSH-Verwaltungszugang"):
        mod.start()

    assert conn.send.call_args_list == []


def test_check_reports_match(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Stimmt das Fake-Regelwerk mit der Konfiguration überein, liefert check 0."""
    mod, conn = _make_module(monkeypatch)
    mod.operation = "check"
    fake_ufw = _make_executable(
        tmp_path / "fake_ufw",
        "#!/bin/sh\n"
        'if [ "$1" = "show" ] && [ "$2" = "added" ]; then\n'
        '    echo "ufw allow 22/tcp"\n'
        '    echo "ufw allow out 80/tcp"\n'
        '    echo "ufw allow out 443/tcp"\n'
        '    echo "ufw allow out 53/udp"\n'
        "fi\n"
        "exit 0\n",
    )
    monkeypatch.setattr(Ufw, "UFW_BIN", fake_ufw)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("überein" in str(m) for m in messages)


def test_check_reports_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Weicht das Fake-Regelwerk von der Konfiguration ab, liefert check 1."""
    mod, conn = _make_module(monkeypatch)
    mod.operation = "check"
    fake_ufw = _make_executable(
        tmp_path / "fake_ufw",
        "#!/bin/sh\n"
        'if [ "$1" = "show" ] && [ "$2" = "added" ]; then\n'
        '    echo "ufw allow 22/tcp"\n'
        "fi\n"
        "exit 0\n",
    )
    monkeypatch.setattr(Ufw, "UFW_BIN", fake_ufw)

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("weicht ab" in str(m) for m in messages)


# --- uninstall ---


def test_uninstall_skips_when_package_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist ufw nicht installiert, meldet uninstall Erfolg ohne Systemeingriff."""
    mod, conn = _make_uninstall_module(tmp_path, monkeypatch, installed=False)
    # Würde die Kurzschluss-Prüfung nicht greifen, ließe dieser Platzhalter
    # den ersten echten Schritt fehlschlagen.
    monkeypatch.setattr(Ufw, "UFW_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("nicht installiert" in str(m) for m in messages)


def test_uninstall_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist ufw installiert, laufen alle Rückbau-Schritte mit Platzhaltern durch."""
    mod, conn = _make_uninstall_module(tmp_path, monkeypatch, installed=True)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("ungeschützt" in str(m) for m in messages)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_uninstall_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_uninstall_module(tmp_path, monkeypatch, installed=True)
    monkeypatch.setattr(Ufw, "UFW_BIN", "/usr/bin/false")

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Firewall deaktivieren (ufw --force disable)" in messages
    assert "Dienst deaktivieren" not in messages


def test_uninstall_ignores_invalid_port_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall lädt/prüft die Portkonfiguration nicht (fail-safe wie im Original)."""
    mod, conn = _make_uninstall_module(tmp_path, monkeypatch, installed=True)
    mod.allow_in_tcp = "70000"  # ungültig, würde _validate() zum Absturz bringen

    result = mod.start()

    assert result == 0
    assert conn.send.call_args_list != []


# --- test ---


def test_test_reports_all_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Regelsatz stimmt, SSH-Port erreichbar: test liefert 0."""
    mod, conn = _make_test_module(tmp_path, monkeypatch)

    with _listening_port() as port:
        monkeypatch.setattr(Ufw, "SSH_PORT", port)
        mod.allow_in_tcp = str(port)
        fake_ufw = _make_executable(
            tmp_path / "fake_ufw",
            "#!/bin/sh\n"
            'if [ "$1" = "show" ] && [ "$2" = "added" ]; then\n'
            f'    echo "ufw allow {port}/tcp"\n'
            '    echo "ufw allow out 80/tcp"\n'
            '    echo "ufw allow out 443/tcp"\n'
            '    echo "ufw allow out 53/udp"\n'
            "fi\n"
            "exit 0\n",
        )
        monkeypatch.setattr(Ufw, "UFW_BIN", fake_ufw)
        result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert any("überein" in str(m) for m in messages)
    assert any("Connect auf" in str(m) and "ok" in str(m) for m in messages)
    assert any("kein Hard-Fail" in str(m) for m in messages)
    assert any("manuell verifizieren" in str(m) for m in messages)


def test_test_collects_all_failures_without_aborting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regelsatzabweichung und nicht erreichbarer SSH-Port: beide werden gemeldet."""
    mod, conn = _make_test_module(tmp_path, monkeypatch)
    fake_ufw = _make_executable(
        tmp_path / "fake_ufw",
        "#!/bin/sh\n"
        'if [ "$1" = "show" ] && [ "$2" = "added" ]; then\n'
        '    echo "ufw allow 22/tcp"\n'
        "fi\n"
        "exit 0\n",
    )
    monkeypatch.setattr(Ufw, "UFW_BIN", fake_ufw)
    with _listening_port() as port:
        pass  # Port wird sofort wieder geschlossen — garantiert nicht erreichbar.
    monkeypatch.setattr(Ufw, "SSH_PORT", port)
    mod.allow_in_tcp = str(port)

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("weicht von Konfiguration ab" in str(m) for m in messages)
    assert any("fehlgeschlagen" in str(m) and "Connect" in str(m) for m in messages)
    # Sammelnd: trotz zweier Fehler kommt es bis zur Abschlussmeldung.
    assert any("manuell verifizieren" in str(m) for m in messages)
