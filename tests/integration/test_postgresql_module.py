"""Integrationstest für secure_base.modules.postgresql.

Startet Postgresql.start() direkt im Testprozess statt über einen echten
Modul-Subprozess (spawn), analog zu test_nginx_module.py: Systembefehle
werden durch harmlose Platzhalter ersetzt (Plan Abschnitt 2.12), Apt- und
Systemd-Aktionen durch No-Op-Unterklassen. Die Aktionen selbst sind bereits
in pifos getestet. Eigentümer/Gruppe (real: postgres) werden auf den
aufrufenden Testbenutzer umgelenkt, damit PermissionsAction ohne
Systemrechte läuft; die Cluster-/Datenverzeichnisse unter PG_ETC_BASE/
PG_DATA_BASE stehen für das, was das echte Paket postgresql beim
Postinst anlegt (pg_createcluster) — AptAction selbst wirkt im Test nicht.
"""

import grp
import os
import pwd
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from secure_base.modules import REGISTRY
from secure_base.modules.postgresql import Postgresql, _pg_hba_content


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


class _FailOnEnableSystemdAction(SystemdServiceAction):
    """Wie _NoOpSystemdAction, aber operation='enable' schlägt fehl (Abbruch-Test)."""

    def run(self) -> str:
        if self.operation == "enable":
            self.status = "failed"
            raise ActionError("enable absichtlich fehlgeschlagen (Test)")
        self.status = "finished"
        return self.status


def _prepare_cluster(
    tmp_path: Path, version: str = "16", cluster: str = "main"
) -> None:
    """Legt Cluster- und Datenverzeichnis an, wie es pg_createcluster täte."""
    etc_dir = Path(tmp_path) / "etc-postgresql" / version / cluster
    etc_dir.mkdir(parents=True)
    (etc_dir / "postgresql.conf").write_text("# dummy\n", encoding="utf-8")
    data_dir = Path(tmp_path) / "var-lib-postgresql" / version / cluster
    data_dir.mkdir(parents=True)


def _make_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Postgresql, MagicMock]:
    """Baut ein Postgresql-Modul mit harmlosen Platzhaltern für alle Systembefehle."""
    monkeypatch.setattr(Postgresql, "DPKG_QUERY_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postgresql, "SYSTEMCTL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postgresql, "PSQL_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postgresql, "RUNUSER_BIN", "/usr/bin/true")
    monkeypatch.setattr(Postgresql, "APT_ACTION_CLS", _NoOpAptAction)
    monkeypatch.setattr(Postgresql, "SYSTEMD_ACTION_CLS", _NoOpSystemdAction)
    # Eigentümerwechsel auf postgres/root verlangt Systemrechte; im Test auf
    # den aufrufenden Benutzer umgelenkt (PermissionsAction bleibt unverändert).
    monkeypatch.setattr(Postgresql, "PG_OWNER", pwd.getpwuid(os.getuid()).pw_name)
    monkeypatch.setattr(Postgresql, "PG_GROUP", grp.getgrgid(os.getgid()).gr_name)
    monkeypatch.setattr(Postgresql, "DUMP_OWNER", pwd.getpwuid(os.getuid()).pw_name)
    monkeypatch.setattr(Postgresql, "DUMP_GROUP", grp.getgrgid(os.getgid()).gr_name)

    monkeypatch.setattr(Postgresql, "PG_ETC_BASE", str(tmp_path / "etc-postgresql"))
    monkeypatch.setattr(
        Postgresql, "PG_DATA_BASE", str(tmp_path / "var-lib-postgresql")
    )
    # Reale Zielpfade (/var/backup/postgresql, /usr/local/sbin, /etc/cron.d)
    # sind ohne Systemrechte nicht beschreibbar — im Test auf tmp_path
    # umgelenkt.
    backup_base_dir = tmp_path / "var-backup"
    monkeypatch.setattr(Postgresql, "BACKUP_BASE_DIR", str(backup_base_dir))
    monkeypatch.setattr(Postgresql, "DUMP_DIR", str(backup_base_dir / "postgresql"))
    monkeypatch.setattr(
        Postgresql, "DUMP_SCRIPT_PATH", str(tmp_path / "secure-base-pg-dump.sh")
    )
    monkeypatch.setattr(
        Postgresql, "DUMP_CRON_PATH", str(tmp_path / "secure-base-pg-dump.cron")
    )
    _prepare_cluster(tmp_path)

    conn = MagicMock()
    mod = Postgresql(conn=conn, loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.timezone = "Europe/Berlin"
    mod.pg_dump_time = "02:00"
    mod.force_overwrite = "no"
    mod.backup_run_dir = str(tmp_path / "backup-run")
    return mod, conn


def _sent_messages(conn: MagicMock) -> list[object]:
    """Sammelt die per send_message gesendeten payload-Texte."""
    return [call.args[0].payload for call in conn.send.call_args_list]


def _hardening_path(mod: Postgresql) -> Path:
    """Baut den Pfad der eigenen conf.d-Datei des Test-Clusters."""
    return (
        Path(mod.PG_ETC_BASE) / "16" / "main" / "conf.d" / "secure-base-hardening.conf"
    )


def _pg_hba_path(mod: Postgresql) -> Path:
    """Baut den Pfad der pg_hba.conf des Test-Clusters."""
    return Path(mod.PG_ETC_BASE) / "16" / "main" / "pg_hba.conf"


def _data_dir(mod: Postgresql) -> Path:
    """Baut den Pfad des Datenverzeichnisses des Test-Clusters."""
    return Path(mod.PG_DATA_BASE) / "16" / "main"


# --- Registrierung / ModuleSpec ---


def test_registry_contains_postgresql_as_optional_module() -> None:
    """Die Registratur führt postgresql als optionales Modul mit eigenem Label."""
    matches = [spec for spec in REGISTRY if spec.name == "postgresql"]
    assert len(matches) == 1
    spec = matches[0]
    assert spec.optional is True
    assert spec.module_cls is Postgresql
    assert spec.label
    assert spec.optional_keys == ()


# --- Betriebsart install ---


def test_install_all_steps_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Alle Schritte mit harmlosen Platzhaltern: Rückgabewert 0, keine Fehlermeldung."""
    mod, conn = _make_module(tmp_path, monkeypatch)

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "Dienst neu starten" in messages
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)

    hardening_file = _hardening_path(mod)
    assert hardening_file.is_file()
    assert hardening_file.read_text(encoding="utf-8") == mod._hardening_conf_content()

    pg_hba_file = _pg_hba_path(mod)
    assert pg_hba_file.is_file()
    assert pg_hba_file.read_text(encoding="utf-8") == _pg_hba_content()

    assert _data_dir(mod).stat().st_mode & 0o777 == 0o700

    backup_base_dir = Path(mod.BACKUP_BASE_DIR)
    assert backup_base_dir.is_dir()
    assert backup_base_dir.stat().st_mode & 0o777 == 0o700

    dump_dir = Path(mod.DUMP_DIR)
    assert dump_dir.is_dir()
    assert dump_dir.stat().st_mode & 0o777 == 0o700

    dump_script = Path(mod.DUMP_SCRIPT_PATH)
    assert dump_script.is_file()
    assert dump_script.stat().st_mode & 0o777 == 0o700
    assert dump_script.read_text(encoding="utf-8") == mod._build_dump_script_content()

    dump_cron = Path(mod.DUMP_CRON_PATH)
    assert dump_cron.is_file()
    assert dump_cron.stat().st_mode & 0o777 == 0o644
    assert dump_cron.read_text(encoding="utf-8") == mod._build_dump_cron_content()
    assert "0 2 * * *  root " in dump_cron.read_text(encoding="utf-8")


def test_install_stops_at_first_failed_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein fehlschlagender Schritt liefert 1 und stoppt vor den folgenden Schritten."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Postgresql, "SYSTEMD_ACTION_CLS", _FailOnEnableSystemdAction)

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert "fehlgeschlagen: Dienst aktivieren" in messages
    assert "Dienst neu starten" not in messages
    # pg_hba.conf wurde bereits vor dem fehlschlagenden Schritt geschrieben.
    assert _pg_hba_path(mod).is_file()


def test_install_raises_when_no_cluster_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Legt das simulierte Paket keinen Cluster an, bricht install mit Fehler ab."""
    mod, _conn = _make_module(tmp_path, monkeypatch)
    # Cluster wieder entfernen: simuliert ein Paket, das keinen Standardcluster anlegt.
    shutil.rmtree(Path(mod.PG_ETC_BASE) / "16")

    with pytest.raises(ModuleError, match="kein Cluster"):
        mod.start()


def test_install_converts_pg_dump_time_into_cron_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pg_dump_time HH:MM wird korrekt in Cron-Minute/-Stunde umgesetzt."""
    mod, _conn = _make_module(tmp_path, monkeypatch)
    mod.pg_dump_time = "23:45"

    assert mod.start() == 0

    dump_cron = Path(mod.DUMP_CRON_PATH).read_text(encoding="utf-8")
    assert "45 23 * * *  root " in dump_cron
    assert mod.DUMP_SCRIPT_PATH in dump_cron


# --- Drift-Schutz (installer-drift-schutz) ---


def test_install_second_run_reports_unchanged_and_writes_nothing_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein zweiter, unveränderter install-Lauf überschreibt keine Datei erneut."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    hardening_mtime = _hardening_path(mod).stat().st_mtime_ns
    pg_hba_mtime = _pg_hba_path(mod).stat().st_mtime_ns
    dump_script_mtime = Path(mod.DUMP_SCRIPT_PATH).stat().st_mtime_ns
    dump_cron_mtime = Path(mod.DUMP_CRON_PATH).stat().st_mtime_ns
    conn.reset_mock()

    result = mod.start()

    assert result == 0
    assert _hardening_path(mod).stat().st_mtime_ns == hardening_mtime
    assert _pg_hba_path(mod).stat().st_mtime_ns == pg_hba_mtime
    assert Path(mod.DUMP_SCRIPT_PATH).stat().st_mtime_ns == dump_script_mtime
    assert Path(mod.DUMP_CRON_PATH).stat().st_mtime_ns == dump_cron_mtime
    assert not Path(mod.backup_run_dir).exists()
    messages = _sent_messages(conn)
    assert any("unverändert — übersprungen" in str(m) for m in messages)


def test_install_rejects_hand_edited_hardening_conf_without_force(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine Hand-Änderung an der Härtungsdatei wird ohne Freigabe nicht
    überschrieben."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    hardening_file = _hardening_path(mod)
    hardening_file.write_text("von hand geändert\n", encoding="utf-8")
    conn.reset_mock()

    result = mod.start()

    assert result == 1
    assert hardening_file.read_text(encoding="utf-8") == "von hand geändert\n"
    messages = _sent_messages(conn)
    assert any("--force-overwrite" in str(m) for m in messages)
    assert "Eigentümer/Rechte der Härtungs-Konfiguration setzen" not in messages


def test_install_adopts_freshly_installed_pg_hba_conf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine im selben Lauf frisch installierte pg_hba.conf wird ohne Freigabe ersetzt.

    DPKG_QUERY_BIN bleibt bei der Fixture-Voreinstellung (/usr/bin/true,
    keine Ausgabe) — das Paket gilt als noch nicht installiert, wie beim
    echten Erstlauf; die vorgefundene pg_hba.conf gilt dann als unberührte
    Paket-Vorgabe (adopt, Plan installer-drift-schutz Kap. 2.6).
    """
    mod, conn = _make_module(tmp_path, monkeypatch)
    pg_hba_file = _pg_hba_path(mod)
    package_default = (
        "local   all             all                                     peer\n"
    )
    pg_hba_file.write_text(package_default, encoding="utf-8")

    result = mod.start()

    assert result == 0
    assert pg_hba_file.read_text(encoding="utf-8") == _pg_hba_content()
    backup = Path(mod.backup_run_dir) / pg_hba_file.relative_to("/")
    assert backup.read_text(encoding="utf-8") == package_default
    messages = _sent_messages(conn)
    assert any("wird überschrieben" in str(m) for m in messages)


def test_install_rejects_pg_hba_conf_when_package_already_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bei bereits installiertem Paket verweigert install ein abweichendes
    pg_hba.conf."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    fake_dpkg = tmp_path / "fake-dpkg-query"
    fake_dpkg.write_text("#!/bin/sh\nprintf 'install ok installed'\n", encoding="utf-8")
    fake_dpkg.chmod(0o755)
    monkeypatch.setattr(Postgresql, "DPKG_QUERY_BIN", str(fake_dpkg))
    pg_hba_file = _pg_hba_path(mod)
    pg_hba_file.write_text("von hand geändert\n", encoding="utf-8")

    result = mod.start()

    assert result == 1
    assert pg_hba_file.read_text(encoding="utf-8") == "von hand geändert\n"
    messages = _sent_messages(conn)
    assert any("--force-overwrite" in str(m) for m in messages)


# --- Betriebsart check ---


def test_check_reports_mismatch_before_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Betriebsart check meldet Abweichungen, solange nichts eingerichtet ist."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    mod.operation = "check"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any("fehlt" in str(m) for m in messages)


def test_check_succeeds_after_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nach erfolgreichem install meldet check vollständige Übereinstimmung."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0

    fake_dpkg = tmp_path / "fake-dpkg-query"
    fake_dpkg.write_text("#!/bin/sh\nprintf 'install ok installed'\n", encoding="utf-8")
    fake_dpkg.chmod(0o755)
    monkeypatch.setattr(Postgresql, "DPKG_QUERY_BIN", str(fake_dpkg))
    fake_systemctl = tmp_path / "fake-systemctl-active"
    fake_systemctl.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "is-active" ]; then printf active; fi\n'
        'if [ "$1" = "is-enabled" ]; then printf enabled; fi\n',
        encoding="utf-8",
    )
    fake_systemctl.chmod(0o755)
    monkeypatch.setattr(Postgresql, "SYSTEMCTL_BIN", str(fake_systemctl))

    conn.reset_mock()
    mod.operation = "check"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


# --- Betriebsart uninstall ---


def test_uninstall_removes_own_conf_but_keeps_pg_hba_and_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall entfernt nur die eigene conf.d-Datei; pg_hba.conf/Daten bleiben."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    pg_hba_before = _pg_hba_path(mod).read_text(encoding="utf-8")

    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    assert not _hardening_path(mod).exists()
    assert _pg_hba_path(mod).is_file()
    assert _pg_hba_path(mod).read_text(encoding="utf-8") == pg_hba_before
    assert _data_dir(mod).is_dir()
    messages = _sent_messages(conn)
    assert any("gehärteten Fassung bestehen" in str(m) for m in messages)
    assert any(
        "Paket und" in str(m) and "Cluster bleiben installiert" in str(m)
        for m in messages
    )
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_uninstall_removes_dump_script_and_cron_but_keeps_dump_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uninstall entfernt Dump-Skript/-Cron; DUMP_DIR und vorhandene Dumps bleiben."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    old_dump = Path(mod.DUMP_DIR) / "kundendaten.sql"
    old_dump.write_text("-- vorheriger Dump --\n", encoding="utf-8")

    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    assert not Path(mod.DUMP_SCRIPT_PATH).exists()
    assert not Path(mod.DUMP_CRON_PATH).exists()
    assert Path(mod.DUMP_DIR).is_dir()
    assert old_dump.exists()
    assert old_dump.read_text(encoding="utf-8") == "-- vorheriger Dump --\n"
    messages = _sent_messages(conn)
    assert any(mod.DUMP_DIR in str(m) and "bleibt bestehen" in str(m) for m in messages)
    assert not any(str(m).startswith("fehlgeschlagen:") for m in messages)


def test_uninstall_returns_zero_without_cluster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne jemals installierten Cluster liefert uninstall 0, ohne Schritte."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    shutil.rmtree(Path(mod.PG_ETC_BASE))
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "kein Cluster gefunden — nichts zurückzunehmen" in messages


def test_uninstall_short_circuits_when_own_file_already_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist die eigene conf.d-Datei bereits weg, meldet uninstall dies und tut nichts."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    assert mod.start() == 0
    _hardening_path(mod).unlink()

    conn.reset_mock()
    mod.operation = "uninstall"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "eigene conf.d-Datei bereits entfernt — nichts zu tun" in messages
    assert _pg_hba_path(mod).is_file()


# --- Betriebsart test ---


def test_test_operation_all_checks_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mit aktivem Dienst, Verbindung und ausführbarem Skript meldet test Erfolg."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    fake_systemctl = tmp_path / "fake-systemctl-active"
    fake_systemctl.write_text("#!/bin/sh\nprintf 'active'\n", encoding="utf-8")
    fake_systemctl.chmod(0o755)
    monkeypatch.setattr(Postgresql, "SYSTEMCTL_BIN", str(fake_systemctl))
    fake_runuser = tmp_path / "fake-runuser"
    fake_runuser.write_text("#!/bin/sh\nprintf '1'\n", encoding="utf-8")
    fake_runuser.chmod(0o755)
    monkeypatch.setattr(Postgresql, "RUNUSER_BIN", str(fake_runuser))
    Path(mod.DUMP_SCRIPT_PATH).write_text("#!/bin/sh\n", encoding="utf-8")
    Path(mod.DUMP_SCRIPT_PATH).chmod(0o700)
    mod.operation = "test"

    result = mod.start()

    assert result == 0
    messages = _sent_messages(conn)
    assert "lokale Verbindung (SELECT 1): ok" in messages
    assert any("Dump-Skript vorhanden und ausführbar" in str(m) for m in messages)


def test_test_operation_reports_failure_without_running_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne aktiven Dienst, Verbindung und Dump-Skript meldet test einen Fehlschlag."""
    mod, conn = _make_module(tmp_path, monkeypatch)
    monkeypatch.setattr(Postgresql, "SYSTEMCTL_BIN", "/usr/bin/false")
    monkeypatch.setattr(Postgresql, "RUNUSER_BIN", "/usr/bin/false")
    mod.operation = "test"

    result = mod.start()

    assert result == 1
    messages = _sent_messages(conn)
    assert any(
        "lokale Verbindung" in str(m) and "fehlgeschlagen" in str(m) for m in messages
    )
    assert any("Dump-Skript fehlt" in str(m) for m in messages)
