"""Unit-Tests für secure_base.modules.postgresql."""

import grp
import os
import pwd
from functools import partial
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.action import Action
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.permissions_action import PermissionsAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.postgresql import (
    _HARDENING_GUC_LINES,
    _PG_HBA_LINES,
    Postgresql,
    _cron_fields,
    _dump_cron_content,
    _dump_script_content,
    _pg_hba_content,
)


def _write_script(tmp_path: Path, name: str, body: str) -> str:
    """Legt ein ausführbares Fake-Programm unter tmp_path an und liefert den Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def _unwrap_action(step: object) -> Action:
    """Entpackt eine von _act gebaute Schritt-Funktion und liefert die Aktion."""
    assert isinstance(step, partial)
    action = step.args[0]
    assert isinstance(action, Action)
    return action


def _make_module(
    *,
    operation: str = "install",
    timezone: str = "Europe/Berlin",
    pg_dump_time: str = "02:00",
) -> Postgresql:
    """Baut ein Postgresql-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Postgresql(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = operation
    mod.timezone = timezone
    mod.pg_dump_time = pg_dump_time
    mod.force_overwrite = "no"
    mod.backup_run_dir = "/var/backup/secure-base/test-lauf"
    return mod


def _make_cluster_dir(base: Path, version: str = "16", cluster: str = "main") -> Path:
    """Legt unter base ein Cluster-Verzeichnis mit postgresql.conf an."""
    cluster_dir = base / version / cluster
    cluster_dir.mkdir(parents=True)
    (cluster_dir / "postgresql.conf").write_text("# dummy\n", encoding="utf-8")
    return cluster_dir


def _current_owner() -> tuple[str, str]:
    """Liefert (Benutzername, Gruppenname) des aufrufenden Testprozesses."""
    return (
        pwd.getpwuid(os.getuid()).pw_name,
        grp.getgrgid(os.getgid()).gr_name,
    )


# --- CONFIG ---


def test_config_declares_operation_timezone_and_pg_dump_time() -> None:
    """CONFIG nennt operation, timezone, pg_dump_time und die Drift-Schutz-Werte."""
    assert Postgresql.CONFIG == [
        "operation",
        "timezone",
        "pg_dump_time",
        "force_overwrite",
        "backup_run_dir",
    ]


# --- _validate ---


def test_validate_accepts_known_timezone() -> None:
    """Eine bekannte tzdata-Zeitzone löst keine Ausnahme aus."""
    mod = _make_module(timezone="Europe/Berlin")
    mod._validate()


def test_validate_rejects_unknown_timezone() -> None:
    """Eine unbekannte Zeitzone erzeugt ModuleError."""
    mod = _make_module(timezone="Nirgendwo/Erfunden")
    with pytest.raises(ModuleError, match="unbekannte Zeitzone"):
        mod._validate()


def test_validate_accepts_valid_pg_dump_time() -> None:
    """Eine gültige HH:MM-Uhrzeit löst keine Ausnahme aus."""
    mod = _make_module(pg_dump_time="02:00")
    mod._validate()


def test_validate_rejects_invalid_pg_dump_time() -> None:
    """Eine ungültige Uhrzeit erzeugt ModuleError."""
    mod = _make_module(pg_dump_time="25:99")
    with pytest.raises(ModuleError, match="pg_dump_time"):
        mod._validate()


def test_uninstall_is_config_independent(tmp_path: Path) -> None:
    """start() ruft bei operation='uninstall' _validate() nicht auf."""
    mod = _make_module(operation="uninstall", timezone="Nirgendwo/Erfunden")
    mod.PG_ETC_BASE = "/nichts-vorhanden"  # type: ignore[misc]
    mod.DUMP_CRON_PATH = str(tmp_path / "fehlt.cron")  # type: ignore[misc]
    mod.DUMP_SCRIPT_PATH = str(tmp_path / "fehlt.sh")  # type: ignore[misc]
    mod.DUMP_DIR = str(tmp_path / "fehlt-dump")  # type: ignore[misc]
    assert mod.start() == 0


# --- Cluster-Ermittlung ---


def test_detect_cluster_returns_none_without_directory(tmp_path: Path) -> None:
    """Fehlt PG_ETC_BASE, liefert _detect_cluster None."""
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path / "nicht-vorhanden")  # type: ignore[misc]
    assert mod._detect_cluster() is None


def test_detect_cluster_returns_none_when_empty(tmp_path: Path) -> None:
    """Existiert PG_ETC_BASE, aber ohne Cluster, liefert _detect_cluster None."""
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path)  # type: ignore[misc]
    assert mod._detect_cluster() is None


def test_detect_cluster_finds_single_cluster(tmp_path: Path) -> None:
    """Ein einzelner Cluster mit postgresql.conf wird gefunden."""
    _make_cluster_dir(tmp_path, version="16", cluster="main")
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path)  # type: ignore[misc]
    assert mod._detect_cluster() == ("16", "main")


def test_detect_cluster_picks_highest_version(tmp_path: Path) -> None:
    """Bei mehreren Versionen gewinnt die numerisch höchste."""
    _make_cluster_dir(tmp_path, version="14", cluster="main")
    _make_cluster_dir(tmp_path, version="16", cluster="main")
    _make_cluster_dir(tmp_path, version="9", cluster="main")
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path)  # type: ignore[misc]
    assert mod._detect_cluster() == ("16", "main")


def test_detect_cluster_ignores_non_numeric_version_dir(tmp_path: Path) -> None:
    """Ein nicht-numerisches Verzeichnis unter PG_ETC_BASE wird übersprungen."""
    (tmp_path / "common").mkdir()
    (tmp_path / "common" / "postgresql.conf").write_text("x", encoding="utf-8")
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path)  # type: ignore[misc]
    assert mod._detect_cluster() is None


def test_detect_cluster_ignores_dir_without_postgresql_conf(tmp_path: Path) -> None:
    """Ein Cluster-Verzeichnis ohne postgresql.conf zählt nicht als Cluster."""
    (tmp_path / "16" / "main").mkdir(parents=True)
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path)  # type: ignore[misc]
    assert mod._detect_cluster() is None


def test_require_cluster_raises_when_none_found(tmp_path: Path) -> None:
    """_require_cluster bricht mit ModuleError ab, wenn kein Cluster existiert."""
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path)  # type: ignore[misc]
    with pytest.raises(ModuleError, match="kein Cluster"):
        mod._require_cluster()


# --- Pfad-/Namensbausteine ---


def test_unit_name_builds_versioned_instance_name() -> None:
    """Der systemd-Einheitenname folgt dem Muster postgresql@<version>-<cluster>."""
    mod = _make_module()
    assert mod._unit_name("16", "main") == "postgresql@16-main"


def test_conf_d_dir_and_pg_hba_path_and_data_dir() -> None:
    """Die Pfad-Bausteine hängen Version und Cluster korrekt an die Basis an."""
    mod = _make_module()
    mod.PG_ETC_BASE = "/etc/postgresql"  # type: ignore[misc]
    mod.PG_DATA_BASE = "/var/lib/postgresql"  # type: ignore[misc]
    assert mod._conf_d_dir("16", "main") == Path("/etc/postgresql/16/main/conf.d")
    assert mod._pg_hba_path("16", "main") == "/etc/postgresql/16/main/pg_hba.conf"
    assert mod._data_dir("16", "main") == "/var/lib/postgresql/16/main"


# --- Härtungs-GUC / pg_hba-Inhalt ---


def test_expected_hardening_lines_contains_fixed_gucs_and_timezone() -> None:
    """Die Sollzeilen enthalten alle festen GUCs plus log_timezone."""
    mod = _make_module(timezone="Europe/Berlin")
    lines = mod._expected_hardening_lines()
    for expected in _HARDENING_GUC_LINES:
        assert expected in lines
    assert "log_timezone = 'Europe/Berlin'" in lines
    assert lines[-1] == "log_timezone = 'Europe/Berlin'"


def test_hardening_conf_content_contains_marker_and_all_lines() -> None:
    """Der Dateiinhalt trägt den Eigen-Marker und alle Sollzeilen."""
    mod = _make_module(timezone="Europe/Berlin")
    content = mod._hardening_conf_content()
    assert content.startswith("# Von secure-base/postgresql angelegt")
    for line in mod._expected_hardening_lines():
        assert line in content
    assert "listen_addresses = 'localhost'" in content
    assert "password_encryption = scram-sha-256" in content


def test_pg_hba_content_has_exact_lines_in_order() -> None:
    """pg_hba.conf enthält exakt die vier Sollzeilen in fester Reihenfolge."""
    content = _pg_hba_content()
    assert content.startswith("# Von secure-base/postgresql angelegt")
    lines = [line for line in content.splitlines() if line and not line.startswith("#")]
    assert tuple(lines) == _PG_HBA_LINES


def test_pg_hba_content_contains_no_trust_or_replication() -> None:
    """pg_hba.conf enthält weder trust noch eine Replikationszeile."""
    content = _pg_hba_content()
    assert "trust" not in content
    assert "replication" not in content


def test_pg_hba_content_local_all_all_uses_scram() -> None:
    """Die generische local-Zeile nutzt scram-sha-256, nicht das Default peer."""
    content = _pg_hba_content()
    assert (
        "local   all             all                                     scram-sha-256"
        in content
    )


# --- Dump-Skript/-Cron-Inhalte ---


def test_cron_fields_splits_hhmm_into_minute_and_hour() -> None:
    """_cron_fields liefert (Minute, Stunde) ohne führende Nullen."""
    assert _cron_fields("02:00") == ("0", "2")
    assert _cron_fields("23:45") == ("45", "23")


def test_dump_cron_content_uses_converted_fields_and_script_path() -> None:
    """Die Cron-Zeile nutzt die aus HH:MM umgesetzten Felder und den Skriptpfad."""
    content = _dump_cron_content("02:30", "/usr/local/sbin/secure-base-pg-dump.sh")
    assert "30 2 * * *  root  /usr/local/sbin/secure-base-pg-dump.sh" in content
    assert content.startswith(
        "# Datensicherung (pg_dump je Datenbank) - täglich um 02:30"
    )


def _script() -> str:
    """Baut einen Skriptinhalt mit festen Pfaden für die Inhaltsprüfungen."""
    return _dump_script_content(
        dump_dir="/var/backup/postgresql",
        globals_file_name="globals.sql",
        runuser_bin="/usr/sbin/runuser",
        psql_bin="/usr/bin/psql",
        pg_dump_bin="/usr/bin/pg_dump",
        pg_dumpall_bin="/usr/bin/pg_dumpall",
    )


def test_dump_script_content_dumps_each_database_separately_via_runuser() -> None:
    """Je Datenbank ein pg_dump als postgres über runuser — kein Cluster-Gesamtdump."""
    content = _script()
    assert "set -euo pipefail" in content
    assert 'dump_to "$DUMP_DIR/$db.sql" "/usr/sbin/runuser" -u postgres --' in content
    assert '"/usr/bin/pg_dump" --create --clean --if-exists "$db"' in content


def test_dump_script_content_lists_only_connectable_non_template_databases() -> None:
    """Die Datenbankliste kommt aus pg_database ohne Vorlagen/nicht verbindbare."""
    content = _script()
    assert '"/usr/sbin/runuser" -u postgres -- "/usr/bin/psql" -tAc' in content
    assert (
        "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate"
        in content
    )


def test_dump_script_content_dumps_globals_only_not_whole_cluster() -> None:
    """pg_dumpall läuft ausschließlich mit --globals-only (Rollen, Tablespaces)."""
    content = _script()
    assert '"/usr/bin/pg_dumpall" --globals-only' in content
    assert content.count("pg_dumpall") == 1


def test_dump_script_content_moves_atomically_and_sets_mode_0600() -> None:
    """dump_to setzt 0600 und ersetzt die Zieldatei per mv (atomar)."""
    content = _script()
    assert 'chmod 0600 "$TMP_FILE"' in content
    assert 'mv -f "$TMP_FILE" "$target"' in content


def test_dump_script_content_discards_temp_file_via_exit_trap() -> None:
    """Ein EXIT-trap räumt die Temp-Datei bei Erfolg wie bei Fehlschlag auf."""
    content = _script()
    assert """trap 'rm -f "$TMP_FILE"' EXIT""" in content
    assert "exit 1" in content


def test_dump_script_content_writes_globals_last() -> None:
    """globals.sql entsteht nach den Einzeldumps — ihr Zeitstempel belegt den Erfolg."""
    content = _script()
    per_db_pos = content.index('dump_to "$DUMP_DIR/$db.sql"')
    globals_pos = content.index('dump_to "$GLOBALS_FILE"')
    assert per_db_pos < globals_pos


def test_dump_script_content_rejects_database_names_with_special_characters() -> None:
    """Ein Datenbankname außerhalb [A-Za-z0-9_-] bricht den Lauf ab (Pfadschutz)."""
    content = _script()
    assert "*[!A-Za-z0-9_-]*)" in content
    assert "Datenbankname mit unzulässigen Zeichen" in content


# --- Instanzgebundene Dump-Inhalte ---


def test_globals_file_path_joins_dir_and_name() -> None:
    """_globals_file_path hängt GLOBALS_FILE_NAME an DUMP_DIR an."""
    mod = _make_module()
    mod.DUMP_DIR = "/var/backup/postgresql"  # type: ignore[misc]
    mod.GLOBALS_FILE_NAME = "globals.sql"  # type: ignore[misc]
    assert mod._globals_file_path() == "/var/backup/postgresql/globals.sql"


def test_build_dump_script_content_uses_instance_paths() -> None:
    """Das gebaute Skript enthält die konfigurierten Programmpfade."""
    mod = _make_module()
    content = mod._build_dump_script_content()
    assert mod.RUNUSER_BIN in content
    assert mod.PSQL_BIN in content
    assert mod.PG_DUMP_BIN in content
    assert mod.PG_DUMPALL_BIN in content
    assert mod.DUMP_DIR in content


def test_build_dump_cron_content_uses_configured_pg_dump_time() -> None:
    """Der gebaute Cron-Inhalt nutzt die konfigurierte pg_dump_time."""
    mod = _make_module(pg_dump_time="03:15")
    content = mod._build_dump_cron_content()
    assert "15 3 * * *" in content
    assert mod.DUMP_SCRIPT_PATH in content


# --- _install_steps ---


def test_install_steps_order_and_targets(tmp_path: Path) -> None:
    """_install_steps liefert die Schritte in fester Reihenfolge mit korrektem Ziel."""
    etc_base = tmp_path / "etc-pg"
    _make_cluster_dir(etc_base, version="16", cluster="main")
    mod = _make_module()
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]

    steps = list(mod._install_steps())
    labels = [label for label, _ in steps]

    assert labels == [
        "Paket installieren",
        "conf.d-Verzeichnis sicherstellen",
        "Verbindungs- und Protokolleinstellungen schreiben",
        "Eigentümer/Rechte der Härtungs-Konfiguration setzen",
        "pg_hba.conf ersetzen",
        "Eigentümer/Rechte von pg_hba.conf setzen",
        "Datenverzeichnis-Rechte setzen",
        "Dienst aktivieren",
        "Dienst neu starten",
        "Sicherungsverzeichnis anlegen",
        "Sicherungsverzeichnis-Rechte setzen",
        "Dump-Zielverzeichnis anlegen",
        "Dump-Zielverzeichnis-Rechte setzen",
        "Dump-Skript schreiben",
        "Dump-Cron-Datei schreiben",
    ]

    by_label = dict(steps)

    # Schreibziele laufen über write_managed — die Schritte sind gebundene
    # Aufrufe, keine WriteFileAction-Objekte mehr; geprüft wird über die
    # gleichnamigen ManagedFile-Bausteine, die _install_steps intern nutzt.
    write_hardening = by_label["Verbindungs- und Protokolleinstellungen schreiben"]
    assert callable(write_hardening) and not isinstance(write_hardening, Action)
    hardening_mf = mod._hardening_managed_file("16", "main")
    assert hardening_mf.dst == str(
        etc_base / "16" / "main" / "conf.d" / "secure-base-hardening.conf"
    )
    assert hardening_mf.mode == 0o640
    assert hardening_mf.content == mod._hardening_conf_content()

    chown_hardening = _unwrap_action(
        by_label["Eigentümer/Rechte der Härtungs-Konfiguration setzen"]
    )
    assert isinstance(chown_hardening, PermissionsAction)
    assert chown_hardening.mode == 0o640
    assert chown_hardening.owner == "postgres"
    assert chown_hardening.group == "postgres"

    write_hba = by_label["pg_hba.conf ersetzen"]
    assert callable(write_hba) and not isinstance(write_hba, Action)
    pg_hba_mf = mod._pg_hba_managed_file("16", "main")
    assert pg_hba_mf.dst == str(etc_base / "16" / "main" / "pg_hba.conf")
    assert pg_hba_mf.mode == 0o640
    assert pg_hba_mf.content == _pg_hba_content()

    chown_hba = _unwrap_action(by_label["Eigentümer/Rechte von pg_hba.conf setzen"])
    assert isinstance(chown_hba, PermissionsAction)
    assert chown_hba.mode == 0o640
    assert chown_hba.owner == "postgres"
    assert chown_hba.group == "postgres"

    chown_data_dir = _unwrap_action(by_label["Datenverzeichnis-Rechte setzen"])
    assert isinstance(chown_data_dir, PermissionsAction)
    assert chown_data_dir.mode == 0o700
    assert chown_data_dir.owner == "postgres"
    assert chown_data_dir.group == "postgres"

    enable_step = _unwrap_action(by_label["Dienst aktivieren"])
    assert isinstance(enable_step, SystemdServiceAction)
    assert enable_step.operation == "enable"
    assert enable_step.unit == "postgresql@16-main"

    restart_step = _unwrap_action(by_label["Dienst neu starten"])
    assert isinstance(restart_step, SystemdServiceAction)
    assert restart_step.operation == "restart"
    assert restart_step.unit == "postgresql@16-main"

    mkdir_backup_base = _unwrap_action(by_label["Sicherungsverzeichnis anlegen"])
    assert isinstance(mkdir_backup_base, MakeDirAction)
    assert mkdir_backup_base.path == mod.BACKUP_BASE_DIR
    assert mkdir_backup_base.mode == 0o700

    chown_backup_base = _unwrap_action(by_label["Sicherungsverzeichnis-Rechte setzen"])
    assert isinstance(chown_backup_base, PermissionsAction)
    assert chown_backup_base.path == mod.BACKUP_BASE_DIR
    assert chown_backup_base.mode == 0o700
    assert chown_backup_base.owner == "root"
    assert chown_backup_base.group == "root"

    mkdir_dump_dir = _unwrap_action(by_label["Dump-Zielverzeichnis anlegen"])
    assert isinstance(mkdir_dump_dir, MakeDirAction)
    assert mkdir_dump_dir.path == mod.DUMP_DIR
    assert mkdir_dump_dir.mode == 0o700

    chown_dump_dir = _unwrap_action(by_label["Dump-Zielverzeichnis-Rechte setzen"])
    assert isinstance(chown_dump_dir, PermissionsAction)
    assert chown_dump_dir.path == mod.DUMP_DIR
    assert chown_dump_dir.mode == 0o700
    assert chown_dump_dir.owner == "root"
    assert chown_dump_dir.group == "root"

    write_dump_script = by_label["Dump-Skript schreiben"]
    assert callable(write_dump_script) and not isinstance(write_dump_script, Action)
    dump_script_mf = mod._dump_script_managed_file()
    assert dump_script_mf.dst == mod.DUMP_SCRIPT_PATH
    assert dump_script_mf.mode == 0o700
    assert dump_script_mf.content == mod._build_dump_script_content()

    write_dump_cron = by_label["Dump-Cron-Datei schreiben"]
    assert callable(write_dump_cron) and not isinstance(write_dump_cron, Action)
    dump_cron_mf = mod._dump_cron_managed_file()
    assert dump_cron_mf.dst == mod.DUMP_CRON_PATH
    assert dump_cron_mf.mode == 0o644
    assert dump_cron_mf.content == mod._build_dump_cron_content()


def test_install_steps_raises_when_no_cluster_after_apt(tmp_path: Path) -> None:
    """Fehlt nach der Paketinstallation weiterhin ein Cluster, bricht die Liste ab."""
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path / "nichts")  # type: ignore[misc]
    steps = mod._install_steps()
    next(steps)  # "Paket installieren" liefern
    with pytest.raises(ModuleError, match="kein Cluster"):
        next(steps)


# --- _check_file_mode ---


def test_check_file_mode_matches(tmp_path: Path) -> None:
    """Stimmen Rechte und Eigentümer überein, liefert _check_file_mode True."""
    target = tmp_path / "pg_hba.conf"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o640)
    mod = _make_module()
    owner, group = _current_owner()
    assert mod._check_file_mode(str(target), 0o640, owner, group) is True


def test_check_file_mode_mismatch_returns_false(tmp_path: Path) -> None:
    """Abweichende Rechte liefern False."""
    target = tmp_path / "pg_hba.conf"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o644)
    mod = _make_module()
    owner, group = _current_owner()
    assert mod._check_file_mode(str(target), 0o640, owner, group) is False


def test_check_file_mode_missing_path_returns_false(tmp_path: Path) -> None:
    """Fehlt der Pfad, liefert _check_file_mode False."""
    mod = _make_module()
    assert (
        mod._check_file_mode(str(tmp_path / "fehlt"), 0o640, "postgres", "postgres")
        is False
    )


def test_check_file_mode_returns_false_when_owner_not_resolvable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist die UID nicht auf einen Namen auflösbar (KeyError), liefert False."""
    target = tmp_path / "pg_hba.conf"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o640)

    def _raise_pwd(uid: int) -> pwd.struct_passwd:
        raise KeyError(f"uid {uid} nicht auflösbar")

    monkeypatch.setattr(pwd, "getpwuid", _raise_pwd)
    mod = _make_module()
    assert mod._check_file_mode(str(target), 0o640, "postgres", "postgres") is False


def test_check_file_mode_returns_false_when_group_not_resolvable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ist die GID nicht auf einen Namen auflösbar (KeyError), liefert False."""
    target = tmp_path / "pg_hba.conf"
    target.write_text("x", encoding="utf-8")
    target.chmod(0o640)

    def _raise_grp(gid: int) -> grp.struct_group:
        raise KeyError(f"gid {gid} nicht auflösbar")

    monkeypatch.setattr(grp, "getgrgid", _raise_grp)
    mod = _make_module()
    assert mod._check_file_mode(str(target), 0o640, "postgres", "postgres") is False


# --- _verify ---


def _prepare_verified_cluster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Postgresql:
    """Baut ein Modul mit vollständig korrekt gehärtetem Fake-Cluster."""
    owner, group = _current_owner()
    monkeypatch.setattr(Postgresql, "PG_OWNER", owner)
    monkeypatch.setattr(Postgresql, "PG_GROUP", group)
    monkeypatch.setattr(Postgresql, "DUMP_OWNER", owner)
    monkeypatch.setattr(Postgresql, "DUMP_GROUP", group)

    etc_base = tmp_path / "etc-pg"
    cluster_dir = _make_cluster_dir(etc_base, version="16", cluster="main")
    conf_d = cluster_dir / "conf.d"
    conf_d.mkdir()

    mod = _make_module()
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]

    hardening_file = conf_d / "secure-base-hardening.conf"
    hardening_file.write_text(mod._hardening_conf_content(), encoding="utf-8")
    hardening_file.chmod(0o640)

    pg_hba_file = cluster_dir / "pg_hba.conf"
    pg_hba_file.write_text(_pg_hba_content(), encoding="utf-8")
    pg_hba_file.chmod(0o640)

    data_dir = tmp_path / "data-pg" / "16" / "main"
    data_dir.mkdir(parents=True)
    data_dir.chmod(0o700)
    mod.PG_DATA_BASE = str(tmp_path / "data-pg")  # type: ignore[misc]

    backup_base_dir = tmp_path / "var-backup"
    backup_base_dir.mkdir()
    backup_base_dir.chmod(0o700)
    mod.BACKUP_BASE_DIR = str(backup_base_dir)  # type: ignore[misc]

    dump_dir = backup_base_dir / "postgresql"
    dump_dir.mkdir()
    dump_dir.chmod(0o700)
    mod.DUMP_DIR = str(dump_dir)  # type: ignore[misc]

    dump_script_path = tmp_path / "secure-base-pg-dump.sh"
    mod.DUMP_SCRIPT_PATH = str(dump_script_path)  # type: ignore[misc]
    dump_script_path.write_text(mod._build_dump_script_content(), encoding="utf-8")
    dump_script_path.chmod(0o700)

    dump_cron_path = tmp_path / "secure-base-pg-dump.cron"
    mod.DUMP_CRON_PATH = str(dump_cron_path)  # type: ignore[misc]
    dump_cron_path.write_text(mod._build_dump_cron_content(), encoding="utf-8")
    dump_cron_path.chmod(0o644)

    dpkg_stub = _write_script(
        tmp_path, "fake-dpkg-query", "printf 'install ok installed'"
    )
    monkeypatch.setattr(Postgresql, "DPKG_QUERY_BIN", dpkg_stub)

    systemctl_stub = _write_script(
        tmp_path,
        "fake-systemctl",
        'if [ "$1" = "is-active" ]; then printf active; fi\n'
        'if [ "$1" = "is-enabled" ]; then printf enabled; fi',
    )
    monkeypatch.setattr(Postgresql, "SYSTEMCTL_BIN", systemctl_stub)

    return mod


def test_verify_succeeds_for_fully_hardened_cluster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stimmt der Ist-Zustand vollständig, liefert _verify 0."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    assert mod._verify() == 0


def test_verify_fails_without_cluster(tmp_path: Path) -> None:
    """Fehlt der Cluster, liefert _verify 1."""
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path / "nichts")  # type: ignore[misc]
    mod.DPKG_QUERY_BIN = "/bin/false"  # type: ignore[misc]
    assert mod._verify() == 1


def test_verify_detects_replication_line_in_pg_hba(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine zusätzliche Replikationszeile in pg_hba.conf lässt _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    pg_hba_file = Path(mod.PG_ETC_BASE) / "16" / "main" / "pg_hba.conf"
    pg_hba_file.write_text(
        _pg_hba_content() + "local   replication     all                     peer\n",
        encoding="utf-8",
    )
    pg_hba_file.chmod(0o640)
    assert mod._verify() == 1


def test_verify_detects_non_loopback_host_line_in_pg_hba(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine host-Zeile mit Nicht-Loopback-Adresse lässt _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    pg_hba_file = Path(mod.PG_ETC_BASE) / "16" / "main" / "pg_hba.conf"
    pg_hba_file.write_text(
        _pg_hba_content() + "host    all             all             0.0.0.0/0"
        "               scram-sha-256\n",
        encoding="utf-8",
    )
    pg_hba_file.chmod(0o640)
    assert mod._verify() == 1


def test_verify_detects_trust_in_pg_hba(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein trust-Eintrag in pg_hba.conf lässt _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    pg_hba_file = Path(mod.PG_ETC_BASE) / "16" / "main" / "pg_hba.conf"
    pg_hba_file.write_text(
        "local   all             all                                     trust\n",
        encoding="utf-8",
    )
    pg_hba_file.chmod(0o640)
    assert mod._verify() == 1


def test_verify_detects_wrong_pg_hba_rights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Abweichende Rechte an pg_hba.conf lassen _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    pg_hba_file = Path(mod.PG_ETC_BASE) / "16" / "main" / "pg_hba.conf"
    pg_hba_file.chmod(0o644)
    assert mod._verify() == 1


def test_verify_detects_missing_hardening_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt eine GUC-Zeile in der conf.d-Datei, lässt _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    hardening_file = (
        Path(mod.PG_ETC_BASE) / "16" / "main" / "conf.d" / "secure-base-hardening.conf"
    )
    hardening_file.write_text("listen_addresses = 'localhost'\n", encoding="utf-8")
    hardening_file.chmod(0o640)
    assert mod._verify() == 1


def test_verify_detects_wrong_data_dir_rights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Abweichende Rechte am Datenverzeichnis lassen _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    data_dir = Path(mod.PG_DATA_BASE) / "16" / "main"
    data_dir.chmod(0o750)
    assert mod._verify() == 1


def test_verify_detects_missing_dump_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt das Dump-Skript, lässt _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    Path(mod.DUMP_SCRIPT_PATH).unlink()
    assert mod._verify() == 1


def test_verify_detects_missing_dump_cron(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Dump-Cron-Datei, lässt _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    Path(mod.DUMP_CRON_PATH).unlink()
    assert mod._verify() == 1


def test_verify_detects_dump_cron_content_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Abweichender Inhalt der Cron-Datei lässt _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    Path(mod.DUMP_CRON_PATH).write_text("* * * * * root /bin/true\n", encoding="utf-8")
    assert mod._verify() == 1


def test_verify_detects_wrong_dump_script_rights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Abweichende Rechte am Dump-Skript lassen _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    Path(mod.DUMP_SCRIPT_PATH).chmod(0o755)
    assert mod._verify() == 1


def test_verify_detects_wrong_dump_dir_rights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Abweichende Rechte am Dump-Zielverzeichnis lassen _verify scheitern."""
    mod = _prepare_verified_cluster(tmp_path, monkeypatch)
    Path(mod.DUMP_DIR).chmod(0o750)
    assert mod._verify() == 1


# --- _test ---


def test_check_local_connection_success(tmp_path: Path) -> None:
    """Liefert psql über runuser '1', gilt die lokale Verbindung als ok."""
    fake_runuser = _write_script(tmp_path, "fake-runuser", "printf '1'")
    mod = _make_module()
    mod.RUNUSER_BIN = fake_runuser  # type: ignore[misc]
    assert mod._check_local_connection() is True


def test_check_local_connection_unexpected_output_returns_false(
    tmp_path: Path,
) -> None:
    """Liefert psql eine unerwartete Ausgabe, liefert die Prüfung False."""
    fake_runuser = _write_script(tmp_path, "fake-runuser", "printf '0'")
    mod = _make_module()
    mod.RUNUSER_BIN = fake_runuser  # type: ignore[misc]
    assert mod._check_local_connection() is False


def test_check_local_connection_command_failure_returns_false(
    tmp_path: Path,
) -> None:
    """Scheitert der Aufruf selbst, liefert die Prüfung False."""
    fake_runuser = _write_script(tmp_path, "fake-runuser", "exit 1")
    mod = _make_module()
    mod.RUNUSER_BIN = fake_runuser  # type: ignore[misc]
    assert mod._check_local_connection() is False


def test_test_operation_fails_without_cluster(tmp_path: Path) -> None:
    """Ohne Cluster meldet _test einen Fehler und liefert 1."""
    mod = _make_module()
    mod.PG_ETC_BASE = str(tmp_path / "nichts")  # type: ignore[misc]
    assert mod._test() == 1


def _write_executable_dump_script(tmp_path: Path) -> str:
    """Legt ein harmloses, ausführbares Dump-Skript unter tmp_path an."""
    script = tmp_path / "dump.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o700)
    return str(script)


def test_test_operation_succeeds_with_active_service_and_connection(
    tmp_path: Path,
) -> None:
    """Aktiver Dienst, Verbindung und ausführbares Dump-Skript liefern 0."""
    etc_base = tmp_path / "etc-pg"
    _make_cluster_dir(etc_base, version="16", cluster="main")
    mod = _make_module()
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]
    mod.SYSTEMCTL_BIN = _write_script(  # type: ignore[misc]
        tmp_path, "fake-systemctl", "printf active"
    )
    mod.RUNUSER_BIN = _write_script(  # type: ignore[misc]
        tmp_path, "fake-runuser", "printf '1'"
    )
    mod.DUMP_SCRIPT_PATH = _write_executable_dump_script(tmp_path)  # type: ignore[misc]
    assert mod._test() == 0


def test_test_operation_fails_when_dump_script_missing(tmp_path: Path) -> None:
    """Fehlt das Dump-Skript, meldet _test einen Fehlschlag trotz laufendem Dienst."""
    etc_base = tmp_path / "etc-pg"
    _make_cluster_dir(etc_base, version="16", cluster="main")
    mod = _make_module()
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]
    mod.SYSTEMCTL_BIN = _write_script(  # type: ignore[misc]
        tmp_path, "fake-systemctl", "printf active"
    )
    mod.RUNUSER_BIN = _write_script(  # type: ignore[misc]
        tmp_path, "fake-runuser", "printf '1'"
    )
    mod.DUMP_SCRIPT_PATH = str(tmp_path / "fehlt.sh")  # type: ignore[misc]
    assert mod._test() == 1


# --- _check_dump_script_executable ---


def test_check_dump_script_executable_true(tmp_path: Path) -> None:
    """Ein vorhandenes, ausführbares Skript liefert True."""
    mod = _make_module()
    mod.DUMP_SCRIPT_PATH = _write_executable_dump_script(tmp_path)  # type: ignore[misc]
    assert mod._check_dump_script_executable() is True


def test_check_dump_script_executable_missing_returns_false(tmp_path: Path) -> None:
    """Fehlt das Skript, liefert die Prüfung False."""
    mod = _make_module()
    mod.DUMP_SCRIPT_PATH = str(tmp_path / "fehlt.sh")  # type: ignore[misc]
    assert mod._check_dump_script_executable() is False


def test_check_dump_script_executable_not_executable_returns_false(
    tmp_path: Path,
) -> None:
    """Ist das Skript nicht ausführbar, liefert die Prüfung False."""
    script = tmp_path / "dump.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")
    script.chmod(0o600)
    mod = _make_module()
    mod.DUMP_SCRIPT_PATH = str(script)  # type: ignore[misc]
    assert mod._check_dump_script_executable() is False


# --- _uninstall ---


def test_uninstall_returns_zero_without_cluster(tmp_path: Path) -> None:
    """Ohne Cluster gibt es nichts zurückzunehmen; _uninstall liefert 0."""
    mod = _make_module(operation="uninstall")
    mod.PG_ETC_BASE = str(tmp_path / "nichts")  # type: ignore[misc]
    mod.DUMP_CRON_PATH = str(tmp_path / "fehlt.cron")  # type: ignore[misc]
    mod.DUMP_SCRIPT_PATH = str(tmp_path / "fehlt.sh")  # type: ignore[misc]
    mod.DUMP_DIR = str(tmp_path / "fehlt-dump")  # type: ignore[misc]
    conn = mod._conn
    assert mod._uninstall() == 0
    messages = [call.args[0].payload for call in conn.send.call_args_list]  # type: ignore[attr-defined]
    assert "kein Cluster gefunden — nichts zurückzunehmen" in messages


def test_uninstall_leaves_pg_hba_untouched_and_removes_own_conf_d_file(
    tmp_path: Path,
) -> None:
    """uninstall entfernt nur die eigene conf.d-Datei; pg_hba.conf bleibt bestehen."""
    from pifos.actions.systemd_service_action import SystemdServiceAction

    class _NoOpSystemdAction(SystemdServiceAction):
        def run(self) -> str:
            self.status = "finished"
            return self.status

    etc_base = tmp_path / "etc-pg"
    cluster_dir = _make_cluster_dir(etc_base, version="16", cluster="main")
    conf_d = cluster_dir / "conf.d"
    conf_d.mkdir()
    hardening_file = conf_d / "secure-base-hardening.conf"
    hardening_file.write_text("listen_addresses = 'localhost'\n", encoding="utf-8")
    pg_hba_file = cluster_dir / "pg_hba.conf"
    pg_hba_original = _pg_hba_content()
    pg_hba_file.write_text(pg_hba_original, encoding="utf-8")

    mod = _make_module(operation="uninstall")
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]
    mod.DUMP_CRON_PATH = str(tmp_path / "fehlt.cron")  # type: ignore[misc]
    mod.DUMP_SCRIPT_PATH = str(tmp_path / "fehlt.sh")  # type: ignore[misc]
    mod.DUMP_DIR = str(tmp_path / "fehlt-dump")  # type: ignore[misc]
    mod.SYSTEMD_ACTION_CLS = _NoOpSystemdAction  # type: ignore[misc]

    result = mod._uninstall()

    assert result == 0
    assert not hardening_file.exists()
    assert pg_hba_file.exists()
    assert pg_hba_file.read_text(encoding="utf-8") == pg_hba_original


def test_uninstall_warns_about_pg_hba_and_names_backup_recovery_path(
    tmp_path: Path,
) -> None:
    """Die WARN-Meldung nennt Pfad und Sicherungsmuster zur Wiederherstellung."""
    from pifos.actions.systemd_service_action import SystemdServiceAction

    class _NoOpSystemdAction(SystemdServiceAction):
        def run(self) -> str:
            self.status = "finished"
            return self.status

    etc_base = tmp_path / "etc-pg"
    cluster_dir = _make_cluster_dir(etc_base, version="16", cluster="main")
    (cluster_dir / "conf.d").mkdir()
    pg_hba_file = cluster_dir / "pg_hba.conf"
    pg_hba_file.write_text(_pg_hba_content(), encoding="utf-8")

    mod = _make_module(operation="uninstall")
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]
    mod.DUMP_CRON_PATH = str(tmp_path / "fehlt.cron")  # type: ignore[misc]
    mod.DUMP_SCRIPT_PATH = str(tmp_path / "fehlt.sh")  # type: ignore[misc]
    mod.DUMP_DIR = str(tmp_path / "fehlt-dump")  # type: ignore[misc]
    mod.SYSTEMD_ACTION_CLS = _NoOpSystemdAction  # type: ignore[misc]
    conn = mod._conn

    mod._uninstall()

    messages = [str(call.args[0].payload) for call in conn.send.call_args_list]  # type: ignore[attr-defined]
    warn = next(m for m in messages if "gehärteten Fassung bestehen" in m)
    assert str(pg_hba_file) in warn
    assert ".bak-<Zeitstempel>" in warn
    assert "zurückkopiert" in warn


def test_uninstall_short_circuits_when_own_conf_file_already_removed(
    tmp_path: Path,
) -> None:
    """Fehlt die eigene conf.d-Datei bereits, liefert _uninstall 0 ohne Schritte."""
    etc_base = tmp_path / "etc-pg"
    cluster_dir = _make_cluster_dir(etc_base, version="16", cluster="main")
    (cluster_dir / "conf.d").mkdir()
    pg_hba_file = cluster_dir / "pg_hba.conf"
    pg_hba_file.write_text(_pg_hba_content(), encoding="utf-8")

    mod = _make_module(operation="uninstall")
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]
    mod.DUMP_CRON_PATH = str(tmp_path / "fehlt.cron")  # type: ignore[misc]
    mod.DUMP_SCRIPT_PATH = str(tmp_path / "fehlt.sh")  # type: ignore[misc]
    mod.DUMP_DIR = str(tmp_path / "fehlt-dump")  # type: ignore[misc]
    mod.SYSTEMD_ACTION_CLS = "sollte-nicht-verwendet-werden"  # type: ignore[misc,assignment]

    assert mod._uninstall() == 0
    assert pg_hba_file.exists()


def test_uninstall_removes_dump_script_and_cron_but_keeps_dump_dir(
    tmp_path: Path,
) -> None:
    """uninstall entfernt Dump-Skript/-Cron; DUMP_DIR und vorhandene Dumps bleiben."""
    from pifos.actions.systemd_service_action import SystemdServiceAction

    class _NoOpSystemdAction(SystemdServiceAction):
        def run(self) -> str:
            self.status = "finished"
            return self.status

    etc_base = tmp_path / "etc-pg"
    cluster_dir = _make_cluster_dir(etc_base, version="16", cluster="main")
    (cluster_dir / "conf.d").mkdir()
    (cluster_dir / "pg_hba.conf").write_text(_pg_hba_content(), encoding="utf-8")

    dump_dir = tmp_path / "dump-dir"
    dump_dir.mkdir()
    dump_file = dump_dir / "kundendaten.sql"
    dump_file.write_text("-- alter Dump --\n", encoding="utf-8")

    dump_script = tmp_path / "dump.sh"
    dump_script.write_text("#!/bin/sh\n", encoding="utf-8")
    dump_cron = tmp_path / "dump.cron"
    dump_cron.write_text("0 2 * * * root /dump.sh\n", encoding="utf-8")

    mod = _make_module(operation="uninstall")
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]
    mod.SYSTEMD_ACTION_CLS = _NoOpSystemdAction  # type: ignore[misc]
    mod.DUMP_DIR = str(dump_dir)  # type: ignore[misc]
    mod.DUMP_SCRIPT_PATH = str(dump_script)  # type: ignore[misc]
    mod.DUMP_CRON_PATH = str(dump_cron)  # type: ignore[misc]

    result = mod._uninstall()

    assert result == 0
    assert not dump_script.exists()
    assert not dump_cron.exists()
    assert dump_dir.is_dir()
    assert dump_file.exists()
    assert dump_file.read_text(encoding="utf-8") == "-- alter Dump --\n"


def test_uninstall_warns_about_dump_dir_when_present(tmp_path: Path) -> None:
    """Die WARN-Meldung nennt DUMP_DIR, wenn dort Dumps liegen könnten."""
    from pifos.actions.systemd_service_action import SystemdServiceAction

    class _NoOpSystemdAction(SystemdServiceAction):
        def run(self) -> str:
            self.status = "finished"
            return self.status

    etc_base = tmp_path / "etc-pg"
    cluster_dir = _make_cluster_dir(etc_base, version="16", cluster="main")
    (cluster_dir / "conf.d").mkdir()
    (cluster_dir / "pg_hba.conf").write_text(_pg_hba_content(), encoding="utf-8")

    dump_dir = tmp_path / "dump-dir"
    dump_dir.mkdir()

    mod = _make_module(operation="uninstall")
    mod.PG_ETC_BASE = str(etc_base)  # type: ignore[misc]
    mod.SYSTEMD_ACTION_CLS = _NoOpSystemdAction  # type: ignore[misc]
    mod.DUMP_DIR = str(dump_dir)  # type: ignore[misc]
    mod.DUMP_SCRIPT_PATH = str(tmp_path / "fehlt.sh")  # type: ignore[misc]
    mod.DUMP_CRON_PATH = str(tmp_path / "fehlt.cron")  # type: ignore[misc]
    conn = mod._conn

    mod._uninstall()

    messages = [str(call.args[0].payload) for call in conn.send.call_args_list]  # type: ignore[attr-defined]
    assert any(str(dump_dir) in m and "bleibt bestehen" in m for m in messages)


def test_uninstall_removes_dump_artifacts_even_without_cluster(
    tmp_path: Path,
) -> None:
    """Dump-Skript/-Cron werden auch entfernt, wenn kein Cluster gefunden wird."""
    dump_script = tmp_path / "dump.sh"
    dump_script.write_text("#!/bin/sh\n", encoding="utf-8")
    dump_cron = tmp_path / "dump.cron"
    dump_cron.write_text("0 2 * * * root /dump.sh\n", encoding="utf-8")

    mod = _make_module(operation="uninstall")
    mod.PG_ETC_BASE = str(tmp_path / "nichts")  # type: ignore[misc]
    mod.DUMP_SCRIPT_PATH = str(dump_script)  # type: ignore[misc]
    mod.DUMP_CRON_PATH = str(dump_cron)  # type: ignore[misc]

    result = mod._uninstall()

    assert result == 0
    assert not dump_script.exists()
    assert not dump_cron.exists()


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, Pakete, Dateien, Rechte und Dienst."""
    values = {"timezone": "Europe/Berlin", "pg_dump_time": "02:00"}
    section = Postgresql.doc(values)
    assert section.startswith("\n## Datenbankserver postgresql (optional)\n\n")
    assert "**Pakete:** postgresql\n\n" in section
    for guc in _HARDENING_GUC_LINES:
        assert guc in section
    assert "log_timezone = 'Europe/Berlin'" in section
    for line in _PG_HBA_LINES:
        assert line in section
    assert "0o640" in section
    assert "postgres:postgres" in section
    assert "0o700" in section
    assert "**Dienste:** postgresql@<version>-<cluster>" in section


def test_doc_contains_backup_section_with_script_cron_and_freshness() -> None:
    """doc() beschreibt Dump-Skript, Cron-Zeit, Ablage und Frische-Überwachung."""
    values = {
        "timezone": "Europe/Berlin",
        "pg_dump_time": "02:00",
        "restic_backup_time": "02:30",
    }
    section = Postgresql.doc(values)
    assert "**Backup (Einzeldump je Datenbank):**" in section
    assert Postgresql.DUMP_SCRIPT_PATH in section
    assert Postgresql.DUMP_CRON_PATH in section
    assert "täglich 02:00 Uhr" in section
    assert "restic_backup_time 02:30 Uhr" in section
    assert f"{Postgresql.DUMP_DIR}/<datenbank>.sql" in section
    assert f"{Postgresql.DUMP_DIR}/{Postgresql.GLOBALS_FILE_NAME}" in section
    assert Postgresql.BACKUP_BASE_DIR in section
    assert "postgresql_dump" in section
    assert "26 Stunden" in section
    assert "psql -f" in section


def test_doc_marks_missing_timezone_and_pg_dump_time_as_leer_default() -> None:
    """Fehlen timezone/pg_dump_time, erscheint '(leer/Default)' statt leerer Werte."""
    section = Postgresql.doc({})
    assert "log_timezone = '(leer/Default)'" in section
    assert "täglich (leer/Default) Uhr" in section
    assert "restic_backup_time (leer/Default) Uhr" in section


def test_doc_never_leaks_secrets_from_unrelated_config_keys() -> None:
    """Ein Kunstgeheimnis unter fremdem Schlüssel erscheint nie in doc()."""
    values = {
        "timezone": "Europe/Berlin",
        "pg_dump_time": "02:00",
        "relay_password": "KUNST-GEHEIMNIS-42",
        "restic_passphrase": "KUNST-GEHEIMNIS-42",
    }
    section = Postgresql.doc(values)
    assert "KUNST-GEHEIMNIS-42" not in section
    assert "relay_password" not in section
    assert "restic_passphrase" not in section


def test_doc_notes_pg_hba_stays_hardened_after_uninstall() -> None:
    """doc() weist auf das Verbleiben der gehärteten pg_hba.conf hin."""
    section = Postgresql.doc({"timezone": "Europe/Berlin", "pg_dump_time": "02:00"})
    assert "pg_hba.conf und" in section
    assert "vorhandene Dumps" in section
    assert "Paket und Cluster bleiben in" in section
