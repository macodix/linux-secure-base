"""Unit-Tests für secure_base.modules.postgresql."""

import grp
import os
import pwd
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.postgresql import (
    _HARDENING_GUC_LINES,
    _PG_HBA_LINES,
    Postgresql,
    _pg_hba_content,
)


def _write_script(tmp_path: Path, name: str, body: str) -> str:
    """Legt ein ausführbares Fake-Programm unter tmp_path an und liefert den Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def _make_module(
    *, operation: str = "install", timezone: str = "Europe/Berlin"
) -> Postgresql:
    """Baut ein Postgresql-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Postgresql(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = operation
    mod.timezone = timezone
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


def test_config_declares_operation_and_timezone() -> None:
    """CONFIG nennt nur operation und timezone (kein eigener pg_-Schlüssel nötig)."""
    assert Postgresql.CONFIG == ["operation", "timezone"]


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


def test_uninstall_is_config_independent() -> None:
    """start() ruft bei operation='uninstall' _validate() nicht auf."""
    mod = _make_module(operation="uninstall", timezone="Nirgendwo/Erfunden")
    mod.PG_ETC_BASE = "/nichts-vorhanden"  # type: ignore[misc]
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
    ]

    by_label = dict(steps)

    write_hardening = by_label["Verbindungs- und Protokolleinstellungen schreiben"]
    assert write_hardening.dst == str(  # type: ignore[attr-defined]
        etc_base / "16" / "main" / "conf.d" / "secure-base-hardening.conf"
    )
    assert write_hardening.mode == 0o640  # type: ignore[attr-defined]
    assert write_hardening.content == mod._hardening_conf_content()  # type: ignore[attr-defined]

    chown_hardening = by_label["Eigentümer/Rechte der Härtungs-Konfiguration setzen"]
    assert chown_hardening.mode == 0o640  # type: ignore[attr-defined]
    assert chown_hardening.owner == "postgres"  # type: ignore[attr-defined]
    assert chown_hardening.group == "postgres"  # type: ignore[attr-defined]

    write_hba = by_label["pg_hba.conf ersetzen"]
    assert write_hba.dst == str(etc_base / "16" / "main" / "pg_hba.conf")  # type: ignore[attr-defined]
    assert write_hba.mode == 0o640  # type: ignore[attr-defined]
    assert write_hba.content == _pg_hba_content()  # type: ignore[attr-defined]

    chown_hba = by_label["Eigentümer/Rechte von pg_hba.conf setzen"]
    assert chown_hba.mode == 0o640  # type: ignore[attr-defined]
    assert chown_hba.owner == "postgres"  # type: ignore[attr-defined]
    assert chown_hba.group == "postgres"  # type: ignore[attr-defined]

    chown_data_dir = by_label["Datenverzeichnis-Rechte setzen"]
    assert chown_data_dir.mode == 0o700  # type: ignore[attr-defined]
    assert chown_data_dir.owner == "postgres"  # type: ignore[attr-defined]
    assert chown_data_dir.group == "postgres"  # type: ignore[attr-defined]

    enable_step = by_label["Dienst aktivieren"]
    assert enable_step.operation == "enable"  # type: ignore[attr-defined]
    assert enable_step.unit == "postgresql@16-main"  # type: ignore[attr-defined]

    restart_step = by_label["Dienst neu starten"]
    assert restart_step.operation == "restart"  # type: ignore[attr-defined]
    assert restart_step.unit == "postgresql@16-main"  # type: ignore[attr-defined]


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


def test_test_operation_succeeds_with_active_service_and_connection(
    tmp_path: Path,
) -> None:
    """Aktiver Dienst und erfolgreiche SELECT-1-Verbindung liefern 0."""
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
    assert mod._test() == 0


# --- _uninstall ---


def test_uninstall_returns_zero_without_cluster(tmp_path: Path) -> None:
    """Ohne Cluster gibt es nichts zurückzunehmen; _uninstall liefert 0."""
    mod = _make_module(operation="uninstall")
    mod.PG_ETC_BASE = str(tmp_path / "nichts")  # type: ignore[misc]
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
    mod.SYSTEMD_ACTION_CLS = "sollte-nicht-verwendet-werden"  # type: ignore[misc,assignment]

    assert mod._uninstall() == 0
    assert pg_hba_file.exists()


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, Pakete, Dateien, Rechte und Dienst."""
    values = {"timezone": "Europe/Berlin"}
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


def test_doc_marks_missing_timezone_as_leer_default() -> None:
    """Fehlt timezone, erscheint '(leer/Default)' statt eines leeren Werts."""
    section = Postgresql.doc({})
    assert "log_timezone = '(leer/Default)'" in section


def test_doc_never_leaks_secrets_from_unrelated_config_keys() -> None:
    """Ein Kunstgeheimnis unter fremdem Schlüssel erscheint nie in doc()."""
    values = {
        "timezone": "Europe/Berlin",
        "relay_password": "KUNST-GEHEIMNIS-42",
        "restic_passphrase": "KUNST-GEHEIMNIS-42",
    }
    section = Postgresql.doc(values)
    assert "KUNST-GEHEIMNIS-42" not in section
    assert "relay_password" not in section
    assert "restic_passphrase" not in section


def test_doc_notes_pg_hba_stays_hardened_after_uninstall() -> None:
    """doc() weist auf das Verbleiben der gehärteten pg_hba.conf hin."""
    section = Postgresql.doc({"timezone": "Europe/Berlin"})
    assert "pg_hba.conf bleibt aus Sicherheitsgründen" in section
    assert "Paket und" in section
    assert "Cluster bleiben in jedem Fall installiert" in section
