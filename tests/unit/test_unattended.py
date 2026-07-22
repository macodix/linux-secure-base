"""Unit-Tests für secure_base.modules.unattended."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.unattended import (
    DEBIAN_ORIGINS_BLOCK,
    UBUNTU_ORIGINS_BLOCK,
    Unattended,
    _periodic_conf_content,
    _timer_override_content,
    _uu_conf_content,
)

_UBUNTU_OS_RELEASE = 'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n'
_DEBIAN_OS_RELEASE = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\n'


def _set_distro(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, os_release: str
) -> None:
    """Lenkt die Distributionserkennung auf eine eigene os-release-Datei um."""
    path = tmp_path / "os-release"
    path.write_text(os_release, encoding="utf-8")
    monkeypatch.setattr(Unattended, "OS_RELEASE", str(path))


def _make_unattended(
    admin_mail: str = "admin@example.com",
    auto_reboot: str = "yes",
    auto_reboot_time: str = "23:45",
    apt_daily_time: str = "23:15",
    apt_daily_upgrade_time: str = "23:30",
) -> Unattended:
    """Baut ein Unattended-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Unattended(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.admin_mail = admin_mail
    mod.auto_reboot = auto_reboot
    mod.auto_reboot_time = auto_reboot_time
    mod.apt_daily_time = apt_daily_time
    mod.apt_daily_upgrade_time = apt_daily_upgrade_time
    mod.force_overwrite = "no"
    mod.backup_run_dir = "/var/backup/secure-base/test-lauf"
    return mod


# --- CONFIG ---


def test_unattended_config_declares_all_keys() -> None:
    """CONFIG nennt genau die sechs benötigten Schlüssel in dieser Reihenfolge."""
    assert Unattended.CONFIG == [
        "operation",
        "admin_mail",
        "auto_reboot",
        "auto_reboot_time",
        "apt_daily_time",
        "apt_daily_upgrade_time",
        "force_overwrite",
        "backup_run_dir",
    ]


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, Paket, Dateien, Werte und Timer-Zeile."""
    values = {
        "auto_reboot": "yes",
        "auto_reboot_time": "23:45",
        "apt_daily_time": "23:15",
        "apt_daily_upgrade_time": "23:30",
    }
    section = Unattended.doc(values)
    assert section.startswith("\n## Automatische Sicherheitsupdates\n\n")
    assert "**Pakete:** unattended-upgrades" in section
    assert f"`{Unattended.UU_CONF}`" in section
    assert "Automatic-Reboot = yes" in section
    assert "Automatic-Reboot-Time = 23:45" in section
    assert f"`{Unattended.PERIODIC_CONF}`" in section
    assert "APT::Periodic::Update-Package-Lists = 1" in section
    assert "APT::Periodic::Unattended-Upgrade = 1" in section
    assert f"`{Unattended.DAILY_DROPIN}`" in section
    assert "OnCalendar = 23:15" in section
    assert f"`{Unattended.UPGRADE_DROPIN}`" in section
    assert "OnCalendar = 23:30" in section
    assert (
        "**Timer/Cron:** apt-daily.timer und apt-daily-upgrade.timer"
        " (systemd) mit konfigurierten Uhrzeiten" in section
    )


def test_doc_marks_missing_values_as_leer_default() -> None:
    """Fehlende Werte in values erscheinen als "(leer/Default)"."""
    section = Unattended.doc({})
    assert "Automatic-Reboot = (leer/Default)" in section
    assert "Automatic-Reboot-Time = (leer/Default)" in section
    assert section.count("OnCalendar = (leer/Default)") == 2


def test_doc_never_leaks_unrelated_secret_value() -> None:
    """Ein Kunstgeheimnis unter fremdem Schlüssel erscheint nie in doc()."""
    values = {
        "auto_reboot": "yes",
        "auto_reboot_time": "23:45",
        "apt_daily_time": "23:15",
        "apt_daily_upgrade_time": "23:30",
        "admin_mail": "admin@example.com",
        "relay_password": "GEHEIM-X-KUNSTWERT",
    }
    section = Unattended.doc(values)
    assert "GEHEIM-X-KUNSTWERT" not in section
    assert "relay_password" not in section
    # admin_mail ist kein Geheimnis: die Mail-Zeile dokumentiert sie
    # wie das Bash-Original.
    assert "Mail = admin@example.com (only-on-error)" in section


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige Werte in korrekter Zeit-Reihenfolge lösen keine Ausnahme aus."""
    mod = _make_unattended()
    mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Eine ungültige admin_mail-Adresse erzeugt ModuleError."""
    mod = _make_unattended(admin_mail="keine-mail-adresse")
    with pytest.raises(ModuleError, match="Ungültige admin_mail-Adresse"):
        mod._validate()


def test_validate_rejects_invalid_auto_reboot() -> None:
    """Ein auto_reboot-Wert außerhalb yes/no erzeugt ModuleError."""
    mod = _make_unattended(auto_reboot="vielleicht")
    with pytest.raises(ModuleError, match="auto_reboot muss"):
        mod._validate()


def test_validate_rejects_invalid_time_format() -> None:
    """Eine Uhrzeit außerhalb HH:MM erzeugt ModuleError."""
    mod = _make_unattended(auto_reboot_time="25:99")
    with pytest.raises(ModuleError, match="auto_reboot_time ist keine gültige"):
        mod._validate()


def test_validate_warns_on_time_order() -> None:
    """Uhrzeiten außer der Reihe lösen eine WARN-Meldung, keine Ausnahme, aus."""
    mod = _make_unattended(
        apt_daily_time="23:45", apt_daily_upgrade_time="23:15", auto_reboot_time="23:30"
    )
    mod._validate()
    conn = mod._conn
    assert isinstance(conn, MagicMock)
    levels = [call.args[0].level for call in conn.send.call_args_list]
    assert LogLevel.WARN in levels


# --- Inhaltsfunktionen ---


def test_uu_conf_content_contains_origins_block_and_directives() -> None:
    """_uu_conf_content enthält den übergebenen Quellen-Block und alle Direktiven."""
    content = _uu_conf_content(
        "admin@example.com", "true", "23:45", UBUNTU_ORIGINS_BLOCK
    )
    assert "${distro_id}:${distro_codename}" in content
    assert "${distro_id}:${distro_codename}-security" in content
    assert "${distro_id}:${distro_codename}-updates" in content
    assert 'Unattended-Upgrade::Automatic-Reboot "true";' in content
    assert 'Unattended-Upgrade::Automatic-Reboot-Time "23:45";' in content
    assert 'Unattended-Upgrade::Mail "admin@example.com";' in content
    assert 'Unattended-Upgrade::MailReport "only-on-error";' in content


def test_uu_conf_content_takes_the_debian_block_verbatim() -> None:
    """Der Debian-Block landet unverändert in der Datei."""
    content = _uu_conf_content(
        "admin@example.com", "false", "23:45", DEBIAN_ORIGINS_BLOCK
    )
    assert DEBIAN_ORIGINS_BLOCK in content
    assert "Allowed-Origins" not in content


def test_ubuntu_origins_block_uses_allowed_origins() -> None:
    """Ubuntu: Kurzform Allowed-Origins, drei Quellen, kein -proposed."""
    assert UBUNTU_ORIGINS_BLOCK.startswith("Unattended-Upgrade::Allowed-Origins {")
    assert "-proposed" not in UBUNTU_ORIGINS_BLOCK
    assert "-backports" not in UBUNTU_ORIGINS_BLOCK


def test_debian_origins_block_uses_origins_pattern_with_labels() -> None:
    """Debian: Origins-Pattern mit Label und Codename statt der Kurzform.

    Die Kurzform vergleicht Origin mit der Suite. Debians Suite heißt "stable"
    bzw. "stable-security", nicht wie der Codename — sie träfe nichts.
    """
    assert DEBIAN_ORIGINS_BLOCK.startswith("Unattended-Upgrade::Origins-Pattern {")
    assert (
        'origin=Debian,codename=${distro_codename},label=Debian"'
        in DEBIAN_ORIGINS_BLOCK
    )
    assert (
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"
        in DEBIAN_ORIGINS_BLOCK
    )
    assert (
        "origin=Debian,codename=${distro_codename}-updates,label=Debian"
        in DEBIAN_ORIGINS_BLOCK
    )
    assert "${distro_id}" not in DEBIAN_ORIGINS_BLOCK
    assert "-proposed" not in DEBIAN_ORIGINS_BLOCK
    assert "-backports" not in DEBIAN_ORIGINS_BLOCK


# --- Distributionszweig ---


def test_origins_block_follows_the_running_distro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_origins_block liefert je Distribution den passenden Block."""
    mod = _make_unattended()
    _set_distro(monkeypatch, tmp_path, _UBUNTU_OS_RELEASE)
    assert mod._origins_block() == UBUNTU_ORIGINS_BLOCK
    _set_distro(monkeypatch, tmp_path, _DEBIAN_OS_RELEASE)
    assert mod._origins_block() == DEBIAN_ORIGINS_BLOCK


def test_origins_block_rejects_unsupported_distro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Auf einer fremden Distribution bricht das Modul ab, statt zu raten."""
    mod = _make_unattended()
    _set_distro(monkeypatch, tmp_path, "ID=fedora\n")
    with pytest.raises(ModuleError, match="wird nicht unterstützt"):
        mod._origins_block()


def test_periodic_conf_content_contains_all_directives() -> None:
    """_periodic_conf_content enthält alle drei Periodic-Direktiven."""
    content = _periodic_conf_content()
    assert 'APT::Periodic::Update-Package-Lists "1";' in content
    assert 'APT::Periodic::Unattended-Upgrade "1";' in content
    assert 'APT::Periodic::AutocleanInterval "7";' in content


def test_timer_override_content_pins_oncalendar() -> None:
    """_timer_override_content pinnt OnCalendar auf die übergebene Uhrzeit."""
    content = _timer_override_content("23:15")
    assert "OnCalendar=*-*-* 23:15:00" in content
    assert "RandomizedDelaySec=0" in content


# --- _check_command_succeeds ---


def test_check_command_succeeds_true() -> None:
    """Ein erfolgreicher Befehl liefert True."""
    mod = _make_unattended()
    assert mod._check_command_succeeds(["/bin/true"], "Testwert") is True


def test_check_command_succeeds_false() -> None:
    """Ein scheiternder Befehl liefert False."""
    mod = _make_unattended()
    assert mod._check_command_succeeds(["/bin/false"], "Testwert") is False


# --- start-Verzweigung (uninstall/test) ---


def test_start_dispatches_to_uninstall(monkeypatch: pytest.MonkeyPatch) -> None:
    """operation 'uninstall' ruft _uninstall auf."""
    mod = _make_unattended()
    mod.operation = "uninstall"
    monkeypatch.setattr(mod, "_uninstall", lambda: 42)
    assert mod.start() == 42


def test_start_dispatches_to_test(monkeypatch: pytest.MonkeyPatch) -> None:
    """operation 'test' ruft _test auf."""
    mod = _make_unattended()
    mod.operation = "test"
    monkeypatch.setattr(mod, "_test", lambda: 43)
    assert mod.start() == 43


def test_start_dispatches_to_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    """operation 'preflight' ruft preflight_managed auf."""
    mod = _make_unattended()
    mod.operation = "preflight"
    monkeypatch.setattr(mod, "preflight_managed", lambda name: 44)
    assert mod.start() == 44


# --- _package_installed ---


def test_package_installed_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """dpkg -s meldet Erfolg, wenn das Paket installiert ist."""
    monkeypatch.setattr(Unattended, "DPKG_BIN", "/usr/bin/true")
    mod = _make_unattended()
    assert mod._package_installed() is True


def test_package_installed_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """dpkg -s meldet Fehlschlag, wenn das Paket nicht installiert ist."""
    monkeypatch.setattr(Unattended, "DPKG_BIN", "/usr/bin/false")
    mod = _make_unattended()
    assert mod._package_installed() is False


# --- _cleanup_empty_dropin_dirs ---


def test_cleanup_empty_dropin_dirs_removes_empty_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leere Timer-Override-Verzeichnisse werden entfernt."""
    daily_dir = tmp_path / "apt-daily.timer.d"
    upgrade_dir = tmp_path / "apt-daily-upgrade.timer.d"
    daily_dir.mkdir()
    upgrade_dir.mkdir()
    monkeypatch.setattr(Unattended, "DAILY_DROPIN", str(daily_dir / "secure-base.conf"))
    monkeypatch.setattr(
        Unattended, "UPGRADE_DROPIN", str(upgrade_dir / "secure-base.conf")
    )
    mod = _make_unattended()

    mod._cleanup_empty_dropin_dirs()

    assert not daily_dir.exists()
    assert not upgrade_dir.exists()


def test_cleanup_empty_dropin_dirs_keeps_nonempty_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ein nicht-leeres Timer-Override-Verzeichnis bleibt bestehen (best effort)."""
    daily_dir = tmp_path / "apt-daily.timer.d"
    daily_dir.mkdir()
    (daily_dir / "andere-datei.conf").write_text("bleibt\n")
    monkeypatch.setattr(Unattended, "DAILY_DROPIN", str(daily_dir / "secure-base.conf"))
    monkeypatch.setattr(
        Unattended, "UPGRADE_DROPIN", str(tmp_path / "fehlt" / "secure-base.conf")
    )
    mod = _make_unattended()

    mod._cleanup_empty_dropin_dirs()

    assert daily_dir.exists()


# --- _test_dry_run ---


def test_test_dry_run_reports_missing_package(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fehlt das Paket, liefert der Trockenlauf False, ohne ihn auszuführen."""
    monkeypatch.setattr(Unattended, "DPKG_BIN", "/usr/bin/false")
    mod = _make_unattended()
    conn = mod._conn
    assert mod._test_dry_run() is False
    assert isinstance(conn, MagicMock)
    messages = [call.args[0].payload for call in conn.send.call_args_list]
    assert any("kein Funktionstest möglich" in str(m) for m in messages)


def test_test_dry_run_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    """Installiertes Paket und erfolgreicher Trockenlauf liefern True."""
    monkeypatch.setattr(Unattended, "DPKG_BIN", "/usr/bin/true")
    monkeypatch.setattr(Unattended, "UNATTENDED_UPGRADE_BIN", "/usr/bin/true")
    mod = _make_unattended()
    assert mod._test_dry_run() is True


def test_test_dry_run_fails_when_dry_run_command_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ein scheiternder Trockenlauf liefert False."""
    monkeypatch.setattr(Unattended, "DPKG_BIN", "/usr/bin/true")
    monkeypatch.setattr(Unattended, "UNATTENDED_UPGRADE_BIN", "/usr/bin/false")
    mod = _make_unattended()
    assert mod._test_dry_run() is False


# --- _log_timers ---


def test_log_timers_logs_output_lines(monkeypatch: pytest.MonkeyPatch) -> None:
    """Jede Ausgabezeile von list-timers wird protokolliert."""
    monkeypatch.setattr(Unattended, "SYSTEMCTL_BIN", "/bin/echo")
    mod = _make_unattended()
    conn = mod._conn

    mod._log_timers()

    assert isinstance(conn, MagicMock)
    messages = [call.args[0].payload for call in conn.send.call_args_list]
    assert any(str(m).startswith("list-timers: list-timers") for m in messages)


def test_log_timers_reports_error_without_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Schlägt list-timers fehl, wird das nur protokolliert, keine Ausnahme."""
    monkeypatch.setattr(Unattended, "SYSTEMCTL_BIN", "/usr/bin/false")
    mod = _make_unattended()
    conn = mod._conn

    mod._log_timers()

    assert isinstance(conn, MagicMock)
    messages = [call.args[0].payload for call in conn.send.call_args_list]
    assert any("list-timers nicht lesbar" in str(m) for m in messages)
