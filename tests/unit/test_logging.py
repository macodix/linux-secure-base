"""Unit-Tests für secure_base.modules.logging."""

import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.logging import (
    AUDIT_RULES,
    SUDO_AUDIT_RULES,
    Logging,
    _audit_rules,
    _audit_rules_content,
    _logrotate_content,
    _report_cron_content,
    _report_script_content,
    _sudolog_content,
)


def _set_sudo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, present: bool
) -> None:
    """Lenkt die sudo-Vorbedingung auf tmp_path um — vorhanden oder fehlend.

    Ohne Umlenkung hinge das Ergebnis daran, ob auf dem Testrechner sudo
    installiert ist.
    """
    sudoers = tmp_path / "sudoers"
    sudoers_d = tmp_path / "sudoers.d"
    if present:
        sudoers.write_text("", encoding="utf-8")
        sudoers_d.mkdir()
    monkeypatch.setattr(Logging, "SUDOERS_FILE", str(sudoers))
    monkeypatch.setattr(Logging, "SUDOERS_DIR", str(sudoers_d))


def _make_logging(
    fqdn: str = "server.example.com",
    admin_mail: str = "admin@example.com",
    journald_max_use: str = "1G",
    journald_max_retention: str = "3month",
) -> Logging:
    """Baut ein Logging-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Logging(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.admin_mail = admin_mail
    mod.journald_max_use = journald_max_use
    mod.journald_max_retention = journald_max_retention
    return mod


# --- CONFIG ---


def test_logging_config_declares_expected_keys() -> None:
    """CONFIG nennt operation, fqdn, admin_mail und die journald-Schlüssel."""
    assert Logging.CONFIG == [
        "operation",
        "fqdn",
        "admin_mail",
        "journald_max_use",
        "journald_max_retention",
    ]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige Werte lösen keine Ausnahme aus."""
    mod = _make_logging()
    mod._validate()


def test_validate_rejects_invalid_fqdn_chars() -> None:
    """fqdn mit unzulässigen Zeichen erzeugt ModuleError."""
    mod = _make_logging(fqdn="server_example!.com")
    with pytest.raises(ModuleError, match="unzulässige Zeichen"):
        mod._validate()


def test_validate_rejects_fqdn_without_domain() -> None:
    """fqdn ohne Punkt lässt keine Domain ableiten und erzeugt ModuleError."""
    mod = _make_logging(fqdn="server")
    with pytest.raises(ModuleError, match="keine Domain ableitbar"):
        mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Ein ungültiges admin_mail erzeugt ModuleError."""
    mod = _make_logging(admin_mail="ungueltig")
    with pytest.raises(ModuleError, match="Ungültige admin_mail"):
        mod._validate()


def test_validate_rejects_invalid_journald_max_use() -> None:
    """Ein journald_max_use außerhalb des Größenmusters erzeugt ModuleError."""
    mod = _make_logging(journald_max_use="viel")
    with pytest.raises(ModuleError, match="Ungültiges journald_max_use"):
        mod._validate()


def test_validate_rejects_invalid_journald_max_retention() -> None:
    """Ein journald_max_retention außerhalb des Zeitmusters erzeugt ModuleError."""
    mod = _make_logging(journald_max_retention="lange")
    with pytest.raises(ModuleError, match="Ungültiges journald_max_retention"):
        mod._validate()


# --- _mailfrom ---


def test_mailfrom_derives_domain_from_fqdn() -> None:
    """_mailfrom leitet root@<domain> aus einem mehrteiligen fqdn ab."""
    mod = _make_logging(fqdn="srv001.example.com")
    assert mod._mailfrom() == "root@example.com"


def test_mailfrom_empty_without_domain() -> None:
    """_mailfrom liefert leer, wenn fqdn keinen Punkt enthält."""
    mod = _make_logging()
    mod.fqdn = "srv001"
    assert mod._mailfrom() == ""


# --- Inhaltsfunktionen ---


def test_audit_rules_content_contains_all_rules() -> None:
    """_audit_rules_content enthält jede Regel aus AUDIT_RULES als eigene Zeile."""
    content = _audit_rules_content(sudo_present=True)
    lines = content.splitlines()
    assert lines == list(AUDIT_RULES)


def test_audit_rules_content_ends_with_immutable_rule() -> None:
    """Die Immutable-Regel -e 2 steht als letzte Regel."""
    assert AUDIT_RULES[-1] == "-e 2"


def test_audit_rules_without_sudo_omit_sudoers_watches() -> None:
    """Ohne sudo entfallen genau die sudoers-Regeln — die übrigen bleiben."""
    rules = _audit_rules(sudo_present=False)
    assert not any(rule in SUDO_AUDIT_RULES for rule in rules)
    assert rules == tuple(r for r in AUDIT_RULES if r not in SUDO_AUDIT_RULES)
    assert rules[-1] == "-e 2"
    assert "-w /usr/bin/su -p x -k priv_esc" in rules


def test_audit_rules_content_without_sudo_omits_sudoers_watches() -> None:
    """Die Regeldatei enthält ohne sudo keine Überwachung eines sudoers-Pfads."""
    content = _audit_rules_content(sudo_present=False)
    assert "sudoers" not in content


def test_logrotate_content_contains_expected_directives() -> None:
    """_logrotate_content enthält die logrotate-Direktiven für das Logfile."""
    content = _logrotate_content()
    assert "/var/log/secure-base/secure-base.log {" in content
    assert "weekly" in content
    assert "size 5M" in content
    assert "rotate 8" in content


def test_sudolog_content_sets_logfile_directive() -> None:
    """_sudolog_content setzt die sudo-Logdatei-Direktive."""
    assert _sudolog_content() == 'Defaults logfile="/var/log/sudo.log"\n'


# --- _check_value ---


def test_check_value_matches_expected() -> None:
    """Stimmt die Befehlsausgabe mit dem Soll überein, liefert _check_value True."""
    mod = _make_logging()
    assert mod._check_value(["/bin/echo", "aktiv"], "aktiv", "Testwert") is True


def test_check_value_mismatch_returns_false() -> None:
    """Weicht die Befehlsausgabe vom Soll ab, liefert _check_value False."""
    mod = _make_logging()
    assert mod._check_value(["/bin/echo", "nein"], "ja", "Testwert") is False


def test_check_value_command_failure_returns_false() -> None:
    """Scheitert der Befehl, liefert _check_value False."""
    mod = _make_logging()
    assert mod._check_value(["/bin/false"], "irrelevant", "Testwert") is False


# --- _check_file_line ---


def test_check_file_line_present_returns_true(tmp_path: Path) -> None:
    """Eine vorhandene Zeile liefert True."""
    path = tmp_path / "datei.conf"
    path.write_text("Storage=persistent\nAndereZeile\n", encoding="utf-8")
    mod = _make_logging()
    assert mod._check_file_line(str(path), "Storage=persistent", "Testwert") is True


def test_check_file_line_missing_returns_false(tmp_path: Path) -> None:
    """Eine fehlende Zeile liefert False."""
    path = tmp_path / "datei.conf"
    path.write_text("AndereZeile\n", encoding="utf-8")
    mod = _make_logging()
    assert mod._check_file_line(str(path), "Storage=persistent", "Testwert") is False


def test_check_file_line_missing_file_returns_false(tmp_path: Path) -> None:
    """Eine nicht existierende Datei liefert False."""
    mod = _make_logging()
    assert (
        mod._check_file_line(str(tmp_path / "fehlt.conf"), "irrelevant", "Testwert")
        is False
    )


# --- _check_file_exists / _check_dir_exists ---


def test_check_file_exists_true_for_file(tmp_path: Path) -> None:
    """Eine vorhandene Datei liefert True."""
    path = tmp_path / "datei.conf"
    path.write_text("Inhalt\n", encoding="utf-8")
    mod = _make_logging()
    assert mod._check_file_exists(str(path), "Testwert") is True


def test_check_file_exists_false_for_missing(tmp_path: Path) -> None:
    """Eine fehlende Datei liefert False."""
    mod = _make_logging()
    assert mod._check_file_exists(str(tmp_path / "fehlt.conf"), "Testwert") is False


def test_check_dir_exists_true_for_dir(tmp_path: Path) -> None:
    """Ein vorhandenes Verzeichnis liefert True."""
    mod = _make_logging()
    assert mod._check_dir_exists(str(tmp_path), "Testwert") is True


def test_check_dir_exists_false_for_missing(tmp_path: Path) -> None:
    """Ein fehlendes Verzeichnis liefert False."""
    mod = _make_logging()
    assert mod._check_dir_exists(str(tmp_path / "fehlt"), "Testwert") is False


# --- _check_installed ---


def _make_fake_dpkg(tmp_path: Path, output: str, returncode: int = 0) -> str:
    """Baut ein ausführbares Fake-dpkg, das output ausgibt und returncode liefert."""
    script = tmp_path / "fake-dpkg"
    script.write_text(f"#!/bin/sh\nprintf '%s' {output!r}\nexit {returncode}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def test_check_installed_true_for_installed_status(tmp_path: Path) -> None:
    """Ein Status "install ok installed" liefert True."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "Status: install ok installed\n")
    try:
        assert mod._check_installed("logwatch", "Testwert") is True
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"


def test_check_installed_false_for_other_status(tmp_path: Path) -> None:
    """Ein abweichender Status liefert False."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "Status: deinstall ok config-files\n")
    try:
        assert mod._check_installed("logwatch", "Testwert") is False
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"


def test_check_installed_false_on_command_failure(tmp_path: Path) -> None:
    """Ein fehlschlagender Befehl liefert False."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "unbekanntes Paket\n", returncode=1)
    try:
        assert mod._check_installed("logwatch", "Testwert") is False
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"


# --- _package_installed (Vorbedingung für _uninstall-Schritte) ---


def test_package_installed_true_for_installed_status(tmp_path: Path) -> None:
    """Ein Status "install ok installed" liefert True."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "Status: install ok installed\n")
    try:
        assert mod._package_installed("logwatch") is True
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"


def test_package_installed_false_for_other_status(tmp_path: Path) -> None:
    """Ein abweichender Status liefert False."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "Status: deinstall ok config-files\n")
    try:
        assert mod._package_installed("logwatch") is False
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"


def test_package_installed_false_on_command_failure(tmp_path: Path) -> None:
    """Ein fehlschlagender Befehl liefert False."""
    mod = _make_logging()
    Logging.DPKG_BIN = _make_fake_dpkg(tmp_path, "unbekanntes Paket\n", returncode=1)
    try:
        assert mod._package_installed("logwatch") is False
    finally:
        Logging.DPKG_BIN = "/usr/bin/dpkg"


# --- _remove_file_if_exists ---


def test_remove_file_if_exists_deletes_existing_file(tmp_path: Path) -> None:
    """Eine vorhandene Datei wird ohne Sicherung gelöscht, Rückgabe 0."""
    path = tmp_path / "datei.conf"
    path.write_text("Inhalt\n", encoding="utf-8")
    mod = _make_logging()
    assert mod._remove_file_if_exists(str(path)) == 0
    assert not path.exists()
    assert not path.with_name("datei.conf.bak").exists()


def test_remove_file_if_exists_returns_zero_for_missing_file(tmp_path: Path) -> None:
    """Eine bereits fehlende Datei liefert 0, ohne einen Fehler auszulösen."""
    mod = _make_logging()
    assert mod._remove_file_if_exists(str(tmp_path / "fehlt.conf")) == 0


# --- doc ---


def test_doc_contains_section_title_and_core_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """doc() enthält Abschnittstitel, Pakete, Dateien, Werte und Dienst."""
    _set_sudo(monkeypatch, tmp_path, present=True)
    values = {
        "journald_max_use": "1G",
        "journald_max_retention": "3month",
        "admin_mail": "admin@example.com",
    }
    section = Logging.doc(values)
    assert section.startswith("\n## Protokollierung und Auditing\n\n")
    assert "**Pakete:** rsyslog, logwatch, auditd" in section
    assert "**Dienste:** rsyslog, auditd (enabled, aktiv nach install)" in section
    assert f"`{Logging.JOURNALD_CONF}`" in section
    assert "Storage = persistent" in section
    assert "SystemMaxUse = 1G" in section
    assert "MaxRetentionSec = 3month" in section
    assert f"`{Logging.LOGWATCH_CONF}`" in section
    assert "MailTo = admin@example.com" in section
    assert f"`{Logging.LOGROTATE_CONF}`" in section
    assert f"`{Logging.AUDIT_RULES_FILE}`" in section
    assert "-w /etc/sudoers -p wa -k scope" in section
    assert "-e 2 (Immutable" in section
    assert f"`{Logging.SUDOLOG_CONF}`" in section
    assert 'Defaults logfile="/var/log/sudo.log"' in section
    assert "**Timer/Cron:** täglicher Lauf via" in section
    assert Logging.REPORT_CRON in section
    assert Logging.REPORT_SCRIPT in section
    assert Logging.STOCK_CRON in section
    assert f"{Logging.JOURNAL_DIR} abgelegt" in section


def test_doc_without_sudo_omits_sudo_parts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt sudo, nennt doc() weder sudoers-Regeln noch sudo-Protokollierung."""
    _set_sudo(monkeypatch, tmp_path, present=False)
    section = Logging.doc({"admin_mail": "admin@example.com"})
    assert "-w /etc/sudoers -p wa -k scope" not in section
    assert "-w /etc/sudoers.d -p wa -k scope" not in section
    assert "/var/log/sudo.log" not in section
    assert "sudo ist auf diesem System nicht vorhanden" in section
    # Die übrigen Audit-Regeln stehen unverändert im Bericht.
    assert "-w /etc/passwd -p wa -k identity" in section
    assert "-e 2 (Immutable" in section


def test_doc_marks_missing_values_as_leer_default() -> None:
    """Fehlende Werte in values erscheinen als "(leer/Default)"."""
    section = Logging.doc({})
    assert "SystemMaxUse = (leer/Default)" in section
    assert "MaxRetentionSec = (leer/Default)" in section
    assert "MailTo = (leer/Default)" in section


def test_doc_never_leaks_unrelated_secret_values() -> None:
    """Werte fremder (nicht abgefragter) Schlüssel erscheinen nie in doc()."""
    values = {
        "journald_max_use": "1G",
        "journald_max_retention": "3month",
        "admin_mail": "admin@example.com",
        "relay_password": "GEHEIM-X",
    }
    section = Logging.doc(values)
    assert "GEHEIM-X" not in section
    assert "relay_password" not in section


# --- Tagesbericht (Skript und Cron) ---


def _script() -> str:
    """Baut einen Skriptinhalt mit festen Werten für die Inhaltsprüfungen."""
    return _report_script_content(
        admin_mail="admin@example.com",
        mail_from="root@example.com",
        fqdn="server.example.com",
        logwatch_bin="/usr/sbin/logwatch",
        journalctl_bin="/usr/bin/journalctl",
        systemctl_bin="/usr/bin/systemctl",
        df_bin="/usr/bin/df",
        base64_bin="/usr/bin/base64",
        sendmail_bin="/usr/sbin/sendmail",
    )


def test_report_script_writes_logwatch_report_to_a_file_not_to_mail() -> None:
    """logwatch schreibt in eine Datei — der volle Bericht geht als Anhang mit."""
    content = _script()
    assert '"/usr/sbin/logwatch" --output file --format text' in content
    assert "--output mail" not in content


def test_report_script_summary_covers_the_agreed_sections() -> None:
    """Die Zusammenfassung enthält die vereinbarten Abschnitte."""
    content = _script()
    for title in (
        "Erfolgreiche SSH-Anmeldungen",
        "Zwei-Faktor (TOTP)",
        "Fehlgeschlagene Anmeldungen bekannter Benutzer",
        "Rechteerhöhung (sudo, su)",
        "Sperren durch fail2ban",
        "Abgewiesene Anmeldeversuche (unbekannte Benutzer)",
        "Fehlgeschlagene Dienste",
        "Fehlgeschlagene Cron-Läufe",
        "Plattenplatz",
    ):
        assert title in content


def test_report_script_excludes_unknown_users_from_the_failed_logins_section() -> None:
    """Bot-Versuche auf unbekannte Namen zählen nicht als fehlgeschlagene Anmeldung."""
    content = _script()
    assert "awk '!/invalid user/'" in content


def test_report_script_reads_auth_messages_from_the_journal() -> None:
    """Die Zusammenfassung stammt aus dem Journal (Facility auth/authpriv)."""
    content = _script()
    assert "SYSLOG_FACILITY=4 + SYSLOG_FACILITY=10" in content


def test_report_script_sends_a_mime_mail_with_the_report_attached() -> None:
    """Die Mail hat zwei Teile: Zusammenfassung als Text, Bericht als Anhang."""
    content = _script()
    assert "Content-Type: multipart/mixed" in content
    assert "Content-Disposition: attachment" in content
    assert '"/usr/sbin/sendmail" -t' in content


def test_report_cron_content_calls_the_report_script() -> None:
    """Der cron.daily-Eintrag ruft das Berichts-Skript auf."""
    content = _report_cron_content("/usr/local/sbin/secure-base-logwatch.sh")
    assert content.startswith("#!/bin/sh\n")
    assert "exec /usr/local/sbin/secure-base-logwatch.sh\n" in content


def test_build_report_script_uses_the_configured_values() -> None:
    """Das gebaute Skript enthält Empfänger, Absender und Rechnernamen des Laufs."""
    mod = _make_logging(fqdn="srv.example.com", admin_mail="admin@example.com")
    content = mod._report_script("root@example.com")
    assert 'ADMIN_MAIL="admin@example.com"' in content
    assert 'MAIL_FROM="root@example.com"' in content
    assert 'FQDN="srv.example.com"' in content


def test_check_stock_cron_disabled_accepts_a_missing_file(tmp_path: Path) -> None:
    """Fehlt der mitgelieferte logwatch-Cron, ist nichts stillzulegen."""
    mod = _make_logging()
    mod.STOCK_CRON = str(tmp_path / "fehlt")  # type: ignore[misc]
    assert mod._check_stock_cron_disabled() is True


def test_check_stock_cron_disabled_rejects_an_executable_file(tmp_path: Path) -> None:
    """Ein ausführbarer logwatch-Cron würde eine zweite Mail verschicken."""
    mod = _make_logging()
    stock = tmp_path / "00logwatch"
    stock.write_text("#!/bin/bash\n", encoding="utf-8")
    stock.chmod(0o755)
    mod.STOCK_CRON = str(stock)  # type: ignore[misc]
    assert mod._check_stock_cron_disabled() is False

    stock.chmod(0o644)
    assert mod._check_stock_cron_disabled() is True


def test_logwatch_bin_points_to_the_path_the_package_ships() -> None:
    """Das Paket logwatch legt den Aufruf unter /usr/sbin ab, nicht unter /usr/bin.

    Belegt aus den Paketdateien beider Zieldistributionen: Debian 13 und
    Ubuntu 26.04 liefern beide /usr/sbin/logwatch (Symlink auf logwatch.pl)
    und führen /usr/sbin und /usr/bin nicht zusammen.
    """
    assert Logging.LOGWATCH_BIN == "/usr/sbin/logwatch"
    mod = _make_logging()
    assert Logging.LOGWATCH_BIN in mod._report_script("root@example.com")
