"""Unit-Tests für secure_base.modules.rkhunter."""

from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock

import pytest
from pifos.action import Action
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from secure_base.modules import rkhunter as rkhunter_module
from secure_base.modules.rkhunter import Rkhunter


def _make_rkhunter(fqdn: str, admin_mail: str) -> Rkhunter:
    """Baut ein Rkhunter-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Rkhunter(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.fqdn = fqdn
    mod.admin_mail = admin_mail
    return mod


# --- CONFIG ---


def test_rkhunter_config_declares_operation_fqdn_admin_mail() -> None:
    """CONFIG nennt genau operation, fqdn und admin_mail in dieser Reihenfolge."""
    assert Rkhunter.CONFIG == ["operation", "fqdn", "admin_mail"]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültiger Rechnername und gültige E-Mail-Adresse lösen keine Ausnahme aus."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    mod._validate()


def test_validate_rejects_invalid_fqdn_charset() -> None:
    """Ein Rechnername mit unzulässigen Zeichen erzeugt ModuleError."""
    mod = _make_rkhunter("server_example!com", "admin@example.com")
    with pytest.raises(ModuleError, match="Ungültiger Rechnername"):
        mod._validate()


def test_validate_rejects_fqdn_without_domain() -> None:
    """Ein Rechnername ohne Domain (kein Punkt) erzeugt ModuleError."""
    mod = _make_rkhunter("server", "admin@example.com")
    with pytest.raises(ModuleError, match="Kein Absender ableitbar"):
        mod._validate()


def test_validate_rejects_invalid_admin_mail() -> None:
    """Eine ungültige E-Mail-Adresse erzeugt ModuleError."""
    mod = _make_rkhunter("server.example.com", "keine-email-adresse")
    with pytest.raises(ModuleError, match="Ungültige E-Mail-Adresse"):
        mod._validate()


# --- Absender-Ableitung ---


def test_domain_returns_part_after_first_dot() -> None:
    """_domain liefert den Domain-Anteil nach dem ersten Punkt."""
    mod = _make_rkhunter("srv001.example.com", "admin@example.com")
    assert mod._domain() == "example.com"


def test_domain_empty_without_dot() -> None:
    """_domain liefert leer, wenn fqdn keinen Punkt enthält."""
    mod = _make_rkhunter("srv001", "admin@example.com")
    assert mod._domain() == ""


def test_mailfrom_builds_root_at_domain() -> None:
    """_mailfrom baut root@<domain> aus fqdn."""
    mod = _make_rkhunter("srv001.example.com", "admin@example.com")
    assert mod._mailfrom() == "root@example.com"


def test_mail_cmd_contains_mailfrom_and_literal_hostname_var() -> None:
    """_mail_cmd enthält den Absender und lässt ${HOST_NAME} literal stehen."""
    mod = _make_rkhunter("srv001.example.com", "admin@example.com")
    cmd = mod._mail_cmd()
    assert "mail -r root@example.com" in cmd
    assert "${HOST_NAME}" in cmd


# --- _file_has_line ---


def test_file_has_line_matches_existing_line(tmp_path: Path) -> None:
    """Eine vorhandene, passende Zeile liefert True."""
    target = tmp_path / "rkhunter"
    target.write_text('CRON_DAILY_RUN="yes"\n', encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._file_has_line(str(target), r'^CRON_DAILY_RUN="yes"$') is True


def test_file_has_line_missing_line_returns_false(tmp_path: Path) -> None:
    """Fehlt die passende Zeile, liefert _file_has_line False."""
    target = tmp_path / "rkhunter"
    target.write_text("# leer\n", encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._file_has_line(str(target), r'^CRON_DAILY_RUN="yes"$') is False


def test_file_has_line_missing_file_returns_false(tmp_path: Path) -> None:
    """Eine fehlende Datei liefert _file_has_line False."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._file_has_line(str(tmp_path / "fehlt"), r".*") is False


# --- _check_setting ---


def test_check_setting_matches_returns_true(tmp_path: Path) -> None:
    """Passt die Zeile auf das Muster, liefert _check_setting True."""
    target = tmp_path / "rkhunter"
    target.write_text('APT_AUTOGEN="yes"\n', encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._check_setting(str(target), r'^APT_AUTOGEN="yes"$', "apt-Hook") is True


def test_check_setting_mismatch_returns_false(tmp_path: Path) -> None:
    """Fehlt die Sollzeile, liefert _check_setting False."""
    target = tmp_path / "rkhunter"
    target.write_text('APT_AUTOGEN="no"\n', encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._check_setting(str(target), r'^APT_AUTOGEN="yes"$', "apt-Hook") is False


# --- _baseline_present / _check_baseline ---


def test_baseline_present_true_for_nonempty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine vorhandene, nicht-leere Baseline-Datei liefert True."""
    baseline = tmp_path / "rkhunter.dat"
    baseline.write_text("baseline-inhalt\n", encoding="utf-8")
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(baseline))
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._baseline_present() is True


def test_baseline_present_false_for_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine leere Baseline-Datei liefert False."""
    baseline = tmp_path / "rkhunter.dat"
    baseline.write_text("", encoding="utf-8")
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(baseline))
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._baseline_present() is False


def test_baseline_present_false_for_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Eine fehlende Baseline-Datei liefert False."""
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(tmp_path / "fehlt.dat"))
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._baseline_present() is False


def test_check_baseline_reports_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fehlt die Baseline, liefert _check_baseline False."""
    monkeypatch.setattr(Rkhunter, "RK_BASELINE", str(tmp_path / "fehlt.dat"))
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    assert mod._check_baseline() is False


# --- _revert_config ---


def test_revert_config_removes_matching_lines(tmp_path: Path) -> None:
    """Eine vorhandene, passende Zeile wird entfernt; der Aufruf liefert True."""
    target = tmp_path / "default_rkhunter"
    target.write_text('CRON_DAILY_RUN="yes"\nCRON_DB_UPDATE="yes"\n', encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")

    result = mod._revert_config(
        str(target),
        (
            ("täglichen Lauf zurücknehmen", r"^CRON_DAILY_RUN="),
            ("DB-Update zurücknehmen", r"^CRON_DB_UPDATE="),
        ),
    )

    assert result is True
    content = target.read_text(encoding="utf-8")
    assert "CRON_DAILY_RUN" not in content
    assert "CRON_DB_UPDATE" not in content


def test_revert_config_missing_file_is_idempotent(tmp_path: Path) -> None:
    """Eine fehlende Zieldatei gilt als bereits zurückgenommen (True, kein Fehler)."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")

    result = mod._revert_config(
        str(tmp_path / "fehlt"), (("täglichen Lauf zurücknehmen", r"^CRON_DAILY_RUN="),)
    )

    assert result is True


def test_revert_config_missing_line_is_idempotent(tmp_path: Path) -> None:
    """Eine bereits fehlende Sollzeile führt nicht zum Fehler."""
    target = tmp_path / "default_rkhunter"
    target.write_text("# leer\n", encoding="utf-8")
    mod = _make_rkhunter("server.example.com", "admin@example.com")

    result = mod._revert_config(
        str(target), (("täglichen Lauf zurücknehmen", r"^CRON_DAILY_RUN="),)
    )

    assert result is True


# --- _check_package_installed ---


def test_check_package_installed_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """Meldet dpkg-query das Paket als installiert, liefert die Methode True."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    monkeypatch.setattr(Rkhunter, "DPKG_QUERY_BIN", "/bin/echo")

    def fake_run_action(action: Action) -> int:
        action.stdout = "install ok installed"  # type: ignore[attr-defined]
        return 0

    monkeypatch.setattr(mod, "run_action", fake_run_action)
    assert mod._check_package_installed() is True


def test_check_package_installed_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """Meldet dpkg-query das Paket nicht als installiert, liefert die Methode False."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")

    def fake_run_action(action: Action) -> int:
        action.stdout = ""  # type: ignore[attr-defined]
        return 1

    monkeypatch.setattr(mod, "run_action", fake_run_action)
    assert mod._check_package_installed() is False


# --- _run_scan ---


class _FakeScan:
    """Ersetzt SysCmdAction für _run_scan-Tests: liefert feste stdout/returncode."""

    RESULT_STDOUT: ClassVar[str] = ""
    RESULT_RETURNCODE: ClassVar[int] = 0
    RAISES_WITHOUT_RESULT: ClassVar[bool] = False

    def __init__(self, command: list[str], timeout: float) -> None:
        self.command = command
        self.timeout = timeout
        self.stdout = ""
        self.returncode = -1

    def run(self) -> str:
        if self.RAISES_WITHOUT_RESULT:
            raise ActionError("Befehl konnte nicht gestartet werden")
        self.stdout = self.RESULT_STDOUT
        self.returncode = self.RESULT_RETURNCODE
        if self.returncode != 0:
            raise ActionError("Scan meldet Warnungen oder Fehler")
        return "finished"


def test_run_scan_returncode_zero_is_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exit-Code 0 gilt als erfolgreicher Scan ohne Warnungen."""
    _FakeScan.RESULT_STDOUT = ""
    _FakeScan.RESULT_RETURNCODE = 0
    _FakeScan.RAISES_WITHOUT_RESULT = False
    monkeypatch.setattr(rkhunter_module, "SysCmdAction", _FakeScan)
    mod = _make_rkhunter("server.example.com", "admin@example.com")

    assert mod._run_scan() is True


def test_run_scan_returncode_one_is_warning_not_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exit-Code 1 (Warnungen) gilt nicht als Testfehler."""
    _FakeScan.RESULT_STDOUT = "Warning: something suspicious\n"
    _FakeScan.RESULT_RETURNCODE = 1
    _FakeScan.RAISES_WITHOUT_RESULT = False
    monkeypatch.setattr(rkhunter_module, "SysCmdAction", _FakeScan)
    mod = _make_rkhunter("server.example.com", "admin@example.com")

    assert mod._run_scan() is True


def test_run_scan_other_returncode_is_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein anderer Exit-Code als 0 oder 1 gilt als Testfehler."""
    _FakeScan.RESULT_STDOUT = ""
    _FakeScan.RESULT_RETURNCODE = 2
    _FakeScan.RAISES_WITHOUT_RESULT = False
    monkeypatch.setattr(rkhunter_module, "SysCmdAction", _FakeScan)
    mod = _make_rkhunter("server.example.com", "admin@example.com")

    assert mod._run_scan() is False


def test_run_scan_start_failure_is_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ein Startfehler (Binary fehlt o. Ä.) gilt als Testfehler."""
    _FakeScan.RAISES_WITHOUT_RESULT = True
    monkeypatch.setattr(rkhunter_module, "SysCmdAction", _FakeScan)
    mod = _make_rkhunter("server.example.com", "admin@example.com")

    assert mod._run_scan() is False


# --- Ausnahmen (ALLOWHIDDENFILE/ALLOWDEVFILE) ---


def test_allow_entries_lists_hidden_files_then_dev_files() -> None:
    """_allow_entries liefert erst die versteckten Dateien, dann die /dev-Muster."""
    assert Rkhunter._allow_entries() == [
        ("ALLOWHIDDENFILE", "/etc/.resolv.conf.systemd-resolved.bak"),
        ("ALLOWHIDDENFILE", "/etc/.updated"),
        ("ALLOWDEVFILE", "/dev/shm/PostgreSQL.*"),  # noqa: S108 — nur Text
    ]


def test_allow_pattern_matches_only_the_full_entry(tmp_path: Path) -> None:
    """Das Muster trifft den ganzen Eintrag, nicht andere Werte desselben Schlüssels."""
    mod = _make_rkhunter("srv.example.com", "admin@example.com")
    pattern = mod._allow_pattern("ALLOWHIDDENFILE", "/etc/.updated")

    conf = tmp_path / "rkhunter.conf"
    conf.write_text("ALLOWHIDDENFILE=/etc/.fremd\n", encoding="utf-8")
    assert mod._file_has_line(str(conf), pattern) is False

    conf.write_text("ALLOWHIDDENFILE=/etc/.updated\n", encoding="utf-8")
    assert mod._file_has_line(str(conf), pattern) is True


def test_allow_pattern_escapes_the_dev_file_wildcard(tmp_path: Path) -> None:
    """Der Stern im /dev/shm-Muster ist ein Literal, kein Regex-Quantor."""
    mod = _make_rkhunter("srv.example.com", "admin@example.com")
    pattern = mod._allow_pattern("ALLOWDEVFILE", "/dev/shm/PostgreSQL.*")  # noqa: S108

    conf = tmp_path / "rkhunter.conf"
    conf.write_text("ALLOWDEVFILE=/dev/shm/PostgreSQL.1967000986\n", encoding="utf-8")
    assert mod._file_has_line(str(conf), pattern) is False

    conf.write_text("ALLOWDEVFILE=/dev/shm/PostgreSQL.*\n", encoding="utf-8")
    assert mod._file_has_line(str(conf), pattern) is True


# --- doc ---


def test_doc_contains_section_title_and_core_fields() -> None:
    """doc() enthält Abschnittstitel, Paket, Datei und Report-Empfänger."""
    values = {"fqdn": "server.example.com", "admin_mail": "admin@example.com"}
    section = Rkhunter.doc(values)
    assert section.startswith("\n## Schadsoftware-Schutz\n\n")
    assert "**Pakete:** rkhunter" in section
    assert f"`{Rkhunter.RK_DEFAULT}`" in section
    assert "CRON_DAILY_RUN=true" in section
    assert "CRON_DB_UPDATE=true" in section
    assert "REPORT_EMAIL=admin@example.com" in section
    assert "**Timer/Cron:**" in section
    assert "/etc/cron.daily/rkhunter" in section
    assert "> Hinweis:" in section


def test_doc_lists_the_false_positive_exceptions() -> None:
    """doc() nennt jede Ausnahme aus rkhunter.conf mit Schlüssel und Wert."""
    section = Rkhunter.doc({"fqdn": "srv.example.com", "admin_mail": "a@example.com"})
    assert f"`{Rkhunter.RK_CONF}`" in section
    for key, value in Rkhunter._allow_entries():
        assert f"`{key}={value}`" in section


def test_doc_marks_missing_admin_mail_as_leer_default() -> None:
    """Fehlt admin_mail in values, erscheint der Platzhalter "(leer/Default)"."""
    section = Rkhunter.doc({})
    assert "REPORT_EMAIL=(leer/Default)" in section


def test_doc_never_leaks_secrets() -> None:
    """Ein Kunstgeheimnis in values erscheint weder als Name noch als Wert."""
    values = {
        "fqdn": "server.example.com",
        "admin_mail": "admin@example.com",
        "relay_password": "GEHEIM-X",
    }
    section = Rkhunter.doc(values)
    assert "GEHEIM-X" not in section
    assert "relay_password" not in section


# --- _test ---


def test_test_operation_ok_when_installed_and_scan_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test liefert 0, wenn Paket installiert ist und der Scan sauber ist."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    monkeypatch.setattr(mod, "_check_package_installed", lambda: True)
    monkeypatch.setattr(mod, "_run_scan", lambda: True)
    assert mod._test() == 0


def test_test_operation_fails_when_package_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test liefert 1, wenn das Paket fehlt, auch wenn der Scan (isoliert) ok wäre."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    monkeypatch.setattr(mod, "_check_package_installed", lambda: False)
    monkeypatch.setattr(mod, "_run_scan", lambda: True)
    assert mod._test() == 1


def test_test_operation_runs_scan_even_if_package_check_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """test läuft sammelnd: der Scan läuft auch nach fehlgeschlagener Paketprüfung."""
    mod = _make_rkhunter("server.example.com", "admin@example.com")
    monkeypatch.setattr(mod, "_check_package_installed", lambda: False)
    scan_called = False

    def fake_run_scan() -> bool:
        nonlocal scan_called
        scan_called = True
        return True

    monkeypatch.setattr(mod, "_run_scan", fake_run_scan)
    mod._test()
    assert scan_called is True
