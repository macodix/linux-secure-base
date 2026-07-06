"""Unit-Tests für secure_base.modules.ufw."""

from unittest.mock import MagicMock

import pytest
from pifos.errors import ModuleError
from pifos.ipc import LogLevel
from secure_base.modules.ufw import Ufw, _parse_port_list


def _make_ufw(in_tcp: str, out_tcp: str, out_udp: str) -> Ufw:
    """Baut ein Ufw-Modul mit gesetzten Werten, ohne Prozess/IPC."""
    mod = Ufw(conn=MagicMock(), loglevel=LogLevel.INFO)
    mod.operation = "install"
    mod.allow_in_tcp = in_tcp
    mod.allow_out_tcp = out_tcp
    mod.allow_out_udp = out_udp
    return mod


# --- CONFIG ---


def test_ufw_config_declares_operation_and_port_lists() -> None:
    """CONFIG nennt operation und die drei Portlisten-Schlüssel."""
    assert Ufw.CONFIG == [
        "operation",
        "allow_in_tcp",
        "allow_out_tcp",
        "allow_out_udp",
    ]


# --- _parse_port_list ---


def test_parse_port_list_empty_string_returns_empty_list() -> None:
    """Eine leere Zeichenkette ergibt eine leere Liste, kein Fehler."""
    assert _parse_port_list("", "allow_out_tcp") == []


def test_parse_port_list_sorts_and_converts_to_int() -> None:
    """Die Liste wird nach int sortiert und als int-Werte geliefert."""
    assert _parse_port_list("80,22,443", "allow_in_tcp") == [22, 80, 443]


def test_parse_port_list_strips_whitespace() -> None:
    """Leerzeichen um die Einträge werden entfernt."""
    assert _parse_port_list(" 22 , 80 ", "allow_in_tcp") == [22, 80]


def test_parse_port_list_rejects_non_numeric_entry() -> None:
    """Ein nicht-numerischer Eintrag erzeugt ModuleError."""
    with pytest.raises(ModuleError, match="ungültigen Port"):
        _parse_port_list("22,abc", "allow_in_tcp")


def test_parse_port_list_rejects_out_of_range_low() -> None:
    """Port 0 liegt außerhalb des gültigen Bereichs."""
    with pytest.raises(ModuleError, match="ungültigen Port"):
        _parse_port_list("0", "allow_in_tcp")


def test_parse_port_list_rejects_out_of_range_high() -> None:
    """Port 65536 liegt außerhalb des gültigen Bereichs."""
    with pytest.raises(ModuleError, match="ungültigen Port"):
        _parse_port_list("65536", "allow_in_tcp")


def test_parse_port_list_accepts_boundary_values() -> None:
    """Die Grenzwerte 1 und 65535 sind gültig."""
    assert _parse_port_list("1,65535", "allow_in_tcp") == [1, 65535]


# --- _validate ---


def test_validate_accepts_valid_values() -> None:
    """Gültige Portlisten mit SSH-Port lösen keine Ausnahme aus."""
    mod = _make_ufw("22,80", "443", "53")
    mod._validate()
    assert mod._in_tcp == [22, 80]
    assert mod._out_tcp == [443]
    assert mod._out_udp == [53]


def test_validate_rejects_invalid_port() -> None:
    """Ein ungültiger Port in einer der Listen erzeugt ModuleError."""
    mod = _make_ufw("22,70000", "443", "53")
    with pytest.raises(ModuleError, match="ungültigen Port"):
        mod._validate()


def test_validate_rejects_missing_ssh_port() -> None:
    """Fehlt Port 22 unter allow_in_tcp, erzeugt _validate ModuleError."""
    mod = _make_ufw("80", "443", "53")
    with pytest.raises(ModuleError, match="22"):
        mod._validate()


# --- _require_ssh_port_or_die ---


def test_require_ssh_port_or_die_accepts_present_port() -> None:
    """Ist SSH_PORT enthalten, wirft die Methode nichts."""
    mod = _make_ufw("22", "", "")
    mod._require_ssh_port_or_die([22, 80])


def test_require_ssh_port_or_die_rejects_missing_port() -> None:
    """Fehlt SSH_PORT, erzeugt die Methode ModuleError."""
    mod = _make_ufw("80", "", "")
    with pytest.raises(ModuleError, match="SSH-Verwaltungszugang"):
        mod._require_ssh_port_or_die([80])


# --- _expected_rules ---


def test_expected_rules_covers_all_three_lists() -> None:
    """_expected_rules baut je einen Eintrag pro konfiguriertem Port."""
    mod = _make_ufw("22,80", "443", "53")
    mod._validate()
    expected = sorted(
        [
            "ufw allow 22/tcp",
            "ufw allow 80/tcp",
            "ufw allow out 443/tcp",
            "ufw allow out 53/udp",
        ]
    )
    assert mod._expected_rules() == expected


def test_expected_rules_empty_out_lists() -> None:
    """Leere ausgehende Listen erzeugen keine ausgehenden Regelzeilen."""
    mod = _make_ufw("22", "", "")
    mod._validate()
    assert mod._expected_rules() == ["ufw allow 22/tcp"]


# --- start: Dispatch nach Betriebsart ---


def test_start_uninstall_skips_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """uninstall ruft _validate() nicht auf — ein ungültiger Port bricht nicht ab."""
    mod = _make_ufw("70000", "", "")  # ungültig, würde _validate() zum Absturz bringen
    mod.operation = "uninstall"
    called: list[bool] = []

    def _fake_uninstall(self: Ufw) -> int:
        called.append(True)
        return 0

    monkeypatch.setattr(Ufw, "_uninstall", _fake_uninstall)

    assert mod.start() == 0
    assert called == [True]


def test_start_test_still_validates_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """test validiert die Konfiguration wie install/check vor der Ausführung."""
    mod = _make_ufw("70000", "", "")  # ungültig
    mod.operation = "test"

    with pytest.raises(ModuleError, match="ungültigen Port"):
        mod.start()


def test_start_test_dispatches_to_test_method(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bei gültiger Konfiguration ruft start() _test() auf."""
    mod = _make_ufw("22", "", "")
    mod.operation = "test"
    called: list[bool] = []

    def _fake_test(self: Ufw) -> int:
        called.append(True)
        return 0

    monkeypatch.setattr(Ufw, "_test", _fake_test)

    assert mod.start() == 0
    assert called == [True]
