"""Unit-Tests für lsb.installer."""

import argparse
import logging
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock

import lsb.installer as installer_module
import pytest
from lsb.installer import LsbInstaller, main
from lsb.module_spec import ModuleSpec
from lsb.ui import StatusView
from pifos.config.config import Config
from pifos.errors import ConfigError
from pifos.ipc import IpcMessage, LogLevel, MessageKind


@pytest.fixture(autouse=True)
def _reset_shared_logger() -> Iterator[None]:
    """Sichert/stellt den über den Klassennamen geteilten Logger wieder her.

    PifosCaller.__init__ nutzt logging.getLogger(type(self).__name__); ohne
    Wiederherstellung würden configure_logging-Tests einander beeinflussen
    (Muster aus pifos test_caller.py).
    """
    logger = logging.getLogger("LsbInstaller")
    saved = (list(logger.handlers), logger.level, logger.propagate)
    yield
    for h in list(logger.handlers):
        logger.removeHandler(h)
    for h in saved[0]:
        logger.addHandler(h)
    logger.setLevel(saved[1])
    logger.propagate = saved[2]


# --- DEFAULT_CONF ---


def test_default_conf_is_anchored_at_package_root() -> None:
    """DEFAULT_CONF liegt am Paket-Root, unabhängig vom Arbeitsverzeichnis.

    installer.py liegt unter usr/lib/lsb/; der Paket-Root ist drei
    Verzeichnisebenen darüber (analog _ROOT in bin/lsb-installer).
    """
    package_root = Path(installer_module.__file__).resolve().parents[3]
    assert package_root / "etc" / "lsb" / "lsb.conf" == installer_module.DEFAULT_CONF
    assert installer_module.DEFAULT_CONF.is_absolute()


class _DummyModuleCls:
    """Platzhalter für eine Modulklasse; in diesen Tests nie instanziiert."""

    CONFIG: ClassVar[list[str]] = ["operation"]


class _StubInstaller:
    """Ersetzt LsbInstaller in main()-Tests; keine echten Subprozesse."""

    fail_names: ClassVar[set[str]] = set()
    last_instance: ClassVar["_StubInstaller | None"] = None

    def __init__(self, view: StatusView) -> None:
        self.view = view
        self.failures = 0
        self.run_calls: list[tuple[str, str]] = []
        _StubInstaller.last_instance = self

    def load_config(self, path: str, format: str) -> None:
        pass

    def configure_logging(self) -> None:
        pass

    def run_module(self, spec: ModuleSpec, config: Config, operation: str) -> bool:
        self.run_calls.append((spec.name, operation))
        ok = spec.name not in type(self).fail_names
        if not ok:
            self.failures += 1
        return ok

    def write_log(self, message: str, level: object) -> None:
        pass


def _base_args(**overrides: object) -> argparse.Namespace:
    """Baut ein argparse.Namespace mit den von main() erwarteten Feldern."""
    defaults: dict[str, object] = {
        "conf": None,
        "modules": [],
        "optional": False,
        "command": "install",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# --- LsbInstaller._drain ---


def test_drain_stops_at_result_and_returns_payload() -> None:
    """_drain sammelt Meldungen und stoppt beim RESULT mit dessen Payload."""
    view = MagicMock()
    caller = LsbInstaller(view)
    messages = [
        IpcMessage(
            kind=MessageKind.LOG, level=LogLevel.INFO, name="x", payload="Schritt 1"
        ),
        IpcMessage(kind=MessageKind.RESULT, level=None, name="start", payload=0),
    ]
    caller.receive_result = MagicMock(side_effect=messages)  # type: ignore[method-assign]
    caller.write_log = MagicMock()  # type: ignore[method-assign]

    result = caller._drain(MagicMock(), "base")

    assert result == 0
    view.set_status_line.assert_called_once_with("base", "Schritt 1", LogLevel.INFO)


def test_drain_returns_1_on_exception_message() -> None:
    """_drain liefert 1, wenn eine EXCEPTION-Meldung eintrifft."""
    caller = LsbInstaller(MagicMock())
    messages = [
        IpcMessage(
            kind=MessageKind.EXCEPTION,
            level=LogLevel.ERROR,
            name="Boom",
            payload="kaputt",
        ),
    ]
    caller.receive_result = MagicMock(side_effect=messages)  # type: ignore[method-assign]
    caller.write_log = MagicMock()  # type: ignore[method-assign]

    result = caller._drain(MagicMock(), "base")

    assert result == 1
    caller.write_log.assert_called_once_with("base: kaputt", LogLevel.ERROR)


# --- LsbInstaller.configure_logging ---


def test_configure_logging_raises_without_config() -> None:
    """Ohne geladene Konfiguration bricht configure_logging ab."""
    caller = LsbInstaller(MagicMock())
    with pytest.raises(RuntimeError, match="Keine Konfiguration"):
        caller.configure_logging()


def test_configure_logging_creates_missing_log_directory(tmp_path: Path) -> None:
    """Fehlt das Verzeichnis der Logdatei, legt configure_logging es an.

    Reproduziert den Servertest-Befund: /var/log/lsb existierte auf dem
    Zielsystem nicht, os.open in der Basisklasse scheiterte deshalb mit
    FileNotFoundError. configure_logging legt das Verzeichnis jetzt vorher an.
    """
    caller = LsbInstaller(MagicMock())
    logfile = tmp_path / "noch" / "nicht" / "vorhanden" / "installer.log"
    assert not logfile.parent.exists()
    cfg = Config()
    cfg.load_dict(
        {
            "installer": {"logfile": str(logfile), "loglevel": "INFO"},
            "general": {"fqdn": "server.example.com"},
        }
    )
    caller.config = cfg

    caller.configure_logging()

    assert logfile.parent.is_dir()
    assert logfile.exists()
    assert stat.S_IMODE(logfile.stat().st_mode) == 0o600


def test_configure_logging_hoists_installer_section(tmp_path: Path) -> None:
    """logfile/loglevel aus [installer] werden auf die oberste Ebene gehoben."""
    caller = LsbInstaller(MagicMock())
    logfile = tmp_path / "installer.log"
    cfg = Config()
    cfg.load_dict(
        {
            "installer": {"logfile": str(logfile), "loglevel": "INFO"},
            "general": {"fqdn": "server.example.com"},
        }
    )
    caller.config = cfg

    caller.configure_logging()

    assert logfile.exists()
    assert stat.S_IMODE(logfile.stat().st_mode) == 0o600


# --- LsbInstaller.on_module_failure / on_module_abort ---


def test_on_module_failure_increments_failures() -> None:
    """on_module_failure zählt die Gesamtbilanz hoch."""
    caller = LsbInstaller(MagicMock())
    caller.on_module_failure(MagicMock(), 1)
    assert caller.failures == 1


def test_on_module_abort_increments_failures() -> None:
    """on_module_abort zählt die Gesamtbilanz hoch."""
    caller = LsbInstaller(MagicMock())
    caller.on_module_abort(MagicMock())
    assert caller.failures == 1


# --- main() ---


def test_main_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ohne Systemrechte bricht main mit Exitcode 2 ab."""
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    assert main(_base_args()) == 2


def test_main_returns_2_when_config_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Kann keine Konfiguration erzeugt werden, bricht main mit Exitcode 2 ab."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: None)
    assert main(_base_args()) == 2


def test_main_returns_2_when_no_modules_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ohne ausgewählte Module bricht main mit Exitcode 2 ab."""
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: MagicMock())
    monkeypatch.setattr(installer_module, "select_modules", lambda named, opt, cfg: [])
    assert main(_base_args()) == 2


def test_main_runs_selected_modules_and_returns_0(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bei Erfolg aller ausgewählten Module liefert main 0."""
    _StubInstaller.fail_names = set()
    spec = ModuleSpec("base", "Grundkonfiguration", _DummyModuleCls, optional=False)  # type: ignore[arg-type]
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: MagicMock())
    monkeypatch.setattr(
        installer_module, "select_modules", lambda named, opt, cfg: [spec]
    )
    monkeypatch.setattr(
        installer_module, "module_config", lambda cfg, spec, op: MagicMock()
    )
    monkeypatch.setattr(installer_module, "LsbInstaller", _StubInstaller)

    result = main(_base_args())

    assert result == 0
    assert _StubInstaller.last_instance is not None
    assert _StubInstaller.last_instance.run_calls == [("base", "install")]


def test_main_returns_1_when_a_module_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Schlägt ein Modul fehl, liefert main 1."""
    _StubInstaller.fail_names = {"base"}
    spec = ModuleSpec("base", "Grundkonfiguration", _DummyModuleCls, optional=False)  # type: ignore[arg-type]
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: MagicMock())
    monkeypatch.setattr(
        installer_module, "select_modules", lambda named, opt, cfg: [spec]
    )
    monkeypatch.setattr(
        installer_module, "module_config", lambda cfg, spec, op: MagicMock()
    )
    monkeypatch.setattr(installer_module, "LsbInstaller", _StubInstaller)

    result = main(_base_args())

    assert result == 1


def test_main_install_aborts_after_first_failed_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """install stoppt nach dem ersten fehlgeschlagenen Modul den Gesamtlauf."""
    _StubInstaller.fail_names = {"base"}
    specs = [
        ModuleSpec("base", "Grundkonfiguration", _DummyModuleCls, optional=False),  # type: ignore[arg-type]
        ModuleSpec("ssh", "SSH-Härtung", _DummyModuleCls, optional=False),  # type: ignore[arg-type]
    ]
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: MagicMock())
    monkeypatch.setattr(
        installer_module, "select_modules", lambda named, opt, cfg: specs
    )
    monkeypatch.setattr(
        installer_module, "module_config", lambda cfg, spec, op: MagicMock()
    )
    monkeypatch.setattr(installer_module, "LsbInstaller", _StubInstaller)

    result = main(_base_args())

    assert result == 1
    assert _StubInstaller.last_instance is not None
    assert _StubInstaller.last_instance.run_calls == [("base", "install")]


def test_main_check_continues_after_failed_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """check läuft nach einem fehlgeschlagenen Modul weiter (Abweichungsliste)."""
    _StubInstaller.fail_names = {"base"}
    specs = [
        ModuleSpec("base", "Grundkonfiguration", _DummyModuleCls, optional=False),  # type: ignore[arg-type]
        ModuleSpec("ssh", "SSH-Härtung", _DummyModuleCls, optional=False),  # type: ignore[arg-type]
    ]
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: MagicMock())
    monkeypatch.setattr(
        installer_module, "select_modules", lambda named, opt, cfg: specs
    )
    monkeypatch.setattr(
        installer_module, "module_config", lambda cfg, spec, op: MagicMock()
    )
    monkeypatch.setattr(installer_module, "LsbInstaller", _StubInstaller)

    result = main(_base_args(command="check"))

    assert result == 1
    assert _StubInstaller.last_instance is not None
    assert _StubInstaller.last_instance.run_calls == [
        ("base", "check"),
        ("ssh", "check"),
    ]


def test_main_install_offers_ufw_enable_after_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nach erfolgreichem install-Lauf mit ufw wird die Aktivierung angeboten."""
    _StubInstaller.fail_names = set()
    spec = ModuleSpec("ufw", "Firewall", _DummyModuleCls, optional=False)  # type: ignore[arg-type]
    offered: list[bool] = []
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: MagicMock())
    monkeypatch.setattr(
        installer_module, "select_modules", lambda named, opt, cfg: [spec]
    )
    monkeypatch.setattr(
        installer_module, "module_config", lambda cfg, spec, op: MagicMock()
    )
    monkeypatch.setattr(installer_module, "LsbInstaller", _StubInstaller)
    monkeypatch.setattr(
        installer_module, "_offer_ufw_enable", lambda: offered.append(True)
    )

    result = main(_base_args())

    assert result == 0
    assert offered == [True]


def test_main_check_never_offers_ufw_enable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Im check-Lauf wird die Firewall-Aktivierung nie angeboten."""
    _StubInstaller.fail_names = set()
    spec = ModuleSpec("ufw", "Firewall", _DummyModuleCls, optional=False)  # type: ignore[arg-type]
    offered: list[bool] = []
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: MagicMock())
    monkeypatch.setattr(
        installer_module, "select_modules", lambda named, opt, cfg: [spec]
    )
    monkeypatch.setattr(
        installer_module, "module_config", lambda cfg, spec, op: MagicMock()
    )
    monkeypatch.setattr(installer_module, "LsbInstaller", _StubInstaller)
    monkeypatch.setattr(
        installer_module, "_offer_ufw_enable", lambda: offered.append(True)
    )

    result = main(_base_args(command="check"))

    assert result == 0
    assert offered == []


def test_main_returns_2_and_logs_when_ensure_config_raises_configerror(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """ConfigError aus ensure_config endet als knappe Meldung, nicht als Traceback.

    Reproduziert den Servertest-Befund auf main()-Ebene: Ein Fehler, der aus
    der Konfigurationsklärung kommt, darf nie als roher Traceback enden.
    """
    monkeypatch.setattr("os.geteuid", lambda: 0)

    def _raise(path: Path) -> Config | None:
        raise ConfigError("Vorlage kann nicht kopiert werden: kaputt")

    monkeypatch.setattr(installer_module, "ensure_config", _raise)

    with caplog.at_level(logging.ERROR, logger="lsb.installer"):
        result = main(_base_args())

    assert result == 2
    assert "Konfiguration ungültig" in caplog.text


def test_main_returns_2_and_logs_when_configure_logging_raises_configerror(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """ConfigError aus configure_logging (fehlender Abschnitt) endet sauber.

    Genau der gemeldete Ablauf: Die Konfiguration wurde geladen, aber
    configure_logging scheitert am fehlenden Abschnitt [installer].
    """
    spec = ModuleSpec("base", "Grundkonfiguration", _DummyModuleCls, optional=False)  # type: ignore[arg-type]
    monkeypatch.setattr("os.geteuid", lambda: 0)
    monkeypatch.setattr(installer_module, "ensure_config", lambda path: MagicMock())
    monkeypatch.setattr(
        installer_module, "select_modules", lambda named, opt, cfg: [spec]
    )

    class _FailingConfigureInstaller(_StubInstaller):
        def configure_logging(self) -> None:
            raise ConfigError("Konfigurationswert 'installer' nicht gefunden")

    monkeypatch.setattr(installer_module, "LsbInstaller", _FailingConfigureInstaller)

    with caplog.at_level(logging.ERROR, logger="lsb.installer"):
        result = main(_base_args())

    assert result == 2
    assert "Konfiguration ungültig" in caplog.text
