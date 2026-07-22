"""Ende-zu-Ende-Integrationstest: main() über einen echten Modulprozess.

Spielt main() für beide Betriebsarten (install, check) vollständig durch:
echter Spawn-Subprozess des Moduls base (keine Klassen-Stubs im Auslieferungs-
modul), Konfigurationsanlage aus der Beispielvorlage, Logdatei-Anlage in einem
frischen tmp-Verzeichnis, Modulausführung bis zur Gesamtbilanz.

secure_base.modules.base bleibt dabei unverändert und frei von jeder Testlogik: keine
Umgebungsvariable, kein Laufzeit-Schalter. Die Systembefehle laufen über eine
Testunterklasse _TestBase(Base), die ausschließlich die dafür vorgesehenen
Klassenattribute (Programmpfade, Schreibziele, AppArmor-Aktionsklassen) auf
harmlose Platzhalter setzt. Diese Unterklasse liegt hier im Testbaum, wird
main() über eine eigens gebaute Modulauswahl (statt der echten REGISTRY)
untergeschoben und dabei echt gespawnt: Der Spawn-Kindprozess importiert
dieses Testmodul frisch und findet _TestBase über den regulären
Python-Import — dieselbe IPC-/Subprozess-Strecke wie im echten Betrieb.

Die Platzhalter-Skripte liegen unter einem festen, deterministischen
Verzeichnis (tempfile.gettempdir(), nicht pytest tmp_path): Die Klassen-
attribute von _TestBase sind im Quelltext dieser Datei fest verankert und
müssen in Eltern- und Kindprozess identisch aufgelöst werden, ein per Test
wechselnder tmp_path-Wert stünde dafür nicht rechtzeitig fest.
"""

import argparse
import shutil
import stat
import tempfile
from pathlib import Path

import pytest
import secure_base.installer as installer_module
from pifos.actions.apt_action import AptAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from secure_base.installer import main
from secure_base.module_spec import ModuleSpec
from secure_base.modules.base import SYSCTL_PARAMS, Base

_FQDN = "server.example.com"
_TIMEZONE = "Europe/Berlin"

_ARTIFACT_DIR = Path(tempfile.gettempdir()) / "secure-base-installer-e2e-test-artifacts"


def _true_bin() -> str:
    """Liefert den Pfad des Platzhalters /usr/bin/true (harmlos, immer 0)."""
    found = shutil.which("true")
    assert found is not None, "Platzhalter /usr/bin/true nicht gefunden"
    return found


_TRUE_BIN = _true_bin()


def _make_executable(path: Path, content: str) -> str:
    """Legt ein ausführbares Shell-Skript an und liefert seinen Pfad."""
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def _prepare_artifacts() -> None:
    """Legt die Platzhalter-Skripte im festen Testverzeichnis an (idempotent).

    Läuft sowohl beim Import dieses Testmoduls im Elternprozess als auch beim
    frischen Reimport im gespawnten Kindprozess — dort schadet das erneute,
    identische Anlegen nicht.
    """
    _ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    _make_executable(_ARTIFACT_DIR / "fake_hostname", f'#!/bin/sh\necho "{_FQDN}"\n')
    _make_executable(
        _ARTIFACT_DIR / "fake_timedatectl",
        "#!/bin/sh\n"
        'if [ "$1" = "show" ] && [ "$3" = "Timezone" ]; then\n'
        f'    echo "{_TIMEZONE}"\n'
        'elif [ "$1" = "show" ] && [ "$3" = "NTPSynchronized" ]; then\n'
        '    echo "yes"\n'
        "fi\n"
        "exit 0\n",
    )
    cases = "\n".join(
        f'        "{key}") echo "{value}" ;;' for key, value in SYSCTL_PARAMS
    )
    _make_executable(
        _ARTIFACT_DIR / "fake_sysctl",
        "#!/bin/sh\n"
        'if [ "$1" = "-n" ]; then\n'
        '    case "$2" in\n'
        f"{cases}\n"
        "    esac\n"
        "fi\n"
        "exit 0\n",
    )


_prepare_artifacts()


class _NoOpAptAction(AptAction):
    """Platzhalter für AptAction in Tests; wirkt nicht real."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


class _NoOpSystemdAction(SystemdServiceAction):
    """Platzhalter für SystemdServiceAction in Tests; wirkt nicht real."""

    def run(self) -> str:
        self.status = "finished"
        return self.status


class _TestBase(Base):
    """Testunterklasse von Base: echte Modullogik, Systembefehle auf Platzhalter.

    Überschreibt ausschließlich die dafür vorgesehenen Klassenattribute
    (Plan Abschnitt 2.12); secure_base.modules.base selbst bleibt unverändert.
    """

    HOSTNAMECTL = _TRUE_BIN
    HOSTNAME_BIN = str(_ARTIFACT_DIR / "fake_hostname")
    TIMEDATECTL = str(_ARTIFACT_DIR / "fake_timedatectl")
    SYSCTL_BIN = str(_ARTIFACT_DIR / "fake_sysctl")
    SYSTEMCTL_BIN = _TRUE_BIN
    SYSCTL_CONF = str(_ARTIFACT_DIR / "sysctl.conf")
    MODPROBE_CONF = str(_ARTIFACT_DIR / "modprobe.conf")
    APT_ACTION_CLS = _NoOpAptAction
    SYSTEMD_ACTION_CLS = _NoOpSystemdAction


def _write_example(tmp_path: Path, logfile: Path) -> Path:
    """Legt eine Beispielvorlage neben der (noch nicht vorhandenen) Zieldatei an.

    ensure_config sucht zuerst <Zielpfad>.example, bevor es auf die
    mitgelieferte Paketvorlage zurückfällt (_example_path).
    """
    conf_path = tmp_path / "secure-base.conf"
    example_path = tmp_path / "secure-base.conf.example"
    example_path.write_text(
        "[installer]\n"
        f"logfile = {logfile}\n"
        "loglevel = INFO\n"
        "modules_enabled = base\n"
        "optional_enabled =\n"
        "\n"
        "[general]\n"
        f"fqdn = {_FQDN}\n"
        "admin_mail =\n"
        "\n"
        "[base]\n"
        f"timezone = {_TIMEZONE}\n"
    )
    return conf_path


def _args(conf_path: Path, command: str) -> argparse.Namespace:
    return argparse.Namespace(
        conf=str(conf_path),
        modules=[],
        command=command,
        dry_run=False,
    )


@pytest.fixture(autouse=True)
def _use_test_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Schiebt main() die Testunterklasse statt der echten REGISTRY unter.

    Wirkt nur im Elternprozess (select_modules läuft dort); der gewählte
    module_cls (_TestBase) wird als Klassenobjekt an den Spawn-Subprozess
    übergeben und dort über den regulären Import gefunden.
    """
    spec = ModuleSpec("base", "Grundkonfiguration (Test)", _TestBase, optional=False)
    monkeypatch.setattr(installer_module, "select_modules", lambda named, cfg: [spec])
    monkeypatch.setattr("os.geteuid", lambda: 0)
    (_ARTIFACT_DIR / "sysctl.conf").unlink(missing_ok=True)
    (_ARTIFACT_DIR / "modprobe.conf").unlink(missing_ok=True)


def test_main_e2e_install_real_module_subprocess(tmp_path: Path) -> None:
    """main() install, echter base-Subprozess: Rückgabe 0, Logdatei geschrieben.

    Deckt genau die beiden früher gefundenen Defekte ab: fehlender Abschnitt
    [installer] nach Konfigurationsaufbau und fehlendes Logverzeichnis.
    """
    logfile = tmp_path / "var" / "log" / "secure-base" / "secure-base-installer.log"
    assert not logfile.parent.exists()
    conf_path = _write_example(tmp_path, logfile)

    result = main(_args(conf_path, "install"))

    assert result == 0
    assert logfile.exists()
    assert logfile.read_text().strip() != ""
    assert (_ARTIFACT_DIR / "sysctl.conf").exists()
    assert (_ARTIFACT_DIR / "modprobe.conf").exists()


def test_main_e2e_check_real_module_subprocess(tmp_path: Path) -> None:
    """main() check nach install, echter base-Subprozess: Rückgabe 0, Logdatei da.

    check läuft nach einem install-Lauf: Seit dem Drift-Schutz meldet check
    fehlende verwaltete Dateien als Abweichung (Rückgabe 1) — auf einem
    nie installierten Stand wäre 0 falsch.
    """
    logfile = tmp_path / "var" / "log" / "secure-base" / "secure-base-installer.log"
    assert not logfile.parent.exists()
    conf_path = _write_example(tmp_path, logfile)
    assert main(_args(conf_path, "install")) == 0

    result = main(_args(conf_path, "check"))

    assert result == 0
    assert logfile.exists()
    assert logfile.read_text().strip() != ""
