"""Unit-Tests für secure_base.distro."""

from pathlib import Path

import pytest
from pifos.errors import ModuleError
from secure_base.distro import DEBIAN, SUPPORTED_IDS, UBUNTU, distro_id, read_os_release

_UBUNTU_OS_RELEASE = """\
PRETTY_NAME="Ubuntu 26.04 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
ID=ubuntu
ID_LIKE=debian
VERSION_CODENAME=resolute
"""

_DEBIAN_OS_RELEASE = """\
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION_CODENAME=trixie
ID=debian
"""


def _os_release(tmp_path: Path, content: str) -> str:
    """Schreibt eine os-release-Datei und liefert ihren Pfad."""
    path = tmp_path / "os-release"
    path.write_text(content, encoding="utf-8")
    return str(path)


# --- read_os_release ---


def test_read_os_release_strips_quotes(tmp_path: Path) -> None:
    """Werte in Anführungszeichen werden ohne diese geliefert."""
    values = read_os_release(_os_release(tmp_path, _UBUNTU_OS_RELEASE))
    assert values["ID"] == "ubuntu"
    assert values["VERSION_ID"] == "26.04"
    assert values["PRETTY_NAME"] == "Ubuntu 26.04 LTS"
    assert values["VERSION_CODENAME"] == "resolute"


def test_read_os_release_skips_comments_and_blank_lines(tmp_path: Path) -> None:
    """Kommentar- und Leerzeilen erscheinen nicht in den Werten."""
    values = read_os_release(_os_release(tmp_path, "# Kommentar\n\nID=debian\n"))
    assert values == {"ID": "debian"}


def test_read_os_release_raises_when_file_missing(tmp_path: Path) -> None:
    """Eine fehlende os-release-Datei ist ein Fehler, kein leeres Ergebnis."""
    with pytest.raises(ModuleError, match="nicht lesbar"):
        read_os_release(str(tmp_path / "fehlt"))


# --- distro_id ---


def test_distro_id_reads_ubuntu(tmp_path: Path) -> None:
    """Ubuntu wird an der ID erkannt."""
    assert distro_id(_os_release(tmp_path, _UBUNTU_OS_RELEASE)) == UBUNTU


def test_distro_id_reads_debian(tmp_path: Path) -> None:
    """Debian wird an der ID erkannt."""
    assert distro_id(_os_release(tmp_path, _DEBIAN_OS_RELEASE)) == DEBIAN


def test_distro_id_rejects_unsupported_distro(tmp_path: Path) -> None:
    """Eine fremde Distribution wird abgewiesen, nicht als Debian behandelt."""
    with pytest.raises(ModuleError, match="wird nicht unterstützt"):
        distro_id(_os_release(tmp_path, 'ID=fedora\nID_LIKE="rhel fedora"\n'))


def test_distro_id_rejects_missing_id(tmp_path: Path) -> None:
    """Eine os-release ohne ID wird abgewiesen."""
    with pytest.raises(ModuleError, match="nennt keine ID"):
        distro_id(_os_release(tmp_path, 'NAME="Irgendwas"\n'))


def test_supported_ids_are_ubuntu_and_debian() -> None:
    """Unterstützt sind genau Ubuntu und Debian."""
    assert SUPPORTED_IDS == (UBUNTU, DEBIAN)
