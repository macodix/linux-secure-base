"""Feststellung der laufenden Distribution aus /etc/os-release.

Die Module fragen hier nur ab, welche Distribution läuft. Was das jeweils
bedeutet, entscheidet jedes Modul selbst — dieses Modul kennt keine
Modul-Interna.

Unterstützt sind Ubuntu und Debian. Auf jeder anderen Distribution bricht
die Abfrage mit ModuleError ab, statt einen der beiden Stände zu unterstellen.
"""

from pathlib import Path
from typing import Final

from pifos.errors import ModuleError

OS_RELEASE_FILE: Final[str] = "/etc/os-release"

UBUNTU: Final[str] = "ubuntu"
DEBIAN: Final[str] = "debian"

SUPPORTED_IDS: Final[tuple[str, ...]] = (UBUNTU, DEBIAN)


def read_os_release(path: str = OS_RELEASE_FILE) -> dict[str, str]:
    """Liest /etc/os-release als Schlüssel-Wert-Paare.

    Das Format ist in os-release(5) festgelegt: je Zeile KEY=VALUE, der Wert
    wahlweise in Anführungszeichen. Leerzeilen und Kommentarzeilen entfallen.

    Args:
        path: Zu lesende Datei.

    Returns:
        Alle Schlüssel-Wert-Paare der Datei.

    Raises:
        ModuleError: Wenn die Datei nicht lesbar ist.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as err:
        raise ModuleError(f"{path} nicht lesbar: {err}") from err
    values: dict[str, str] = {}
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#") or "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        values[key.strip()] = value.strip().strip("\"'")
    return values


def distro_id(path: str = OS_RELEASE_FILE) -> str:
    """Liefert die Kennung der laufenden Distribution.

    Args:
        path: Zu lesende os-release-Datei.

    Returns:
        "ubuntu" oder "debian".

    Raises:
        ModuleError: Wenn os-release keine ID nennt oder die Distribution
            nicht unterstützt wird.
    """
    current = read_os_release(path).get("ID", "").lower()
    if not current:
        raise ModuleError(f"{path} nennt keine ID")
    if current not in SUPPORTED_IDS:
        raise ModuleError(
            f"Distribution {current!r} wird nicht unterstützt"
            f" (unterstützt: {', '.join(SUPPORTED_IDS)})"
        )
    return current
