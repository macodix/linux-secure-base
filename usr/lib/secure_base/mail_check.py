"""Gemeinsamer Helfer: Zustellstatus einer Mail über das Mail-Log nachweisen.

Wertet /var/log/mail.log (oder ersatzweise journalctl) aus, um für einen
Empfänger den tatsächlichen Zustellstatus (status=sent/bounced/deferred)
nachzuweisen — eine leere Postfix-Queue allein ist kein Zustellungsnachweis,
da auch ein Bounce die Queue verlässt. Reine Auswertungslogik ohne
pifos-Modul-Abhängigkeit: Pfade, Programm und Versuchs-/Wartewerte sind
Parameter, Meldungstexte liefert diese Datei nur als Ergebniswert zurück —
das Senden der Meldung (send_message) bleibt Sache des aufrufenden Moduls.
Genutzt von secure_base.modules.postfix (Testmail-Zustellungsnachweis) und
secure_base.modules.users (TOTP-Einrichtungsmail).
"""

import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

# Felder status=/relay= aus gefilterten Mail-Log-Zeilen (reines Auslesen zur
# Auswertung, keine Eingabe in Kommandos).
_LOG_STATUS_RE = re.compile(r"status=(\w+)")
_LOG_RELAY_RE = re.compile(r"relay=([^,]+)")


@dataclass
class MailLogResult:
    """Ergebnis der Zustellstatus-Auswertung im Mail-Log für einen Empfänger.

    Attributes:
        ok: True nur bei nachgewiesenem status=sent.
        status: "sent", "bounced", "deferred" oder "unknown" (kein
            auswertbarer Logeintrag gefunden oder status-Feld unerwartet).
        detail: Bei "sent" der relay-Wert; bei "bounced"/"deferred" die
            auswertende Logzeile (getrimmt); bei "unknown" leer.
    """

    ok: bool
    status: str
    detail: str


def format_result(result: MailLogResult) -> str:
    """Baut einen Meldungstext aus einem MailLogResult.

    Args:
        result: Auszugebendes Ergebnis.

    Returns:
        Meldungstext ohne Geheimnisse; bei status "sent" mit relay-Angabe,
        bei "bounced"/"deferred" mit der auswertenden Logzeile, sonst der
        feste Text "Zustellstatus nicht nachweisbar".
    """
    if result.status == "sent":
        return f"status=sent, relay={result.detail}"
    if result.status in ("bounced", "deferred"):
        return f"unzustellbar: {result.detail}"
    return "Zustellstatus nicht nachweisbar"


def log_anchor() -> str:
    """Baut den Zeit-Anker vor dem Mailversand für die Log-Auswertung.

    Returns:
        Aktueller Zeitpunkt im journalctl-kompatiblen --since-Format.
    """
    return time.strftime("%Y-%m-%d %H:%M:%S")


def mail_log_lines(
    mail_log: str, journalctl_bin: str, anchor: str, timeout: float = 15.0
) -> list[str] | None:
    """Liest Mail-Log-Zeilen, bevorzugt aus mail_log, sonst per journalctl.

    Ist mail_log nicht lesbar oder nicht vorhanden, weicht die Funktion auf
    journalctl_bin aus (Einheiten postfix@- und postfix, ab anchor).

    Args:
        mail_log: Pfad der Mail-Logdatei (z. B. /var/log/mail.log).
        journalctl_bin: Pfad zum journalctl-Programm (Fallback).
        anchor: Log-Anker aus log_anchor, für den journalctl-Fallback.
        timeout: Zeitgrenze in Sekunden für den journalctl-Aufruf (SIC-05).

    Returns:
        Liste der Logzeilen, oder None, wenn keine der beiden Quellen
        lesbar ist.
    """
    try:
        content = Path(mail_log).read_text(encoding="utf-8", errors="replace")
        return content.splitlines()
    except OSError:
        pass
    try:
        result = subprocess.run(
            [
                journalctl_bin,
                "-u",
                "postfix@-",
                "-u",
                "postfix",
                "--since",
                anchor,
                "--no-pager",
            ],
            shell=False,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace").splitlines()


def evaluate_log_line(line: str) -> MailLogResult:
    """Bewertet eine gefilterte Mail-Log-Zeile anhand ihres status-Felds.

    Args:
        line: Log-Zeile, die den Empfänger betrifft (enthält "to=<...>").

    Returns:
        MailLogResult mit ok=True nur bei status=sent.
    """
    match = _LOG_STATUS_RE.search(line)
    status = match.group(1) if match else ""
    if status == "sent":
        relay_match = _LOG_RELAY_RE.search(line)
        relay = relay_match.group(1) if relay_match else "unbekannt"
        return MailLogResult(ok=True, status="sent", detail=relay)
    if status in ("bounced", "deferred"):
        return MailLogResult(ok=False, status=status, detail=line.strip())
    return MailLogResult(ok=False, status="unknown", detail="")


def check_delivery_log(
    recipient: str,
    anchor: str,
    mail_log: str,
    journalctl_bin: str,
    attempts: int,
    interval: float,
) -> MailLogResult:
    """Weist den Zustellstatus einer Mail an recipient im Mail-Log nach.

    Filtert die Log-Zeilen auf den Empfänger (to=<recipient>) und bewertet
    die letzte passende Zeile. Findet sich keine passende Zeile oder ist das
    Log nicht zugreifbar, gilt das als Fehlschlag (fail-closed) — kein
    stiller Erfolg aus einer leeren Queue oder einem fehlenden Logeintrag.

    Args:
        recipient: Empfängeradresse, nach der gefiltert wird (to=<...>).
        anchor: Log-Anker aus log_anchor, vor dem Mailversand erzeugt.
        mail_log: Pfad der Mail-Logdatei.
        journalctl_bin: Pfad zum journalctl-Programm (Fallback).
        attempts: Anzahl Leseversuche.
        interval: Wartezeit in Sekunden zwischen zwei Leseversuchen.

    Returns:
        MailLogResult mit ok=True nur bei nachgewiesenem status=sent.
    """
    needle = f"to=<{recipient}>"
    for attempt in range(1, attempts + 1):
        lines = mail_log_lines(mail_log, journalctl_bin, anchor)
        if lines is not None:
            matches = [line for line in lines if needle in line]
            if matches:
                return evaluate_log_line(matches[-1])
        if attempt < attempts:
            time.sleep(interval)
    return MailLogResult(ok=False, status="unknown", detail="")
