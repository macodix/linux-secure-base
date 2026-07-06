"""Unit-Tests für secure_base.mail_check."""

import re
import time
from pathlib import Path

import pytest
from secure_base import mail_check
from secure_base.mail_check import MailLogResult

_SENT_LINE = (
    "Jul  6 10:00:00 host postfix/smtp[123]: ABC123: to=<admin@example.com>, "
    "relay=smtp.example.com[1.2.3.4]:587, delay=0.1, delays=0/0/0/0.1, dsn=2.0.0, "
    "status=sent (250 2.0.0 Ok: queued as 12345)"
)
_BOUNCED_LINE = (
    "Jul  6 10:00:00 host postfix/smtp[123]: ABC123: to=<admin@example.com>, "
    "relay=none, delay=0.1, delays=0/0/0/0.1, dsn=5.1.2, "
    "status=bounced (host smtp.example.com said: 550 5.1.2 unknown recipient)"
)
_DEFERRED_LINE = (
    "Jul  6 10:00:00 host postfix/smtp[123]: ABC123: to=<admin@example.com>, "
    "relay=none, delay=0.1, status=deferred (connection timed out)"
)


def _write_mail_log(tmp_path: Path, status_line: str) -> str:
    """Legt eine Mail-Log-Datei mit genau einer Statuszeile an und liefert den Pfad."""
    mail_log = tmp_path / "mail.log"
    mail_log.write_text(status_line + "\n")
    return str(mail_log)


def _write_script(tmp_path: Path, name: str, body: str) -> str:
    """Legt ein ausführbares Fake-Programm unter tmp_path an und liefert den Pfad."""
    script = tmp_path / name
    script.write_text(f"#!/usr/bin/env python3\n{body}")
    script.chmod(0o755)
    return str(script)


# --- log_anchor ---


def test_log_anchor_matches_since_format() -> None:
    """log_anchor liefert einen journalctl-kompatiblen --since-Zeitstempel."""
    anchor = mail_check.log_anchor()
    assert re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", anchor)


# --- mail_log_lines ---


def test_mail_log_lines_reads_mail_log_file(tmp_path: Path) -> None:
    """Ist mail_log lesbar, liest mail_log_lines daraus, ohne journalctl."""
    mail_log = _write_mail_log(tmp_path, _SENT_LINE)
    assert mail_check.mail_log_lines(mail_log, "/bin/false", "2026-01-01 00:00:00") == [
        _SENT_LINE
    ]


def test_mail_log_lines_falls_back_to_journalctl_when_file_missing(
    tmp_path: Path,
) -> None:
    """Fehlt mail_log, weicht mail_log_lines auf journalctl_bin aus."""
    journalctl = _write_script(tmp_path, "fake-journalctl", f"print({_SENT_LINE!r})\n")
    missing = str(tmp_path / "missing-mail.log")
    assert mail_check.mail_log_lines(missing, journalctl, "2026-01-01 00:00:00") == [
        _SENT_LINE
    ]


def test_mail_log_lines_returns_none_when_journalctl_fails(tmp_path: Path) -> None:
    """Schlägt auch journalctl fehl, liefert mail_log_lines None."""
    missing = str(tmp_path / "missing-mail.log")
    assert (
        mail_check.mail_log_lines(missing, "/bin/false", "2026-01-01 00:00:00") is None
    )


def test_mail_log_lines_returns_none_when_journalctl_missing_program(
    tmp_path: Path,
) -> None:
    """Ein nicht startbares journalctl-Programm liefert mail_log_lines None."""
    missing = str(tmp_path / "missing-mail.log")
    result = mail_check.mail_log_lines(
        missing, "/no/such/journalctl-binary", "2026-01-01 00:00:00"
    )
    assert result is None


# --- evaluate_log_line ---


def test_evaluate_log_line_sent_returns_ok_with_relay() -> None:
    """Eine status=sent-Zeile liefert ok=True mit dem relay-Wert als detail."""
    result = mail_check.evaluate_log_line(_SENT_LINE)
    assert result == MailLogResult(
        ok=True, status="sent", detail="smtp.example.com[1.2.3.4]:587"
    )


def test_evaluate_log_line_bounced_returns_not_ok_with_line() -> None:
    """Eine status=bounced-Zeile liefert ok=False mit der Zeile als detail."""
    result = mail_check.evaluate_log_line(_BOUNCED_LINE)
    assert result.ok is False
    assert result.status == "bounced"
    assert "unknown recipient" in result.detail


def test_evaluate_log_line_deferred_returns_not_ok_with_line() -> None:
    """Eine status=deferred-Zeile liefert ok=False mit der Zeile als detail."""
    result = mail_check.evaluate_log_line(_DEFERRED_LINE)
    assert result.ok is False
    assert result.status == "deferred"
    assert "connection timed out" in result.detail


def test_evaluate_log_line_unknown_status_returns_unknown() -> None:
    """Eine Zeile ohne erkennbares status-Feld liefert status='unknown'."""
    result = mail_check.evaluate_log_line("keine passende Zeile")
    assert result == MailLogResult(ok=False, status="unknown", detail="")


# --- format_result ---


def test_format_result_sent_includes_relay() -> None:
    """format_result baut aus status=sent den relay-Text."""
    result = MailLogResult(ok=True, status="sent", detail="smtp.example.com")
    assert mail_check.format_result(result) == "status=sent, relay=smtp.example.com"


def test_format_result_bounced_includes_detail() -> None:
    """format_result baut aus status=bounced den Zeilentext."""
    result = MailLogResult(ok=False, status="bounced", detail="550 unknown recipient")
    assert mail_check.format_result(result) == "unzustellbar: 550 unknown recipient"


def test_format_result_unknown_is_fixed_text() -> None:
    """format_result liefert für status='unknown' den festen Text."""
    result = MailLogResult(ok=False, status="unknown", detail="")
    assert mail_check.format_result(result) == "Zustellstatus nicht nachweisbar"


# --- check_delivery_log ---


def test_check_delivery_log_returns_ok_when_sent(tmp_path: Path) -> None:
    """Findet sich eine status=sent-Zeile für den Empfänger, liefert
    check_delivery_log ok=True."""
    mail_log = _write_mail_log(tmp_path, _SENT_LINE)
    result = mail_check.check_delivery_log(
        recipient="admin@example.com",
        anchor="2026-01-01 00:00:00",
        mail_log=mail_log,
        journalctl_bin="/bin/false",
        attempts=1,
        interval=0,
    )
    assert result.ok is True
    assert result.status == "sent"


def test_check_delivery_log_fails_when_no_matching_line(tmp_path: Path) -> None:
    """Findet sich keine passende Zeile, liefert check_delivery_log
    fail-closed ok=False."""
    mail_log = _write_mail_log(tmp_path, "keine passende Zeile")
    result = mail_check.check_delivery_log(
        recipient="admin@example.com",
        anchor="2026-01-01 00:00:00",
        mail_log=mail_log,
        journalctl_bin="/bin/false",
        attempts=1,
        interval=0,
    )
    assert result.ok is False
    assert result.status == "unknown"


def test_check_delivery_log_ignores_lines_for_other_recipients(tmp_path: Path) -> None:
    """Eine Log-Zeile für einen anderen Empfänger zählt nicht als Beleg."""
    other_line = _SENT_LINE.replace(
        "to=<admin@example.com>", "to=<someone-else@example.com>"
    )
    mail_log = _write_mail_log(tmp_path, other_line)
    result = mail_check.check_delivery_log(
        recipient="admin@example.com",
        anchor="2026-01-01 00:00:00",
        mail_log=mail_log,
        journalctl_bin="/bin/false",
        attempts=1,
        interval=0,
    )
    assert result.ok is False
    assert result.status == "unknown"


def test_check_delivery_log_retries_until_line_appears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Erscheint die passende Zeile erst nach dem ersten Versuch, liefert
    check_delivery_log dennoch ok=True."""
    mail_log = tmp_path / "mail.log"
    mail_log.write_text("keine passende Zeile\n")
    calls = {"n": 0}
    real_sleep = time.sleep

    def fake_sleep(seconds: float) -> None:
        calls["n"] += 1
        mail_log.write_text(_SENT_LINE + "\n")
        real_sleep(0)

    monkeypatch.setattr(time, "sleep", fake_sleep)
    result = mail_check.check_delivery_log(
        recipient="admin@example.com",
        anchor="2026-01-01 00:00:00",
        mail_log=str(mail_log),
        journalctl_bin="/bin/false",
        attempts=2,
        interval=0,
    )
    assert result.ok is True
    assert calls["n"] == 1
