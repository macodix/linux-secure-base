"""Modul logging — Protokollierung und Auditing.

Härtet journald (persistentes Journal mit Größen-/Zeitgrenze), stellt rsyslog
als Schreiber der Protokolldateien sicher, richtet den täglichen Bericht per
Mail ein, schreibt die logrotate-Konfig für das secure-base-Logfile und
aktiviert auditd mit sudo-Protokollierung und Audit-Regeln nach konv-system.md
Abschnitt 3.4. Betriebsart über den Schlüssel operation.

rsyslog gehört nicht auf jeder Distribution zur Standardinstallation — unter
Debian 13 hat das Paket nur Priorität "optional". Ohne rsyslog gibt es keine
Protokolldateien unter /var/log (auth.log, syslog, mail.log), und der
angehängte Logwatch-Bericht bliebe weitgehend leer. Das Modul installiert es
deshalb; ist es bereits vorhanden, ändert der Schritt nichts.

Die beiden Audit-Regeln auf die sudoers-Pfade richtet das Modul nur ein,
wenn sudo auf dem System vorhanden ist. Administriert wird über su; sudo
gehört nicht auf jeder Distribution zur Standardinstallation. Eine eigene
sudo-Logdatei über "Defaults logfile" in sudoers.d gibt es nicht mehr:
Ubuntu liefert sudo als sudo-rs aus, das diese Direktive nicht kennt — ein
solches Drop-in ist dort ein Parse-Fehler, mit dem sudo jeden Aufruf
verweigert. sudo-Aufrufe protokollieren beide sudo-Varianten ohnehin ins
Syslog/Journal.

Die Anmeldehistorie führt wtmpdb (/var/log/wtmp.db, lesbar mit last); das Modul
installiert die Pakete mit. Die frühere Datei /var/log/lastlog gibt es nicht
mehr — pam_lastlog ist aus libpam-modules entfernt. Die Audit-Regel überwacht
deshalb die Datenbank, die das System tatsächlich führt (wtmpdb oder lastlog2),
und entfällt, wenn es keine führt.

Der Tagesbericht besteht aus einer Zusammenfassung im Mailtext und dem
vollständigen Logwatch-Bericht als Anhang. Die Zusammenfassung entsteht aus
dem Journal und nennt die sicherheitsrelevanten Vorgänge des Tages —
erfolgreiche Anmeldungen, Zwei-Faktor-Vorgänge, Rechteerhöhungen,
fehlgeschlagene Dienste. Der mitgelieferte Cron-Lauf von logwatch, der den
vollständigen Bericht in den Mailtext schreibt, wird dafür stillgelegt.
"""

import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.permissions_action import PermissionsAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

_Step = Callable[[], int]

# fqdn-Zeichensatz für die Mailfrom-Ableitung (bewusst locker — die
# strenge Rechnername-Prüfung ist Aufgabe des Moduls base).
_FQDN_CHARS_RE = re.compile(r"^[A-Za-z0-9.-]+$")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# systemd-Größenmaß (journald SystemMaxUse), z. B. "500M", "1G".
_JOURNALD_SIZE_RE = re.compile(r"^[0-9]+[KMGT]?$")

# systemd-Zeitspanne (journald MaxRetentionSec), z. B. "4week", "3month".
_JOURNALD_RETENTION_RE = re.compile(r"^[0-9]+(s|min|h|day|week|month|year)$")

# Soll-Regeln nach konv-system.md Abschnitt 3.4 b. Feste Regeln — sie
# überwachen Pfade, die auf jedem System vorliegen.
IDENTITY_AUDIT_RULES: tuple[str, ...] = (
    "-w /etc/passwd -p wa -k identity",
    "-w /etc/shadow -p wa -k identity",
    "-w /etc/group -p wa -k identity",
)

PRIV_ESC_AUDIT_RULE: str = "-w /usr/bin/su -p x -k priv_esc"

CONFIG_AUDIT_RULES: tuple[str, ...] = (
    "-w /etc/ssh/sshd_config -p wa -k sshd",
    "-w /etc/pam.d -p wa -k pam",
    "-w /etc/ufw -p wa -k firewall",
    "-w /etc/audit -p wa -k auditconfig",
)

# Immutable — steht als letzte Regel.
IMMUTABLE_AUDIT_RULE: str = "-e 2"

# Regeln, die einen sudoers-Pfad überwachen. /etc/sudoers.d ist ein
# Verzeichnis; auditctl weist eine Überwachung eines nicht existierenden
# Verzeichnisses ab, das Regelwerk würde dann mit Fehler geladen, statt die
# übrigen Regeln zu setzen. (Bei einer Datei genügt das Elternverzeichnis —
# die Regel auf /etc/sudoers allein würde also laden, aber nie greifen.)
SUDO_AUDIT_RULES: tuple[str, ...] = (
    "-w /etc/sudoers -p wa -k scope",
    "-w /etc/sudoers.d -p wa -k scope",
)

# Überwachung der Anmeldehistorie. /var/log/lastlog gibt es nicht mehr:
# pam_lastlog ist aus libpam-modules entfernt, unter Debian 13 wie unter
# Ubuntu 26.04. Eine Regel darauf würde zwar laden (das Elternverzeichnis
# /var/log existiert), aber nie greifen — eine stille Lücke.
#
# Überwacht wird deshalb die Datenbank, die das System tatsächlich führt. Je
# Eintrag: Vorbedingung (ein Pfad aus dem jeweiligen Paket) und die Regel, die
# gilt, wenn die Vorbedingung erfüllt ist.
LOGIN_AUDIT_RULES: tuple[tuple[str, str], ...] = (
    # wtmpdb — unter Debian 13 die Standard-Anmeldehistorie (Paketpriorität
    # "standard"), sshd schreibt direkt hinein. Die Datenbank liegt unter
    # /var/log/wtmp.db; /var/lib/wtmpdb/wtmp.db ist nur ein Symlink darauf und
    # als Überwachungsziel deshalb ungeeignet.
    ("/usr/bin/wtmpdb", "-w /var/log/wtmp.db -p wa -k logins"),
    # lastlog2 — Nachfolger von /var/log/lastlog. Das Verzeichnis legt das
    # Paket an; es ist zugleich Ladevoraussetzung der Regel, denn die Datenbank
    # entsteht erst bei der ersten Anmeldung.
    ("/var/lib/lastlog", "-w /var/lib/lastlog/lastlog2.db -p wa -k logins"),
)


def _audit_rules(sudo_present: bool, login_rules: tuple[str, ...]) -> tuple[str, ...]:
    """Setzt die Soll-Regeln für das vorliegende System zusammen.

    Args:
        sudo_present: Ob sudo auf dem System vorhanden ist.
        login_rules: Regeln zur Anmeldehistorie, deren Vorbedingung erfüllt ist.

    Returns:
        Alle Soll-Regeln in fester Reihenfolge, "-e 2" als letzte.
    """
    return (
        *IDENTITY_AUDIT_RULES,
        *login_rules,
        PRIV_ESC_AUDIT_RULE,
        *(SUDO_AUDIT_RULES if sudo_present else ()),
        *CONFIG_AUDIT_RULES,
        IMMUTABLE_AUDIT_RULE,
    )


def _audit_rules_content(sudo_present: bool, login_rules: tuple[str, ...]) -> str:
    """Baut den Inhalt der Audit-Regeldatei.

    Args:
        sudo_present: Ob sudo auf dem System vorhanden ist.
        login_rules: Regeln zur Anmeldehistorie, deren Vorbedingung erfüllt ist.

    Returns:
        Regeldatei-Inhalt, eine Regel je Zeile.
    """
    return "".join(f"{rule}\n" for rule in _audit_rules(sudo_present, login_rules))


def _logrotate_content() -> str:
    """Baut den Inhalt der logrotate-Konfiguration für das secure-base-Logfile."""
    return (
        "/var/log/secure-base/secure-base.log {\n"
        "    weekly\n"
        "    size 5M\n"
        "    compress\n"
        "    rotate 8\n"
        "    missingok\n"
        "    notifempty\n"
        "    copytruncate\n"
        "}\n"
    )


# Berichts-Skript: Zusammenfassung im Mailtext, vollständiger Logwatch-Bericht
# als Anhang. Es ersetzt den mitgelieferten Cron-Lauf von logwatch, der den
# vollständigen Bericht direkt in den Mailtext schreibt.
#
# Die Zusammenfassung entsteht aus dem Journal, nicht aus dem Logwatch-Text:
# die Meldungsmuster von sshd, sudo und pam sind stabil, die Abschnitts-
# Formatierung von Logwatch ist es nicht.
#
# Die Mail wird als MIME-Nachricht selbst gebaut und über sendmail zugestellt.
# Das Postfix-Relay steht durch das Modul postfix fest zur Verfügung; ein
# Anhang über den mail-Befehl hinge dagegen an dessen Optionsumfang, der je
# nach mailx-Herkunft abweicht.
_REPORT_SCRIPT_TEMPLATE = """#!/usr/bin/env bash
set -euo pipefail

# Von secure-base/logging angelegt (wird bei erneutem Installer-Lauf überschrieben).
# cron-Umgebung ist spartanisch — PATH explizit setzen.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ADMIN_MAIL="{admin_mail}"
MAIL_FROM="{mail_from}"
FQDN="{fqdn}"

REPORT="$(mktemp)"
AUTH="$(mktemp)"
BODY="$(mktemp)"
trap 'rm -f "$REPORT" "$AUTH" "$BODY"' EXIT
chmod 0600 "$REPORT" "$AUTH" "$BODY"

DAY="$(date -d yesterday +%F)"
SINCE="$DAY 00:00:00"
UNTIL="$(date +%F) 00:00:00"

# Vollständiger Logwatch-Bericht — Anhang der Mail, nicht Mailtext.
"{logwatch_bin}" --output file --format text --range yesterday --filename "$REPORT"

# Authentifizierungsmeldungen des Berichtstags: Journal-Facility auth (4) und
# authpriv (10) — dieselbe Quelle, aus der auch auth.log gespeist wird.
"{journalctl_bin}" --since "$SINCE" --until "$UNTIL" --no-pager -o short-iso \\
    SYSLOG_FACILITY=4 + SYSLOG_FACILITY=10 >"$AUTH"

# Schreibt einen Abschnitt: $1 Überschrift, Inhalt von stdin. Ohne Inhalt
# erscheint "(keine)" — eine Überschrift ohne Zeilen wäre missverständlich.
abschnitt() {{
    local titel="$1"
    local inhalt
    inhalt="$(cat)"
    printf '%s\\n' "$titel"
    if [ -z "$inhalt" ]; then
        printf '  (keine)\\n\\n'
        return 0
    fi
    printf '%s\\n' "$inhalt" | sed 's/^/  /'
    printf '\\n'
}}

# Durchsucht die Authentifizierungsmeldungen; kein Treffer ist kein Fehler
# (grep endet dann mit 1, was unter "set -o pipefail" den Lauf abbräche).
auth_suche() {{
    grep -E "$1" "$AUTH" || true
}}

# Kürzt eine Journal-Zeile: Zeitstempel bleibt, der Rechnername fällt weg.
kurz() {{
    awk '{{ $2 = ""; sub("  ", " "); print }}'
}}

BANS="$("{journalctl_bin}" -u fail2ban --since "$SINCE" --until "$UNTIL" \\
    --no-pager -q | grep -c ' Ban ' || true)"
ABGEWIESEN="$(grep -c 'invalid user' "$AUTH" || true)"
ABGEWIESEN_IPS="$(grep 'invalid user' "$AUTH" \\
    | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | sort -u | wc -l || true)"
FEHLER="$("{journalctl_bin}" --since "$SINCE" --until "$UNTIL" -p err \\
    --no-pager -q -o short-iso || true)"

{{
    printf 'Tagesbericht %s — %s\\n\\n' "$DAY" "$FQDN"
    printf 'Der vollständige Logwatch-Bericht liegt dieser Mail als Datei bei.\\n\\n'

    auth_suche 'sshd\\[[0-9]+\\]: Accepted ' | kurz \\
        | abschnitt 'Erfolgreiche SSH-Anmeldungen'

    auth_suche 'pam_google_auth' | kurz \\
        | abschnitt 'Zwei-Faktor (TOTP)'

    auth_suche 'Failed [^ ]+ for ' | awk '!/invalid user/' | kurz \\
        | abschnitt 'Fehlgeschlagene Anmeldungen bekannter Benutzer'

    auth_suche 'sudo:.*(COMMAND=|authentication failure)|su\\[[0-9]+\\]: .*opened' \\
        | kurz | abschnitt 'Rechteerhöhung (sudo, su)'

    printf 'Sperren durch fail2ban\\n  %s\\n\\n' "$BANS"

    printf 'Abgewiesene Anmeldeversuche (unbekannte Benutzer)\\n'
    printf '  %s Versuche von %s Adressen — Einzelheiten im Anhang\\n\\n' \\
        "$ABGEWIESEN" "$ABGEWIESEN_IPS"

    "{systemctl_bin}" list-units --state=failed --no-legend --plain \\
        | abschnitt 'Fehlgeschlagene Dienste'

    "{journalctl_bin}" -t CRON --since "$SINCE" --until "$UNTIL" --no-pager -q \\
        -o short-iso | grep -iE 'error|failed' | kurz \\
        | abschnitt 'Fehlgeschlagene Cron-Läufe' || true

    printf '%s' "$FEHLER" | kurz | head -n 20 \\
        | abschnitt 'Fehlermeldungen im Journal (Priorität error, höchstens 20)'

    "{df_bin}" -h --local -x tmpfs -x devtmpfs -x squashfs \\
        | abschnitt 'Plattenplatz'
}} >"$BODY"

BOUNDARY="secure-base-$(date +%s)-$$"
{{
    printf 'From: %s\\n' "$MAIL_FROM"
    printf 'To: %s\\n' "$ADMIN_MAIL"
    printf 'Subject: [secure-base] Tagesbericht %s %s\\n' "$FQDN" "$DAY"
    printf 'MIME-Version: 1.0\\n'
    printf 'Content-Type: multipart/mixed; boundary="%s"\\n\\n' "$BOUNDARY"
    printf -- '--%s\\n' "$BOUNDARY"
    printf 'Content-Type: text/plain; charset=UTF-8\\n'
    printf 'Content-Transfer-Encoding: base64\\n\\n'
    "{base64_bin}" "$BODY"
    printf -- '--%s\\n' "$BOUNDARY"
    printf 'Content-Type: text/plain; charset=UTF-8\\n'
    printf 'Content-Disposition: attachment; filename="logwatch-%s.txt"\\n' "$DAY"
    printf 'Content-Transfer-Encoding: base64\\n\\n'
    "{base64_bin}" "$REPORT"
    printf -- '--%s--\\n' "$BOUNDARY"
}} | "{sendmail_bin}" -t
"""


def _report_script_content(
    admin_mail: str,
    mail_from: str,
    fqdn: str,
    logwatch_bin: str,
    journalctl_bin: str,
    systemctl_bin: str,
    df_bin: str,
    base64_bin: str,
    sendmail_bin: str,
) -> str:
    """Baut den Inhalt des Berichts-Skripts.

    Args:
        admin_mail: Empfänger der Tagesbericht-Mail.
        mail_from: Absender der Tagesbericht-Mail.
        fqdn: Rechnername für Betreff und Kopfzeile.
        logwatch_bin: Pfad zu logwatch.
        journalctl_bin: Pfad zu journalctl.
        systemctl_bin: Pfad zu systemctl.
        df_bin: Pfad zu df.
        base64_bin: Pfad zu base64.
        sendmail_bin: Pfad zu sendmail.

    Returns:
        Vollständiger Skriptinhalt.
    """
    return _REPORT_SCRIPT_TEMPLATE.format(
        admin_mail=admin_mail,
        mail_from=mail_from,
        fqdn=fqdn,
        logwatch_bin=logwatch_bin,
        journalctl_bin=journalctl_bin,
        systemctl_bin=systemctl_bin,
        df_bin=df_bin,
        base64_bin=base64_bin,
        sendmail_bin=sendmail_bin,
    )


def _report_cron_content(script_path: str) -> str:
    """Baut den Inhalt des cron.daily-Eintrags für den Tagesbericht.

    Der Eintrag liegt in cron.daily, nicht in cron.d: der Bericht läuft
    damit zur selben Tageszeit wie zuvor der mitgelieferte logwatch-Lauf,
    ohne dass dafür ein eigener Zeitpunkt zu konfigurieren wäre.

    Args:
        script_path: Pfad des Berichts-Skripts.

    Returns:
        Vollständiger Inhalt des cron.daily-Eintrags.
    """
    return (
        "#!/bin/sh\n"
        "# Von secure-base/logging angelegt (wird bei erneutem Installer-Lauf überschrieben).\n"
        f"exec {script_path}\n"
    )


def _doc_value(values: dict[str, str], key: str) -> str:
    """Liest einen Wert für den Installationsbericht aus values.

    doc() fragt hier ausschließlich fest benannte, unkritische Schlüssel ab
    (journald_max_use, journald_max_retention, admin_mail) — ein
    Allowlist-Mechanismus wie im Bash-Original (doc_val) ist deshalb hier
    nicht nötig.

    Args:
        values: Konfigurationswerte des Moduls.
        key: Abzufragender Schlüssel.

    Returns:
        Wert aus values, oder "(leer/Default)" wenn leer oder nicht gesetzt.
    """
    return values.get(key) or "(leer/Default)"


class Logging(Module):
    """Protokollierung und Auditing des Systems über pifos-Aktionen."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "fqdn",
        "admin_mail",
        "journald_max_use",
        "journald_max_retention",
    ]

    # Programmpfade und Schreibziele als Klassenattribute statt Literale in
    # den Schritten (Begründung wie im Referenzmodul base).
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"
    DPKG_BIN: ClassVar[str] = "/usr/bin/dpkg"
    JOURNALCTL_BIN: ClassVar[str] = "/usr/bin/journalctl"
    # /usr/sbin, nicht /usr/bin: das Paket logwatch legt den Aufruf unter
    # /usr/sbin/logwatch ab (Symlink auf logwatch.pl). Weder Ubuntu 26.04 noch
    # Debian 13 führen /usr/sbin und /usr/bin zusammen — der Pfad muss stimmen.
    LOGWATCH_BIN: ClassVar[str] = "/usr/sbin/logwatch"
    JOURNALD_CONF: ClassVar[str] = "/etc/systemd/journald.conf"
    LOGWATCH_CONF: ClassVar[str] = "/etc/logwatch/conf/logwatch.conf"
    JOURNAL_DIR: ClassVar[str] = "/var/log/journal"
    LOGROTATE_CONF: ClassVar[str] = "/etc/logrotate.d/secure-base"
    AUDIT_RULES_FILE: ClassVar[str] = "/etc/audit/rules.d/secure-base.rules"
    # Altbestand früherer Versionen: das Drop-in setzte "Defaults logfile",
    # was sudo-rs nicht kennt (Parse-Fehler — sudo verweigert dann jeden
    # Aufruf). Es wird nicht mehr geschrieben; die Pfade bleiben nur für den
    # Rückbau auf Bestandssystemen.
    SUDOLOG_CONF: ClassVar[str] = "/etc/sudoers.d/secure-base-sudolog"
    SUDO_LOGFILE: ClassVar[str] = "/var/log/sudo.log"
    # Prüfziele für die sudo-Vorbedingung: die Konfigurationsdatei und das
    # Einbindeverzeichnis von sudo. Beide sind zugleich die Pfade, die die
    # sudoers-Audit-Regeln überwachen.
    SUDOERS_FILE: ClassVar[str] = "/etc/sudoers"
    SUDOERS_DIR: ClassVar[str] = "/etc/sudoers.d"
    # Anmeldehistorie: (Vorbedingung, Regel) — siehe LOGIN_AUDIT_RULES.
    LOGIN_RULES: ClassVar[tuple[tuple[str, str], ...]] = LOGIN_AUDIT_RULES
    # Pakete der Anmeldehistorie. wtmpdb führt die Datenbank und bringt "last"
    # mit; libpam-wtmpdb trägt die Anmeldungen über PAM ein. Unter Debian 13
    # gehören beide zur Standardinstallation (Priorität "standard") und sshd
    # schreibt zusätzlich direkt über libwtmpdb0 — die mitgelieferte
    # PAM-Vorgabe lässt sshd-Sitzungen deshalb aus. Unter Ubuntu 26.04 sind
    # beide "optional" und sshd ist nicht gegen libwtmpdb0 gebunden; dort
    # erfasst das PAM-Modul auch die SSH-Anmeldungen.
    LOGIN_HISTORY_PACKAGES: ClassVar[tuple[str, ...]] = ("wtmpdb", "libpam-wtmpdb")

    # Tagesbericht: Zusammenfassung im Mailtext, vollständiger Logwatch-Bericht
    # als Anhang (siehe _REPORT_SCRIPT_TEMPLATE).
    DF_BIN: ClassVar[str] = "/usr/bin/df"
    BASE64_BIN: ClassVar[str] = "/usr/bin/base64"
    SENDMAIL_BIN: ClassVar[str] = "/usr/sbin/sendmail"
    REPORT_SCRIPT: ClassVar[str] = "/usr/local/sbin/secure-base-logwatch.sh"
    REPORT_CRON: ClassVar[str] = "/etc/cron.daily/secure-base-logwatch"
    REPORT_SCRIPT_MODE: ClassVar[int] = 0o700
    REPORT_CRON_MODE: ClassVar[int] = 0o755

    # Der mitgelieferte Cron-Lauf von logwatch schreibt den vollständigen
    # Bericht in den Mailtext und ruft logwatch mit "--output mail" auf, was
    # jede Vorgabe aus logwatch.conf übergeht. Er wird deshalb stillgelegt,
    # indem ihm das Ausführungsrecht genommen wird (run-parts überspringt
    # nicht ausführbare Dateien) — die Paketdatei selbst bleibt unangetastet.
    # Ein Paket-Upgrade kann das Recht zurücksetzen; die Betriebsart check
    # prüft es deshalb mit.
    STOCK_CRON: ClassVar[str] = "/etc/cron.daily/00logwatch"
    STOCK_CRON_MODE_OFF: ClassVar[int] = 0o644
    STOCK_CRON_MODE_ON: ClassVar[int] = 0o755

    # apt-/systemd-Aktionsklassen als Klassenattribute (Begründung wie im
    # Referenzmodul base): Testunterklasse kann sie im Testbaum umlenken.
    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Zeitgrenze für den probeweisen logwatch-Mailversand in _test (echter
    # Versand über das postfix-Relay, Klassenattribut wie im Referenzmodul
    # base testbar).
    LOGWATCH_TEST_TIMEOUT: ClassVar[float] = 60.0

    # Von check_config per setattr gesetzt (siehe Module.check_config);
    # hier nur als Typdeklaration für mypy --strict, ohne eigenen __init__.
    operation: str
    fqdn: str
    admin_mail: str
    journald_max_use: str
    journald_max_retention: str

    def start(self) -> int:
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültigen Konfigurationswerten.
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        if self.operation == "uninstall":
            return self._uninstall()
        if self.operation == "test":
            return self._test()
        return self._install()

    @classmethod
    def _sudo_present(cls) -> bool:
        """Prüft, ob sudo auf dem System vorhanden ist.

        Maßgeblich sind die Pfade, nicht der Paketstatus: die sudoers.d-Datei
        braucht das Einbindeverzeichnis, die beiden Audit-Regeln brauchen die
        überwachten Pfade.

        Returns:
            True, wenn sudoers-Datei und sudoers.d-Verzeichnis vorliegen.
        """
        return Path(cls.SUDOERS_FILE).exists() and Path(cls.SUDOERS_DIR).is_dir()

    @classmethod
    def _login_rules(cls) -> tuple[str, ...]:
        """Liefert die Audit-Regeln der auf dem System geführten Anmeldehistorie.

        Returns:
            Je Eintrag aus LOGIN_RULES die Regel, wenn deren Vorbedingung
            vorliegt; leer, wenn keine Anmeldehistorie geführt wird.
        """
        return tuple(
            rule
            for precondition, rule in cls.LOGIN_RULES
            if Path(precondition).exists()
        )

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Markdown-Abschnitt für den Installationsbericht.

        SICHERHEIT: doc() liest ausschließlich die unten aufgeführten,
        unkritischen Schlüssel (journald_max_use, journald_max_retention,
        admin_mail) — keine Geheimnisse gehen in diesen Abschnitt ein.

        Args:
            values: Konfigurationswerte des Moduls (fqdn, admin_mail,
                journald_max_use, journald_max_retention, …).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Protokollierung und
            Auditing".
        """
        journald_max_use = _doc_value(values, "journald_max_use")
        journald_max_retention = _doc_value(values, "journald_max_retention")
        admin_mail = _doc_value(values, "admin_mail")
        sudo_present = cls._sudo_present()
        sudo_audit_doc = (
            "  - `-w /etc/sudoers -p wa -k scope`\n"
            "  - `-w /etc/sudoers.d -p wa -k scope`\n"
            if sudo_present
            else ""
        )
        sudo_hinweis = (
            ""
            if sudo_present
            else " sudo ist auf diesem System nicht vorhanden — die beiden"
            " Audit-Regeln auf die sudoers-Pfade entfallen (administriert"
            " wird über su)."
        )
        login_rules = cls._login_rules()
        login_audit_doc = "".join(f"  - `{rule}`\n" for rule in login_rules)
        login_hinweis = (
            ""
            if login_rules
            else " Auf diesem System wird keine Anmeldehistorie als Datenbank"
            " geführt (weder wtmpdb noch lastlog2) — die Audit-Regel darauf"
            " entfällt. Die Anmeldungen selbst stehen im Journal."
        )
        return (
            "\n## Protokollierung und Auditing\n\n"
            "**Pakete:** rsyslog, wtmpdb, libpam-wtmpdb, logwatch, auditd\n\n"
            "\n**Dienste:** rsyslog, auditd (enabled, aktiv nach install)\n"
            "**Dateien/Einstellungen:**\n\n"
            f"- `{cls.JOURNALD_CONF}`:\n"
            "  - `Storage = persistent`\n"
            f"  - `SystemMaxUse = {journald_max_use}`\n"
            f"  - `MaxRetentionSec = {journald_max_retention}`\n"
            f"- `{cls.LOGWATCH_CONF}`:\n"
            f"  - `MailTo = {admin_mail}`\n"
            "  - `Detail = Med`\n"
            "  - `Service = All`\n"
            "  - `Output = mail`\n"
            f"- `{cls.LOGROTATE_CONF}`:\n"
            "  - `logrotate-Konfig für /var/log/secure-base/secure-base.log`\n"
            f"- `{cls.AUDIT_RULES_FILE}`:\n"
            f"{sudo_audit_doc}"
            "  - `-w /etc/passwd -p wa -k identity`\n"
            "  - `-w /etc/shadow -p wa -k identity`\n"
            "  - `-w /etc/group -p wa -k identity`\n"
            f"{login_audit_doc}"
            "  - `-e 2 (Immutable — Regeländerungen ohne Reboot gesperrt)`\n"
            f"- `{cls.REPORT_SCRIPT}`:\n"
            "  - `Tagesbericht: Zusammenfassung im Mailtext, vollständiger"
            " Logwatch-Bericht als Anhang`\n"
            f"- `{cls.REPORT_CRON}`:\n"
            "  - `täglicher Aufruf des Berichts-Skripts`\n"
            "\n**Timer/Cron:** täglicher Lauf via"
            f" {cls.REPORT_CRON}; der mitgelieferte Lauf {cls.STOCK_CRON} ist"
            f" stillgelegt (Rechte {oct(cls.STOCK_CRON_MODE_OFF)})\n"
            "\n> Hinweis: systemd-journald wird nicht neu installiert "
            f"(Basis-Infrastruktur); persistentes Journal wird unter "
            f"{cls.JOURNAL_DIR} abgelegt. rsyslog schreibt die Protokolldateien "
            "unter /var/log, aus denen der angehängte Logwatch-Bericht entsteht; "
            "es wird installiert, falls es fehlt, und beim Rückbau nicht entfernt. "
            "wtmpdb führt die Anmeldehistorie (/var/log/wtmp.db, lesbar mit last) "
            "— ebenfalls installiert, falls es fehlt, und beim Rückbau nicht "
            "entfernt; die Audit-Regel überwacht diese Datenbank. "
            "auditd-Regeln mit -e 2 (Immutable) "
            "greifen erst nach dem nächsten Reboot. Die Zusammenfassung im"
            " Mailtext nennt erfolgreiche SSH-Anmeldungen, Zwei-Faktor-Vorgänge,"
            " fehlgeschlagene Anmeldungen bekannter Benutzer, sudo/su,"
            " fail2ban-Sperren, fehlgeschlagene Dienste und Cron-Läufe,"
            " Journal-Fehler und Plattenplatz; die Aufzählung der abgewiesenen"
            " Anmeldeversuche unbekannter Benutzer steht als Summe im Text und"
            f" vollständig im Anhang.{sudo_hinweis}{login_hinweis}\n"
        )

    def _validate(self) -> None:
        """Prüft alle Konfigurationswerte, die in Befehle oder Dateien gehen.

        Raises:
            ModuleError: Wenn fqdn keine Domain erkennen lässt oder
                unzulässige Zeichen enthält, admin_mail keine gültige
                Adresse ist, oder journald_max_use/journald_max_retention
                nicht dem jeweiligen systemd-Muster entsprechen.
        """
        if not _FQDN_CHARS_RE.match(self.fqdn):
            raise ModuleError(f"fqdn enthält unzulässige Zeichen: {self.fqdn!r}")
        if not self._mailfrom():
            raise ModuleError(f"Aus fqdn ist keine Domain ableitbar: {self.fqdn!r}")
        if not _EMAIL_RE.match(self.admin_mail):
            raise ModuleError(f"Ungültige admin_mail: {self.admin_mail!r}")
        if not _JOURNALD_SIZE_RE.match(self.journald_max_use):
            raise ModuleError(f"Ungültiges journald_max_use: {self.journald_max_use!r}")
        if not _JOURNALD_RETENTION_RE.match(self.journald_max_retention):
            raise ModuleError(
                f"Ungültiges journald_max_retention: {self.journald_max_retention!r}"
            )

    def _mailfrom(self) -> str:
        """Leitet den Logwatch-Absender root@<domain> aus fqdn ab.

        Returns:
            "root@<domain>", oder leer, wenn fqdn keinen Punkt enthält.
        """
        _, sep, domain = self.fqdn.partition(".")
        if not sep:
            return ""
        return f"root@{domain}"

    def _report_script(self, mailfrom: str) -> str:
        """Baut den Inhalt des Berichts-Skripts mit den Werten dieses Laufs.

        Args:
            mailfrom: Absender-Adresse (Rückgabe von _mailfrom()).

        Returns:
            Vollständiger Skriptinhalt.
        """
        return _report_script_content(
            admin_mail=self.admin_mail,
            mail_from=mailfrom,
            fqdn=self.fqdn,
            logwatch_bin=self.LOGWATCH_BIN,
            journalctl_bin=self.JOURNALCTL_BIN,
            systemctl_bin=self.SYSTEMCTL_BIN,
            df_bin=self.DF_BIN,
            base64_bin=self.BASE64_BIN,
            sendmail_bin=self.SENDMAIL_BIN,
        )

    def _logwatch_directives(self, mailfrom: str) -> list[tuple[str, str]]:
        """Baut die Soll-Direktiven der logwatch-Konfiguration.

        Args:
            mailfrom: Absender-Adresse (Rückgabe von _mailfrom()).

        Returns:
            Liste aus (Schlüssel, Wert)-Paaren in fester Reihenfolge.
        """
        return [
            ("Output", "mail"),
            ("Format", "text"),
            ("Detail", "Med"),
            ("Range", "yesterday"),
            ("MailTo", self.admin_mail),
            ("MailFrom", mailfrom),
        ]

    def _install(self) -> int:
        """Richtet Protokollierung und Auditing ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        mailfrom = self._mailfrom()
        steps: list[tuple[str, Action]] = [
            (
                "journald Storage setzen",
                LineInFileAction(
                    path=self.JOURNALD_CONF,
                    line="Storage=persistent",
                    match=r"^#?\s*Storage\s*=",
                ),
            ),
            (
                "journald SystemMaxUse setzen",
                LineInFileAction(
                    path=self.JOURNALD_CONF,
                    line=f"SystemMaxUse={self.journald_max_use}",
                    match=r"^#?\s*SystemMaxUse\s*=",
                ),
            ),
            (
                "journald MaxRetentionSec setzen",
                LineInFileAction(
                    path=self.JOURNALD_CONF,
                    line=f"MaxRetentionSec={self.journald_max_retention}",
                    match=r"^#?\s*MaxRetentionSec\s*=",
                ),
            ),
            (
                "systemd-journald neu starten",
                self.SYSTEMD_ACTION_CLS(
                    operation="restart", unit="systemd-journald", timeout=30
                ),
            ),
            (
                "rsyslog installieren",
                self.APT_ACTION_CLS(packages=["rsyslog"]),
            ),
            (
                "rsyslog aktivieren",
                self.SYSTEMD_ACTION_CLS(operation="enable", unit="rsyslog", timeout=60),
            ),
            (
                "rsyslog starten",
                self.SYSTEMD_ACTION_CLS(operation="start", unit="rsyslog", timeout=60),
            ),
            (
                "Anmeldehistorie installieren",
                self.APT_ACTION_CLS(packages=list(self.LOGIN_HISTORY_PACKAGES)),
            ),
            (
                "logwatch installieren",
                self.APT_ACTION_CLS(packages=["logwatch"]),
            ),
        ]
        if not Path(self.LOGWATCH_CONF).exists():
            steps.append(
                (
                    "logwatch-Konfig anlegen",
                    WriteFileAction(
                        dst=self.LOGWATCH_CONF,
                        content="",
                        mode=0o644,
                        overwrite=False,
                        safe_mode=False,
                    ),
                )
            )
        for key, value in self._logwatch_directives(mailfrom):
            steps.append(
                (
                    f"logwatch {key} setzen",
                    LineInFileAction(
                        path=self.LOGWATCH_CONF,
                        line=f"{key} = {value}",
                        match=rf"^\s*{key}\s*=",
                    ),
                )
            )
        sudo_present = self._sudo_present()
        steps += [
            (
                "Berichts-Skript schreiben",
                WriteFileAction(
                    dst=self.REPORT_SCRIPT,
                    content=self._report_script(mailfrom),
                    mode=self.REPORT_SCRIPT_MODE,
                    overwrite=True,
                    safe_mode=False,
                ),
            ),
            (
                "Berichts-Cron schreiben",
                WriteFileAction(
                    dst=self.REPORT_CRON,
                    content=_report_cron_content(self.REPORT_SCRIPT),
                    mode=self.REPORT_CRON_MODE,
                    overwrite=True,
                    safe_mode=False,
                ),
            ),
            (
                "mitgelieferten logwatch-Cron stilllegen",
                PermissionsAction(path=self.STOCK_CRON, mode=self.STOCK_CRON_MODE_OFF),
            ),
            (
                "logrotate-Konfig schreiben",
                WriteFileAction(
                    dst=self.LOGROTATE_CONF,
                    content=_logrotate_content(),
                    mode=0o644,
                    overwrite=True,
                    # kein safe_mode: eine .bak-Sicherung würde von
                    # logrotates Include-Glob mitgelesen (doppelter Eintrag).
                    safe_mode=False,
                ),
            ),
        ]
        if not sudo_present:
            self.send_message(
                LogLevel.INFO,
                "logging",
                "sudo nicht vorhanden — sudoers-Audit-Regeln entfallen",
            )
        steps.append(
            (
                "auditd installieren",
                self.APT_ACTION_CLS(packages=["auditd"]),
            )
        )
        if self._run_steps(steps) != 0:
            return 1

        # Erst jetzt steht fest, welche Anmeldehistorie das System führt: Die
        # Pakete dafür installiert der Schritt oben, die Vorbedingung der Regel
        # ist also vorher noch nicht erfüllt.
        login_rules = self._login_rules()
        if not login_rules:
            self.send_message(
                LogLevel.WARN,
                "logging",
                "keine Anmeldehistorie-Datenbank vorhanden (weder wtmpdb noch"
                " lastlog2) — Audit-Regel dafür entfällt; Anmeldungen stehen im"
                " Journal",
            )
        audit_steps: list[tuple[str, Action]] = [
            (
                "Audit-Regeln schreiben",
                WriteFileAction(
                    dst=self.AUDIT_RULES_FILE,
                    content=_audit_rules_content(sudo_present, login_rules),
                    mode=0o640,
                    overwrite=True,
                    safe_mode=False,
                ),
            ),
            (
                "auditd aktivieren",
                self.SYSTEMD_ACTION_CLS(operation="enable", unit="auditd", timeout=60),
            ),
            (
                "auditd starten",
                self.SYSTEMD_ACTION_CLS(operation="start", unit="auditd", timeout=60),
            ),
        ]
        return self._run_steps(audit_steps)

    def _run_steps(self, steps: list[tuple[str, Action]]) -> int:
        """Führt die Schritte der Reihe nach aus und bricht beim ersten Fehler ab.

        Args:
            steps: Paare aus Beschriftung und Aktion.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        for label, action in steps:
            self.send_message(LogLevel.INFO, "logging", label)
            if self.run_action(action) != 0:
                self.send_message(LogLevel.ERROR, "logging", f"fehlgeschlagen: {label}")
                return 1
            if label == "Audit-Regeln schreiben":
                self.send_message(
                    LogLevel.WARN,
                    "logging",
                    "Immutable (-e 2) gesetzt — neue Regeln greifen erst nach "
                    "einem Neustart.",
                )
        return 0

    def _uninstall(self) -> int:
        """Nimmt die eigenen Änderungen von _install zurück.

        systemd-journald bleibt bestehen (Basis-Infrastruktur) — nur die
        eigenen Direktiven werden zurückgenommen. rsyslog und die Pakete der
        Anmeldehistorie (wtmpdb, libpam-wtmpdb) bleiben ebenfalls bestehen:
        Sie schreiben Dateien, auf die auch Werkzeuge außerhalb von
        secure-base zugreifen, und auf einem Teil der Distributionen gehören
        sie zur Standardinstallation — ein Rückbau träfe dort einen Zustand,
        den das Modul nicht hergestellt hat.
        logwatch und auditd werden nur entfernt, wenn sie installiert sind
        (wie im Bash-Original). Das sudoers-Drop-in ist Altbestand früherer
        Versionen (siehe SUDOLOG_CONF) und wird mit entfernt; eine dabei
        entstandene /var/log/sudo.log bleibt als Datensicherung erhalten.

        Schrittliste mit Abbruch beim ersten Fehler (wie _install). Jeder
        Schritt ist idempotent: bereits Zurückgenommenes ist kein Fehler.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        steps: list[tuple[str, _Step]] = [
            ("journald-Direktiven zurücknehmen", self._step_remove_journald),
            ("Tagesbericht zurücknehmen", self._step_remove_report),
            ("logwatch entfernen", self._step_remove_logwatch),
            ("logrotate-Konfig entfernen", self._step_remove_logrotate),
            ("Audit-Regeln entfernen", self._step_remove_audit_rules),
            ("sudoers-Drop-in (Altbestand) entfernen", self._step_remove_sudolog),
            ("auditd entfernen", self._step_remove_auditd),
        ]
        for label, step in steps:
            self.send_message(LogLevel.INFO, "logging", label)
            if step() != 0:
                self.send_message(LogLevel.ERROR, "logging", f"fehlgeschlagen: {label}")
                return 1
        self.send_message(
            LogLevel.INFO,
            "logging",
            "rsyslog bleibt installiert (Schreiber der Protokolldateien unter"
            " /var/log)",
        )
        self.send_message(
            LogLevel.INFO,
            "logging",
            "wtmpdb bleibt installiert (Anmeldehistorie) — die Datenbank"
            " /var/log/wtmp.db bleibt erhalten",
        )
        # Altbestand früherer Versionen (Defaults logfile): nur melden, wenn
        # die Logdatei tatsächlich existiert.
        if Path(self.SUDO_LOGFILE).exists():
            self.send_message(
                LogLevel.WARN,
                "logging",
                f"{self.SUDO_LOGFILE} bleibt erhalten (Audit-Datensicherung) — bei"
                " Bedarf manuell entfernen.",
            )
        return 0

    def _step_remove_journald(self) -> int:
        """Nimmt die journald-Direktiven zurück und startet den Dienst neu.

        Returns:
            0 bei Erfolg oder wenn journald.conf bereits fehlt, sonst 1.
        """
        if not Path(self.JOURNALD_CONF).exists():
            self.send_message(
                LogLevel.INFO,
                "logging",
                f"{self.JOURNALD_CONF} nicht vorhanden — keine journald-Reverts nötig",
            )
            return 0
        for key in ("Storage", "SystemMaxUse", "MaxRetentionSec"):
            action = LineInFileAction(
                path=self.JOURNALD_CONF,
                line="",
                match=rf"^#?\s*{key}\s*=",
                state="absent",
            )
            if self.run_action(action) != 0:
                return 1
        return self.run_action(
            self.SYSTEMD_ACTION_CLS(
                operation="restart", unit="systemd-journald", timeout=30
            )
        )

    def _step_remove_report(self) -> int:
        """Entfernt Berichts-Skript und -Cron und gibt den logwatch-Cron frei.

        Der mitgelieferte Cron-Lauf bekommt sein Ausführungsrecht zurück,
        damit nach dem Rückbau wieder der Zustand vor der Installation
        gilt — vorausgesetzt, das Paket bleibt (sonst entfernt der Schritt
        "logwatch entfernen" die Datei ohnehin mit).

        Returns:
            0 bei Erfolg, 1 bei Fehlschlag.
        """
        if self._remove_file_if_exists(self.REPORT_CRON) != 0:
            return 1
        if self._remove_file_if_exists(self.REPORT_SCRIPT) != 0:
            return 1
        if not Path(self.STOCK_CRON).exists():
            return 0
        return self.run_action(
            PermissionsAction(path=self.STOCK_CRON, mode=self.STOCK_CRON_MODE_ON)
        )

    def _step_remove_logwatch(self) -> int:
        """Nimmt die logwatch-Konfiguration zurück und entfernt das Paket.

        logwatch hat keinen eigenen Dienst (Lauf via cron.daily) — kein
        Dienst-Stopp nötig.

        Returns:
            0 bei Erfolg oder wenn logwatch nicht installiert ist, sonst 1.
        """
        if not self._package_installed("logwatch"):
            self.send_message(
                LogLevel.INFO,
                "logging",
                "Paket logwatch nicht installiert — nichts zu entfernen",
            )
            return 0
        if Path(self.LOGWATCH_CONF).exists():
            for key, _ in self._logwatch_directives(""):
                action = LineInFileAction(
                    path=self.LOGWATCH_CONF,
                    line="",
                    match=rf"^\s*{key}\s*=",
                    state="absent",
                )
                if self.run_action(action) != 0:
                    return 1
        return self.run_action(
            self.APT_ACTION_CLS(packages=["logwatch"], state="absent")
        )

    def _step_remove_logrotate(self) -> int:
        """Entfernt die logrotate-Konfiguration für das secure-base-Logfile.

        Returns:
            0 bei Erfolg oder wenn die Datei bereits fehlt, sonst 1.
        """
        return self._remove_file_if_exists(self.LOGROTATE_CONF)

    def _step_remove_audit_rules(self) -> int:
        """Entfernt die Audit-Regeldatei.

        Returns:
            0 bei Erfolg oder wenn die Datei bereits fehlt, sonst 1.
        """
        return self._remove_file_if_exists(self.AUDIT_RULES_FILE)

    def _step_remove_sudolog(self) -> int:
        """Entfernt das sudoers-Drop-in früherer Versionen (Altbestand).

        Returns:
            0 bei Erfolg oder wenn die Datei bereits fehlt, sonst 1.
        """
        return self._remove_file_if_exists(self.SUDOLOG_CONF)

    def _remove_file_if_exists(self, path: str) -> int:
        """Löscht path ohne Sicherung, falls vorhanden; idempotent.

        Args:
            path: Zu entfernende Datei.

        Returns:
            0 bei Erfolg oder wenn path bereits fehlt, sonst 1.
        """
        if not Path(path).exists():
            self.send_message(
                LogLevel.INFO, "logging", f"{path} nicht vorhanden — übersprungen"
            )
            return 0
        return self.run_action(DeleteFileAction(path=path, safe_mode=False))

    def _step_remove_auditd(self) -> int:
        """Stoppt, deaktiviert und entfernt auditd, sofern installiert.

        Returns:
            0 bei Erfolg oder wenn auditd nicht installiert ist, sonst 1.
        """
        if not self._package_installed("auditd"):
            self.send_message(
                LogLevel.INFO,
                "logging",
                "Paket auditd nicht installiert — nichts zu entfernen",
            )
            return 0
        if self.run_action(
            self.SYSTEMD_ACTION_CLS(operation="stop", unit="auditd", timeout=60)
        ):
            return 1
        if self.run_action(
            self.SYSTEMD_ACTION_CLS(operation="disable", unit="auditd", timeout=60)
        ):
            return 1
        return self.run_action(self.APT_ACTION_CLS(packages=["auditd"], state="absent"))

    def _package_installed(self, package: str) -> bool:
        """Prüft still über dpkg, ob package installiert ist.

        Dient als Vorbedingung für Rückbau-Schritte — anders als
        _check_installed erzeugt diese Methode keine Meldung, da sie kein
        Prüfergebnis, sondern nur eine Ablaufentscheidung liefert.

        Args:
            package: Paketname.

        Returns:
            True, wenn dpkg den Status "install ok installed" meldet.
        """
        action = SysCmdAction(command=[self.DPKG_BIN, "-s", package], timeout=15)
        try:
            action.run()
        except ActionError:
            return False
        return "Status: install ok installed" in action.stdout

    def _test(self) -> int:
        """Führt den Funktionstest ohne Systemänderung aus.

        Weist die journald-Persistenz nach und verschickt probeweise den
        logwatch-Report per Mail (echter Versand über das postfix-Relay).
        Sammelt beide Prüfungen; bricht nicht bei der ersten
        fehlgeschlagenen Prüfung ab.

        Returns:
            0, wenn beide Prüfungen erfolgreich waren, sonst 1.
        """
        ok = True
        ok &= self._test_journald_persistence()
        ok &= self._test_logwatch_report()
        return 0 if ok else 1

    def _test_journald_persistence(self) -> bool:
        """Weist die journald-Persistenz über journalctl --header nach.

        Returns:
            True bei erfolgreichem journalctl-Lauf und vorhandenem
            JOURNAL_DIR, sonst False.
        """
        action = SysCmdAction(command=[self.JOURNALCTL_BIN, "--header"], timeout=15)
        result = self.run_action(action)
        for line in action.stdout.splitlines():
            self.send_message(LogLevel.INFO, "logging", f"journald: {line}")
        if result == 0 and Path(self.JOURNAL_DIR).is_dir():
            self.send_message(
                LogLevel.INFO,
                "logging",
                f"journald-Persistenz nachgewiesen ({self.JOURNAL_DIR} vorhanden)",
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "logging",
            f"journald-Persistenz nicht nachweisbar (journalctl rc={result}, "
            f"{self.JOURNAL_DIR} "
            f"{'vorhanden' if Path(self.JOURNAL_DIR).is_dir() else 'fehlt'})",
        )
        return False

    def _test_logwatch_report(self) -> bool:
        """Verschickt den logwatch-Report probeweise per Mail.

        Returns:
            True, wenn logwatch installiert ist und der Versand gelang,
            sonst False.
        """
        if not self._check_installed("logwatch", "Paket logwatch"):
            return False
        action = SysCmdAction(
            command=[
                self.LOGWATCH_BIN,
                "--output",
                "mail",
                "--format",
                "text",
                "--range",
                "yesterday",
                "--detail",
                "Med",
            ],
            timeout=self.LOGWATCH_TEST_TIMEOUT,
        )
        result = self.run_action(action)
        for line in action.stdout.splitlines():
            self.send_message(LogLevel.INFO, "logging", f"logwatch: {line}")
        if result != 0:
            self.send_message(
                LogLevel.ERROR,
                "logging",
                f"logwatch-Mailversand fehlgeschlagen: {action.stderr.strip()}",
            )
            return False
        self.send_message(
            LogLevel.INFO,
            "logging",
            f"logwatch-Report abgesetzt — Eingang bei {self.admin_mail} prüfen",
        )
        return True

    def _verify(self) -> int:
        """Gleicht die eigenen install-Wirkungen mit dem Soll ab.

        Prüft nur, ob die Schritte aus _install gewirkt haben — kein
        allgemeiner System-Audit.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        mailfrom = self._mailfrom()
        ok = True
        ok &= self._check_file_line(
            self.JOURNALD_CONF, "Storage=persistent", "journald Storage"
        )
        ok &= self._check_file_line(
            self.JOURNALD_CONF,
            f"SystemMaxUse={self.journald_max_use}",
            "journald SystemMaxUse",
        )
        ok &= self._check_file_line(
            self.JOURNALD_CONF,
            f"MaxRetentionSec={self.journald_max_retention}",
            "journald MaxRetentionSec",
        )
        ok &= self._check_dir_exists(self.JOURNAL_DIR, "journald-Persistenzverzeichnis")
        ok &= self._check_installed("rsyslog", "Paket rsyslog")
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", "--", "rsyslog"],
            "active",
            "rsyslog-Dienst",
        )
        for package in self.LOGIN_HISTORY_PACKAGES:
            ok &= self._check_installed(package, f"Paket {package}")
        ok &= self._check_installed("logwatch", "Paket logwatch")
        # Der Aufruf steht im Berichts-Skript und im Funktionstest — ein
        # falscher Pfad fällt sonst erst auf, wenn der Nachtlauf ausbleibt.
        ok &= self._check_file_exists(self.LOGWATCH_BIN, "logwatch-Programm")
        for key, value in self._logwatch_directives(mailfrom):
            ok &= self._check_file_line(
                self.LOGWATCH_CONF, f"{key} = {value}", f"logwatch {key}"
            )
        ok &= self._check_report_script(mailfrom)
        ok &= self._check_report_cron()
        ok &= self._check_stock_cron_disabled()
        ok &= self._check_file_exists(self.LOGROTATE_CONF, "logrotate-Konfig")
        ok &= self._check_installed("auditd", "Paket auditd")
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", "--", "auditd"], "active", "auditd-Dienst"
        )
        sudo_present = self._sudo_present()
        login_rules = self._login_rules()
        if not login_rules:
            self.send_message(
                LogLevel.WARN,
                "logging",
                "keine Anmeldehistorie-Datenbank vorhanden — Audit-Regel dafür"
                " nicht zutreffend",
            )
        for rule in _audit_rules(sudo_present, login_rules):
            ok &= self._check_file_line(
                self.AUDIT_RULES_FILE, rule, f"Audit-Regel {rule}"
            )
        # Altbestand früherer Versionen: das Drop-in mit "Defaults logfile"
        # legt sudo-rs lahm — sein Vorhandensein ist ein Befund.
        if Path(self.SUDOLOG_CONF).exists():
            self.send_message(
                LogLevel.ERROR,
                "logging",
                f"{self.SUDOLOG_CONF} vorhanden (Altbestand) — unter sudo-rs"
                " Parse-Fehler, sudo verweigert jeden Aufruf; entfernen",
            )
            ok = False
        return 0 if ok else 1

    def _check_value(self, command: list[str], expected: str, label: str) -> bool:
        """Liest einen Wert über einen Befehl und vergleicht ihn mit dem Soll.

        Args:
            command: Befehl, dessen Ausgabe den Ist-Wert liefert.
            expected: Soll-Wert.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        action = SysCmdAction(command=command, timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "logging", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "logging", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "logging", f"{label}: ist {current}, soll {expected}"
        )
        return False

    def _check_file_line(self, path: str, expected_line: str, label: str) -> bool:
        """Prüft, ob expected_line unverändert in der Datei path vorkommt.

        Args:
            path: Zu lesende Datei.
            expected_line: Erwartete Zeile (ohne Zeilenumbruch).
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn die Zeile vorkommt, sonst False.
        """
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError:
            self.send_message(
                LogLevel.ERROR, "logging", f"{label}: Datei nicht lesbar ({path})"
            )
            return False
        if expected_line in lines:
            self.send_message(LogLevel.INFO, "logging", f"{label}: gesetzt — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "logging", f"{label}: nicht gesetzt (soll: {expected_line})"
        )
        return False

    def _check_report_script(self, mailfrom: str) -> bool:
        """Prüft Inhalt und Rechte des Berichts-Skripts.

        Args:
            mailfrom: Absender-Adresse (Rückgabe von _mailfrom()).

        Returns:
            True bei übereinstimmendem Inhalt und korrekten Rechten.
        """
        try:
            content = Path(self.REPORT_SCRIPT).read_text(encoding="utf-8")
        except OSError:
            self.send_message(
                LogLevel.ERROR,
                "logging",
                f"Berichts-Skript: fehlt oder nicht lesbar ({self.REPORT_SCRIPT})",
            )
            return False
        if content != self._report_script(mailfrom):
            self.send_message(
                LogLevel.ERROR,
                "logging",
                f"Berichts-Skript: Inhalt weicht vom Soll ab ({self.REPORT_SCRIPT})",
            )
            return False
        self.send_message(LogLevel.INFO, "logging", "Berichts-Skript: Inhalt OK")
        return self._check_mode(
            self.REPORT_SCRIPT, self.REPORT_SCRIPT_MODE, "Berichts-Skript"
        )

    def _check_report_cron(self) -> bool:
        """Prüft Inhalt und Rechte des cron.daily-Eintrags für den Tagesbericht.

        Returns:
            True bei übereinstimmendem Inhalt und korrekten Rechten.
        """
        if not self._check_file_line(
            self.REPORT_CRON, f"exec {self.REPORT_SCRIPT}", "Berichts-Cron"
        ):
            return False
        return self._check_mode(
            self.REPORT_CRON, self.REPORT_CRON_MODE, "Berichts-Cron"
        )

    def _check_stock_cron_disabled(self) -> bool:
        """Prüft, ob der mitgelieferte logwatch-Cron stillgelegt ist.

        Ist die Datei nicht vorhanden, ist nichts stillzulegen. Ist sie
        ausführbar, würde sie neben dem Tagesbericht eine zweite Mail mit
        dem vollständigen Bericht verschicken — etwa nachdem ein
        Paket-Upgrade die Rechte zurückgesetzt hat.

        Returns:
            True, wenn die Datei fehlt oder nicht ausführbar ist.
        """
        path = Path(self.STOCK_CRON)
        if not path.exists():
            self.send_message(
                LogLevel.INFO,
                "logging",
                f"mitgelieferter logwatch-Cron nicht vorhanden ({self.STOCK_CRON})",
            )
            return True
        return self._check_mode(
            self.STOCK_CRON, self.STOCK_CRON_MODE_OFF, "mitgelieferter logwatch-Cron"
        )

    def _check_mode(self, path: str, expected_mode: int, label: str) -> bool:
        """Prüft die Rechte eines Dateisystemobjekts.

        Args:
            path: Zu prüfender Pfad.
            expected_mode: Erwartete Rechte.
            label: Beschreibung für die Meldung.

        Returns:
            True bei Übereinstimmung, sonst False.
        """
        try:
            current = stat.S_IMODE(Path(path).stat().st_mode)
        except OSError:
            self.send_message(LogLevel.ERROR, "logging", f"{label}: fehlt ({path})")
            return False
        if current == expected_mode:
            self.send_message(
                LogLevel.INFO, "logging", f"{label}: Rechte {oct(current)} — OK"
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "logging",
            f"{label}: Rechte {oct(current)}, erwartet {oct(expected_mode)}",
        )
        return False

    def _check_file_exists(self, path: str, label: str) -> bool:
        """Prüft, ob path als Datei existiert.

        Args:
            path: Zu prüfender Pfad.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn path eine Datei ist, sonst False.
        """
        if Path(path).is_file():
            self.send_message(LogLevel.INFO, "logging", f"{label}: vorhanden — OK")
            return True
        self.send_message(LogLevel.ERROR, "logging", f"{label}: fehlt ({path})")
        return False

    def _check_dir_exists(self, path: str, label: str) -> bool:
        """Prüft, ob path als Verzeichnis existiert.

        Args:
            path: Zu prüfender Pfad.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn path ein Verzeichnis ist, sonst False.
        """
        if Path(path).is_dir():
            self.send_message(LogLevel.INFO, "logging", f"{label}: vorhanden — OK")
            return True
        self.send_message(LogLevel.ERROR, "logging", f"{label}: fehlt ({path})")
        return False

    def _check_installed(self, package: str, label: str) -> bool:
        """Prüft über dpkg, ob package installiert ist.

        Args:
            package: Paketname.
            label: Beschreibung für die Meldung.

        Returns:
            True, wenn dpkg den Status "install ok installed" meldet.
        """
        action = SysCmdAction(command=[self.DPKG_BIN, "-s", package], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "logging", f"{label}: nicht installiert")
            return False
        if "Status: install ok installed" in action.stdout:
            self.send_message(LogLevel.INFO, "logging", f"{label}: installiert — OK")
            return True
        self.send_message(LogLevel.ERROR, "logging", f"{label}: nicht installiert")
        return False
