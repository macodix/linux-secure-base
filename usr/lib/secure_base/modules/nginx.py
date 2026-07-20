"""Modul nginx — Multidomain-Webserver mit Let's-Encrypt-Zertifikaten.

Richtet je Domain einen eigenen Server-Block mit eigenem Zertifikat ein
(certbot, HTTP-01). Ergänzt die Firewall additiv (443/tcp dauerhaft,
80/tcp nur temporär für den Zertifikatsbezug). Optionales Modul; setzt
das gehärtete Grundsystem voraus. Betriebsart über den Schlüssel
operation.
"""

import contextlib
import grp
import pwd
import re
import socket
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from pifos.action import Action
from pifos.actions.apt_action import AptAction
from pifos.actions.delete_file_action import DeleteFileAction
from pifos.actions.line_in_file_action import LineInFileAction
from pifos.actions.make_dir_action import MakeDirAction
from pifos.actions.permissions_action import PermissionsAction
from pifos.actions.symlink_action import SymlinkAction
from pifos.actions.sys_cmd_action import SysCmdAction
from pifos.actions.systemd_service_action import SystemdServiceAction
from pifos.actions.write_file_action import WriteFileAction
from pifos.errors import ActionError, ModuleError
from pifos.ipc import LogLevel
from pifos.module import Module

# Domainname: Labels aus a-z, 0-9 und Bindestrich, nicht am Rand;
# mindestens zwei Labels (FQDN, kein einzelnes Label).
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)

# Formale E-Mail-Prüfung, wie in pifos.config.config.Config verwendet.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# docroot geht in den nginx-Server-Block (root <pfad>;) und in eine
# Eigentümer-Änderung auf www-data — strenge Allowlist statt bloßer
# Absolut-Prüfung (konv-scripting-python.md Abschnitt 4.2; Audit-Befund
# 2026-07-05, Schweregrad mittel).
_DOCROOT_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")

# Kennzeichnet von diesem Modul angelegte Dateien (erste Zeile). uninstall
# erkennt darüber die eigenen Server-Blöcke, unabhängig von nginx_vhosts
# (Original: do_uninstall läuft auch ohne optional-conf).
_OWN_FILE_MARKER = "Von secure-base/nginx angelegt"
_OWN_FILE_MARKER_LINE = f"# {_OWN_FILE_MARKER} (wird bei erneutem Installer-Lauf überschrieben).\n"


def _http_block_content(domain: str, docroot: str) -> str:
    """Baut den Port-80-Server-Block für den Zertifikatsbezug.

    certbot ergänzt später den 443-Block und den 80→443-Redirect.

    Args:
        domain: Domainname des vhosts.
        docroot: Wurzelverzeichnis des vhosts.

    Returns:
        Inhalt der Server-Block-Datei.
    """
    return (
        _OWN_FILE_MARKER_LINE + "server {\n"
        "    listen 80;\n"
        "    listen [::]:80;\n"
        f"    server_name {domain};\n"
        f"    root {docroot};\n"
        "    location / { try_files $uri $uri/ =404; }\n"
        "}\n"
    )


def _hardening_content() -> str:
    """Baut den Inhalt des systemd-Hardening-Drop-ins."""
    return (
        _OWN_FILE_MARKER_LINE + "[Service]\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "ProtectHome=true\n"
        "PrivateTmp=true\n"
        "ReadWritePaths=/var/log/nginx /var/lib/nginx /run\n"
    )


class Nginx(Module):
    """Richtet nginx mit Let's-Encrypt-Zertifikaten je Domain ein."""

    CONFIG: ClassVar[list[str]] = [
        "operation",
        "admin_mail",
        "nginx_certbot_mail",
        "nginx_vhosts",
        "nginx_certbot_mode",
    ]

    # Programmpfade und Schreibziele als Klassenattribute (siehe base.py):
    # feste Vorgaben, im Auslieferungsbaum nie von außen überschrieben; eine
    # Testunterklasse kann sie für harmlose Platzhalter überschreiben.
    NGINX_BIN: ClassVar[str] = "/usr/sbin/nginx"
    CERTBOT_BIN: ClassVar[str] = "/usr/bin/certbot"
    UFW_BIN: ClassVar[str] = "/usr/sbin/ufw"
    DPKG_QUERY_BIN: ClassVar[str] = "/usr/bin/dpkg-query"
    SYSTEMCTL_BIN: ClassVar[str] = "/usr/bin/systemctl"
    AA_STATUS_BIN: ClassVar[str] = "/usr/sbin/aa-status"
    AA_AUTODEP_BIN: ClassVar[str] = "/usr/sbin/aa-autodep"
    AA_COMPLAIN_BIN: ClassVar[str] = "/usr/sbin/aa-complain"
    APPARMOR_PARSER_BIN: ClassVar[str] = "/usr/sbin/apparmor_parser"

    NGINX_CONF: ClassVar[str] = "/etc/nginx/nginx.conf"
    SITES_AVAILABLE: ClassVar[str] = "/etc/nginx/sites-available"
    SITES_ENABLED: ClassVar[str] = "/etc/nginx/sites-enabled"
    AA_PROFILE: ClassVar[str] = "/etc/apparmor.d/usr.sbin.nginx"
    HARDENING_DROPIN: ClassVar[str] = (
        "/etc/systemd/system/nginx.service.d/secure-base-hardening.conf"
    )
    DOCROOT_BASE: ClassVar[str] = "/var/www"
    DOCROOT_OWNER: ClassVar[str] = "www-data"
    DOCROOT_GROUP: ClassVar[str] = "www-data"
    LETSENCRYPT_LIVE: ClassVar[str] = "/etc/letsencrypt/live"

    PACKAGES: ClassVar[tuple[str, ...]] = (
        "apparmor-utils",
        "certbot",
        "nginx",
        "python3-certbot-nginx",
    )
    # uninstall entfernt nur die von install hinzugefügten Pakete; certbot
    # und apparmor-utils bleiben (können von anderem genutzt werden).
    UNINSTALL_PACKAGES: ClassVar[tuple[str, ...]] = ("nginx", "python3-certbot-nginx")

    CERTBOT_TIMEOUT: ClassVar[float] = 120.0

    # Betriebsart test: lokaler TCP-Connect ohne TLS-Handshake, nur
    # Erreichbarkeit (dependency-frei, sitzungs-neutral, wie im Original).
    TEST_TCP_HOST: ClassVar[str] = "127.0.0.1"
    TEST_TCP_PORT: ClassVar[int] = 443
    TEST_TCP_TIMEOUT: ClassVar[float] = 2.0

    APT_ACTION_CLS: ClassVar[type[AptAction]] = AptAction
    SYSTEMD_ACTION_CLS: ClassVar[type[SystemdServiceAction]] = SystemdServiceAction

    # Von check_config per setattr gesetzt; hier nur Typdeklaration für
    # mypy --strict, ohne eigenen __init__ (siehe base.py).
    operation: str
    admin_mail: str
    nginx_certbot_mail: str
    nginx_vhosts: str
    nginx_certbot_mode: str

    # Von _validate abgeleitete Werte, ebenfalls nur als Typdeklaration.
    _vhosts: list[tuple[str, str]]
    _certbot_mail: str
    _certbot_mode: str

    def start(self) -> int:
        """Führt Einrichtung, Abgleich, Rückbau oder Funktionstest aus.

        uninstall ist Konfig-unabhängig (wie das Original: do_uninstall
        läuft auch ohne gültige nginx_vhosts/certbot-Werte) und ruft
        deshalb _validate() bewusst nicht auf.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültiger Konfiguration (vhosts, Mail, Modus);
                nicht bei operation == "uninstall".
        """
        if self.operation == "uninstall":
            return self._uninstall()
        self._validate()
        if self.operation == "check":
            return self._verify()
        if self.operation == "test":
            return self._test()
        return self._install()

    @classmethod
    def doc(cls, values: dict[str, str]) -> str:
        """Markdown-Abschnitt für den Installationsbericht.

        Nutzt dieselbe vhost-Zerlegung wie _validate() (_parse_vhosts), damit
        Bericht und Installation nie auseinanderlaufen. Reine Textmontage:
        kein Dateizugriff, kein Prozessaufruf, keine Uhrzeit.

        SICHERHEIT: Es geht ausschließlich nginx_vhosts, die aufgelöste
        certbot-Mail (E-Mail-Adresse, kein Geheimnis) und der certbot-Modus
        in die Ausgabe ein — kein Zugangsdatum, kein Zertifikatsschlüssel.

        Args:
            values: Konfigurationswerte des Moduls (nginx_vhosts,
                nginx_certbot_mail, nginx_certbot_mode, admin_mail).

        Returns:
            Markdown-Abschnitt, beginnend mit "## Webserver nginx (optional)".

        Raises:
            ModuleError: Wenn nginx_vhosts fehlt oder ungültig ist (siehe
                _parse_vhosts) — analog zum Bash-Original, dessen
                module_doc über nginx_parse_vhosts ebenfalls abbricht.
        """
        vhosts = cls._parse_vhosts(values.get("nginx_vhosts", ""))
        certbot_mail = (
            values.get("nginx_certbot_mail", "").strip()
            or values.get("admin_mail", "").strip()
            or "(leer/Default)"
        )
        certbot_mode = values.get("nginx_certbot_mode", "").strip() or "live"

        vhost_lines = "".join(
            f"- `{domain}` (root `{docroot}`)\n" for domain, docroot in vhosts
        )
        return (
            "\n## Webserver nginx (optional)\n\n"
            f"**Pakete:** {', '.join(cls.PACKAGES)}\n\n"
            "**Virtuelle Hosts:**\n"
            f"{vhost_lines}"
            "\n**Firewall:** 443/tcp eingehend dauerhaft; 80/tcp nur"
            " temporär für Zertifikatsbezug/-erneuerung.\n\n"
            f"**certbot:** Modus `{certbot_mode}`, Mail `{certbot_mail}`\n\n"
            "**Dateien/Einstellungen:**\n\n"
            f"- `{cls.HARDENING_DROPIN}`:\n"
            "  - `NoNewPrivileges=true`\n"
            "  - `ProtectSystem=strict`\n"
            "  - `ProtectHome=true`\n"
            "  - `PrivateTmp=true`\n"
            "  - `ReadWritePaths=/var/log/nginx /var/lib/nginx /run`\n"
            f"- `{cls.AA_PROFILE}`\n"
            "\n**Dienste:** nginx (enabled, aktiv nach install)\n"
            "\n> Hinweis: TLS je Domain über certbot/HTTP-01 (Let's"
            " Encrypt). HTTP→HTTPS-Redirect von certbot gesetzt, bleibt"
            " als Absicherung erhalten. AppArmor-Basisprofil für nginx"
            " per aa-autodep erzeugt und im complain-Modus (protokolliert,"
            " blockiert nicht; kein mitgeliefertes Profil vorhanden,"
            " konv-system.md 3.10). Weg zu enforce: Testbetrieb →"
            " aa-logprof → aa-enforce (siehe Anleitung 13). server_tokens"
            " off gesetzt.\n"
        )

    # --- Validierung -----------------------------------------------------

    def _validate(self) -> None:
        """Prüft und normalisiert alle konfigurierten Werte.

        Alle Werte gehen in Systembefehle oder Dateiinhalte; SysCmdAction
        hat bewusst keinen Optionsterminator, deshalb prüft das Modul die
        Werte vor der Verwendung (konv-scripting-python.md Abschnitt 4.2).

        Raises:
            ModuleError: Bei fehlender/ungültiger certbot-Mail, ungültigem
                certbot-Modus oder ungültigen/fehlenden vhost-Einträgen.
        """
        mail = (self.nginx_certbot_mail or self.admin_mail).strip()
        if not mail:
            raise ModuleError(
                "nginx: keine Mail für certbot (nginx_certbot_mail oder"
                " admin_mail setzen)"
            )
        if mail.startswith("-") or not _EMAIL_RE.match(mail):
            raise ModuleError(f"nginx: ungültige certbot-Mail: {mail!r}")
        self._certbot_mail = mail

        mode = self.nginx_certbot_mode.strip() or "live"
        if mode not in ("live", "staging"):
            raise ModuleError(f"nginx: ungültiger certbot-Modus: {mode!r}")
        self._certbot_mode = mode

        self._vhosts = self._parse_vhosts(self.nginx_vhosts)

    @classmethod
    def _parse_vhosts(cls, raw: str) -> list[tuple[str, str]]:
        """Zerlegt die kommagetrennten vhost-Einträge in (domain, docroot).

        Format je Eintrag: "domain" oder "domain|docroot"; ohne docroot
        gilt DOCROOT_BASE/domain. Sortiert nach Domainname (Determinismus).
        Klassenmethode, damit doc() dieselbe Logik ohne Instanz nutzen kann.

        Args:
            raw: Kommagetrennte vhost-Einträge.

        Returns:
            Nach Domainname sortierte Liste von (domain, docroot)-Tupeln.

        Raises:
            ModuleError: Wenn kein Eintrag vorhanden ist, ein Domainname
                ungültig ist oder ein docroot nicht dem Muster _DOCROOT_RE
                entspricht.
        """
        entries = [e.strip() for e in raw.split(",") if e.strip()]
        if not entries:
            raise ModuleError("nginx: kein vhost definiert (nginx_vhosts ist leer)")

        vhosts: list[tuple[str, str]] = []
        for entry in entries:
            domain, sep, docroot = entry.partition("|")
            domain = domain.strip().replace(" ", "")
            docroot = docroot.strip() if sep else ""
            cls._validate_domain(domain)
            if not docroot:
                docroot = f"{cls.DOCROOT_BASE}/{domain}"
            if not _DOCROOT_RE.match(docroot) or "/../" in docroot:
                raise ModuleError(
                    f"nginx: ungültiger docroot: {docroot!r} (vhost {domain})"
                )
            vhosts.append((domain, docroot))
        return sorted(vhosts, key=lambda item: item[0])

    @staticmethod
    def _validate_domain(domain: str) -> None:
        """Prüft Zeichensatz, Form und DNS-Längengrenzen eines Domainnamens.

        Args:
            domain: Zu prüfender Domainname.

        Raises:
            ModuleError: Bei ungültigem Domainnamen oder zu langem
                Gesamtnamen bzw. Label.
        """
        if len(domain) > 253 or not _DOMAIN_RE.match(domain):
            raise ModuleError(f"nginx: ungültiger Domainname: {domain!r}")
        for label in domain.split("."):
            if len(label) > 63:
                raise ModuleError(f"nginx: DNS-Label zu lang in {domain!r}: {label!r}")

    # --- Installation ------------------------------------------------------

    def _install(self) -> int:
        """Richtet nginx, die vhosts und die Zertifikate ein.

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        for label, action in self._pre_certbot_steps():
            if self._step(label, action) != 0:
                return 1
        if self._run_certbot() != 0:
            return 1
        for label, action in self._post_certbot_steps():
            if self._step(label, action) != 0:
                return 1
        return 0

    def _pre_certbot_steps(self) -> Iterator[tuple[str, Action]]:
        """Liefert die Schritte bis einschließlich der Freigabe von 443/tcp.

        Als Generator, damit die Existenzprüfung der Distributions-
        Standardseite erst zur Laufzeit ausgewertet wird — nach der
        vorhergehenden Paketinstallation, nicht beim Aufbau der Liste.

        Yields:
            (Label, Aktion)-Paare in Ausführungsreihenfolge.
        """
        yield (
            "Pakete installieren",
            self.APT_ACTION_CLS(packages=list(self.PACKAGES)),
        )

        default_site = Path(self.SITES_ENABLED) / "default"
        if default_site.is_symlink() or default_site.exists():
            yield (
                "Distributions-Standardseite entfernen",
                DeleteFileAction(path=str(default_site), safe_mode=False),
            )

        yield (
            "Versionsanzeige deaktivieren",
            LineInFileAction(
                path=self.NGINX_CONF,
                line="    server_tokens off;",
                match=r"^\s*server_tokens\b",
            ),
        )

        for domain, docroot in self._vhosts:
            yield (
                f"Docroot anlegen ({domain})",
                MakeDirAction(path=docroot, mode=0o755, parents=True),
            )
            yield (
                f"Docroot-Eigentümer setzen ({domain})",
                PermissionsAction(
                    path=docroot, owner=self.DOCROOT_OWNER, group=self.DOCROOT_GROUP
                ),
            )
            site_file = str(Path(self.SITES_AVAILABLE) / domain)
            yield (
                f"vhost schreiben ({domain})",
                WriteFileAction(
                    dst=site_file,
                    content=_http_block_content(domain, docroot),
                    mode=0o644,
                    overwrite=True,
                    safe_mode=False,
                ),
            )
            yield (
                f"vhost aktivieren ({domain})",
                SymlinkAction(
                    link_path=str(Path(self.SITES_ENABLED) / domain),
                    target=site_file,
                    overwrite=True,
                ),
            )

        yield (
            "nginx-Konfiguration prüfen",
            SysCmdAction([self.NGINX_BIN, "-t"], timeout=30),
        )
        yield (
            "nginx neu laden",
            self.SYSTEMD_ACTION_CLS(operation="reload", unit="nginx", timeout=60),
        )
        yield (
            "Firewall 443/tcp öffnen",
            SysCmdAction([self.UFW_BIN, "allow", "443/tcp"], timeout=30),
        )

    def _run_certbot(self) -> int:
        """Bezieht die Zertifikate je Domain; öffnet Port 80 nur dafür.

        Fail-closed: Port 80 wird im finally-Zweig in jedem Fall wieder
        geschlossen, auch wenn ein certbot-Aufruf scheitert (konv-
        scripting-python.md Abschnitt 4.7, analog zum EXIT-trap im
        Bash-Original).

        Returns:
            0 bei Erfolg, 1 beim ersten fehlgeschlagenen Schritt.
        """
        if (
            self._step(
                "Firewall 80/tcp temporär öffnen (certbot)",
                SysCmdAction([self.UFW_BIN, "allow", "80/tcp"], timeout=30),
            )
            != 0
        ):
            return 1
        try:
            command_base = [
                self.CERTBOT_BIN,
                "--nginx",
                "--non-interactive",
                "--agree-tos",
                "-m",
                self._certbot_mail,
                "--redirect",
            ]
            if self._certbot_mode == "staging":
                command_base.append("--staging")
            for domain, _docroot in self._vhosts:
                command = [*command_base, "-d", domain]
                if (
                    self._step(
                        f"certbot für {domain}",
                        SysCmdAction(command, timeout=self.CERTBOT_TIMEOUT),
                    )
                    != 0
                ):
                    return 1
            return 0
        finally:
            self._step(
                "Firewall 80/tcp schließen",
                SysCmdAction([self.UFW_BIN, "delete", "allow", "80/tcp"], timeout=30),
            )

    def _post_certbot_steps(self) -> Iterator[tuple[str, Action]]:
        """Liefert die Schritte nach dem Zertifikatsbezug.

        Yields:
            (Label, Aktion)-Paare in Ausführungsreihenfolge.
        """
        yield (
            "nginx-Konfiguration nach certbot prüfen",
            SysCmdAction([self.NGINX_BIN, "-t"], timeout=30),
        )
        yield (
            "nginx neu laden (nach certbot)",
            self.SYSTEMD_ACTION_CLS(operation="reload", unit="nginx", timeout=60),
        )
        yield (
            "systemd-Hardening-Verzeichnis anlegen",
            MakeDirAction(
                path=str(Path(self.HARDENING_DROPIN).parent),
                mode=0o755,
                parents=True,
            ),
        )
        yield (
            "systemd-Hardening schreiben",
            WriteFileAction(
                dst=self.HARDENING_DROPIN,
                content=_hardening_content(),
                mode=0o644,
                overwrite=True,
                safe_mode=False,
            ),
        )
        yield (
            "systemd neu laden",
            self.SYSTEMD_ACTION_CLS(operation="daemon-reload", timeout=60),
        )
        yield (
            "nginx neu starten",
            self.SYSTEMD_ACTION_CLS(operation="restart", unit="nginx", timeout=60),
        )
        yield (
            "nginx aktivieren",
            self.SYSTEMD_ACTION_CLS(operation="enable", unit="nginx", timeout=60),
        )
        if not Path(self.AA_PROFILE).exists():
            yield (
                "AppArmor-Profil erzeugen",
                SysCmdAction([self.AA_AUTODEP_BIN, "nginx"], timeout=60),
            )
        yield (
            "AppArmor-Profil auf complain setzen",
            SysCmdAction([self.AA_COMPLAIN_BIN, "nginx"], timeout=30),
        )

    def _step(self, label: str, action: Action) -> int:
        """Führt einen einzelnen Installationsschritt aus und meldet ihn.

        Args:
            label: Beschreibung für die Meldung.
            action: Auszuführende Aktion.

        Returns:
            0 bei Erfolg, 1 bei Fehlschlag.
        """
        self.send_message(LogLevel.INFO, "nginx", label)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "nginx", f"fehlgeschlagen: {label}")
            return 1
        return 0

    # --- Rückbau (uninstall) ---------------------------------------------

    def _uninstall(self) -> int:
        """Baut nginx zurück: vhosts, Härtung, Firewall-Regeln, Paket.

        Konfig-unabhängig wie das Original (do_uninstall läuft auch ohne
        gültige nginx_vhosts/certbot-Werte): die eigenen Server-Blöcke
        werden über den Marker-Kommentar ermittelt, nicht über
        nginx_vhosts. docroots und Let's-Encrypt-Zertifikate bleiben in
        jedem Fall unangetastet — kein Datenverlust durch uninstall.

        Returns:
            0 bei Erfolg (auch wenn nginx nicht installiert war), 1 beim
            ersten fehlgeschlagenen Schritt.
        """
        if not self._nginx_package_installed():
            self.send_message(
                LogLevel.INFO, "nginx", "Paket nginx nicht installiert — nichts zu tun"
            )
            return 0
        for label, action in self._uninstall_steps():
            if self._step(label, action) != 0:
                return 1
        return 0

    def _uninstall_steps(self) -> Iterator[tuple[str, Action]]:
        """Liefert die Rückbau-Schritte in Ausführungsreihenfolge.

        Als Generator, damit die Existenzprüfungen (Hardening-Drop-in,
        eigene vhost-Dateien, AppArmor-Profil) erst zur Laufzeit
        ausgewertet werden, analog zu _pre_certbot_steps.

        Yields:
            (Label, Aktion)-Paare in Ausführungsreihenfolge.
        """
        if self._ufw_rule_present(80):
            yield (
                "Firewall 80/tcp zurücknehmen",
                SysCmdAction([self.UFW_BIN, "delete", "allow", "80/tcp"], timeout=30),
            )
        if self._ufw_rule_present(443):
            yield (
                "Firewall 443/tcp zurücknehmen",
                SysCmdAction([self.UFW_BIN, "delete", "allow", "443/tcp"], timeout=30),
            )

        yield (
            "nginx stoppen",
            self.SYSTEMD_ACTION_CLS(operation="stop", unit="nginx", timeout=60),
        )
        yield (
            "nginx deaktivieren",
            self.SYSTEMD_ACTION_CLS(operation="disable", unit="nginx", timeout=60),
        )

        if Path(self.HARDENING_DROPIN).exists():
            yield (
                "systemd-Hardening-Drop-in entfernen",
                DeleteFileAction(path=self.HARDENING_DROPIN, safe_mode=False),
            )
            yield (
                "systemd neu laden",
                self.SYSTEMD_ACTION_CLS(operation="daemon-reload", timeout=60),
            )

        if Path(self.NGINX_CONF).exists():
            yield (
                "server_tokens-Einstellung entfernen",
                LineInFileAction(
                    path=self.NGINX_CONF,
                    line="    server_tokens off;",
                    match=r"^\s*server_tokens\b",
                    state="absent",
                ),
            )

        for name in self._own_vhost_names():
            enabled_link = Path(self.SITES_ENABLED) / name
            if enabled_link.exists() or enabled_link.is_symlink():
                yield (
                    f"vhost-Symlink entfernen ({name})",
                    DeleteFileAction(path=str(enabled_link), safe_mode=False),
                )
            yield (
                f"Server-Block entfernen ({name})",
                DeleteFileAction(
                    path=str(Path(self.SITES_AVAILABLE) / name), safe_mode=False
                ),
            )

        if Path(self.AA_PROFILE).exists():
            if Path(self.APPARMOR_PARSER_BIN).exists():
                yield (
                    "AppArmor-Profil entladen",
                    SysCmdAction(
                        [self.APPARMOR_PARSER_BIN, "-R", self.AA_PROFILE], timeout=30
                    ),
                )
            else:
                self.send_message(
                    LogLevel.WARN,
                    "nginx",
                    f"{self.APPARMOR_PARSER_BIN} nicht verfügbar — AppArmor-Profil"
                    " wird nur als Datei entfernt, nicht aktiv entladen",
                )
            yield (
                "AppArmor-Profil-Datei entfernen",
                DeleteFileAction(path=self.AA_PROFILE, safe_mode=False),
            )

        self.send_message(
            LogLevel.WARN,
            "nginx",
            f"Let's-Encrypt-Zertifikate unter {self.LETSENCRYPT_LIVE} bleiben"
            " bestehen — bei Bedarf manuell entfernen (certbot delete)",
        )
        yield (
            "Pakete entfernen",
            self.APT_ACTION_CLS(packages=list(self.UNINSTALL_PACKAGES), state="absent"),
        )

    def _nginx_package_installed(self) -> bool:
        """Prüft still, ob das Paket nginx aktuell installiert ist.

        Kein Teil von _verify (dort meldet _check_package jedes Ergebnis);
        hier nur ein stiller Vorab-Check für den frühen Ausstieg aus
        _uninstall.

        Returns:
            True, wenn dpkg das Paket nginx als installiert führt.
        """
        action = SysCmdAction(
            [self.DPKG_QUERY_BIN, "-W", "-f=${Status}", "nginx"], timeout=15
        )
        with contextlib.suppress(ActionError):
            action.run()
        return "install ok installed" in action.stdout

    def _ufw_rule_present(self, port: int) -> bool:
        """Prüft, ob ufw eine eingehende allow-Regel für den Port gespeichert hat.

        Ein Fehlschlag des ufw-Aufrufs selbst gilt als „Regel nicht
        gesetzt" (wie im Original: dessen grep gegen die — dann leere —
        Ausgabe liefert ebenfalls keinen Treffer).

        Args:
            port: Zu prüfender TCP-Port.

        Returns:
            True, wenn eine passende allow-Regel gespeichert ist.
        """
        action = SysCmdAction([self.UFW_BIN, "show", "added"], timeout=15)
        if self.run_action(action) != 0:
            return False
        return (
            re.search(rf"^ufw allow {port}/tcp$", action.stdout, re.MULTILINE)
            is not None
        )

    def _own_vhost_names(self) -> list[str]:
        """Ermittelt die von diesem Modul angelegten Server-Block-Dateinamen.

        Liest SITES_AVAILABLE unabhängig von nginx_vhosts — die eigenen
        Dateien tragen den Marker-Kommentar in der ersten Zeile (siehe
        _OWN_FILE_MARKER).

        Returns:
            Nach Dateiname sortierte Liste der eigenen Server-Blöcke.
        """
        directory = Path(self.SITES_AVAILABLE)
        if not directory.is_dir():
            return []
        names: list[str] = []
        for entry in sorted(directory.iterdir()):
            if not entry.is_file():
                continue
            content = self._read_text(str(entry))
            first_line = content.splitlines()[0] if content else ""
            if _OWN_FILE_MARKER in first_line:
                names.append(entry.name)
        return names

    # --- Funktionstest (test) --------------------------------------------

    def _test(self) -> int:
        """Führt einen Funktionstest ohne Systemänderung durch.

        Sammelnd wie _verify: alle Prüfungen laufen durch, ohne beim
        ersten Fehlschlag abzubrechen.

        Returns:
            0, wenn alle Prüfungen erfolgreich waren, sonst 1.
        """
        ok = True
        ok &= self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", "nginx"], "active", "nginx aktiv"
        )
        ok &= self._check_tcp_connect()
        ok &= self._check_certbot_dry_run()
        self.send_message(
            LogLevel.INFO,
            "nginx",
            "HTTPS-Abruf der Domains von außen manuell verifizieren"
            " (Zertifikatskette, Redirect 80→443)",
        )
        return 0 if ok else 1

    def _check_tcp_connect(self) -> bool:
        """Prüft einen lokalen TCP-Connect, ohne TLS-Handshake.

        Dependency-frei und sitzungs-neutral, wie im Original (dort über
        /dev/tcp statt eines echten HTTPS-Abrufs).

        Returns:
            True bei erfolgreichem Connect, sonst False.
        """
        target = f"{self.TEST_TCP_HOST}:{self.TEST_TCP_PORT}"
        try:
            with socket.create_connection(
                (self.TEST_TCP_HOST, self.TEST_TCP_PORT), timeout=self.TEST_TCP_TIMEOUT
            ):
                pass
        except OSError:
            self.send_message(
                LogLevel.ERROR, "nginx", f"TCP-Connect auf {target} fehlgeschlagen"
            )
            return False
        self.send_message(LogLevel.INFO, "nginx", f"TCP-Connect auf {target} ok")
        return True

    def _check_certbot_dry_run(self) -> bool:
        """Prüft die Zertifikatserneuerung als Trockenlauf.

        Braucht erreichbaren Port 80 — deshalb temporär geöffnet.
        Fail-closed (konv-scripting-python.md Abschnitt 4.7, analog zu
        _run_certbot): der finally-Zweig schließt Port 80 in jedem Fall
        wieder, auch wenn certbot renew scheitert.

        Returns:
            True, wenn certbot renew --dry-run erfolgreich lief und Port
            80 danach wieder geschlossen wurde.
        """
        self.send_message(
            LogLevel.INFO, "nginx", "certbot renew --dry-run (Port 80/tcp temporär)"
        )
        if (
            self.run_action(SysCmdAction([self.UFW_BIN, "allow", "80/tcp"], timeout=30))
            != 0
        ):
            self.send_message(
                LogLevel.ERROR, "nginx", "Firewall 80/tcp öffnen fehlgeschlagen"
            )
            return False
        try:
            action = SysCmdAction(
                [self.CERTBOT_BIN, "renew", "--dry-run"], timeout=self.CERTBOT_TIMEOUT
            )
            if self.run_action(action) == 0:
                self.send_message(LogLevel.INFO, "nginx", "certbot renew --dry-run ok")
                dry_run_ok = True
            else:
                self.send_message(
                    LogLevel.ERROR, "nginx", "certbot renew --dry-run fehlgeschlagen"
                )
                dry_run_ok = False
        finally:
            close_ok = (
                self.run_action(
                    SysCmdAction(
                        [self.UFW_BIN, "delete", "allow", "80/tcp"], timeout=30
                    )
                )
                == 0
            )
            if not close_ok:
                self.send_message(
                    LogLevel.ERROR, "nginx", "Firewall 80/tcp schließen fehlgeschlagen"
                )
        return dry_run_ok and close_ok

    # --- Abgleich (check) ----------------------------------------------

    def _verify(self) -> int:
        """Gleicht den Ist-Zustand mit den eigenen Installationsschritten ab.

        Prüft nur, ob die eigenen install-Aktionen gewirkt haben — kein
        System-Audit. Läuft alle Prüfungen durch und sammelt das Ergebnis.

        Returns:
            0 bei vollständiger Übereinstimmung, sonst 1.
        """
        ok = True
        ok &= self._check_packages()
        ok &= self._check_svc_enabled("nginx")
        ok &= self._check_nginx_syntax()
        ok &= self._check_server_tokens()
        for domain, docroot in self._vhosts:
            ok &= self._check_vhost(domain, docroot)
        ok &= self._check_firewall()
        ok &= self._check_hardening_dropin()
        ok &= self._check_apparmor()
        return 0 if ok else 1

    def _check_packages(self) -> bool:
        """Prüft, ob alle PACKAGES installiert sind."""
        ok = True
        for package in self.PACKAGES:
            ok &= self._check_package(package)
        return ok

    def _check_package(self, package: str) -> bool:
        """Prüft, ob ein einzelnes Paket installiert ist.

        Args:
            package: Zu prüfender Paketname.

        Returns:
            True, wenn dpkg das Paket als installiert führt.
        """
        action = SysCmdAction(
            [self.DPKG_QUERY_BIN, "-W", "-f=${Status}", package], timeout=15
        )
        with contextlib.suppress(ActionError):
            action.run()
        if "install ok installed" in action.stdout:
            self.send_message(LogLevel.INFO, "nginx", f"Paket installiert: {package}")
            return True
        self.send_message(LogLevel.ERROR, "nginx", f"Paket fehlt: {package}")
        return False

    def _check_svc_enabled(self, unit: str) -> bool:
        """Prüft, ob eine systemd-Einheit aktiv und boot-persistent ist.

        Args:
            unit: Name der Einheit.

        Returns:
            True, wenn aktiv und enabled.
        """
        active = self._check_value(
            [self.SYSTEMCTL_BIN, "is-active", unit], "active", f"{unit} aktiv"
        )
        enabled = self._check_value(
            [self.SYSTEMCTL_BIN, "is-enabled", unit],
            "enabled",
            f"{unit} aktiviert (boot-persistent)",
        )
        return active and enabled

    def _check_nginx_syntax(self) -> bool:
        """Prüft die nginx-Konfiguration per nginx -t."""
        action = SysCmdAction([self.NGINX_BIN, "-t"], timeout=30)
        if self.run_action(action) == 0:
            self.send_message(LogLevel.INFO, "nginx", "nginx -t: ok")
            return True
        self.send_message(LogLevel.ERROR, "nginx", "nginx -t meldet Fehler")
        return False

    def _check_server_tokens(self) -> bool:
        """Prüft, ob server_tokens off; in NGINX_CONF gesetzt ist."""
        content = self._read_text(self.NGINX_CONF)
        if content is not None and re.search(
            r"^\s*server_tokens\s+off;", content, re.MULTILINE
        ):
            self.send_message(LogLevel.INFO, "nginx", "server_tokens off gesetzt")
            return True
        self.send_message(
            LogLevel.ERROR, "nginx", f"server_tokens off fehlt in {self.NGINX_CONF}"
        )
        return False

    def _check_vhost(self, domain: str, docroot: str) -> bool:
        """Prüft Server-Block, docroot und Zertifikat eines vhosts.

        Args:
            domain: Domainname des vhosts.
            docroot: Erwartetes Wurzelverzeichnis.

        Returns:
            True, wenn alle Teilprüfungen des vhosts erfolgreich sind.
        """
        ok = True
        site_file = Path(self.SITES_AVAILABLE) / domain
        enabled_link = Path(self.SITES_ENABLED) / domain
        if site_file.is_file() and enabled_link.is_symlink():
            self.send_message(LogLevel.INFO, "nginx", f"vhost {domain} aktiviert")
        else:
            self.send_message(
                LogLevel.ERROR, "nginx", f"vhost {domain} fehlt oder nicht aktiviert"
            )
            ok = False

        if Path(docroot).is_dir():
            self.send_message(LogLevel.INFO, "nginx", f"docroot {docroot} vorhanden")
        else:
            self.send_message(LogLevel.ERROR, "nginx", f"docroot {docroot} fehlt")
            ok = False

        cert_dir = Path(self.LETSENCRYPT_LIVE) / domain
        if cert_dir.is_dir():
            self.send_message(
                LogLevel.INFO, "nginx", f"Zertifikat für {domain} vorhanden"
            )
        else:
            self.send_message(
                LogLevel.ERROR,
                "nginx",
                f"kein Zertifikat für {domain} unter {self.LETSENCRYPT_LIVE}",
            )
            ok = False

        ok &= self._check_privkey_perms(domain)

        content = self._read_text(str(site_file))
        if content is not None and "options-ssl-nginx.conf" in content:
            self.send_message(
                LogLevel.INFO,
                "nginx",
                f"certbot-TLS-Konfig in vhost {domain} eingebunden",
            )
        else:
            self.send_message(
                LogLevel.ERROR,
                "nginx",
                f"certbot-TLS-Konfig im vhost {domain} nicht eingebunden",
            )
            ok = False
        return ok

    def _check_privkey_perms(self, domain: str) -> bool:
        """Prüft, dass der TLS-Privatschlüssel für andere nicht lesbar ist.

        Args:
            domain: Domainname des vhosts.

        Returns:
            True, wenn der Schlüssel vorhanden ist und "others" keinen
            Zugriff hat.
        """
        privkey = Path(self.LETSENCRYPT_LIVE) / domain / "privkey.pem"
        try:
            mode = stat.S_IMODE(privkey.stat().st_mode)
        except OSError:
            self.send_message(
                LogLevel.ERROR,
                "nginx",
                f"TLS-Privatschlüssel für {domain} fehlt ({privkey})",
            )
            return False
        if mode & 0o007 == 0:
            self.send_message(
                LogLevel.INFO,
                "nginx",
                f"TLS-Privatschlüssel {domain} nicht für andere lesbar ({oct(mode)})",
            )
            return True
        self.send_message(
            LogLevel.ERROR,
            "nginx",
            f"TLS-Privatschlüssel {domain} zu offen ({oct(mode)})",
        )
        return False

    def _check_firewall(self) -> bool:
        """Prüft, dass 443/tcp offen und 80/tcp im Normalbetrieb zu ist."""
        action = SysCmdAction([self.UFW_BIN, "show", "added"], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "nginx", "ufw-Regeln nicht lesbar")
            return False
        rules = action.stdout

        ok = True
        if re.search(r"^ufw allow 443/tcp$", rules, re.MULTILINE):
            self.send_message(LogLevel.INFO, "nginx", "443/tcp eingehend erlaubt")
        else:
            self.send_message(
                LogLevel.ERROR, "nginx", "443/tcp eingehend nicht erlaubt"
            )
            ok = False

        if not re.search(r"^ufw allow 80/tcp$", rules, re.MULTILINE):
            self.send_message(
                LogLevel.INFO, "nginx", "80/tcp eingehend nicht erlaubt (Soll)"
            )
            return ok

        status_action = SysCmdAction([self.UFW_BIN, "status", "verbose"], timeout=15)
        ufw_active = (
            self.run_action(status_action) == 0
            and "Status: active" in status_action.stdout
        )
        if ufw_active:
            self.send_message(
                LogLevel.ERROR,
                "nginx",
                "80/tcp eingehend offen (ufw aktiv) — soll im Normalbetrieb"
                " geschlossen sein",
            )
            ok = False
        else:
            self.send_message(
                LogLevel.WARN,
                "nginx",
                "80/tcp-Regel gesetzt, ufw inaktiv — greift nicht, im"
                " Normalbetrieb entfernen",
            )
        return ok

    def _check_hardening_dropin(self) -> bool:
        """Prüft Existenz, Rechte und Eigentümer des Hardening-Drop-ins."""
        return self._check_file_mode(self.HARDENING_DROPIN, 0o644, "root", "root")

    def _check_apparmor(self) -> bool:
        """Prüft, ob ein AppArmor-Profil für nginx geladen ist."""
        action = SysCmdAction([self.AA_STATUS_BIN], timeout=15)
        if self.run_action(action) != 0:
            self.send_message(LogLevel.ERROR, "nginx", "AppArmor-Status nicht lesbar")
            return False
        output = action.stdout
        if "usr.sbin.nginx" not in output:
            self.send_message(
                LogLevel.ERROR, "nginx", "AppArmor-Profil für nginx nicht geladen"
            )
            return False
        enforce_section = output.split("complain mode", 1)[0]
        if "usr.sbin.nginx" in enforce_section.split("enforce mode", 1)[-1]:
            self.send_message(
                LogLevel.INFO, "nginx", "AppArmor-Profil geladen (enforce)"
            )
        else:
            self.send_message(
                LogLevel.INFO, "nginx", "AppArmor-Profil geladen (complain)"
            )
        return True

    def _check_file_mode(self, path: str, mode: int, owner: str, group: str) -> bool:
        """Prüft Existenz, Rechte und Eigentümer eines Dateisystemobjekts.

        Args:
            path: Zu prüfender Pfad.
            mode: Erwartete Rechte.
            owner: Erwarteter Eigentümer-Name.
            group: Erwartete Gruppe.

        Returns:
            True bei vollständiger Übereinstimmung.
        """
        try:
            st = Path(path).stat()
        except OSError:
            self.send_message(LogLevel.ERROR, "nginx", f"{path} fehlt")
            return False

        ok = True
        actual_mode = stat.S_IMODE(st.st_mode)
        if actual_mode != mode:
            self.send_message(
                LogLevel.ERROR,
                "nginx",
                f"{path}: Rechte {oct(actual_mode)}, erwartet {oct(mode)}",
            )
            ok = False

        try:
            actual_owner = pwd.getpwuid(st.st_uid).pw_name
            actual_group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            self.send_message(
                LogLevel.ERROR, "nginx", f"{path}: Eigentümer nicht auflösbar"
            )
            return False
        if actual_owner != owner or actual_group != group:
            self.send_message(
                LogLevel.ERROR,
                "nginx",
                f"{path}: Eigentümer {actual_owner}:{actual_group}, erwartet"
                f" {owner}:{group}",
            )
            ok = False

        if ok:
            self.send_message(LogLevel.INFO, "nginx", f"{path}: Rechte/Eigentümer OK")
        return ok

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
            self.send_message(LogLevel.ERROR, "nginx", f"{label}: nicht lesbar")
            return False
        current = action.stdout.strip()
        if current == expected:
            self.send_message(LogLevel.INFO, "nginx", f"{label}: {current} — OK")
            return True
        self.send_message(
            LogLevel.ERROR, "nginx", f"{label}: ist {current}, soll {expected}"
        )
        return False

    def _read_text(self, path: str) -> str | None:
        """Liest eine Textdatei ein, ohne bei fehlender Datei abzubrechen.

        Args:
            path: Zu lesende Datei.

        Returns:
            Dateiinhalt oder None, wenn die Datei nicht lesbar ist.
        """
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError:
            return None
