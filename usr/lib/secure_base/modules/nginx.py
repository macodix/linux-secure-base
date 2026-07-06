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
        "# Von secure-base/nginx angelegt — nicht von Hand bearbeiten.\n"
        "server {\n"
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
        "# Von secure-base/nginx angelegt — nicht von Hand bearbeiten.\n"
        "[Service]\n"
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

    CERTBOT_TIMEOUT: ClassVar[float] = 120.0

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
        """Führt Einrichtung oder Abgleich nach der Betriebsart aus.

        Returns:
            0 bei Erfolg, ungleich 0 bei Fehler.

        Raises:
            ModuleError: Bei ungültiger Konfiguration (vhosts, Mail, Modus).
        """
        self._validate()
        if self.operation == "check":
            return self._verify()
        return self._install()

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

    def _parse_vhosts(self, raw: str) -> list[tuple[str, str]]:
        """Zerlegt die kommagetrennten vhost-Einträge in (domain, docroot).

        Format je Eintrag: "domain" oder "domain|docroot"; ohne docroot
        gilt DOCROOT_BASE/domain. Sortiert nach Domainname (Determinismus).

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
            self._validate_domain(domain)
            if not docroot:
                docroot = f"{self.DOCROOT_BASE}/{domain}"
            if not _DOCROOT_RE.match(docroot) or "/../" in docroot:
                raise ModuleError(
                    f"nginx: ungültiger docroot: {docroot!r} (vhost {domain})"
                )
            vhosts.append((domain, docroot))
        return sorted(vhosts, key=lambda item: item[0])

    def _validate_domain(self, domain: str) -> None:
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
