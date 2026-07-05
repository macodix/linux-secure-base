"""Registratur aller Module in fester Ausführungsreihenfolge."""

from lsb.module_spec import ModuleSpec
from lsb.modules.base import Base
from lsb.modules.fail2ban import Fail2ban
from lsb.modules.logging import Logging
from lsb.modules.lynis import Lynis
from lsb.modules.monit import Monit
from lsb.modules.nginx import Nginx
from lsb.modules.postfix import Postfix
from lsb.modules.restic import Restic
from lsb.modules.rkhunter import Rkhunter
from lsb.modules.ssh import Ssh
from lsb.modules.ufw import Ufw
from lsb.modules.unattended import Unattended
from lsb.modules.users import Users

REGISTRY = [
    ModuleSpec("base", "Grundkonfiguration", Base, optional=False),
    ModuleSpec("postfix", "Mailversand (Relay)", Postfix, optional=False),
    ModuleSpec("users", "Hauptbenutzer", Users, optional=False),
    ModuleSpec("ssh", "SSH-Härtung", Ssh, optional=False),
    ModuleSpec("ufw", "Firewall", Ufw, optional=False),
    ModuleSpec(
        "fail2ban",
        "Login-Sperren",
        Fail2ban,
        optional=False,
        optional_keys=("ignoreip",),
    ),
    ModuleSpec("rkhunter", "Rootkit-Prüfung", Rkhunter, optional=False),
    ModuleSpec("logging", "Protokollierung", Logging, optional=False),
    ModuleSpec("unattended", "Automatische Updates", Unattended, optional=False),
    ModuleSpec("restic", "Backup", Restic, optional=False),
    ModuleSpec("monit", "Dienstüberwachung", Monit, optional=False),
    ModuleSpec("lynis", "Härtungsprüfung", Lynis, optional=False),
    ModuleSpec(
        "nginx",
        "Webserver",
        Nginx,
        optional=True,
        optional_keys=("nginx_certbot_mail",),
    ),
]
