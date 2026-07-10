"""Registratur aller Module in fester Ausführungsreihenfolge."""

from secure_base.module_spec import ModuleSpec
from secure_base.modules.base import Base
from secure_base.modules.fail2ban import Fail2ban
from secure_base.modules.logging import Logging
from secure_base.modules.lynis import Lynis
from secure_base.modules.monit import Monit
from secure_base.modules.nginx import Nginx
from secure_base.modules.postfix import Postfix
from secure_base.modules.restic import Restic
from secure_base.modules.rkhunter import Rkhunter
from secure_base.modules.ssh import Ssh
from secure_base.modules.ufw import Ufw
from secure_base.modules.unattended import Unattended
from secure_base.modules.users import Users

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
