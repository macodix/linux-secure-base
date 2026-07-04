"""Registratur aller Module in fester Ausführungsreihenfolge."""

from lsb.module_spec import ModuleSpec
from lsb.modules.base import Base

REGISTRY = [
    ModuleSpec("base", "Grundkonfiguration", Base, optional=False),
]
