"""Standardaktionen von pifos.

Stellt SysCmdAction und CopyFileAction bereit.
"""

from pifos.actions.copy_file_action import CopyFileAction as CopyFileAction
from pifos.actions.sys_cmd_action import SysCmdAction as SysCmdAction

__all__ = ["CopyFileAction", "SysCmdAction"]
