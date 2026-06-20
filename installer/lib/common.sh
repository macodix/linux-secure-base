# shellcheck shell=bash
#
# secure-base Helper: Sammler
# Sourct alle thematischen Helper. Modul- und Master-Skripte sourcen
# ausschliesslich diese Datei.

_sb_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=log.sh
source "${_sb_lib_dir}/log.sh"
# shellcheck source=ui.sh
source "${_sb_lib_dir}/ui.sh"
# shellcheck source=system.sh
source "${_sb_lib_dir}/system.sh"
# shellcheck source=conf.sh
source "${_sb_lib_dir}/conf.sh"
# shellcheck source=apt.sh
source "${_sb_lib_dir}/apt.sh"
# shellcheck source=svc.sh
source "${_sb_lib_dir}/svc.sh"
# shellcheck source=file.sh
source "${_sb_lib_dir}/file.sh"
# shellcheck source=dispatch.sh
source "${_sb_lib_dir}/dispatch.sh"
# shellcheck source=check.sh
source "${_sb_lib_dir}/check.sh"
# shellcheck source=doc.sh
source "${_sb_lib_dir}/doc.sh"

unset _sb_lib_dir
