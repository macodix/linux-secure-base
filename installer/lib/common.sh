# shellcheck shell=bash
#
# secure-base Helper: Sammler
# Sourct alle thematischen Helper. Modul- und Master-Skripte sourcen
# ausschliesslich diese Datei.

# Deterministischer PATH fuer root-Skripte gemaess konv-scripting-bash.md 4.14 a.
# Gilt fuer den Einstieg (sourct diese Datei) und alle Modul-Prozesse
# (starten als eigene Prozesse, sourcen ebenfalls diese Datei).
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

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
# shellcheck source=optional.sh
source "${_sb_lib_dir}/optional.sh"

unset _sb_lib_dir
