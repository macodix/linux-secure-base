# shellcheck shell=bash
#
# secure-base Helper: Datei-Patcherei nach Marker-Schema
#
# Bietet:
#   file_has_line         — Regex-Suche in einer Datei
#   ensure_setting        — Einzelzeilen-Direktive idempotent setzen
#   remove_setting        — ensure_setting-Eingriff zuruecknehmen
#   ensure_line_commented — Zeile idempotent auskommentieren
#   remove_line_commented — ensure_line_commented-Eingriff zuruecknehmen
#   ensure_block          — Mehrzeiligen Block idempotent setzen
#   remove_block          — ensure_block-Eingriff zuruecknehmen
#
# Alle Aenderungen sind atomar (mktemp + mv) und idempotent.
# Das Marker-Schema (# secure-base:<key>:begin/:end) erlaubt praezisen
# Rueckbau ohne den Rest der Datei zu beschaedigen.

# Erlaubter Zeichensatz fuer den Schluessel in ensure_setting/remove_setting.
# Leerzeichen erlaubt fuer Mehrwort-Direktiven (z. B. in monit.conf).
# Variable statt Inline-Literal, damit das Leerzeichen im [[ =~ ]] nicht
# als Wortgrenze interpretiert wird.
_SB_KEY_RE='^[A-Za-z_][A-Za-z0-9_ :-]*$'

#######################################
# Prueft, ob eine Datei eine Zeile enthaelt, die auf das Regex passt.
# Arguments: $1 — Pfad, $2 — Regex
# Returns:   0 gefunden, 1 nicht gefunden
#######################################
file_has_line() {
    local pfad=$1 regex=$2
    [ -f "$pfad" ] && grep -qE "$regex" "$pfad"
}

# Intern: atomarer Ersatz <tmp> -> <pfad>.
# Permissions und Owner des Originals werden uebernommen.
_sb_replace_atomic() {
    local tmp=$1 pfad=$2
    local mode owner group
    mode=$(stat -c '%a' "$pfad")
    owner=$(stat -c '%U' "$pfad")
    group=$(stat -c '%G' "$pfad")
    chmod "$mode" "$tmp"
    chown "$owner:$group" "$tmp"
    mv "$tmp" "$pfad"
}

#######################################
# Idempotent: setzt eine Einzelzeilen-Direktive auf den Sollwert
# nach dem Marker-Schema (secure-base:<key>:begin/:end).
# Arguments:
#   $1 — Pfad
#   $2 — Schluessel
#   $3 — Sollwert
#   $4 — Separator (default: Leerzeichen)
#   $5 — Kommentar-Praefix (default: #)
#######################################
ensure_setting() {
    local pfad=$1 key=$2 sollwert=$3 sep=${4:- } cp=${5:-#}
    [ -f "$pfad" ] || die "Datei nicht gefunden: $pfad"
    [[ "$key" =~ $_SB_KEY_RE ]] \
        || die "ensure_setting: ungueltiger key: $key"

    local tmp
    tmp=$(mktemp "${pfad}.XXXXXX")

    awk -v key="$key" -v sollwert="$sollwert" -v sep="$sep" -v cp="$cp" '
        BEGIN { patched = 0; in_active = 0; keep_active = 0 }
        $0 == cp " secure-base:" key ":begin" {
            in_active = 1
            if (!patched) {
                print
                getline
                printf "%s%s%s\n", key, sep, sollwert
                patched = 1
                keep_active = 1
            } else {
                keep_active = 0
            }
            next
        }
        in_active {
            if ($0 == cp " secure-base:" key ":end") {
                if (keep_active) print
                in_active = 0
                keep_active = 0
            }
            next
        }
        $0 == cp " secure-base:" key ":original-begin" \
            || $0 == cp " secure-base:" key ":original-comment-begin" \
            || $0 == cp " secure-base:" key ":original-extra-begin" {
            print; getline; print; getline; print
            next
        }
        $0 ~ "^[ \t]*" key "[ \t=]+" {
            if (!patched) {
                printf "%s secure-base:%s:original-begin\n", cp, key
                printf "%s%s\n", cp, $0
                printf "%s secure-base:%s:original-end\n", cp, key
                printf "%s secure-base:%s:begin\n", cp, key
                printf "%s%s%s\n", key, sep, sollwert
                printf "%s secure-base:%s:end\n", cp, key
                patched = 1
            } else {
                printf "%s secure-base:%s:original-extra-begin\n", cp, key
                printf "%s%s\n", cp, $0
                printf "%s secure-base:%s:original-extra-end\n", cp, key
            }
            next
        }
        !patched && $0 ~ "^" cp "[ \t]*" key "[ \t=]+" {
            printf "%s secure-base:%s:original-comment-begin\n", cp, key
            print
            printf "%s secure-base:%s:original-comment-end\n", cp, key
            printf "%s secure-base:%s:begin\n", cp, key
            printf "%s%s%s\n", key, sep, sollwert
            printf "%s secure-base:%s:end\n", cp, key
            patched = 1
            next
        }
        { print }
        END {
            if (!patched) {
                printf "%s secure-base:%s:begin\n", cp, key
                printf "%s%s%s\n", key, sep, sollwert
                printf "%s secure-base:%s:end\n", cp, key
            }
        }
    ' "$pfad" >"$tmp" \
        || { rm -f "$tmp"; die "awk-Fehler in ensure_setting: $pfad ($key)"; }

    _sb_replace_atomic "$tmp" "$pfad"
    log INFO "ensure_setting $pfad: ${key}${sep}${sollwert}"
}

#######################################
# Idempotent: nimmt einen ensure_setting-Eingriff fuer <key> zurueck.
# Arguments: $1 — Pfad, $2 — Schluessel, $3 — Kommentar-Praefix (default: #)
#######################################
remove_setting() {
    local pfad=$1 key=$2 cp=${3:-#}
    [ -f "$pfad" ] || { log INFO "remove_setting: $pfad fehlt — uebersprungen"; return 0; }
    [[ "$key" =~ $_SB_KEY_RE ]] \
        || die "remove_setting: ungueltiger key: $key"

    local tmp
    tmp=$(mktemp "${pfad}.XXXXXX")

    awk -v key="$key" -v cp="$cp" '
        BEGIN { in_active = 0; in_orig = 0; in_orig_extra = 0; in_orig_comment = 0 }
        $0 == cp " secure-base:" key ":begin"        { in_active = 1; next }
        in_active {
            if ($0 == cp " secure-base:" key ":end") in_active = 0
            next
        }
        $0 == cp " secure-base:" key ":original-begin" { in_orig = 1; next }
        in_orig {
            if ($0 == cp " secure-base:" key ":original-end") { in_orig = 0; next }
            sub("^" cp, "")
            print
            next
        }
        $0 == cp " secure-base:" key ":original-extra-begin" { in_orig_extra = 1; next }
        in_orig_extra {
            if ($0 == cp " secure-base:" key ":original-extra-end") { in_orig_extra = 0; next }
            sub("^" cp, "")
            print
            next
        }
        $0 == cp " secure-base:" key ":original-comment-begin" { in_orig_comment = 1; next }
        in_orig_comment {
            if ($0 == cp " secure-base:" key ":original-comment-end") { in_orig_comment = 0; next }
            print
            next
        }
        { print }
    ' "$pfad" >"$tmp" \
        || { rm -f "$tmp"; die "awk-Fehler in remove_setting: $pfad ($key)"; }

    _sb_replace_atomic "$tmp" "$pfad"
    log INFO "remove_setting $pfad: $key"
}

# Intern: prueft, ob die Zielzeile bereits in einem :original-Rahmen
# fuer <key> mit korrektem cp-Praefix ausgekommentiert ist.
_sb_line_already_commented() {
    local pfad=$1 cp=$2 key=$3 line_str=$4
    [ -f "$pfad" ] || return 1
    awk -v cp="$cp" -v key="$key" -v line="$line_str" '
        $0 == cp " secure-base:" key ":original-begin" { in_orig = 1; next }
        in_orig {
            if ($0 == cp " secure-base:" key ":original-end") { in_orig = 0; next }
            stripped = substr($0, length(cp) + 1)
            if (stripped == line) found = 1
            next
        }
        END { exit !found }
    ' "$pfad"
}

#######################################
# Idempotent: kommentiert eine bestehende aktive Zeile aus.
# Nur :original-Rahmen, kein :begin/:end-Aktivblock.
# Voll-Zeilen-Vergleich ($0 == line_str), kein Regex.
# Arguments:
#   $1 — Pfad
#   $2 — Schluessel-Name (fuer Marker)
#   $3 — exakter Zeilen-String
#   $4 — Kommentar-Praefix (default: #)
#######################################
ensure_line_commented() {
    local pfad=$1 key=$2 line_str=$3 cp=${4:-#}
    [ -f "$pfad" ] || die "Datei nicht gefunden: $pfad"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_:-]*$ ]] \
        || die "ensure_line_commented: ungueltiger key-name: $key"

    if grep -qxF "${cp} secure-base:${key}:begin" "$pfad"; then
        die "ensure_line_commented: key '$key' wird bereits durch ensure_setting/ensure_block belegt (Marker :begin in $pfad)"
    fi

    if _sb_line_already_commented "$pfad" "$cp" "$key" "$line_str"; then
        log INFO "ensure_line_commented $pfad: $key bereits gesetzt"
        return 0
    fi

    if ! awk -v line="$line_str" '$0 == line { f=1; exit } END { exit !f }' "$pfad"; then
        log INFO "ensure_line_commented $pfad: $key — Zielzeile nicht gefunden, nichts zu tun"
        return 0
    fi

    local tmp
    tmp=$(mktemp "${pfad}.XXXXXX")

    awk -v key="$key" -v line="$line_str" -v cp="$cp" '
        BEGIN { first = 1 }
        $0 == line {
            if (first) {
                printf "%s secure-base:%s:original-begin\n", cp, key
                printf "%s%s\n", cp, $0
                printf "%s secure-base:%s:original-end\n", cp, key
                first = 0
            } else {
                printf "%s secure-base:%s:original-extra-begin\n", cp, key
                printf "%s%s\n", cp, $0
                printf "%s secure-base:%s:original-extra-end\n", cp, key
            }
            next
        }
        { print }
    ' "$pfad" >"$tmp" \
        || { rm -f "$tmp"; die "awk-Fehler in ensure_line_commented: $pfad ($key)"; }

    _sb_replace_atomic "$tmp" "$pfad"
    log INFO "ensure_line_commented $pfad: $key"
}

#######################################
# Idempotent: nimmt einen ensure_line_commented-Eingriff zurueck.
# Arguments: $1 — Pfad, $2 — Schluessel-Name, $3 — Kommentar-Praefix (default: #)
#######################################
remove_line_commented() {
    local pfad=$1 key=$2 cp=${3:-#}
    [ -f "$pfad" ] || { log INFO "remove_line_commented: $pfad fehlt — uebersprungen"; return 0; }
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_:-]*$ ]] \
        || die "remove_line_commented: ungueltiger key-name: $key"

    if ! grep -qxF "${cp} secure-base:${key}:original-begin" "$pfad" \
        && ! grep -qxF "${cp} secure-base:${key}:original-extra-begin" "$pfad"; then
        log INFO "remove_line_commented $pfad: $key — keine Marker gefunden, uebersprungen"
        return 0
    fi

    local tmp
    tmp=$(mktemp "${pfad}.XXXXXX")

    awk -v key="$key" -v cp="$cp" '
        function strip_cp(s,    n) {
            n = length(cp)
            if (substr(s, 1, n) == cp) return substr(s, n + 1)
            return s
        }
        $0 == cp " secure-base:" key ":original-begin"       { in_orig = 1; next }
        in_orig {
            if ($0 == cp " secure-base:" key ":original-end") { in_orig = 0; next }
            print strip_cp($0)
            next
        }
        $0 == cp " secure-base:" key ":original-extra-begin" { in_extra = 1; next }
        in_extra {
            if ($0 == cp " secure-base:" key ":original-extra-end") { in_extra = 0; next }
            print strip_cp($0)
            next
        }
        { print }
    ' "$pfad" >"$tmp" \
        || { rm -f "$tmp"; die "awk-Fehler in remove_line_commented: $pfad ($key)"; }

    _sb_replace_atomic "$tmp" "$pfad"
    log INFO "remove_line_commented $pfad: $key"
}

# Intern: prueft, ob der Block <name> mit exakt <inhalt> bereits existiert.
_sb_block_exists_with_content() {
    local pfad=$1 cp=$2 name=$3 inhalt=$4
    [ -f "$pfad" ] || return 1
    local current
    current=$(awk -v cp="$cp" -v name="$name" '
        $0 == cp " secure-base:" name ":end"   { inside=0; next }
        inside                                  { print }
        $0 == cp " secure-base:" name ":begin" { inside=1; next }
    ' "$pfad")
    [ "$current" = "$inhalt" ]
}

#######################################
# Idempotent: setzt einen mehrzeiligen Block nach dem Marker-Schema.
# Arguments:
#   $1 — Pfad
#   $2 — Block-Name
#   $3 — Inhalt (mehrzeiliger String)
#   $4 — Regex fuer Beginn des zu kommentierenden Originalbereichs (optional)
#   $5 — Regex fuer Ende des Originalbereichs (optional)
#   $6 — Kommentar-Praefix (default: #)
#######################################
ensure_block() {
    local pfad=$1 name=$2 inhalt=$3
    local orig_begin=${4:-} orig_end=${5:-} cp=${6:-#}
    [ -f "$pfad" ] || die "Datei nicht gefunden: $pfad"

    if _sb_block_exists_with_content "$pfad" "$cp" "$name" "$inhalt"; then
        log INFO "ensure_block $pfad: $name bereits gesetzt"
        return 0
    fi

    local already_orig=0
    if grep -qxF "${cp} secure-base:${name}:original-begin" "$pfad"; then
        already_orig=1
    fi

    local tmp
    tmp=$(mktemp "${pfad}.XXXXXX")

    awk -v name="$name" -v inhalt="$inhalt" \
        -v orig_b="$orig_begin" -v orig_e="$orig_end" -v cp="$cp" \
        -v already_orig="$already_orig" '
        BEGIN { in_old = 0; in_orig = 0 }
        $0 == cp " secure-base:" name ":begin" { in_old = 1; next }
        in_old {
            if ($0 == cp " secure-base:" name ":end") { in_old = 0 }
            next
        }
        in_orig {
            printf "%s %s\n", cp, $0
            if ($0 ~ orig_e) {
                printf "%s secure-base:%s:original-end\n", cp, name
                in_orig = 0
            }
            next
        }
        orig_b != "" && already_orig == 0 && $0 ~ orig_b {
            printf "%s secure-base:%s:original-begin\n", cp, name
            printf "%s %s\n", cp, $0
            in_orig = 1
            next
        }
        { print }
        END {
            printf "%s secure-base:%s:begin\n", cp, name
            printf "%s\n", inhalt
            printf "%s secure-base:%s:end\n", cp, name
        }
    ' "$pfad" >"$tmp" \
        || { rm -f "$tmp"; die "awk-Fehler in ensure_block: $pfad ($name)"; }

    _sb_replace_atomic "$tmp" "$pfad"
    log INFO "ensure_block $pfad: $name"
}

#######################################
# Idempotent: nimmt einen ensure_block-Eingriff zurueck.
# Arguments: $1 — Pfad, $2 — Block-Name, $3 — Kommentar-Praefix (default: #)
#######################################
remove_block() {
    local pfad=$1 name=$2 cp=${3:-#}
    [ -f "$pfad" ] || { log INFO "remove_block: $pfad fehlt — uebersprungen"; return 0; }

    local tmp
    tmp=$(mktemp "${pfad}.XXXXXX")

    awk -v cp="$cp" -v name="$name" '
        BEGIN { in_block = 0; in_orig = 0 }
        $0 == cp " secure-base:" name ":begin" { in_block = 1; next }
        in_block {
            if ($0 == cp " secure-base:" name ":end") { in_block = 0 }
            next
        }
        $0 == cp " secure-base:" name ":original-begin" { in_orig = 1; next }
        in_orig {
            if ($0 == cp " secure-base:" name ":original-end") { in_orig = 0; next }
            sub("^" cp " ?", "")
            print
            next
        }
        { print }
    ' "$pfad" >"$tmp" \
        || { rm -f "$tmp"; die "awk-Fehler in remove_block: $pfad ($name)"; }

    _sb_replace_atomic "$tmp" "$pfad"
    log INFO "remove_block $pfad: $name"
}
