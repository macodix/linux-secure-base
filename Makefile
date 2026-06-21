# linux-secure-base — Qualitaetspruefung (konv-scripting-bash.md Kap. 3b)
#
#   make check  — shfmt -d (Formatdiff) und shellcheck ueber alle Bash-Skripte
#   make fmt    — shfmt -w (Formatierung anwenden)
#
# Pre-commit-Hook und CI rufen `make check`.

SHELL := /bin/bash

# Alle Bash-Skripte: ausfuehrbarer Einstieg (ohne Endung) + .sh-Bibliotheken
# und Module.
SCRIPTS := installer/secure-base-installer \
	$(wildcard installer/lib/*.sh) \
	$(wildcard installer/lib/modules/*.sh)

# shfmt-Optionen einheitlich (konv-scripting-bash.md 5.11): 4 Leerzeichen,
# case-Einrueckung, Binaeroperatoren am Zeilenanfang.
SHFMT_OPTS := -i 4 -ci -bn

.PHONY: check fmt
check:
	shfmt -d $(SHFMT_OPTS) $(SCRIPTS)
	shellcheck -x $(SCRIPTS)

fmt:
	shfmt -w $(SHFMT_OPTS) $(SCRIPTS)
