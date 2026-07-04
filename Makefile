.PHONY: check fmt install-hooks dist

SOURCES := usr/lib/lsb tests

# Version des Auslieferungspakets: einzige Quelle ist pyproject.toml.
VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])")

# pifos-Bezug für das Ein-Schritt-Paket (Plan Abschnitt 2.2): fester,
# geprüfter Versions-Tag; bei einer Anhebung hier ändern.
PIFOS_REPO := https://github.com/macodix/pifos.git
PIFOS_TAG := v0.1.0

# Schlüssel, mit dem das Artefakt signiert wird (README.md, SIGNING-KEY.asc).
SIGNING_KEY := cert@martinhenkel.net

DIST_NAME := lsb-installer-$(VERSION)

check:
	ruff format --check $(SOURCES) $(wildcard bin/*)
	ruff check $(SOURCES) $(wildcard bin/*)
	mypy --strict $(SOURCES) $(wildcard bin/*)
	pytest

fmt:
	ruff check --fix $(SOURCES) $(wildcard bin/*)
	ruff format $(SOURCES) $(wildcard bin/*)

install-hooks:
	pre-commit install

# Baut das signierte Ein-Schritt-Paket (Plan Abschnitt 2.2). Auf dem
# Entwicklungsrechner unter einem unprivilegierten Konto ausführen
# (konv-system.md Abschnitt 3.7 b) — kein Schritt hier braucht Systemrechte.
dist:
	rm -rf dist
	mkdir -p dist
	set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	pkgdir="$$tmpdir/$(DIST_NAME)"; \
	mkdir -p "$$pkgdir"; \
	git archive HEAD | tar -x -C "$$pkgdir"; \
	rm -rf "$$pkgdir/usr/lib/lsb/_vendor" "$$pkgdir/usr/lib/pifos"; \
	git clone --branch $(PIFOS_TAG) --depth 1 $(PIFOS_REPO) "$$tmpdir/pifos"; \
	mkdir -p "$$pkgdir/usr/lib"; \
	cp -r "$$tmpdir/pifos/usr/lib/pifos" "$$pkgdir/usr/lib/pifos"; \
	pip install --require-hashes --no-deps \
		--target "$$pkgdir/usr/lib/lsb/_vendor" -r requirements.txt; \
	tar czf "dist/$(DIST_NAME).tar.gz" -C "$$tmpdir" "$(DIST_NAME)"; \
	gpg --detach-sign --armor --local-user $(SIGNING_KEY) \
		-o "dist/$(DIST_NAME).tar.gz.asc" "dist/$(DIST_NAME).tar.gz"
	@echo "Erzeugt: dist/$(DIST_NAME).tar.gz und dist/$(DIST_NAME).tar.gz.asc"
