.PHONY: check fmt install-hooks dist

SOURCES := usr/lib/secure_base tests

# Version des Auslieferungspakets: einzige Quelle ist secure_base.__version__
# (pyproject.toml leitet sie von dort ab).
VERSION := $(shell python3 -c "import sys; sys.path.insert(0, 'usr/lib'); import secure_base; print(secure_base.__version__)")

# pifos-Bezug für das Ein-Schritt-Paket (Plan Abschnitt 2.2): fester,
# geprüfter Versions-Tag; bei einer Anhebung hier ändern.
# PIFOS_COMMIT pinnt zusätzlich den erwarteten Commit-Kennwert: der Tag
# selbst ist nicht GPG-signiert, ein verschobener Tag würde sonst
# unbemerkt einen anderen Stand liefern. Nach dem Klonen wird der
# tatsächliche Commit-Kennwert dagegen geprüft; bei Abweichung bricht
# der Bau ab, statt den verschobenen Stand stillschweigend zu verwenden.
PIFOS_REPO := https://github.com/macodix/pifos.git
PIFOS_TAG := v0.1.0
PIFOS_COMMIT := 35538b7a43a328e7274b1af66eeb6db36086cabf

# Schlüssel, mit dem das Artefakt signiert wird (README.md, SIGNING-KEY.asc).
SIGNING_KEY := cert@martinhenkel.net

DIST_NAME := secure-base-installer-$(VERSION)

# Inhalt des Auslieferungspakets: nur was auf dem Zielsystem gebraucht wird —
# Entry-Point, Konfigurationsvorlage, Programmcode, dazu die Lizenz (GPL-3.0),
# die README (Bezug, Echtheitsprüfung, Installation) und die Bedienungs- und
# Aufbaubeschreibung des Installers. Test- und Bauwerkzeuge, Systembeschreibung,
# Einrichtungsanleitung und Umstellungsanleitungen bleiben im Repository.
DIST_CONTENT := bin etc usr LICENSE README.md \
	docs/installer/secure-base-installer.md

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
	test $$(id -u) -ne 0 || { echo "dist nicht als root bauen (konv-system.md 3.7 b)"; exit 1; }
	rm -rf dist
	mkdir -p dist
	set -e; \
	tmpdir=$$(mktemp -d); \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	pkgdir="$$tmpdir/$(DIST_NAME)"; \
	mkdir -p "$$pkgdir"; \
	git archive HEAD $(DIST_CONTENT) | tar -x -C "$$pkgdir"; \
	rm -rf "$$pkgdir/usr/lib/secure_base/_vendor" "$$pkgdir/usr/lib/pifos"; \
	git clone --branch $(PIFOS_TAG) --depth 1 $(PIFOS_REPO) "$$tmpdir/pifos"; \
	actual_commit=$$(git -C "$$tmpdir/pifos" rev-parse HEAD); \
	if [ "$$actual_commit" != "$(PIFOS_COMMIT)" ]; then \
		echo "Abbruch: pifos-Tag $(PIFOS_TAG) zeigt auf $$actual_commit," \
			"erwartet $(PIFOS_COMMIT) (Tag verschoben?)"; \
		exit 1; \
	fi; \
	mkdir -p "$$pkgdir/usr/lib"; \
	cp -r "$$tmpdir/pifos/usr/lib/pifos" "$$pkgdir/usr/lib/pifos"; \
	printf 'Bau g%s vom %s\n' \
		"$$(git rev-parse --short HEAD)" "$$(date +%Y-%m-%d)" \
		> "$$pkgdir/BUILD-INFO"; \
	pip install --require-hashes --no-deps \
		--target "$$pkgdir/usr/lib/secure_base/_vendor" -r requirements.txt; \
	find "$$pkgdir" -type d -name __pycache__ -prune -exec rm -rf {} +; \
	tar czf "dist/$(DIST_NAME).tar.gz" \
		--owner=0 --group=0 --numeric-owner --mode='go-w' \
		-C "$$tmpdir" "$(DIST_NAME)"; \
	smokedir="$$tmpdir/selbsttest"; \
	mkdir -p "$$smokedir"; \
	tar xzf "dist/$(DIST_NAME).tar.gz" -C "$$smokedir"; \
	got=$$(cd / && env -i PATH=/usr/bin:/bin \
		python3 "$$smokedir/$(DIST_NAME)/bin/secure-base-installer" --version); \
	case "$$got" in \
		"secure-base-installer $(VERSION)"*) ;; \
		*) echo "Abbruch: Paket-Selbsttest fehlgeschlagen ($$got)"; exit 1 ;; \
	esac; \
	gpg --detach-sign --armor --local-user $(SIGNING_KEY) \
		-o "dist/$(DIST_NAME).tar.gz.asc" "dist/$(DIST_NAME).tar.gz"
	@echo "Erzeugt: dist/$(DIST_NAME).tar.gz und dist/$(DIST_NAME).tar.gz.asc (Selbsttest bestanden)"
