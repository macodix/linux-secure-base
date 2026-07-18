.PHONY: check check-pifos-embed pifos-embed-manifest fmt install-hooks dist

SOURCES := usr/lib/secure_base tests

# Version des Auslieferungspakets: einzige Quelle ist secure_base.__version__
# (pyproject.toml leitet sie von dort ab).
VERSION := $(shell python3 -c "import sys; sys.path.insert(0, 'usr/lib'); import secure_base; print(secure_base.__version__)")

# pifos ist als eingebettete Kopie Teil des Repos (usr/lib/pifos, Herkunft in
# usr/lib/pifos/VENDOR.md und docs/installer/pifos-vendoring.md) und wird über
# `git archive` mit ausgeliefert — kein Bauzeit-Klon mehr. Herkunfts-/Delta-
# Prüfung erfolgt auf Repo-/Review-Ebene (VENDOR.md), die Integrität der
# eingebetteten Kopie zusätzlich über die Prüfsummen-Liste (Ziel
# check-pifos-embed), die des Artefakts über die GPG-Signatur (siehe unten).
PIFOS_EMBED_DIR := usr/lib/pifos
PIFOS_EMBED_MANIFEST := usr/lib/pifos-embed.sha256
# Dateiliste der eingebetteten Kopie, deterministisch, ohne Bytecode.
PIFOS_EMBED_LIST = find $(PIFOS_EMBED_DIR) -type f -not -path '*/__pycache__/*' | LC_ALL=C sort

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

check: check-pifos-embed
	ruff format --check $(SOURCES) $(wildcard bin/*)
	ruff check $(SOURCES) $(wildcard bin/*)
	mypy --strict $(SOURCES) $(wildcard bin/*)
	pytest

# Prüft, dass die eingebettete pifos-Kopie unverändert dem gesegneten Stand
# entspricht (Prüfsummen-Liste; Herkunft in usr/lib/pifos/VENDOR.md). Offline,
# daher Teil von check.
check-pifos-embed:
	@$(PIFOS_EMBED_LIST) | xargs sha256sum | diff -u "$(PIFOS_EMBED_MANIFEST)" - >/dev/null \
		|| { echo "Abbruch: eingebettete pifos-Kopie ($(PIFOS_EMBED_DIR)) weicht von $(PIFOS_EMBED_MANIFEST) ab." \
			"Bei absichtlicher Änderung: 'make pifos-embed-manifest' ausführen und VENDOR.md aktualisieren."; exit 1; }

# Erzeugt die Prüfsummen-Liste neu (nach absichtlicher Änderung oder Upgrade).
pifos-embed-manifest:
	@$(PIFOS_EMBED_LIST) | xargs sha256sum > "$(PIFOS_EMBED_MANIFEST)"
	@echo "Neu erzeugt: $(PIFOS_EMBED_MANIFEST)"

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
	rm -rf "$$pkgdir/usr/lib/secure_base/_vendor"; \
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
