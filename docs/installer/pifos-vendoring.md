# pifos-Vendoring und Upgrade

pifos ist die Grundlage des Installers (siehe [secure-base-installer](secure-base-installer.md), Abschnitt 1). Die pifos-Quelle liegt **fest im Repository** unter `usr/lib/pifos/` (Vendoring). Dieses Dokument hält Herkunft, lokale Anpassungen und das Upgrade-Verfahren fest.

## 1. Herkunft

| Feld | Wert |
|------|------|
| Quelle | `https://github.com/macodix/pifos.git` |
| Tag | `v0.1.0` |
| Commit | `35538b7a43a328e7274b1af66eeb6db36086cabf` |
| Vendort am | 2026-07-18 |
| Ziel im Repo | `usr/lib/pifos/` |

pifos wird als eigenständiges Projekt weiterentwickelt. Die vendorte Kopie ist ein festgehaltener Stand dieses Projekts plus der unten gelisteten lokalen Anpassungen.

## 2. Lokale Anpassungen

Änderungen an der vendorten Kopie gegenüber dem Upstream-Stand — bei jedem Upgrade erneut anzuwenden bzw. gegen den neuen Stand zu prüfen:

| # | Datei | Änderung | Grund |
|---|-------|----------|-------|
| 1 | `usr/lib/pifos/module.py` (`Module.run_action`) | Bei Fehlschlag Ursache (Returncode + stderr) als ERROR-Meldung an den Aufrufer melden, statt die `ActionError` zu verschlucken und nur `1` zurückzugeben. Zusätzlich Hilfsmethode `_action_failure_detail`. | Ohne dies enthielt die Logdatei nur „fehlgeschlagen: <Schritt>", nicht die eigentliche Werkzeug-Fehlermeldung (z. B. von apt). Regressionstest: `tests/unit/test_pifos_run_action_logging.py`. |

**Empfehlung:** Anpassung 1 sollte upstream in pifos einfließen; dann entfällt sie hier beim nächsten Upgrade.

## 3. Einbindung

- **Laufzeit/Dev:** Der Suchpfad enthält `usr/lib` (Entry-Point `bin/secure-base-installer` bzw. die `lsb_installer`-Installation im Dev-venv). `import pifos` löst dadurch auf `usr/lib/pifos/` auf. Es ist **keine** separate pifos-Installation nötig; eine frühere externe `pip -e`-Installation von pifos ist zu entfernen (`pip uninstall pifos`).
- **Typprüfung:** mypy prüft nur den Eigencode (`files = ["usr/lib/secure_base", "tests"]`); die vendorte pifos-Quelle gilt als Fremdcode (`pyproject.toml`, Override `pifos.*`).
- **Lint/Format:** ruff zielt via `SOURCES` nur auf `secure_base`/`tests`, nicht auf `usr/lib/pifos`.

## 4. Upgrade-Verfahren

Um pifos auf einen neuen Stand zu heben:

1. Ziel-Tag/-Commit im Upstream-Repo bestimmen.
2. Externen Klon auf den neuen Stand bringen und Commit prüfen:
   `git -C <klon> fetch --tags && git -C <klon> checkout <tag> && git -C <klon> rev-parse HEAD`.
3. Vendorte Kopie ersetzen: Inhalt von `<klon>/usr/lib/pifos/` nach `usr/lib/pifos/` übernehmen, `__pycache__` entfernen.
4. Lokale Anpassungen aus Abschnitt 2 erneut anwenden bzw. prüfen, ob sie upstream bereits enthalten sind (dann aus der Liste streichen).
5. Herkunftstabelle (Abschnitt 1) aktualisieren.
6. `make check` muss grün sein (inkl. `tests/unit/test_pifos_run_action_logging.py`).

## 5. Auslieferung (`make dist`) — [in Klärung]

Vor dem Vendoring klonte `make dist` pifos zur Bauzeit frisch am gepinnten Tag und verifizierte den Commit-Kennwert. Nach dem Vendoring liefert bereits `git archive HEAD` die pifos-Quelle mit; der Klon-Schritt entfällt und würde die vendorte (angepasste) Kopie sonst überschreiben.

Die Umstellung von `make dist` berührt den Supply-Chain-Schutz (Wegfall der Commit-Verifikation) und ist daher als Sicherheitsentscheidung offen. Der Paketbaum wird weiterhin per GPG-Signatur (`.tar.gz.asc`) als Ganzes abgesichert. Endgültige Regelung nach sicherheitlicher Bewertung.
