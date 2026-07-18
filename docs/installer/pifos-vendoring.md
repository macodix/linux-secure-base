# pifos-Einbettung und Upgrade

pifos ist die Grundlage des Installers (siehe [secure-base-installer](secure-base-installer.md), Abschnitt 1). Die pifos-Quelle liegt als **eingebettete Kopie fest im Repository** unter `usr/lib/pifos/`. Dieses Dokument hält Herkunft, lokale Anpassungen, Integritätsprüfung und das Upgrade-Verfahren fest.

## 1. Herkunft

| Feld | Wert |
|------|------|
| Quelle | `https://github.com/macodix/pifos.git` |
| Tag | `v0.1.0` |
| Commit | `35538b7a43a328e7274b1af66eeb6db36086cabf` |
| Übernommen am | 2026-07-18 |
| Ziel im Repo | `usr/lib/pifos/` |

pifos wird als eigenständiges Projekt weiterentwickelt. Die eingebettete Kopie ist ein festgehaltener Stand dieses Projekts plus der unten gelisteten lokalen Anpassungen. Kurzfassung der Herkunft direkt neben dem Code: `usr/lib/pifos/VENDOR.md`.

## 2. Lokale Anpassungen

Änderungen an der eingebetteten Kopie gegenüber dem Upstream-Stand — bei jedem Upgrade erneut anzuwenden bzw. gegen den neuen Stand zu prüfen:

| # | Datei | Änderung | Grund |
|---|-------|----------|-------|
| 1 | `usr/lib/pifos/module.py` (`Module.run_action`) | Bei Fehlschlag Ursache (Returncode + stderr) als ERROR-Meldung an den Aufrufer melden, statt die `ActionError` zu verschlucken und nur `1` zurückzugeben. Zusätzlich Hilfsmethode `_action_failure_detail`. | Ohne dies enthielt die Logdatei nur „fehlgeschlagen: <Schritt>", nicht die eigentliche Werkzeug-Fehlermeldung (z. B. von apt). Regressionstest: `tests/unit/test_pifos_run_action_logging.py`. |

**Stand:** Anpassung 1 ist upstream eingebracht (pifos Tag `v0.1.1`, Commit `a11e79c`). Beim Anheben der eingebetteten Kopie auf `v0.1.1` entfällt der lokale Delta (siehe Abschnitt 4).

## 3. Einbindung

- **Laufzeit/Dev:** Der Suchpfad enthält `usr/lib` (Entry-Point `bin/secure-base-installer` bzw. die `lsb_installer`-Installation im Dev-venv). `import pifos` löst dadurch auf `usr/lib/pifos/` auf. Es ist **keine** separate pifos-Installation nötig; eine frühere externe `pip -e`-Installation von pifos ist zu entfernen (`pip uninstall pifos`).
- **Typprüfung:** mypy prüft nur den Eigencode (`files = ["usr/lib/secure_base", "tests"]`); die eingebettete pifos-Kopie gilt als Fremdcode (`pyproject.toml`, Override `pifos.*`).
- **Lint/Format:** ruff zielt via `SOURCES` nur auf `secure_base`/`tests`, nicht auf `usr/lib/pifos`.

## 4. Integritätsprüfung

`make check` enthält das Ziel `check-pifos-embed`: Es vergleicht die Prüfsummen aller Dateien unter `usr/lib/pifos/` gegen die versionierte Liste `usr/lib/pifos-embed.sha256` und bricht bei jeder Abweichung ab. Damit fällt eine unbeabsichtigte Änderung der eingebetteten Kopie sofort auf. Der Schritt ist offline (kein Netzabruf) und deshalb Teil von `make check`.

Nach einer **absichtlichen** Änderung (Upgrade oder bewusster Delta) die Liste neu erzeugen:

```
make pifos-embed-manifest
```

Die Neuerzeugung ist im Diff sichtbar und damit im Review nachvollziehbar.

## 5. Upgrade-Verfahren

Um pifos auf einen neuen Stand zu heben:

1. Ziel-Tag/-Commit im Upstream-Repo bestimmen (z. B. `v0.1.1`).
2. Externen Klon auf den neuen Stand bringen und Commit prüfen:
   `git -C <klon> fetch --tags && git -C <klon> checkout <tag> && git -C <klon> rev-parse HEAD`.
3. Eingebettete Kopie ersetzen: Inhalt von `<klon>/usr/lib/pifos/` nach `usr/lib/pifos/` übernehmen, `__pycache__` entfernen.
4. Lokale Anpassungen aus Abschnitt 2 erneut anwenden bzw. prüfen, ob sie upstream bereits enthalten sind (dann aus der Liste streichen).
5. Herkunftstabelle (Abschnitt 1) und `usr/lib/pifos/VENDOR.md` aktualisieren.
6. Prüfsummen-Liste neu erzeugen: `make pifos-embed-manifest`.
7. `make check` muss grün sein (inkl. `check-pifos-embed` und `tests/unit/test_pifos_run_action_logging.py`).

## 6. Auslieferung (`make dist`) — [Abgeschlossen]

`make dist` liefert die eingebettete Kopie über `git archive HEAD` mit aus; der frühere Bauzeit-Klon samt Commit-Verifikation entfällt (er hätte die eingebettete, angepasste Kopie sonst überschrieben).

Der Wegfall der Commit-Verifikation wurde sicherheitlich bewertet (Schweregrad mittel, kein Veto): Die Artefakt-Integrität sichert weiterhin die GPG-Signatur (`.tar.gz.asc`); die Herkunft der eingebetteten Kopie sichern `VENDOR.md` (Basis-Commit + Delta) auf Review-Ebene und die Prüfsummen-Liste (Abschnitt 4) auf Build-Ebene.
