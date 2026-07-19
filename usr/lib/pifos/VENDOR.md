# pifos — Herkunft der eingebetteten Kopie

Dieser `pifos`-Baum ist eine ins Repository übernommene (eingebettete) Kopie
eines Upstream-Standes. Zweck dieser Datei: die Herkunft im Review nachprüfbar
machen (ersetzt die frühere Commit-Verifikation zur Bauzeit). Ausführlich:
[../../../docs/installer/pifos-vendoring.md](../../../docs/installer/pifos-vendoring.md).

## Basis (Upstream)

| Feld | Wert |
|------|------|
| Repo | `https://github.com/macodix/pifos.git` |
| Tag | `v0.1.1` |
| Basis-Commit | `99590525bc0810df50081da9d67435cd00e26655` |
| Übernommen am | 2026-07-19 |

## Lokaler Delta gegenüber der Basis

**Kein Code-Delta.** Der Code unter `usr/lib/pifos/` entspricht genau dem
Upstream-Stand `v0.1.1` (`diff -rq` gegen den Tag bestätigt: keine Abweichung).
Die einzige nicht zu Upstream gehörende Datei ist diese `VENDOR.md` selbst
(Metadaten, kein Code).

Hintergrund: Der frühere lokale Delta an `module.py` (Fehler-Logging in
`run_action`) ist mit `v0.1.1` in den Upstream eingeflossen und daher hier
nicht mehr nötig. Regressionstest weiterhin:
`tests/unit/test_pifos_run_action_logging.py`.

## Integritätsprüfung (Prüfsummen-Liste)

`make check` prüft über das Ziel `check-pifos-embed`, dass diese eingebettete
Kopie unverändert dem gesegneten Stand entspricht (Prüfsummen-Liste
`usr/lib/pifos-embed.sha256`). So fällt jede unbeabsichtigte Änderung an
`usr/lib/pifos/` sofort auf.

Bei einer **absichtlichen** Änderung (Upgrade oder bewusster Delta): danach
`make pifos-embed-manifest` ausführen (erzeugt die Prüfsummen-Liste neu) und
Basis-Tabelle oben aktualisieren. Die Neuerzeugung ist im Diff sichtbar und
damit im Review nachvollziehbar.
