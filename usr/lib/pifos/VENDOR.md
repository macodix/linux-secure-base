# pifos — Herkunft der eingebetteten Kopie

Dieser `pifos`-Baum ist eine ins Repository übernommene (eingebettete) Kopie
eines Upstream-Standes plus einem lokalen Delta. Zweck dieser Datei: die
Herkunft im Review nachprüfbar machen (ersetzt die frühere Commit-Verifikation
zur Bauzeit). Ausführlich: [../../../docs/installer/pifos-vendoring.md](../../../docs/installer/pifos-vendoring.md).

## Basis (Upstream)

| Feld | Wert |
|------|------|
| Repo | `https://github.com/macodix/pifos.git` |
| Tag | `v0.1.0` |
| Basis-Commit | `35538b7a43a328e7274b1af66eeb6db36086cabf` |
| Übernommen am | 2026-07-18 |

## Lokaler Delta gegenüber der Basis

Genau **eine** Datei weicht ab: `module.py`. Alle übrigen Dateien sind
unverändert gegenüber dem Basis-Commit (`diff -rq` bestätigt).

Prüfung: Basis-Commit beziehen und gegen diesen Baum diffen — es darf nur der
folgende Delta an `module.py` bestehen bleiben.

```diff
--- a/usr/lib/pifos/module.py   (Basis 35538b7)
+++ b/usr/lib/pifos/module.py   (eingebettet)
@@ run_action / _action_failure_detail
     def run_action(self, action: Action) -> int:
-        try:
-            status = action.run()
-            return 0 if status == "finished" else 1
-        except ActionError:
-            return 1
+        try:
+            status = action.run()
+        except ActionError as exc:
+            self.send_message(LogLevel.ERROR, type(action).__name__, str(exc))
+            return 1
+        if status != "finished":
+            self.send_message(
+                LogLevel.ERROR,
+                type(action).__name__,
+                self._action_failure_detail(action, status),
+            )
+            return 1
+        return 0
+
+    @staticmethod
+    def _action_failure_detail(action: Action, status: str) -> str:
+        returncode = getattr(action, "returncode", None)
+        stderr = getattr(action, "stderr", "")
+        detail = f"Aktion nicht abgeschlossen (Status {status!r})"
+        if returncode is not None:
+            detail += f", Returncode {returncode}"
+        if stderr:
+            detail += f"; stderr: {stderr.strip()!r}"
+        return detail
```

Zweck des Deltas: gescheiterte Werkzeugaufrufe (z. B. apt) melden Returncode
und stderr als ERROR ins Log, statt nur den Rückgabewert `1`. Regressionstest:
`tests/unit/test_pifos_run_action_logging.py`.

**Upstream-Stand:** Dieser Delta ist inzwischen upstream eingebracht (pifos
Tag `v0.1.1`, Commit `a11e79c`). Beim Anheben der eingebetteten Kopie auf
`v0.1.1` entfällt der lokale Delta, und die Basis-Tabelle verweist dann auf
einen reinen Upstream-Tag.

## Integritätsprüfung (Prüfsummen-Liste)

`make check` prüft über das Ziel `check-pifos-embed`, dass diese eingebettete
Kopie unverändert dem gesegneten Stand entspricht (Prüfsummen-Liste
`usr/lib/pifos-embed.sha256`). So fällt jede unbeabsichtigte Änderung an
`usr/lib/pifos/` sofort auf.

Bei einer **absichtlichen** Änderung (Upgrade oder bewusster Delta): danach
`make pifos-embed-manifest` ausführen (erzeugt die Prüfsummen-Liste neu) und
Basis-Tabelle sowie Delta oben aktualisieren. Die Neuerzeugung ist im Diff
sichtbar und damit im Review nachvollziehbar.
