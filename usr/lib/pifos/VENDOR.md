# pifos — Provenienz des vendorten Standes

Dieser `pifos`-Baum ist eine ins Repository übernommene (vendorte) Kopie eines
Upstream-Standes plus einem lokalen Delta. Zweck dieser Datei: die Herkunft
maschinell und im Review nachprüfbar machen (ersetzt die frühere Commit-
Verifikation zur Bauzeit). Ausführliche Beschreibung: [../../../docs/installer/pifos-vendoring.md](../../../docs/installer/pifos-vendoring.md).

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
+++ b/usr/lib/pifos/module.py   (vendored)
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
`tests/unit/test_pifos_run_action_logging.py`. Der Delta sollte upstream
eingebracht werden; danach entfällt er hier.
