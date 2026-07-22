# Anpassung Produktivsysteme bd0e2b3 → 7eb5452: Drift-Schutz und alte Sicherungsdateien

Anleitung für einen bereits laufenden Server. Auf einem neu aufgesetzten Server ist nur Abschnitt 3 gegenstandslos — alte Sicherungsdateien gibt es dort nicht.

**Ausführung:** alle Befehle als `root` (Wechsel per `su`).

## 1. Geltungsbereich

Gilt für Server, die mit einem Stand **bis einschließlich Commit `bd0e2b3`** eingerichtet wurden. Den neuen Stand bringt Commit `7eb5452` (Plan `installer-drift-schutz`).

## 2. Was sich ändert

Der Installer überschreibt von ihm verwaltete Dateien nicht mehr kommentarlos:

- Vor dem ersten Schreib-Schritt eines `install`-Laufs prüft eine Sammel-Prüfung alle Schreibziele gegen den Soll-Inhalt. Abweichungen (Hand-Änderung oder geänderte `secure-base.conf`) brechen den Lauf ab, bevor etwas geändert wurde; Überschreiben nur mit `--force-overwrite` je Lauf.
- Unveränderte Dateien werden nicht neu geschrieben — keine Sicherungs-Kaskaden mehr.
- Sicherungen liegen zentral unter `/var/backup/secure-base/<lauf-zeitstempel>/` statt als `.bak-*` neben den Dateien; je Datei und Lauf höchstens eine. Die restic-Passphrase und `sasl_passwd` werden nie dorthin kopiert.
- `check` meldet je verwalteter Datei: entspricht dem Soll / fehlt / weicht ab.

Auf dem Server selbst ist dafür **nichts einzurichten** — es gibt keinen gespeicherten Zustand. Das neue Verhalten greift, sobald der neue Installer-Stand benutzt wird.

Zu erwarten bei einem künftigen `install`-Lauf auf einem gepflegten Bestandssystem: Hand-angepasste verwaltete Dateien (z. B. ein von certbot erweiterter nginx-vhost) werden als Abweichung gemeldet und nicht angefasst. Das ist der Zweck der Änderung — überschrieben wird nur noch nach bewusster Freigabe.

## 3. Alte Sicherungsdateien entfernen

Die früheren Läufe haben `.bak-*`-Dateien neben den Zieldateien hinterlassen (eine je Aktion und Lauf). Sie sind Reste des alten Verfahrens und müssen von Hand weg. Erst ansehen:

```
ls /etc/postfix/*.bak-* /etc/ssh/*.bak-* /etc/aliases.bak-* \
   /etc/systemd/journald.conf.bak-* /etc/logwatch/conf/logwatch.conf.bak-* \
   /etc/fail2ban/jail.local.bak-* /etc/rkhunter.conf.bak-* \
   /etc/default/rkhunter.bak-* /etc/monit/monitrc.bak-* \
   /etc/nginx/nginx.conf.bak-* 2>/dev/null
```

Wenn nichts davon noch gebraucht wird:

```
rm -f /etc/postfix/*.bak-* /etc/ssh/*.bak-* /etc/aliases.bak-* \
      /etc/systemd/journald.conf.bak-* /etc/logwatch/conf/logwatch.conf.bak-* \
      /etc/fail2ban/jail.local.bak-* /etc/rkhunter.conf.bak-* \
      /etc/default/rkhunter.bak-* /etc/monit/monitrc.bak-* \
      /etc/nginx/nginx.conf.bak-*
```

## 4. Prüfen

Mit dem neuen Installer-Stand, rein lesend:

```
bin/secure-base-installer check
```

Erwartung: je verwalteter Datei „entspricht dem Soll" — bzw. „weicht vom Soll ab" für Dateien, die bewusst von Hand angepasst wurden (dann ist die Meldung korrekt und bleibt stehen).
