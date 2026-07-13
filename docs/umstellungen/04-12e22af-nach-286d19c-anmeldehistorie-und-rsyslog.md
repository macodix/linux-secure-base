# Anpassung Produktivsysteme 12e22af → 286d19c: Anmeldehistorie, rsyslog, Debian-Unterstützung

Anleitung für einen bereits laufenden Server, der auf den neuen Standard gebracht werden soll. Auf einem neu aufgesetzten Server ist nichts davon nötig — dort erledigt der Installer alles.

**Ausführung:** alle Befehle als `root`.

## 1. Geltungsbereich

Die Anleitung gilt für Server, die mit einem Stand **bis einschließlich Commit `12e22af`** (Version 0.1.1) eingerichtet wurden. Den neuen Standard bringt Commit `286d19c` (Version 0.1.2).

Betroffen ist jeder Server mit eingerichtetem Modul `logging` — also jeder nach secure-base-Standard aufgesetzte Server.

## 2. Was sich ändert

Der Anlass war die Aufnahme von Debian 13 als zweite unterstützte Distribution. Der Vergleich der beiden Distributionen hat zwei Lücken aufgedeckt, die **auch unter Ubuntu** bestanden.

### 2.1 Die Audit-Regel auf die Anmeldungen lief ins Leere

Das Regelwerk überwachte `/var/log/lastlog`. Diese Datei gibt es nicht mehr: `pam_lastlog` ist aus `libpam-modules` entfernt, und die utmp-Dateien (`wtmp`, `btmp`, `lastlog`) sind ersatzlos entfallen. Auf einem aktuellen Ubuntu existiert nicht einmal das Programm `last`.

Die Regel lädt trotzdem ohne Fehler — bei einer Datei genügt dem Kernel das Elternverzeichnis — und liefert dauerhaft null Ereignisse. Der Audit-Schlüssel `logins` war also leer, ohne dass irgendetwas darauf hinwies. Eine Regel, die in `auditctl -l` wie Abdeckung aussieht und keine ist.

Überwacht wird künftig die Datenbank, die das System tatsächlich führt.

### 2.2 Es gab keine Anmeldehistorie mehr

Als Nachfolger tritt `wtmpdb` an: eine SQLite-Datenbank unter `/var/log/wtmp.db`, die Anmelde-, Boot- und Shutdown-Zeiten führt und `last` mitbringt. Unter Debian gehört sie zur Standardinstallation, unter Ubuntu nicht — dort wird sie jetzt mitinstalliert.

Zwei Gründe: Die Datenbank überlebt die Rotation des Journals (dort gilt `MaxRetentionSec`, standardmäßig drei Monate), und sie ist ein Objekt, das die Audit-Regel überwachen kann.

### 2.3 rsyslog

`rsyslog` wird jetzt ausdrücklich mitinstalliert und aktiviert. Unter Ubuntu ist es Teil der Standardinstallation, der Schritt ändert dort nichts. Er ist für Debian nötig, wo das Paket nur `optional` ist.

### 2.4 Übersicht

| Datei / Paket | Bedeutung |
|---|---|
| `wtmpdb`, `libpam-wtmpdb` | neu installiert — Anmeldehistorie; `libpam-wtmpdb` trägt sich über `pam-auth-update` in `/etc/pam.d/common-session` ein |
| `/var/log/wtmp.db` | neu — die Datenbank, lesbar mit `last` |
| `/etc/audit/rules.d/secure-base.rules` | geändert — `-w /var/log/lastlog` entfällt, `-w /var/log/wtmp.db` kommt hinzu |
| `rsyslog` | sichergestellt — unter Ubuntu bereits vorhanden |

Die sudo-Bestandteile (`/etc/sudoers.d/secure-base-sudolog` und die beiden Audit-Regeln auf die sudoers-Pfade) hängen jetzt daran, ob `sudo` auf dem System vorliegt. Unter Ubuntu ist das der Fall — es ändert sich nichts.

Das Modul `unattended` schreibt unter Ubuntu unverändert denselben `Allowed-Origins`-Block. Die neue Fallunterscheidung greift nur unter Debian.

Es kommt **kein neuer Konfigurationsschlüssel** hinzu. Die bestehende `etc/secure-base/secure-base.conf` bleibt unverändert gültig.

## 3. Neuen Installer-Stand einspielen

Den Installer wie gewohnt beziehen und entpacken (siehe [README](../../README.md)).

## 4. Modul neu einrichten

```
bin/secure-base-installer install logging
```

Der Lauf installiert `rsyslog` (falls nicht vorhanden) sowie `wtmpdb` und `libpam-wtmpdb`, und er schreibt die Audit-Regeldatei neu. Alle Schritte sind idempotent.

## 5. Neustart — sonst greift die neue Audit-Regel nicht

Das Regelwerk läuft im Immutable-Modus (`-e 2`). Der Kernel nimmt bis zum nächsten Neustart **keine** Regeländerung an. Die neue Regeldatei liegt also auf der Platte, geladen ist aber weiterhin die alte.

```
reboot
```

Bis dahin bleibt die alte, wirkungslose Regel aktiv. Ein Schaden entsteht dadurch nicht — die neue Überwachung beginnt eben erst mit dem Neustart.

## 6. Prüfen

Nach dem Neustart:

```
last                                  # Anmeldungen aus der neuen Datenbank
ls -l /var/log/wtmp.db                # die Datenbank selbst
auditctl -l | grep logins             # -w /var/log/wtmp.db -p wa -k logins
auditctl -s | grep enabled            # enabled 2
```

`last` zeigt zunächst nur Anmeldungen **ab** der Umstellung — die Datenbank beginnt leer, die alten utmp-Dateien gibt es nicht mehr zu importieren.

Der Abgleich prüft Pakete, Dienst und Regeldatei:

```
bin/secure-base-installer check logging
```

## 7. Grenze

Meldet `install logging` die Warnung „keine Anmeldehistorie-Datenbank vorhanden", ist die Installation von `wtmpdb` fehlgeschlagen. Dann entfällt die `logins`-Regel, und die Anmeldungen sind nur im Journal nachweisbar. Der Abgleich meldet das ebenfalls.
