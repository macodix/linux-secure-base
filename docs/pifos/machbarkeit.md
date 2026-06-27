# pifos — Technische Machbarkeit

**Status:** [in Klärung] · **Stand:** 2026-06-27

Dieses Dokument prüft Vollständigkeit und technische Machbarkeit der Umsetzung des Bausatzes pifos in Python. Maßgeblich sind das Konzept (`docs/pifos/konzept.md`), die Anforderungsliste (`docs/pifos/anforderungen.md`) und die Diagramme (`docs/pifos/diagramme.md`).

Für jede Stelle, an der Konzept oder Anforderungen das WIE offenlassen oder mehrere Umsetzungswege bestehen, folgt ein Abschnitt mit Frage, Optionen und Empfehlung. Detailfragen mit eindeutigem fachlichem Standard sind als Empfehlung entschieden. Nur Fragen mit echter Abwägung ohne klaren Standard sind als „Entscheidung durch Martin offen" markiert. Themen, deren Festlegung noch Vorarbeit voraussetzt, sind als „vertagt" gekennzeichnet, mit Angabe des auslösenden Ereignisses.

Nicht behandelt: Auslieferung, Ablageort und Python-Mindestversion (system-engineer) sowie die Sicherheitsprüfung (sicherheits-auditor). Auffälligkeiten dazu stehen gesammelt am Dokumentende.

## 1. Übersicht der WIE-Themen

| Nr. | Thema | Betrifft | Status |
|-----|-------|----------|--------|
| T1 | Prozessmodell des Moduls | STR-01, STR-05/06, CAL-02 | Empfehlung |
| T2 | IPC-Mechanismus | STR-01/03/04, CAL-03/04 | Empfehlung |
| T3 | Nachrichtenformat über IPC | STR-03/04, LOG-02/03 | Empfehlung |
| T4 | Übergabe des Config-Objekts an den Modulprozess | STR-02, MOD-02 | Empfehlung |
| T5 | Anhalten und Fortsetzen | CAL-02 | Empfehlung |
| T6 | Beenden und terminate-Eskalation | CAL-02, EXC-03 | Empfehlung |
| T7 | Hauptschleife des Modulprozesses | MOD-05/09, STR-04 | Empfehlung |
| T8 | Weiterleitung von Ausnahmen über die Prozessgrenze | EXC-01/02/03 | Empfehlung |
| T9 | Basisklasse je Modultyp | MOD-07/12/13 | Empfehlung |
| T10 | Rollback-Mechanismus | MOD-13 | Empfehlung + Detail vertagt |
| T11 | Umfang von getter/setter | ÜBR-04 | Entscheidung durch Martin offen |
| T12 | Konfigurationsformate und Lese-/Schreibrichtung | KFG-04/05/06/07 | Empfehlung |
| T13 | Prüffeld `check` und Prüfmuster | MOD-08, KFG-09 | Empfehlung + Katalog vertagt |
| T14 | Ausführung von Systembefehlen | AKT-02/08 | Empfehlung |
| T15 | safe-mode-Sicherung | AKT-06/07 | Empfehlung |
| T16 | Weitergabe und Filterung des Loglevels | LOG-02/04/05, EXC-02 | Empfehlung |
| T17 | Konfigurator: Modulerkennung und Steuerdatei | KOR-02/06 | Empfehlung |
| T18 | Idempotenz je Modul | MOD-14 | Vertagt |

## 2. Themen

### 2.1. T1 — Prozessmodell des Moduls

**Frage.** Das Konzept spricht im Kapitel „Standardaufrufer" und in den Diagrammen vom „Modulprozess" und fordert, ihn zu starten, anzuhalten, fortzusetzen und zu beenden (CAL-02). Ein Modul meldet seinen Abschluss über einen Returncode (STR-05). Offen ist, wie ein Modul, das laut Konzept eine Python-Klasse ist, zu einem steuerbaren Prozess wird.

**Optionen.**

- `multiprocessing.Process`: startet einen eigenen Betriebssystem-Prozess derselben Python-Umgebung. Vorteil: eigener Prozess mit eigenem Exitcode (STR-05), anhaltbar und beendbar über Signale, Isolation gegenüber dem Aufrufer, Python-Objekte wie das Config-Objekt lassen sich direkt als Startargument übergeben, IPC-Primitive sind eingebaut. Nachteil: Startargumente und Zielklasse müssen serialisierbar (picklebar) sein.
- `subprocess` mit eigenem Startskript: startet einen getrennten Interpreter. Vorteil: maximale Isolation, auch nicht-pythonbasierte Module denkbar. Nachteil: erfordert ein zusätzliches Launcher-Skript und das Serialisieren der Konfiguration über Datei oder stdin; mehr Eigenbau, widerspricht KISS, da Module laut Konzept Python-Klassen sind.
- `threading`: führt das Modul im selben Prozess. Nachteil: kein eigener Exitcode, kein SIGSTOP/SIGCONT, keine Isolation bei CRITICAL-Selbstbeendigung (EXC-03), echte Parallelität durch den GIL eingeschränkt. Erfüllt die Prozesssemantik des Konzepts nicht.

**Empfehlung.** `multiprocessing.Process`. Jedes Modul läuft in einem eigenen Prozess. Das deckt Returncode (STR-05), sequenzielle und parallele Führung (STR-06) und die Steuerung (CAL-02) mit Bordmitteln ab. Als Startmethode `spawn` wählen: deterministisch und frei von den Sperr-Risiken, die `fork` bei einem mehrfädigen Aufrufer mit Rich-Oberfläche hätte. Voraussetzung ist, dass Modulklasse und Config-Objekt picklebar bleiben, also keine offenen Datei- oder Socket-Handles als Klassenvariablen halten.

### 2.2. T2 — IPC-Mechanismus

**Frage.** STR-01/03/04 und CAL-03/04 fordern bidirektionale Kommunikation zwischen Aufrufer und Modulprozess über IPC. Der konkrete Mechanismus ist offen.

**Optionen.**

- `multiprocessing.Pipe` (duplex): eine Verbindung je Modul, beide Richtungen. Vorteil: leichtgewichtig, synchrone Zustellung ohne Hintergrund-Thread, dadurch verlässliche Auslieferung vor Prozessende (wichtig für EXC-03). Mehrere Module parallel über `multiprocessing.connection.wait()` multiplexbar. Nachteil: kein eingebautes Puffer-/Sperrmanagement, nur zwei Endpunkte je Pipe.
- `multiprocessing.Queue`: je Richtung eine Queue. Vorteil: thread-sicher, mehrere Schreiber. Nachteil: nutzt einen Hintergrund-Feeder-Thread; vor dem Prozessende sind `close()` und `join_thread()` nötig, sonst gehen Nachrichten verloren — Stolperstelle gerade für EXC-03.
- Unix-Domain-Socket oder TCP: Vorteil: sprach- und hostübergreifend. Nachteil: deutlich mehr Eigenbau für einen rein lokalen Python-zu-Python-Fall, widerspricht KISS.

**Empfehlung.** Je Modulprozess eine duplexe `multiprocessing.Pipe`. Der Aufrufer schreibt Befehle hinab, das Modul schreibt Meldungen, Ergebnisse und Ausnahmen hinauf. Mehrere parallele Module multiplext der Aufrufer mit `connection.wait()`. Die synchrone Zustellung der Pipe erfüllt EXC-03 ohne Sonderbehandlung.

### 2.3. T3 — Nachrichtenformat über IPC

**Frage.** STR-03/04 unterscheiden logging-relevante und nicht logging-relevante Nachrichten, Befehle, Datenanforderungen, Ergebnisse und Ausnahmen. LOG-03 fordert die Stufen INFO/WARN/ERROR/CRITICAL. Ein einheitliches Nachrichtenformat ist nicht festgelegt.

**Optionen.**

- Eine `dataclass` `IpcMessage` mit den Feldern `kind` (z. B. COMMAND, LOG, MESSAGE, REQUEST, RESULT, EXCEPTION), `level` (eine der vier Logstufen, soweit zutreffend), `name` und `payload`. Über die Pipe gepickelt. Vorteil: ein typisierter, erweiterbarer Träger für alle Richtungen, klar lesbar. Nachteil: gemeinsame Definition, die Aufrufer und Modul teilen müssen.
- Lose Tupel oder dicts ohne feste Struktur. Vorteil: minimal. Nachteil: kein verbindlicher Vertrag, fehleranfällig bei Erweiterung.

**Empfehlung.** Eine `dataclass` `IpcMessage` mit den genannten Feldern in der pifos-Bibliothek, von beiden Seiten genutzt. `kind` trennt die Nachrichtenarten aus STR-03/04, `level` trägt die Logstufe aus LOG-03. Das hält das Protokoll an einer Stelle nachvollziehbar.

### 2.4. T4 — Übergabe des Config-Objekts an den Modulprozess

**Frage.** STR-02 und MOD-02 fordern, dass der Aufrufer das Config-Objekt beim Start an das Modul übergibt. Über eine Prozessgrenze ist das nicht trivial.

**Optionen.**

- Das Config-Objekt als Startargument von `multiprocessing.Process` übergeben. multiprocessing pickelt es automatisch in den Kindprozess. Vorteil: kein Eigenbau, das Objekt steht im Modul unmittelbar bereit. Nachteil: das Config-Objekt muss picklebar sein, also reine Daten halten.
- Konfiguration in eine temporäre Datei schreiben und den Pfad übergeben. Vorteil: keine Pickle-Anforderung. Nachteil: zusätzlicher Datei-Umweg, Aufräumpflicht, widerspricht KISS.

**Empfehlung.** Das Config-Objekt als Startargument übergeben und über multiprocessing pickeln lassen. Die Config-Klasse hält ihre Daten als einfache Strukturen (dict, list), damit sie picklebar bleibt. Module ohne Konfiguration (MOD-03) erhalten kein Argument.

### 2.5. T5 — Anhalten und Fortsetzen

**Frage.** CAL-02 fordert Methoden zum Anhalten und Fortsetzen eines Modulprozesses. Offen ist, ob das kooperativ über IPC an Prüfpunkten oder über die Signale SIGSTOP/SIGCONT geschieht.

**Optionen.**

- Kooperativ über IPC: Der Aufrufer sendet einen Pause-Befehl; das Modul prüft an definierten Prüfpunkten zwischen Aktionen und hält dort an, bis ein Fortsetzen-Befehl kommt. Vorteil: das Modul hält nur in konsistentem Zustand zwischen atomaren Aktionen, eine laufende Aktion wird nicht zerrissen. Nachteil: keine sofortige Wirkung mitten in einer langlaufenden Aktion.
- Signale SIGSTOP/SIGCONT: friert den Prozess sofort auf Betriebssystemebene ein. Vorteil: unmittelbar. Nachteil: hält den Prozess auch mitten in einer Aktion an, möglicher inkonsistenter Zwischenzustand; ein bereits gestarteter Kindprozess eines Systembefehls läuft weiter, SIGSTOP des Python-Prozesses hält ihn nicht auf. Eine Notbremse über Signale wäre eine Zusatzfunktion über das vom Konzept Geforderte hinaus (ÜBR-05).

**Empfehlung.** Kooperatives Anhalten und Fortsetzen über IPC an Prüfpunkten zwischen Aktionen. Das erfüllt CAL-02 und das Zustandsdiagramm und hält das Modul stets in konsistentem Zustand. SIGSTOP/SIGCONT nicht aufnehmen, solange kein konkreter Bedarf besteht; eine spätere Ergänzung als Notbremse bliebe möglich, bedarf aber einer eigenen Festlegung.

### 2.6. T6 — Beenden und terminate-Eskalation

**Frage.** CAL-02 fordert das Beenden des Modulprozesses; das Zustandsdiagramm zeigt `terminate_module()`. EXC-03 verlangt, dass ein sich selbst beendendes Modul vorher seine Ausnahme-Meldungen zustellt. Offen ist die Eskalationsstufe, wenn ein Modul nicht reagiert.

**Optionen.**

- Nur kooperativ: Beenden ausschließlich über IPC-Befehl. Nachteil: ein hängendes Modul ließe sich nie beenden.
- Nur hart: sofort SIGKILL. Nachteil: kein geordneter Abschluss, kein Aufräumen, EXC-03-Meldungen gingen verloren.
- Gestufte Eskalation: erst IPC-Beenden-Befehl mit geordnetem Abschluss, bei Ausbleiben einer Reaktion innerhalb eines Zeitfensters SIGTERM (`Process.terminate()`), danach SIGKILL (`Process.kill()`).

**Empfehlung.** Gestufte Eskalation in drei Schritten: IPC-Befehl, dann SIGTERM, dann SIGKILL, jeweils mit Zeitfenster. Der Regelfall ist der geordnete Abschluss über IPC, bei dem das Modul gemäß EXC-03 zuerst seine Meldungen zustellt. SIGTERM und SIGKILL sind nur die Rückfallebene für nicht reagierende Module.

### 2.7. T7 — Hauptschleife des Modulprozesses

**Frage.** MOD-09 fordert die Prüfung der Konfiguration beim Start; STR-04 fordert, dass der Aufrufer das Modul zu Aktivitäten auffordern kann. Wie der Modulprozess-Einsprung den `start()`-Aufruf und die Befehlsannahme verbindet, ist offen.

**Optionen.**

- Einmalige Ausführung: Der Prozess instanziiert das Modul, prüft `CONFIG`, ruft `start()` und endet. Nachteil: keine laufende bidirektionale Steuerung, STR-04 nicht erfüllt.
- Befehlsschleife: Eine Einsprungfunktion `module_runner` instanziiert das Modul, prüft `CONFIG` gegen die Deklaration (MOD-09), legt die Werte in den Klassenvariablen ab (MOD-04) und tritt dann in eine Schleife ein, die IPC-Befehle liest, auf Modulmethoden abbildet, Meldungen hinaufreicht und bei terminate mit Returncode endet.

**Empfehlung.** Eine Einsprungfunktion `module_runner` als Ziel von `multiprocessing.Process`, die die Befehlsschleife führt. Sie bildet Aufrufer-Befehle (Aktivität ausführen, Daten anfordern, anhalten/fortsetzen, beenden) auf Modulmethoden ab und kapselt die Ausführung in try/except für die Ausnahme-Weiterleitung (siehe T8). Das erfüllt MOD-04/09 und STR-04 an einer Stelle.

### 2.8. T8 — Weiterleitung von Ausnahmen über die Prozessgrenze

**Frage.** EXC-01/02/03 fordern, dass Aktionen und Module im Fehlerfall Ausnahmen erzeugen und Module diese an den Aufrufer weiterleiten. Python-Exceptions überschreiten eine Prozessgrenze nicht von selbst.

**Optionen.**

- Exception-Objekt pickeln und übertragen. Nachteil: nicht jede Exception ist verlustfrei picklebar, Tracebacks gehen teils verloren.
- Exception in eine `IpcMessage(kind=EXCEPTION)` überführen, die Typname, Meldung und den als Text formatierten Traceback trägt. Der Aufrufer protokolliert oder verarbeitet sie. Vorteil: robust, formatunabhängig, fügt sich in das Nachrichtenformat aus T3.

**Empfehlung.** Die Befehlsschleife (T7) fängt Ausnahmen aus Aktionen und Modulmethoden, verpackt sie in eine `IpcMessage(kind=EXCEPTION)` mit Logstufe und sendet sie hinauf. Bei CRITICAL stellt das Modul über die synchrone Pipe (T2) zuerst die Zustellung sicher und beendet sich dann mit Returncode ungleich 0 (EXC-03, STR-05).

### 2.9. T9 — Basisklasse je Modultyp

**Frage.** Das Konzept lässt offen, ob die Pflichten systemverändernder Module (Überprüfungsmodus, Rollback; MOD-12/13) über eine reine Namenskonvention oder über eine Basisklasse je Modultyp sichergestellt werden. Die Diagramme zeigen bereits `InstModule` mit `check()` und `rollback()`.

**Optionen.**

- Nur Namenskonvention (z. B. `inst_*.py`) plus Dokumentation. Vorteil: keine zusätzliche Klassenebene. Nachteil: keine strukturelle Durchsetzung, das Vorhandensein von `check()` und `rollback()` bleibt ungeprüft.
- Abstrakte Zwischenklasse `SystemChangingModule(Module)` mit den abstrakten Methoden `check()` und `rollback()`. Konkrete systemverändernde Module erben davon. Vorteil: erzwingt MOD-12/13 strukturell, eine fehlende Methode fällt schon bei der Klassendefinition auf. Nachteil: eine zusätzliche Ebene in der Vererbung.
- Mixin-Klassen. Nachteil: lockere Kopplung, keine Erzwingung; ohne Mehrwert gegenüber der Zwischenklasse.

**Empfehlung.** Eine abstrakte Zwischenklasse `SystemChangingModule(Module)` mit abstrakten `check()` und `rollback()`. Sie ist die Heimat der Pflichten aus MOD-12/13. Die beschreibenden Namen aus MOD-07 bleiben zusätzlich erhalten. Eine feinere Aufteilung in Untertypen erst, wenn ein konkreter Bedarf sie rechtfertigt (KISS, ÜBR-03).

### 2.10. T10 — Rollback-Mechanismus

**Frage.** MOD-13 fordert einen Rollback-Mechanismus. Wie ein Rückgängigmachen generisch bereitgestellt wird, hängt von den konkreten Aktionen ab, die noch nicht definiert sind.

**Optionen.**

- Jedes Modul implementiert `rollback()` vollständig selbst. Vorteil: keine gemeinsame Mechanik nötig. Nachteil: wiederkehrende Eigenlogik in jedem Modul.
- Die Basisklasse `SystemChangingModule` führt eine Undo-Registratur: ausgeführte, umkehrbare Eingriffe und die im safe-mode (AKT-06) gesicherten Dateien tragen sich ein; `rollback()` arbeitet die Registratur in umgekehrter Reihenfolge ab. Vorteil: gemeinsame, getestete Mechanik; das konkrete `rollback()` bleibt schlank. Nachteil: setzt voraus, dass die Aktionen ihr Umkehrverhalten kennen.

**Empfehlung.** Die strukturelle Festlegung jetzt treffen: abstrakte `rollback()`-Methode in `SystemChangingModule` plus eine Undo-Registratur in der Basisklasse, an die safe-mode-Sicherungen (T15) anschließen.

**Vertagt.** Die genaue Mechanik der Registratur und das Umkehrverhalten je Aktion sind vertagt. Auslöser: die Definition des konkreten Aktionssatzes und ihres jeweiligen Rückgängig-Verhaltens. Eine frühere Festlegung wäre Spekulation (ÜBR-05).

### 2.11. T11 — Umfang von getter/setter

**Frage.** ÜBR-04 fordert für jede Klassenvariable eine Lese- und eine Schreibmethode. ÜBR-03 fordert zugleich die einfachste ausreichende Lösung (KISS). Offen ist sowohl der Mechanismus als auch der Geltungsumfang.

**Optionen für den Mechanismus.**

- Hand geschriebene `get_x()`/`set_x()` je Variable. Vorteil: explizit, je Variable benannt. Nachteil: viel gleichförmiger Code, Pflegeaufwand, Spannung zu KISS.
- `@property` je Variable. Vorteil: pythonidiomatisch, getter/setter-Paar je Attribut, dort, wo Logik nötig ist, mit Prüfung erweiterbar. Nachteil: bei rein durchreichenden Variablen ebenfalls Wiederholung.
- Generische `get(name)`/`set(name, value)` in den Basisklassen (`Action`, `Module`, `Config`, `PifosCaller`), die alle Instanzattribute über ihren Namen lesen und schreiben; punktuell überschrieben durch `@property`, wo Prüfung nötig ist. Vorteil: erfüllt ÜBR-04 für jede Variable mit minimalem Code, KISS-konform. Nachteil: ein generischer Zugriff ist kein je Variable benannter Accessor; je nach Auslegung von ÜBR-04 zu allgemein.

**Geltungsumfang.** „Jede Klassenvariable" lässt offen, ob auch interne Hilfsvariablen erfasst sind oder nur die Variablen der öffentlichen Schnittstelle. Eine Einschränkung auf die öffentliche Schnittstelle wäre eine einschränkende Festlegung; das Konzept (Kapitel „Für KI") behält solche Festlegungen Martin vor.

**Empfehlung.** Als Mechanismus die generischen `get`/`set` in den Basisklassen, ergänzt um `@property` dort, wo eine Variable eine Prüfung braucht. Das erfüllt ÜBR-04 wörtlich und bleibt KISS-konform.

**Entscheidung durch Martin offen.** Die Auslegung von ÜBR-04: Genügt der generische `get`/`set`-Zugriff über alle Variablen, oder sind je Variable benannte Accessoren gewünscht, und gilt die Pflicht für alle Variablen oder nur für die öffentliche Schnittstelle. Die zweite Frage ist eine einschränkende Festlegung und damit Martin vorbehalten.

### 2.12. T12 — Konfigurationsformate und Lese-/Schreibrichtung

**Frage.** KFG-04 nennt ini, toml und json als Beispiele; KFG-05/06 fordern Übergabe als dict und zusätzlich als raw; KFG-07 erlaubt das Lesen und Schreiben von Dateien über Aktionsklassen. Der Konfigurator schreibt Konfiguration (KOR-05/06). Offen ist, welche Formate Pflicht sind, welche optional, und ob die Formatklassen nur lesen oder auch schreiben.

**Optionen für den Formatumfang.**

- Alle drei Formate sofort. Nachteil: Aufwand und Pflege für Formate, die noch kein Nutzer braucht; Spannung zu ÜBR-05.
- Ein Format zuerst, weitere bei Bedarf. Vorteil: KISS, deckt den ersten Nutzer ab.

**Lese-/Schreibrichtung.** Die Diagramme zeigen nur `to_dict()` (lesen). Der Konfigurator muss aber schreiben. Jede Formatklasse braucht daher beide Richtungen: lesen (Quelle → dict) und schreiben (dict → Datei). Die raw-Übergabe (KFG-06) liefert den unzerlegten Inhalt.

**Standardlage.** ini über `configparser` liest und schreibt mit der Standardbibliothek, ohne Zusatzpaket, und ist gut von Hand editierbar; Sektionen bilden Module natürlich ab. json liest und schreibt ebenfalls mit der Standardbibliothek. Bei toml liest `tomllib` ab Python 3.11 nur; das Schreiben von toml erfordert ein Zusatzpaket oder Eigenserialisierung, was BRS-02 berührt (auf dem Zielserver nichts nachinstallieren).

**Empfehlung.** ini (`configparser`) als primäres Format, weil es mit Bordmitteln liest und schreibt und der Konfigurator es ohne Zusatzpaket erzeugen kann; json als zweites Format für verschachtelte oder maschinennahe Konfiguration. Jede Formatklasse bietet beide Richtungen, `to_dict()` und ein Schreiben (`write()`/`from_dict()`), sowie den raw-Zugang. toml vertagen, bis ein Nutzer es braucht; dann ist die Bündelung eines toml-Schreibers mit dem system-engineer zu klären (siehe Hinweise). Martin kann das primäre Format jederzeit anders setzen.

### 2.13. T13 — Prüffeld `check` und Prüfmuster

**Frage.** MOD-08 fordert je `ConfigItem` ein Feld `check`; KFG-09 erlaubt grundlegende Prüfmuster in der Config-Klasse. KFG-08 schließt eine inhaltliche Prüfung aus. Offen ist die Form von `check`.

**Optionen.**

- `check` als optionale aufrufbare Funktion, die einen Wert annimmt und bool zurückgibt. Vorteil: flexibel, das Modul wendet sie beim Start an (MOD-09). Nachteil: Funktionsreferenzen in einer deklarativen Liste.
- `check` als Name eines vordefinierten Prüfmusters aus der Config-Klasse (KFG-09). Vorteil: rein deklarativ, gut für den Konfigurator les- und anzeigbar. Nachteil: beschränkt auf den Musterkatalog.

**Empfehlung.** `check` als optionales Feld, das entweder ein aufrufbares Prädikat oder den Namen eines Prüfmusters der Config-Klasse trägt. Die Prüfmuster sind formal, nicht inhaltlich (KFG-08): vorhanden, nicht leer, ist Zahl, ist Liste, ist kommasepariert, syntaktisch gültige Mailadresse.

**Vertagt.** Der konkrete Katalog der Prüfmuster (KFG-09, KANN) wird bedarfsgetrieben gefüllt. Auslöser: die in den ersten Modulen tatsächlich benötigten Prüfungen. Ein vollständiger Katalog vorab wäre Spekulation (ÜBR-05).

### 2.14. T14 — Ausführung von Systembefehlen

**Frage.** AKT-08 fordert eine generische Aktion für Systembefehle; AKT-02 fordert vollständige Bereitstellung von Status, stdout und stderr. Die Ausführungsart ist offen.

**Optionen.**

- `subprocess.run`: führt aus und liefert Ergebnis am Ende. Vorteil: einfach. Nachteil: keine laufende Statusmeldung während langer Befehle.
- `subprocess.Popen`: führt aus und erlaubt das laufende Lesen von stdout/stderr. Vorteil: laufende Weitergabe von Ausgaben als Meldungen, voller Zugriff auf Status und Returncode. Nachteil: etwas mehr Code für das Auslesen der Ströme.

**Empfehlung.** `subprocess.Popen` mit getrennten Strömen für stdout und stderr, ohne Shell (`shell=False`, Argumentliste). Die Aktion erfasst Status, stdout, stderr und Returncode und stellt sie gemäß AKT-02 dem Modul bereit; bei Bedarf reicht das Modul Ausgaben laufend als Meldungen hinauf.

### 2.15. T15 — safe-mode-Sicherung

**Frage.** AKT-06/07 fordern für dateiändernde Aktionen einen aktivierbaren safe-mode, der die Datei vor der Änderung sichert, mit einstellbarem Sicherungsort. Die Art der Sicherung ist offen.

**Optionen.**

- Sicherungskopie im selben Verzeichnis mit Namenszusatz (Suffix oder Zeitstempel). Vorteil: einfach, lokal nachvollziehbar.
- Sicherung in ein konfigurierbares Verzeichnis. Vorteil: zentrale Ablage der Sicherungen.

**Empfehlung.** Vor der Änderung eine Kopie anlegen. Standardziel ist derselbe Pfad mit Zeitstempel-Zusatz; das Ziel ist über die Variable `backup_location` überschreibbar (AKT-07). Die Sicherung trägt sich in die Undo-Registratur (T10) ein und dient damit zugleich dem Rollback.

### 2.16. T16 — Weitergabe und Filterung des Loglevels

**Frage.** LOG-04 fordert ein einstellbares Loglevel des Aufrufers, LOG-05 dessen Weitergabe an die Module, LOG-02 die Auswahl durch Modul und Aufrufer, EXC-02 die Weiterleitung von Ausnahmen entsprechend dem Loglevel. Das Zusammenspiel ist offen.

**Optionen.**

- Nur der Aufrufer filtert. Nachteil: das Modul sendet auch Meldungen, die der Aufrufer ohnehin verwirft.
- Loglevel beim Start an das Modul übergeben; das Modul kennzeichnet jede `IpcMessage` mit ihrer Stufe und kann unterhalb der Schwelle bereits selbst zurückhalten; der Aufrufer filtert endgültig vor dem Schreiben ins Logfile.

**Empfehlung.** Das Loglevel als Startparameter an das Modul geben (LOG-05). Das Modul kennzeichnet jede Meldung mit ihrer Stufe (LOG-03) und entscheidet, was es sendet (LOG-02); der Aufrufer entscheidet endgültig, was ins Logfile geht (LOG-01/02). Ausnahmen tragen die Stufen ERROR oder CRITICAL und werden stets weitergeleitet (EXC-02).

### 2.17. T17 — Konfigurator: Modulerkennung und Steuerdatei

**Frage.** KOR-02 fordert, dass der Konfigurator die Konfigurationsdeklarationen der Module nutzt; KOR-06 fordert bei Einzeldateien eine zentrale Steuerdatei für die Reihenfolge. Die Umsetzung ist offen. Der Konfigurator ist insgesamt optional (KOR-01, KANN).

**Optionen.**

- Modulerkennung über Import der als Parameter genannten Modulklassen und Auslesen ihres Klassenattributs `CONFIG`. Vorteil: nutzt die vorhandene Deklaration unmittelbar (MOD-08). Nachteil: erfordert importierbare Modulklassen.
- Steuerdatei im gewählten Konfigurationsformat (ini/json), die die Modulreihenfolge und die Verweise auf die Einzeldateien führt. Vorteil: gleiches Format wie die Konfiguration, keine zweite Technik.

**Empfehlung.** Der Konfigurator importiert die genannten Modulklassen und liest deren `CONFIG`-Deklaration (KOR-02). Bei Einzeldateien schreibt er eine zentrale Steuerdatei im gewählten Konfigurationsformat mit Modulreihenfolge und Dateiverweisen (KOR-06). Oberfläche über Rich und questionary (BRS-01). Die Umsetzung erfolgt erst, wenn der Konfigurator gebaut wird (KANN).

### 2.18. T18 — Idempotenz je Modul

**Frage.** MOD-14 stellt Idempotenz als modulabhängige KANN-Eigenschaft frei und schließt eine allgemeine Pflicht aus. Wie ein Modul einen bereits erfolgten Eingriff erkennt, ist offen.

**Vertagt.** Die Erkennung eines bereits erfolgten Eingriffs hängt von der konkreten Aufgabe des jeweiligen Moduls ab. Auslöser: die Definition der einzelnen systemverändernden Module und ihrer Eingriffe. Eine allgemeine Festlegung ist weder gefordert noch sinnvoll (MOD-14, ÜBR-05).

## 3. Vollständigkeitsabgleich

Alle Anforderungen aus `docs/pifos/anforderungen.md` sind in Python umsetzbar. Die Bausteine greifen widerspruchsfrei ineinander, sofern die Empfehlungen aus Kapitel 2 zugrunde gelegt werden. Zwei Punkte erfordern Aufmerksamkeit über das Konzept hinaus.

- Spannung ÜBR-04 gegen ÜBR-03: getter/setter für jede Variable gegen KISS. Behandelt in T11; Auslegung ist Martin vorbehalten.
- Spannung KFG-04 (toml) gegen BRS-02: toml schreiben erfordert ein Zusatzpaket. Behandelt in T12; toml ist vertagt, die Empfehlung kommt ohne Zusatzpaket aus.

Die Diagramme bilden den Stand korrekt ab. Eine Ergänzung wäre sinnvoll, sobald die Empfehlungen bestätigt sind: Die Config-Formatklassen brauchen neben `to_dict()` auch eine Schreibmethode (T12); diese Erweiterung gehört in das Klassendiagramm, ist hier aber nur als Hinweis vermerkt und nicht in die Diagramme eingetragen.

## 4. Hinweise an andere Rollen

Diese Punkte fallen bei der Machbarkeitsprüfung an, gehören aber nicht in ihren Auftrag.

**An den system-engineer.**

- Startmethode `spawn` für `multiprocessing` (T1) re-importiert die Module im Kindprozess; das berührt Paketstruktur und Importierbarkeit der pifos-Bibliothek auf dem Zielsystem.
- Falls toml später als Schreibformat gewünscht ist (T12), ist die Mitlieferung eines toml-Schreibers gegen BRS-02 zu klären; ini und json kommen ohne Zusatzpaket aus.
- Rich und questionary sind mitzuliefern (BRS-01); die übrigen Empfehlungen nutzen ausschließlich die Standardbibliothek.

**An den sicherheits-auditor.**

- IPC über `multiprocessing` nutzt pickle (T2/T3/T4). Sender und Empfänger liegen in derselben Vertrauensdomäne (der Aufrufer startet seine eigenen Module), dennoch ist die Deserialisierung zu bewerten.
- `subprocess.Popen` ohne Shell und mit Argumentliste (T14) vermeidet Shell-Injektion; die Bewertung der Eingaben für Systembefehle obliegt der Sicherheitsprüfung.
- Die terminate-Eskalation bis SIGKILL (T6) kann einen Eingriff in inkonsistentem Zustand hinterlassen; das Zusammenspiel mit dem Rollback ist sicherheitsseitig zu würdigen.

## 5. Versionshistorie

| Version | Datum | Wer | Änderung |
|---------|-------|-----|----------|
| 0.01 | 2026-06-27 | Claude | Erstanlage: Machbarkeits- und Vollständigkeitsprüfung der pifos-Umsetzung in Python; 18 WIE-Themen mit Optionen und Empfehlung, abgeleitet aus Konzept, Anforderungen und Diagrammen. |
