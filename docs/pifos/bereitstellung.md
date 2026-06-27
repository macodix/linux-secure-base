# pifos — Bereitstellung

**Status:** [in Bearbeitung] · **Stand:** 2026-06-27

Dieses Dokument legt fest, wie der wiederverwendbare Bausatz pifos auf ein Zielsystem gelangt und wo er dort liegt. Es behandelt vier Punkte: die Auslieferung des Kerns mit seinen Bibliotheken (BRS-01, BRS-02), den Ablageort nach dem Filesystem Hierarchy Standard (FHS), die Konsequenzen der gesetzten Python-Mindestversion 3.13 und den Schreibweg je Konfigurationsformat (Bedingung B2 der Machbarkeit). Quellen sind `docs/pifos/konzept.md` (Kapitel „Bereitstellung und Bedienung"), `docs/pifos/anforderungen.md` (Kapitel „Konfiguration" und „Bereitstellung") und `docs/pifos/machbarkeit.md` (Kapitel „Konfiguration" und Bedingung B2).

Nicht behandelt: die Sicherheitsprüfung. Sicherheitsrelevante Auffälligkeiten stehen knapp am Dokumentende.

## 1. Geltung und Abgrenzung

Gegenstand ist allein der pifos-**Kern**: die Basisklassen und -komponenten (Aktionen, Module, Konfiguration, Aufrufer-Basisklasse `PifosCaller`, IPC, die Format-Konfigklassen) samt den Bibliotheken, die der Kern für seine Bedienoberfläche und seinen Betrieb braucht.

Konkrete Module und Aktionen, die auf dem Kern aufbauen, dürfen darüber hinaus eigene Abhängigkeiten mitbringen. Diese sind **nicht** Teil der Kern-Auslieferung und hier nicht behandelt. Der Kern darf keine Laufzeit-Abhängigkeit voraussetzen, die nicht mit ihm ausgeliefert wird (BRS-02).

## 2. Auslieferung des Kerns

### 2.1 Umfang: Kern und mitgelieferte Bibliotheken

Der Kern stützt sich auf die Python-Standardbibliothek und auf die zwei Oberflächen-Bibliotheken Rich und questionary (BRS-01). Andere Bausteine — Prozessmodell, IPC, Nachrichtenformat, Systembefehl-Ausführung — nutzen ausschließlich die Standardbibliothek und erfordern keine Mitlieferung.

Mitzuliefern ist daher die vollständige Abhängigkeitsschließung von Rich und questionary, nicht nur die zwei direkt genannten Pakete. questionary zieht prompt_toolkit nach, Rich weitere reine Python-Pakete. Alle sind reine Python-Pakete ohne kompilierte Erweiterung, daher plattformunabhängig bündelbar. Welche transitiven Pakete genau dazugehören, ergibt die Auflösung der gepinnten `requirements.txt` zum Build-Zeitpunkt; eine feste Aufzählung hier wäre nicht dauerhaft korrekt.

### 2.2 Auslieferungsverfahren

Die Bibliotheken müssen so auf das Zielsystem kommen, dass dort nichts nachinstalliert und kein Netzzugang gebraucht wird (BRS-02).

| Verfahren | Folge |
|-----------|-------|
| **Mitlieferung im Bündel (vendoring)** | Die Abhängigkeitsschließung wird in ein Verzeichnis des pifos-Bündels kopiert und beim Start auf den Importpfad (`sys.path`) gelegt. Selbstständiges Bündel, kein pip und kein Netz auf dem Ziel, reproduzierbar aus gepinnter `requirements.txt`. |
| **Vorgefertigte virtuelle Umgebung (venv)** | Eine venv mit vorinstallierten Bibliotheken wird mitgeliefert. Eine venv ist an ihren Erstellungspfad und den Interpreter gebunden, nicht zuverlässig verschiebbar; höherer Umfang. |
| **pip aus lokalem Paketlager (wheelhouse)** | Installation aus mitgelieferten Wheels beim Deployment. Setzt pip auf dem Ziel voraus und installiert dort, berührt damit BRS-02. |

**Festlegung: Mitlieferung im Bündel (vendoring).** Bei rein aus Python bestehenden Abhängigkeiten ist das Kopieren der Abhängigkeitsschließung in das Bündel der einfachste Weg, der BRS-02 erfüllt: kein pip, kein Netz, kein Installationsschritt auf dem Ziel. Das Bündel wird reproduzierbar aus einer exakt gepinnten `requirements.txt` mit Artefakt-Hashes erzeugt, entsprechend der Vorgabe in `konv-scripting-python.md` (Kapitel „Dependency-Management"). Die venv-Variante lehnen wir ab, weil sie nicht verlässlich verschiebbar ist; die wheelhouse-Variante, weil sie einen Installationsschritt auf dem Ziel verlangt.

Die gebündelten Bibliotheken liegen in einem pifos-eigenen Verzeichnis, das der Aufrufer-Einstiegspunkt dem Importpfad voranstellt. So gewinnen die mitgelieferten Versionen unabhängig davon, ob auf dem Ziel gleichnamige Pakete systemweit vorhanden sind. Das stützt zugleich die Startmethode `spawn` des Modul-Prozessmodells: Der neu gestartete Interpreter findet die pifos-Pakete und ihre gebündelten Bibliotheken über denselben Importpfad wieder.

### 2.3 Python-Interpreter als Voraussetzung

pifos bündelt Bibliotheken, nicht den Interpreter. Der Python-Interpreter ab Version 3.13 ist eine Voraussetzung des Zielsystems (siehe Kapitel „Python-Mindestversion 3.13"). Aktuelle Server-Distributionen liefern Python 3.13 mit. Fehlt er, ist das Bereitstellen des Interpreters Sache der Systemvorbereitung und nicht Teil der pifos-Auslieferung.

## 3. Ablageort nach FHS

pifos soll unabhängig vom Installer nutzbar sein und wird als selbstständiges Bündel mit eigenen mitgelieferten Bibliotheken ausgeliefert (Kapitel „Auslieferung des Kerns"). Maßgeblich ist daher der FHS-Ort für selbstständige Zusatzpakete.

| Ort | Eignung |
|-----|---------|
| **`/opt/pifos/`** | FHS bestimmt `/opt/<paket>` für selbstständige Zusatz-Softwarepakete mit eigenem Verzeichnisbaum. Passt zu einem Bündel, das seine Bibliotheken selbst mitbringt und als Einheit verschoben wird. |
| **`/usr/local/lib/pifos/`** | FHS-Ort für lokal, nicht über die Distributionspaketverwaltung installierte Software. Üblicherweise auf den vom System bereitgestellten Python-Importpfad ausgerichtet; das Einbetten mitgelieferter Fremdbibliotheken in diesen Pfad vermischt Bündel und Systembibliotheken. |
| **`/usr/lib/pifos/`** | Für Software der Distributionspaketverwaltung vorgesehen. pifos wird nicht als Distributionspaket ausgeliefert; daher unpassend. |

**Festlegung: `/opt/pifos/`.** Ein selbstständiges Bündel mit eigener Abhängigkeitsschließung ist genau der Fall, für den FHS `/opt/<paket>` vorsieht. Der Ort hält das Bündel von den Systembibliothekspfaden getrennt und übersteht ein Distributions-Update unverändert. `/usr/local/lib/pifos/` bliebe FHS-konform und ist die Rückfallwahl, falls pifos später am System-Python statt als isoliertes Bündel ausgerichtet werden soll; bei mitgelieferten Fremdbibliotheken ist die Trennung unter `/opt` aber sauberer.

Innerhalb von `/opt/pifos/` spiegelt der Baum die Repo-Struktur aus `konv-scripting-python.md` (Kapitel „Projektstruktur"): `bin/` für Einstiegspunkte, `usr/lib/pifos/` für den Modulcode des Kerns samt dem Verzeichnis der gebündelten Bibliotheken. Damit gilt das in der Konvention geforderte Spiegeln von Repo- und Deployment-Struktur auch hier, nur unter einem eigenen Wurzelverzeichnis.

**Rechte und Eigentümer.** Der pifos-Kern ist ein nur lesbarer Code-Baum: Eigentümer `root`, für Dienstkonten lesbar, nicht schreibbar (geringste Rechte, BSI-Grundschutz). Der Kern selbst braucht keine beschreibbaren Pfade. Laufzeitdaten — Logdateien führt der Aufrufer (LOG-01), Konfigurationsdateien legt der Konfigurator an einem vom Aufrufer bestimmten Ort ab (KOR-07) — gehören dem jeweiligen Aufrufer und liegen außerhalb des Kern-Baums.

## 4. Python-Mindestversion 3.13

Die Mindestversion ist Python 3.13 (gesetzt durch Martin). Daraus folgt für die Umsetzung:

- **toml-Lesen mit der Standardbibliothek gegeben.** `tomllib` ist seit Python 3.11 Teil der Standardbibliothek und damit auf dem Ziel ohne Mitlieferung vorhanden. Das toml-Lesen einer Konfigurationsklasse braucht keine Fremdbibliothek (siehe Kapitel „Schreibweg je Konfigurationsformat").
- **Werkzeug-Zielversion.** Die Zielversion für ruff und mypy ist `py313` statt des in `konv-scripting-python.md` genannten `py314` (siehe Hinweis am Dokumentende).
- **Voraussetzung an das Ziel.** Das Zielsystem muss Python 3.13 oder neuer bereitstellen; der Interpreter wird nicht mitgeliefert (Kapitel „Python-Interpreter als Voraussetzung").

## 5. Schreibweg je Konfigurationsformat

Bedingung B2 der Machbarkeit hält fest, dass die Standardbibliothek kein toml schreibt. Nach Vorgabe Martins kapselt jede Formatklasse ihren eigenen Lade- und Schreibweg und ist dabei nicht auf die Standardbibliothek beschränkt. Lesen ist für alle drei Formate mit der Standardbibliothek möglich (`configparser`, `json`, `tomllib`). Für das Schreiben gilt:

| Format | Schreibweg | Schreibbar |
|--------|------------|-----------|
| ini (`IniConfig`) | `configparser` (Standardbibliothek) | Pflicht, ohne Mitlieferung |
| json (`JsonConfig`) | `json` (Standardbibliothek) | Pflicht, ohne Mitlieferung |
| toml (`TomlConfig`) | mitgelieferte Bibliothek `tomli-w` | optional, erst bei Bedarf |

**Festlegungen.**

ini und json schreibt die jeweilige Formatklasse mit der Standardbibliothek. Beide Formate sind damit ohne zusätzliche Mitlieferung schreibbar und bilden den schreibbaren Pflichtumfang. Das Konzept legt keinen Pflichtumfang fest; diese beiden ergeben sich, weil sie ohne Zusatzkosten schreibbar sind.

toml liest die Formatklasse mit `tomllib` (Standardbibliothek, ab 3.13 gegeben). Geschrieben wird toml — falls gefordert — über die mitgelieferte, reine Python-Bibliothek `tomli-w`, die in dasselbe Bündel aufgenommen wird wie Rich und questionary. Eine Eigenimplementierung eines toml-Schreibers lehnen wir ab: toml umfasst Datentypen, Tabellen-Arrays und Mehrzeiler, deren vollständige und korrekte Serialisierung aufwändig und fehlerträchtig wäre; eine gepflegte kleine Bibliothek ist der verlässlichere Weg und durch die Vorgabe „nicht auf die Standardbibliothek beschränkt" gedeckt.

toml-Schreiben ist optional und wird erst aktiviert, wenn ein Aufrufer es braucht. Erst dann wird `tomli-w` in die Abhängigkeitsschließung und das Bündel aufgenommen. Bis dahin bleibt toml lesbar, aber nicht schreibbar. Das deckt sich mit der Empfehlung im Implementierungsplan (`docs/pifos/implementierungsplan.md`, Thema „Konfigurationsformate und Lese-/Schreibrichtung"), toml zu vertagen, und löst die dortige Spannung KFG-04 gegen BRS-02 auf: nicht durch Verzicht, sondern durch eine kleine mitgelieferte Bibliothek bei Bedarf.

## 6. Hinweise an den sicherheits-auditor

- Die mitgelieferten Fremdbibliotheken (Rich, questionary, deren Schließung, bei Bedarf `tomli-w`) sind Bestandteil der Auslieferung. Ihre Herkunft sichert das Hash-Pinning der `requirements.txt`; die Bewertung der Fremdsoftware obliegt der Sicherheitsprüfung.
- Der voranstehende pifos-eigene Importpfad bestimmt, dass die gebündelten statt etwaiger systemweiter Versionen geladen werden. Die Reihenfolge der Importpfad-Einträge ist sicherheitsrelevant und zu prüfen.

## 7. Hinweis an den Hauptchat

`konv-scripting-python.md` (Kapitel „Werkzeuge und Mindestversion") nennt Python 3.14 als Mindestversion und `py314` als Zielversion für ruff und mypy. Für pifos ist 3.13 gesetzt. Diese Abweichung ist zu klären: entweder eine begründete Ausnahme für pifos in der Konvention vermerken oder die pifos-Mindestversion auf 3.14 anheben. Bis zur Klärung gilt für pifos die gesetzte Version 3.13.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---------|-------|-----|----------|
| 0.01 | 2026-06-27 | Claude | Erstanlage: Auslieferung des Kerns (vendoring), Ablageort `/opt/pifos` nach FHS, Konsequenzen der Mindestversion 3.13, Schreibweg je Konfigurationsformat. |
</content>
</invoke>
