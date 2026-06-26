# pifos — Anforderungen

**Status:** [in Bearbeitung] · **Stand:** 2026-06-26

Dieses Dokument leitet die Anforderungen an den wiederverwendbaren Software-Bausatz pifos (python infrastructure for operational services) aus dem Konzept ab. Es beschreibt das WAS — was pifos leisten muss —, nicht das WIE der Umsetzung. Quelle ist `docs/pifos/konzept.md`; als Nutzungsszenario dient `docs/installer/lsb-installer.md`. Konkrete Klassennamen, Dateinamen und Bibliotheken aus dem Konzept werden nur dort genannt, wo sie selbst Festlegung sind.

## Inhaltsverzeichnis

1. Geltung und Begriffe
2. Anforderungsformat
3. Übergreifende Anforderungen
4. Aktionen
5. Module
6. Konfiguration
7. Konfigurator
8. Aufruf und Steuerung
9. Logging
10. Ausnahmen
11. Standardaufrufer
12. Bereitstellung

## 1. Geltung und Begriffe

pifos ist ein Bausatz aus Python-Komponenten zur Steuerung und Überwachung von Aktivitäten auf einem System. Er wird als allgemein nutzbare Komponente auf dem jeweiligen System bereitgestellt und nicht nur für den Installer. Der LSB-Installer ist der erste Nutzer (Aufrufer) von pifos, aber nur einer von mehreren möglichen.

Die zentralen Begriffe übernimmt dieses Dokument aus dem Konzept.

- **Aktion** — eine Python-Klasse, die genau eine atomare Aufgabe in der Systemumgebung erledigt (z. B. Datei kopieren, Systembefehl ausführen).
- **Modul** — eine Python-Klasse zur Erledigung einer Aufgabe, die dazu Aktionen nutzt und zusätzliche Methoden enthalten kann.
- **Konfiguration** — die Schnittstelle zwischen Anwender und pifos, übergeben als Config-Objekt.
- **Aufrufer** — das Programm (z. B. der Installer), das Module startet und steuert.

## 2. Anforderungsformat

Jede Anforderung trägt eine eindeutige ID, eine Verbindlichkeit und einen Text. Die ID besteht aus einem sprechenden Bereichskürzel und einer laufenden Nummer.

| Bereichskürzel | Bereich |
|----------------|---------|
| ÜBR | Übergreifende Anforderungen |
| AKT | Aktionen |
| MOD | Module |
| KFG | Konfiguration |
| KOR | Konfigurator |
| STR | Aufruf und Steuerung |
| LOG | Logging |
| EXC | Ausnahmen |
| CAL | Standardaufrufer |
| BRS | Bereitstellung |

Die Verbindlichkeit ist entweder MUSS (Pflicht) oder KANN (optional), entsprechend `konv-anforderungsmanagement.md` Kapitel 1 (Formulierung von Anforderungen).

## 3. Übergreifende Anforderungen

Diese Anforderungen gelten für pifos als Ganzes, unabhängig vom einzelnen Baustein.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| ÜBR-01 | MUSS | pifos stellt die drei Bausteine Aktionen, Module und Konfiguration bereit. |
| ÜBR-02 | MUSS | pifos ist von beliebigen Aufrufern nutzbar, nicht nur vom Installer. |
| ÜBR-03 | MUSS | pifos erfüllt jede Anforderung mit der einfachsten dafür ausreichenden Lösung (KISS). |
| ÜBR-04 | MUSS | Jede Klassenvariable verfügt über eine Lesemethode (getter) und eine Schreibmethode (setter). |
| ÜBR-05 | MUSS | pifos enthält nur Funktionen, die das Konzept fordert; keine darüber hinausgehenden Festlegungen oder Funktionen. |

## 4. Aktionen

Eine Aktion erledigt genau eine atomare Aufgabe in der Systemumgebung und liefert vollständige Kontrolle über deren Ausführung und Ausgaben.

### 4.1 Grundverhalten

Die folgenden Anforderungen betreffen jede Aktion.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| AKT-01 | MUSS | Eine Aktion erledigt genau eine Aufgabe (atomar nach der UNIX-Regel: eine Aufgabe gut erledigen). |
| AKT-02 | MUSS | Eine Aktion stellt Status und Ausgaben ihrer Ausführung (insbesondere stdout und stderr) dem aufrufenden Modul vollständig als Variable und/oder Methode bereit. |
| AKT-03 | MUSS | Eine Aktion leitet Fehler und Ausnahmen an das aufrufende Modul weiter. |
| AKT-04 | MUSS | Eine Aktion lässt sich über Optionen an Bedingungen der Ausführung anpassen, ohne ihren atomaren Charakter zu verändern. |
| AKT-05 | MUSS | Alle Aktionen leiten von einer gemeinsamen Elternklasse ab, die ein einheitliches Grundset an Objektvariablen und Methoden sicherstellt. |

### 4.2 Sichere Dateiänderung

Aktionen, die Dateien verändern, müssen den Zustand vor dem Eingriff sichern können.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| AKT-06 | MUSS | Für Aktionen, die Dateien ändern, überschreiben oder löschen, ist ein safe-mode aktivierbar, der die Datei vor der Änderung sichert. |
| AKT-07 | MUSS | Der Ort der Sicherung im safe-mode ist als Variable oder Parameter einstellbar. |

### 4.3 Systembefehle

Für Systembefehle ohne eigene spezifische Aktion existiert eine generische Aktion.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| AKT-08 | MUSS | Es existiert eine Aktion für Systembefehle, die für alle Befehle nutzbar ist, bei denen eine eigene Aktion keinen Sinn ergibt. |

## 5. Module

Ein Modul erledigt eine Aufgabe, indem es Aktionen nutzt, und erhält seine Parameter als Config-Objekt.

### 5.1 Grundverhalten

Die folgenden Anforderungen betreffen jedes Modul.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| MOD-01 | MUSS | Ein Modul erledigt seine Aufgabe unter Nutzung von Aktionen und kann zusätzliche eigene Methoden enthalten. |
| MOD-02 | MUSS | Ein Modul erhält die für die Aufgabe erforderlichen Parameter als Config-Objekt. |
| MOD-03 | MUSS | Module ohne erforderliche Konfiguration sind möglich; bei ihnen entfällt die Übergabe eines Config-Objekts. |
| MOD-04 | MUSS | Ein Modul legt die Konfigurationsdaten aus dem Config-Objekt in seinen Klassenvariablen ab. |
| MOD-05 | MUSS | Alle Module erben von einer gemeinsamen Elternklasse die gemeinsamen Methoden und Variablen zu Systemumgebung, Aufruf von Aktionen, Steuerung von Aktionen und Interaktion mit dem aufrufenden Prozess. |
| MOD-06 | MUSS | Module steuern ihre Aktionen über Parameter oder über das Setzen von Klassenvariablen. |
| MOD-07 | MUSS | Module tragen beschreibende Namen, aus denen ihr Typ erkennbar ist (z. B. Installationsmodul am Namen erkennbar). |

### 5.2 Konfigurationsdeklaration

Ein Modul macht nachvollziehbar sichtbar, welche Konfiguration es benötigt.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| MOD-08 | MUSS | Ein Modul deklariert die benötigte Konfiguration als Klassenattribut, das je Eintrag Name, Verbindlichkeit (Pflicht/Kann), Vorgabewert, Prüfung und Beschreibung trägt. |
| MOD-09 | MUSS | Ein Modul prüft die eingehenden Konfigurationswerte beim Start anhand seiner Deklaration und legt sie danach in seinen Klassenvariablen ab. |
| MOD-10 | MUSS | Die Deklaration unterscheidet zwischen Pflicht- und Kann-Werten. |
| MOD-11 | KANN | Ein Modul enthält sinnfällige Vorgabewerte, wann immer möglich. |

### 5.3 Systemverändernde Module

Module, die das System verändern, müssen ihren Erfolg prüfen und rückgängig machen können.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| MOD-12 | MUSS | Ein Modul, das Veränderungen am System bewirkt, bietet einen Überprüfungsmodus, der den Erfolg seiner Aktionen und Eingriffe gezielt und vollständig prüft. |
| MOD-13 | MUSS | Ein Modul, das Veränderungen am System bewirkt, stellt einen Rollback-Mechanismus bereit. |
| MOD-14 | KANN | Ein systemveränderndes Modul kann bei erneutem Lauf einen bereits erfolgten Eingriff erkennen und nicht wiederholen (Idempotenz). Eine allgemeine Pflicht dazu besteht nicht. |

## 6. Konfiguration

Die Konfiguration ist die Schnittstelle zwischen Anwender und pifos. Sie wird über ein Config-Objekt von den Formaten der Konfigurationsquelle entkoppelt.

### 6.1 Config-Objekt

Das Config-Objekt vermittelt zwischen Konfigurationsquellen und Aufrufern.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| KFG-01 | MUSS | Eine Config-Klasse bildet die zentrale Schnittstelle zwischen Konfigurationen und den aufrufenden Programmen. |
| KFG-02 | MUSS | Die Config-Klasse stellt Methoden bereit, um dem Aufrufer Konfiguration in verschiedenen Formen zu liefern: einzelne Werte, Sektionen als dict oder list sowie sortierte und unsortierte Listen. |
| KFG-03 | MUSS | pifos stellt eine Klasse zur Definition einzelner Konfigurationseinträge bereit. |

### 6.2 Konfigurationsformate

Verschiedene Quellformate werden über je eigene Klassen angebunden.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| KFG-04 | MUSS | Für jede genutzte Konfigurationsart (z. B. ini, toml, json) gibt es eine eigene Klasse, die die Konfiguration standardisiert an die Config-Klasse übergibt. |
| KFG-05 | MUSS | Die Übergabe der Konfiguration an die Config-Klasse erfolgt im Regelfall als dict. |
| KFG-06 | MUSS | Zusätzlich ist die Übergabe der Konfiguration als raw möglich. |
| KFG-07 | KANN | Eine formatspezifische Konfigurationsklasse nutzt zum Einlesen oder Schreiben von Dateien die Aktionsklassen. |

### 6.3 Prüfung von Konfigurationsdaten

pifos prüft die Konfiguration nur formal, nicht inhaltlich.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| KFG-08 | MUSS | Eine inhaltliche Prüfung der Konfigurationsdaten findet nicht statt. |
| KFG-09 | KANN | Die Config-Klasse stellt grundlegende Prüfmuster bereit (z. B. ist leer, Wert existiert, gültige Mailadresse, ist Zahl, ist kommasepariert, ist Liste). |

## 7. Konfigurator

Der Konfigurator ist eine optionale Komponente, die mithilfe der Moduldeklarationen Konfigurationsdateien erstellt.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| KOR-01 | KANN | pifos stellt einen UI-Konfigurator bereit, der für ein oder mehrere Module Konfiguration erstellt. |
| KOR-02 | MUSS | Der Konfigurator nutzt die Konfigurationsdeklarationen der Module, um die erforderlichen Konfigurationseinträge und -werte zu bestimmen. |
| KOR-03 | MUSS | Der Konfigurator kann ein oder mehrere Module als Parameter erhalten. |
| KOR-04 | MUSS | Über Parameter ist festlegbar, ob bei mehreren Modulen die Reihenfolge in der Parameterliste verbindlich ist. |
| KOR-05 | MUSS | Über Parameter ist das Speicherformat festlegbar. |
| KOR-06 | MUSS | Über Parameter ist festlegbar, ob eine gemeinsame Datei für alle Module oder Einzeldateien je Modul erstellt werden; bei Einzeldateien gehört eine zentrale Steuerdatei für die Reihenfolge dazu. |
| KOR-07 | MUSS | Über Parameter ist der Ablageort der Dateien festlegbar. |
| KOR-08 | MUSS | Nicht gesetzte Parameter fragt der Konfigurator per Dialog ab. |

## 8. Aufruf und Steuerung

Der Aufrufer startet Module und tauscht mit ihnen über IPC Befehle und Meldungen aus.

### 8.1 Modulstart

Der Aufrufer ist für Beschaffung und Übergabe der Konfiguration zuständig.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| STR-01 | MUSS | Der Aufrufer startet ein Modul über IPC. |
| STR-02 | MUSS | Der Aufrufer beschafft die erforderlichen Konfigurationsdaten durch Instanziierung eines Config-Objekts und übergibt sie beim Start des Moduls. |

### 8.2 Bidirektionale Kommunikation

Aufrufer und Modul tauschen während der Ausführung Nachrichten in beide Richtungen aus.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| STR-03 | MUSS | Ein Modul kann nicht logging-relevante Nachrichten an den aufrufenden Prozess senden, damit dieser über den weiteren Ablauf entscheiden kann. |
| STR-04 | MUSS | Der Aufrufer kann Nachrichten an ein Modul senden, um Daten anzufordern (z. B. Variablenwerte) oder das Modul zu Aktivitäten aufzufordern. |

### 8.3 Abschluss und Nebenläufigkeit

Ein Modul meldet seinen Abschluss; der Aufrufer kann mehrere Module nebenläufig führen.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| STR-05 | MUSS | Ein Modul signalisiert seinen regulären Abschluss über einen Returncode. 0 bedeutet Erfolg, ein Wert ungleich 0 einen Fehler. Der Aufrufer wertet ihn aus. |
| STR-06 | MUSS | Der Aufrufer kann mehrere Module sequenziell oder parallel führen. |

## 9. Logging

Das Logging übernimmt der Aufrufer; Module und Aktionen führen kein eigenes Log.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| LOG-01 | MUSS | Das Logging nimmt ausschließlich der Aufrufer vor; Module und Aktionen erhalten keine eigene Logger-Umgebung. |
| LOG-02 | MUSS | Ein Modul entscheidet, welche Meldungen es per IPC an den Aufrufer weiterreicht; der Aufrufer entscheidet, welche davon er in das Logfile aufnimmt. |
| LOG-03 | MUSS | Das Logging unterscheidet die vier Stufen INFO, WARN, ERROR und CRITICAL; Module qualifizieren ihre Meldungen nach diesen Stufen. |
| LOG-04 | MUSS | Das Loglevel des Aufrufers ist einstellbar. |
| LOG-05 | MUSS | Der Aufrufer gibt das eingestellte Loglevel an die Module weiter. |

## 10. Ausnahmen

Aktionen und Module melden Fehler über Ausnahmen, die der Aufrufer erhält.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| EXC-01 | MUSS | Aktionen und Module erzeugen im Fehlerfall Ausnahmen. |
| EXC-02 | MUSS | Module leiten Ausnahmen entsprechend dem eingestellten Loglevel an den Aufrufer weiter. |
| EXC-03 | MUSS | Beendet sich ein Modul wegen eines als CRITICAL eingestuften Fehlers, stellt es vor dem Beenden sicher, dass die Ausnahme-Meldungen noch an den Aufrufer gelangen. |

## 11. Standardaufrufer

pifos stellt eine Basisklasse für Aufrufer bereit, die die gemeinsame Infrastruktur enthält.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| CAL-01 | MUSS | pifos stellt eine Aufrufer-Basisklasse bereit, von der konkrete Aufrufer (z. B. der Installer) erben. |
| CAL-02 | MUSS | Die Aufrufer-Basisklasse stellt Methoden bereit, um Modulprozesse zu starten, anzuhalten, fortzusetzen und zu beenden. |
| CAL-03 | MUSS | Die Aufrufer-Basisklasse stellt Methoden bereit, um über IPC Befehle an Module zu senden. |
| CAL-04 | MUSS | Die Aufrufer-Basisklasse stellt Methoden bereit, um über IPC Meldungen und Ergebnisse zu erhalten oder anzufordern. |
| CAL-05 | MUSS | Die Aufrufer-Basisklasse stellt Methoden bereit, um Logfiles zu führen. |
| CAL-06 | MUSS | Ein konkreter Aufrufer steuert nur seine Fachlogik und Oberfläche bei. |
| CAL-07 | MUSS | Die Aufrufer-Basisklasse bietet überschreibbare Leer- oder Standardmethoden, mit denen der konkrete Aufrufer auf den Ausgang eines Moduls (Erfolg, Fehler, Abbruch) reagiert. |

## 12. Bereitstellung

pifos wird mit den nötigen Bibliotheken ausgeliefert, damit auf dem Zielserver nichts nachinstalliert werden muss.

| ID | Verb. | Anforderung |
|----|-------|-------------|
| BRS-01 | MUSS | Für die Bedienoberfläche werden die Bibliotheken Rich und questionary mitgeliefert. |
| BRS-02 | MUSS | Auf dem Zielserver muss für den Betrieb von pifos keine zusätzliche Komponente installiert werden. |

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---------|-------|-----|----------|
| 0.01 | 2026-06-26 | macodix | Erstanlage: Anforderungen aus `docs/pifos/konzept.md` abgeleitet, gegliedert nach den pifos-Bausteinen, mit IDs und Verbindlichkeit (MUSS/KANN). |
| 0.02 | 2026-06-26 | macodix | Klärungen eingearbeitet: CAL-02 um Fortsetzen ergänzt; neu STR-05 (Abschluss über Returncode), STR-06 (sequenziell/parallel), CAL-07 (Reaktion auf Modulausgang), MOD-14 (Idempotenz modulabhängig). |
</content>
</invoke>
