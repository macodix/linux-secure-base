# pifos — Machbarkeit

**Status:** [Abgeschlossen] · **Stand:** 2026-06-27

Dieses Dokument prüft, ob das in `docs/pifos/konzept.md` beschriebene Projekt `pifos` hinreichende Realisierungschancen hat. Grundlage für die Bewertung sind das Konzept und die daraus abgeleitete Anforderungsliste `docs/pifos/anforderungen.md`.

## 1. Maßstab und Lesart

Die Machbarkeit wird in drei Stufen bewertet:
- **ja** - uneingeschränkt machbar (Idealfall),
- **ja, wenn [Bedingung]**,
- **nein**, weil [Begründung]

## 2. Aktionen

Eine Aktion ist eine Python-Klasse für genau eine atomare Aufgabe mit voller Kontrolle über Ausführung und Ausgaben (AKT-01 bis AKT-08). Die gemeinsame Elternklasse mit einheitlichem Grundset an Variablen und Methoden lässt sich als abstrakte Basisklasse umsetzen. Status, stdout und stderr eines Systembefehls erfasst die Standardbibliothek über die Prozessausführung; Fehler und Ausnahmen werden als Python-Exceptions an das Modul weitergereicht. Der safe-mode mit einstellbarem Sicherungsort ist eine Dateioperation mit vorausgehender Kopie. Die generische Aktion für Systembefehle deckt alle Fälle ab, für die keine spezifische Aktion nötig ist.

**Urteil: ja.** Alle Aktionsanforderungen sind mit der Python-Standardbibliothek umsetzbar; keine erfordert eine ungelöste Grundlage.

## 3. Module

Ein Modul erledigt eine Aufgabe über Aktionen, erbt von einer gemeinsamen Elternklasse und erhält seine Parameter als Config-Objekt (MOD-01 bis MOD-11). Die deklarative Konfiguration als Klassenattribut mit Name, Verbindlichkeit, Vorgabewert, Prüfung und Beschreibung ist über eine dataclass je Eintrag abbildbar; die Prüfung der eingehenden Werte beim Start folgt der Deklaration. Vererbung, Klassenvariablen und beschreibende Namen sind unmittelbar machbar.

Der Überprüfungsmodus (MOD-12) prüft den Erfolg der eigenen Aktionen und ist als Methode je systemveränderndem Modul umsetzbar. Der Rollback-Mechanismus (MOD-13) ist die einzige Stelle mit Auslegungsspielraum: pifos kann die Schnittstelle und die Pflicht zu einer rollback-Methode als Konvention oder Basisklasse vorgeben, die fachliche Rücknahme eines Eingriffs leistet aber das konkrete Modul, gestützt auf die Sicherung aus dem safe-mode der Aktionen. Eine vom Bausatz garantierte, universelle Rücknahme beliebiger Systemeingriffe ist nicht möglich und auch nicht gefordert. Die Idempotenz-Erkennung (MOD-14) ist KANN und modulabhängig.

**Urteil: ja, wenn** der Rollback (MOD-13) als bereitzustellende Schnittstelle je systemveränderndem Modul verstanden wird, nicht als vom Bausatz garantierte allgemeine Rücknahmefähigkeit.

## 4. Konfiguration

Die Config-Klasse bildet die zentrale Schnittstelle zwischen Konfigurationsquellen und Aufrufern und entkoppelt diese vom Quellformat (KFG-01 bis KFG-09). Methoden für Einzelwerte, Sektionen und Listen, die Definition einzelner Einträge sowie die optionalen formalen Prüfmuster sind Standard-Python. Je Quellformat eine eigene Klasse, die in ein dict überführt, ist für ini, json und das Lesen von toml mit der Standardbibliothek umsetzbar; die raw-Übergabe ergänzt das. Eine inhaltliche Prüfung ist ausdrücklich ausgeschlossen und damit kein Aufwand.

Das Schreiben von Konfigurationsdateien betrifft den Konfigurator (Kapitel 5). Die Standardbibliothek schreibt ini und json, jedoch kein toml. Welche Schreibformate pifos anbieten muss, legt das Konzept nicht abschließend fest; ini und toml und json sind als Beispiele genannt.

**Urteil: ja, wenn** das Set der vom Konfigurator schreibbaren Formate auf die durch die mitgelieferten Bibliotheken abgedeckten beschränkt bleibt. Das Lesen aller genannten Formate ist uneingeschränkt machbar.

## 5. Konfigurator

Der Konfigurator ist eine KANN-Komponente, die aus den Moduldeklarationen die erforderlichen Konfigurationseinträge bestimmt und Konfigurationsdateien erzeugt (KOR-01 bis KOR-08). Die Auswertung der Deklaration ist durch MOD-08 gedeckt, die Steuerung über Parameter mit Dialog-Rückfall durch die mitgelieferten Bibliotheken Rich und questionary. Reihenfolge, Speicherformat, Sammel- oder Einzeldatei mit Steuerdatei sowie Ablageort sind übliche Parameterlogik.

**Urteil: ja.** Die Erzeugung der Dateien unterliegt der Format-Bedingung aus Kapitel 4 (Konfiguration).

## 6. Aufruf, Steuerung und IPC

Der Aufrufer startet Module als eigene Prozesse über IPC, übergibt das Config-Objekt, tauscht in beide Richtungen Nachrichten aus und kann mehrere Module sequenziell oder parallel führen (STR-01 bis STR-06). Getrennte Prozesse mit bidirektionalem Kanal, Befehlsschleife im Modulprozess und Parallelführung sind ein etabliertes Muster der Python-Standardbibliothek. Der reguläre Abschluss über einen Returncode entspricht dem Prozess-Exitcode. Anhalten und Fortsetzen eines Modulprozesses leisten die POSIX-Signale auf dem Linux-Zielsystem.

Die Übergabe des Config-Objekts an einen getrennten Prozess setzt voraus, dass die übergebenen Daten serialisierbar sind. Bei Übergabe als dict oder über Standardtypen ist das erfüllt; das Konzept sieht die dict-Übergabe als Regelfall vor.

**Urteil: ja, wenn** die an den Modulprozess übergebenen Konfigurationsdaten serialisierbar sind und das Zielsystem POSIX-Prozesssignale für Anhalten und Fortsetzen bereitstellt. Beides ist mit dict-Übergabe und Linux-Zielserver erfüllt.

## 7. Logging

Das Logging übernimmt allein der Aufrufer; Module und Aktionen führen kein eigenes Log, sondern reichen qualifizierte Meldungen per IPC nach oben (LOG-01 bis LOG-05). Die vier Stufen INFO, WARN, ERROR und CRITICAL bildet das logging-Modul der Standardbibliothek unmittelbar ab. Loglevel-Einstellung und Weitergabe an die Module sind ein Wert im Nachrichtenprotokoll.

**Urteil: ja.**

## 8. Fehlerbehandlung und Ausnahmen

Aktionen und Module erzeugen im Fehlerfall Ausnahmen, die der Aufrufer entsprechend dem Loglevel erhält (EXC-01 bis EXC-03). Innerhalb eines Prozesses ist die Exception-Weitergabe Standard. Über die Prozessgrenze zwischen Modul und Aufrufer ist eine Ausnahme nicht als natives Objekt propagierbar; sie wird als serialisierte Meldung über IPC übertragen. Beim selbstbeendenden Modul nach einem als CRITICAL eingestuften Fehler muss die Meldung den Aufrufer vor dem Prozessende erreichen, also der Sendepuffer vor dem Beenden geleert werden.

**Urteil: ja, wenn** Ausnahmen über die Prozessgrenze als serialisierte IPC-Meldung übertragen werden und der Sendepuffer vor dem Beenden eines CRITICAL-Moduls geleert wird.

## 9. Standardaufrufer

Die Basisklasse `PifosCaller` bündelt die gemeinsame Infrastruktur — Prozesssteuerung, IPC und Logfile-Führung — und stellt überschreibbare Methoden für die Reaktion auf den Modulausgang bereit (CAL-01 bis CAL-07). Sie fasst die in den Kapiteln 6 bis 8 als machbar bewerteten Mechanismen zusammen; ein konkreter Aufrufer wie der Installer erbt davon und steuert nur Fachlogik und Oberfläche bei. Die überschreibbaren Leer- oder Standardmethoden sind die übliche Hook-Struktur einer Basisklasse.

**Urteil: ja**, unter den Bedingungen der Kapitel 6 (Aufruf, Steuerung und IPC) und 8 (Fehlerbehandlung und Ausnahmen), die die Basisklasse umschließt.

## 10. Übergreifende Anforderungen

Die drei Bausteine, die Nutzbarkeit durch beliebige Aufrufer und das KISS-Prinzip sind durch die obige Struktur erfüllt (ÜBR-01 bis ÜBR-05). Die Vorgabe, dass jede Klassenvariable eine Lese- und eine Schreibmethode trägt (ÜBR-04), ist über das property-Konstrukt der Standardsprache umsetzbar. Sie erhöht den Umfang des Codes, stellt aber keine Machbarkeitshürde dar.

**Urteil: ja.**

## 11. Gesamturteil

Das Konzept hat als Ganzes hinreichende Erfolgsaussicht, in Python umgesetzt zu werden. Jeder Baustein ist mit der Python-Standardbibliothek und den zwei vorgesehenen Oberflächen-Bibliotheken Rich und questionary umsetzbar. Keine Komponente erfordert eine technisch ungelöste oder unsichere Grundlage. Die offenen Punkte sind Auslegungs- und Umsetzungsbedingungen, keine Machbarkeitshürden.

Die Bedingungen der bedingt positiven Urteile, als Voraussetzungen für das Gelingen:

| Nr. | Bereich | Bedingung |
|-----|---------|-----------|
| B1 | Module (Kap. 3) | Rollback (MOD-13) gilt als bereitzustellende Schnittstelle je systemveränderndem Modul, nicht als vom Bausatz garantierte allgemeine Rücknahme. |
| B2 | Konfiguration / Konfigurator (Kap. 4, 5) | Die schreibbaren Konfigurationsformate bleiben auf die durch mitgelieferte Bibliotheken abgedeckten beschränkt; die Standardbibliothek schreibt kein toml. |
| B3 | Aufruf und IPC (Kap. 6) | Die an einen Modulprozess übergebenen Konfigurationsdaten sind serialisierbar; bei dict-Übergabe erfüllt. |
| B4 | Aufruf und IPC (Kap. 6) | Das Zielsystem stellt POSIX-Prozesssignale für Anhalten und Fortsetzen bereit; beim Linux-Zielserver erfüllt. |
| B5 | Ausnahmen (Kap. 8) | Ausnahmen über die Prozessgrenze werden als serialisierte IPC-Meldung übertragen; bei CRITICAL-Beendigung wird der Sendepuffer vorher geleert. |

## 12. Hinweise an andere Rollen

Die folgenden Auffälligkeiten liegen außerhalb der Machbarkeitsprüfung und gehören in andere Rollen.

- **system-engineer:** Bedingung B2 berührt die mitgelieferten Bibliotheken (BRS-01, BRS-02) und die Python-Mindestversion; das toml-Lesen der Standardbibliothek besteht erst ab einer bestimmten Version, das toml-Schreiben gar nicht. Auslieferung und Ablageort von pifos sind ebenfalls dort zu klären.
- **sicherheits-auditor:** Die IPC zwischen Aufrufer und Modulprozessen, die Serialisierung der übertragenen Daten (B3, B5) und die Ausführung von Systembefehlen über die generische Aktion (AKT-08) sind sicherheitsrelevant und gesondert zu prüfen.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---------|-------|-----|----------|
| 0.01 | 2026-06-27 | Claude | Erstanlage: Machbarkeitsprüfung je Konzeptbaustein mit Einzelurteilen, Gesamturteil und Bedingungsliste, abgeleitet aus `docs/pifos/konzept.md` und `docs/pifos/anforderungen.md`. |
