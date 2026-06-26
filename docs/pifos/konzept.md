# Umstellung auf Python — Konzept

**Status:** [in Bearbeitung] · **Stand:** 2026-06-25

Dieses Dokument hält die Ziele und die getroffenen Festlegungen für die Umstellung des Installers von Bash auf Python fest. Es ist ein Arbeitsstand; offene Punkte werden gesondert geklärt.

## 1. Ziele

Den Installer von Bash auf Python umstellen. Der Installer wird dabei nativ neu aufgebaut, ohne Wrapper um die bestehenden Skripte.

Gründe für die Umstellung sind:

- eine bessere Bedienoberfläche,
- die Kontrolle und Überwachung der Ein- und Ausgaben aufgerufener Befehle,
- ein generischer Aufbau, der sich über die Server-Härtung hinaus für weitere Aufgaben wiederverwenden lässt,
- die Steuerung über Konfigurationsdateien, die als Datei oder über einen Dialog erstellt werden.

# 2. Für KI: Allgemeine Festlegungen für die weitere Planung und Entwicklung 

Setze exakt das um was gefordert ist! Erfinde keine Features, keine Festlegungen.

Grundsatz für die Planung und Entwicklung: KISS 'Keep It Simple & Stupid'. Also immer die einfachste Lösung wählen um eine Anforderung zu erfüllen

Einschränkende Festlegungen werden nur getroffen wenn es dafür eine guten Grund gibt und nur wenn sie von mir genehmigt sind!

Alle Klassenvariablen sollten über getter und setter verfügen.



# 3. Projekt/Teilprojekt 'pifos'

Allerdings hat sich das Projekt weiterentwickelt. Neben der Entwicklung eines neuen Installers soll ein Ökosystem an Python Modulen entstehen, dass eine gute und transparente (z. B. Logging) Steuerung und Kontrolle von Aktivitäten auf einem System ermöglichen soll. Der Installer baut auf diesem Ökosystem auf. Gleichzeitig kann dieses Python-Modul-System auch von anderen Aufrufern genutzt werden. 

Es ist daher sinnvoll im Verlauf dieses Projektes dieses Ökosystem nicht nur im Rahmen des Installers zur Verfügung zu stellen, sondern als allgemein nutzbare Komponente auf dem jeweiligen System zu implementieren. Daher bekommt es auch einen eigenen Namen: 'pifos' - '*p*ython *i*nfrastructure *f*or *o*perational *s*ervices'  

## 3.1. Aufbau / Design 'pifos'

Die grundlegenden Bausteine für 'pifos'

- Aktionen
- Konfiguration (optional mit Konfigurator)
- Module


### 3.1.1. Aktionen

Eine Aktion ist eine Python Klasse die genau eine Aufgabe in der Systemumgebung erledigt. Sie ist atomar und erfüllt genau eine Aufgabe. Beispiele sind Aktionen wie Datei kopieren, in Textdatei suchen und ersetzen, Datei erstellen oder einen Systembefehl auszuführen.

Sinn dieser Klassen ist es eine möglichst vollständig Kontrolle über die jeweiligen Aktionen zu erhalten um diese zu steuern, zu überwachen inkl. der Ausgaben (stdout, stderr) und so auch ein vollständiges Logging erstellen zu können. 

Aktionen sind Experten für ihre spezifische Aufgabe und können daher noch mit Optionen zur versehen werden, um die Ausführung an bestimmte Bedingungen anzupassen, wie z. B. eine Datei sichern, bevor sie neu erstellt oder geändert wird. Dabei soll der "atomare" Charakter i. S. d. der UNIX Regel "Gestalte jedes Programm so, dass es *eine* Aufgabe *gut* erledigt, nicht verändert werden.

Praktisch wird es eine Eltern-Klasse Aktionen geben, die sicherstellt, dass jede konkrete Implementierung dieser Klasse über ein gleiches Grundset an Objektvariablen und Methoden verfügt, insbesondere auch für Rückmeldung an die aufrufenden Module. Fehler und Ausnahmen müssen immer an das aufrufende Modul weitergeleitet werden.

Auch wenn diese Aktionen nun erstmals im Rahmen des Installers definiert werden ist es das Ziel dieses Designentscheidung ist ein flexibles Set an Aktionen zu bekommen, die von unterschiedlichen Werkzeugen/Aufrufern (z. B. in der Systemadministration) genutzt werden können.

In der Praxis muss von Fall zu Fall entschieden werden ob es insbesondere bei Systemaufrufen sinnvoll ist spezielle Aktionen zu erstellen (z. B. für apt) oder ob es ausreichend ist, eine generische Aktionen (z. B. syscmd) für Systemaufrufe zu nutzen. Keinesfalls ist es sinnvoll Systemkommandos (wie z. B. apt) mit vielen Optionen/Parametern quasi in Python "nachzubauen". Die Entscheidung für oder gegen ein spezifisches Modul für einen speziellen Systemaufruf muss sich also an der Frage orientieren, ob die Aufgabe *spezifische* Funktionen/Methoden zur Erfüllung benötigt.

Eine weitere Abgrenzung ist zu treffen bei Aktionen die sowohl auf Systemebene als auch in Python existieren (z. B. cp, mkdir etc.). Hier ist der entscheidende Maßstab welches Werkzeug (Python oder System) die bessere Kontrolle über die Aufgabe bietet.

#### 3.1.1.1. Spezifische Festlegungen zu Aktionen 

Für Aktion die Dateien ändern, überschreiben oder löschen, soll eine 'safe-mode' aktivierbar sein, bei dem die Datei vor der Änderung gesichert wird. Dabei bleibt der Ort der Sicherung (z. B. gleiches Verzeichnis, anderes Verzeichnis) als Variable/Parameter einstellbar.

Es muss eine Klasse für System-Befehle geben, die für alle Befehle genutzt werden kann, bei denen eine eigenen Aktion keine Sinn macht.


### 3.1.2. Module 

Ein Modul ist eine Python Klasse zur Erledigung einer Aufgabe. Zur Erfüllung diese Aufgabe nutzt eine Modul die Aktions-Klassen, kann aber auch zusätzliche Methoden/Aktivitäten die zur Erfüllung der Aufgabe dienen enthalten. Die Parameter, die ggf. für die Erfüllung der Aufgabe erforderlich sind (z. B. Werte zur Änderung einer Konfigurationsdatei) erhält ein Modul als Config Objekt (s. Kap 2.3 Konfiguration).

Die einzelnen Module erben von einer gemeinsamen Elternklasse Modul alle gemeinsamen Methoden und Variablen, u. a. 
- zu der Systemumgebung (z. B. Systemvariablen)
- für den Aufruf von Aktionen
- der Interaktion mit bzw. Steuerung von Aktionen
- der Interaktion mit dem aufrufenden Prozess (z. B. Installer)

Die Konfigurationsdaten aus dem Config-Objekt werden in den Klassenvariablen des Moduls abgelegt.

Die spezifischen Module (als die Erben der Elternklasse) sollen beschreibende Namen erhalten. Ein Modul, welches beispielsweise zur Installation einer Komponente dient, sollte auch eindeutig als Installations-Modul im Namen erkennbar sein (z. B. inst-.....py). Die Namenskonvention sind ggf. noch im Projektverlauf festzulegen. Per Konvention kann dann festgelegt werden, das bestimmte Typen von Module (z. B. aller inst-...-py Module) bestimmte Methoden oder Variablen enthalten sollen (z. B. kann festgelegt werden, dass alle inst* Module eine eine 'rollback'-Methode aufweisen sollen, alternativ Basisklasse je Modultyp).

Module die Veränderungen am System bewirken (z. B. Installationsmodule) sollen 
- einen Überprüfungsmodus anbieten, welches den Erfolg der Aktionen und Eingriffe gezielt und vollständig prüft,
- und einen Rollback-Mechanismus zur Verfügung stellen 

Die Modul-Klassen sollten die erforderlich Konfiguration deklarativ nachvollziehbar enthalten, damit sichtbar ist welche Konfiguration übergeben werden muss. Die Deklaration erfolgt als Klassenattribut `CONFIG`, eine Liste von `ConfigItem` (dataclass in `config.py`). Jedes `ConfigItem` trägt `name`, `required`, `default`, `check` und `description`. Beim Start prüft das Modul die eingehenden Werte gegen diese Liste und legt sie in seinen Klassenvariablen ab. Bei der Deklaration muss zwischen Pflicht- und Kann-Werten unterschieden werden. Grundsätzlich sollten Module - wann immer möglich - sinnfällig Vorgabewerte enthalten.


### 3.1.3. Konfiguration

Die Schnittstelle zwischen Anwender und dem hier geschaffenen Ökosystem bilden die Konfigurationen. In der Praxis können Konfigurationen sehr unterschiedliche Formen haben. Als Datei in verschiedenen Formaten, wie 'ini', 'extended', toml', 'json' oder sogar als Parameterliste. Um hier kein unnötige Festlegung zu schaffen, wird ein Config-Objekt eingeführt.

Die Config-Klasse liefert eine zentrale Schnittstelle zwischen Konfigurationen und den aufrufenden Programmen (z. B. Installer). Für jede genutzte Konfigart (ini, toml etc.) gibt es eine eigene Klasse die von dem config-objekt genutzt wird. Diese spezifische Klasse stellt Methoden zur Verfügung um die jeweilige Konfiguration an die config-Klasse standardisiert zu übergeben. Konkret soll die Konfig i. d. R. als dict an die config-Klasse übergeben werden. Zusätzlich soll aber auch eine Übergabe als "raw" möglich sein.

Die spezifischen Config-Klassen können sich bei Bedarf an den Aktionsklassen bedienen, z. B. um Dateien einzulesen oder zu schreiben.   

Die Config Klasse stellt Methoden zur Verfügung um den Aufrufer mit der gewünschten Konfiguration zu versorgen. Dies können einzelne Werte sein, Sektionen (als dict oder list), sortierte oder unsortierte Listen usw. Für die Definition der jeweiligen Einträge wird ein Klasse `ConfigItem` in der `config.py` zur Verfügung gestellt.
Eine inhaltliche Prüfung der Konfigurationsdaten findet nicht statt. Allerdings können grundlegende Prüfmuster bei Bedarf in die config-Klasse aufgenommen werden (z. B. 'ist leer', 'Wert existiert', 'ist syntaktisch gültige Mailadresse', ist Zahl, ist kommasepariert, ist Liste usw.)

#### 3.1.3.1. Konfigurator

Optional kann ein UI-Konfigurator erstellt werden, mit dessen Hilfe für ein oder mehrere Module Konfiguration erstellt werden können. Der Konfigurator soll die Deklarationen in den Modulen nutzen um die erforderlichen Konfigurationsitems- und werte zu bestimmen und über die Möglichkeit verfügen dies in unterschiedlichen Formaten abzulegen. Der Konfigurator nutzt zur UI Gestaltung rich und questionary.

Dabei kann der Konfigurator für ein oder mehrere Module als Parameter aufgerufen werden.

Mit weiteren Parametern kann festgelegt werden
- ob (bei mehreren Modulen) die Reihenfolge in der Parameterliste verbindlich ist
- das Speicherformat
- ob eine Datei für alle Module oder Einzeldateien erstellt werden sollen (inkl. einer zentralen Steuerdatei für Reihenfolge etc.)
- wo die Dateien abgelegt werden können.

Sind die Parameter nicht gesetzt müssen sie per Dialog abgefragt werden. 


## 3.2. Aufruf, Steuerung, Konfiguration, Logfile und Ausnahmen

### 3.2.1. Aufruf und Steuerung

Die Aufrufer (beispielsweise der Installer) startet ein Modul über IPC. Dabei wird ein Config-Objekt übergeben. 

Die Aktionen stellen sicher, dass die der Status der Aktion und ggf. der IO-Kanäle (insbesondere stdout und stderr) den Modulen vollständig als Variable und/oder Methode zur Verfügung gestellt werden. 

Es muss grundsätzlich  möglich sein, dass ein Modul auch nicht Logging relevante Nachrichten an den aufrufenden Prozess senden kann, damit ggf. der Aufrufer über den weiteren Ablauf entscheiden kann. Genauso muss es umgekehrt möglich sein, dass der Aufrufer Nachrichten an das Modul senden kann um z. B. die Übermittlung von Daten anzufordern (z. B. Variablewerte) oder das Modul zu Aktivitäten (=Modul-Methoden) auffordern kann. 

### 3.2.2. Konfigurationsdaten und Parameter

Der Aufrufer (z. B. der Installer) ist für die Beschaffung der Konfigurationsdaten, sofern erforderlich, zuständig. Dies geschieht durch die Instanziierung eines entsprechenden Konfig-Objekts. 

Die Konfig wird dann entsprechend den Anforderungen des Moduls beim Start des Moduls übergeben. Grundsätzlich ist es auch möglich Module zu haben für die keine Konfig erforderlich ist. In diesen Fällen entfällt die Übergabe eines Config-Objektes.

Die Aktionen sind Bestandteil der Module (Komposition) und werden i. d. R von den Modulen über Parameter oder Manipulation von Klassenvariablen gesteuert.

### 3.2.3. Logging

Das Logging wird durch den Aufrufer vorgenommen. Module und Aktionen erhalten keine eigene Logger Umgebung. Die Module entscheiden welche Meldungen an den Aufrufer per IPC-Kommunikation weitergereicht werden. Der Aufrufer entscheidet was er davon in das Logfile aufnehmen möchte.

Grundsätzlich soll beim Logging zwischen 4 Stufen unterschieden werden: INFO, WARN, ERROR, CRITICAL. Die Module sollten die Meldung entsprechend gleich qualifizieren. Das Loglevel des Aufrufers soll einstellbar sein. Das Loglevel soll auch an die Module weitergegeben werden.


### 3.2.4 Ausnahmen / Exceptions

Aktionen und Module sollen im Fehlerfall Ausnahmen (Exceptions) erzeugen. Die Exceptions sind entsprechend des eingestellten Loglevels durch die Module an den Aufrufer weiterzuleiten. In den seltenen Fällen in denen ein Modul einen Fehler als CRITICAL einstuft und sich beendet, muss vorher sichergestellt sein dass die Exception Meldungen noch an den Aufrufer weitergeleitet werden. 


## 3.3 Standardaufrufer

Der Aufrufer braucht viel gemeinsame Infrastruktur (Logger, IPC usw.). Diese liegt in einer Basisklasse `PifosCaller` in der Datei `pifos_caller.py`, von der die konkreten Aufrufer wie der Installer erben.

Die Basisklasse enthält insbesonder Methoden um
- Modulprozesse zu starten, anzuhalten und zu beenden,
- über IPC Befehle an die Module zu senden
- über IPC Meldungen und Ergebnisse zu erhalten oder anzufordern,
- dieLogfiles zu führen.

Der konkrete Aufrufer bringt nur seine Fachlogik und Oberfläche.   


# 4. LSB Installer

Siehe Dokument linux-secure-base/docks/installer


# 5. Bereitstellung und Bedienung

Für die Bedienoberfläche werden die Python-Komponenten Rich und questionary mitgeliefert, damit auf dem Zielserver nichts installiert werden muss.





