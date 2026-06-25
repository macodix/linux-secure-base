# Umstellung auf Python — Konzept

**Status:** [in Bearbeitung] · **Stand:** 2026-06-25

Dieses Dokument hält die Ziele und die bisher getroffenen Festlegungen für die Umstellung des Installers von Bash auf Python fest. Es ist ein Arbeitsstand; offene Punkte werden gesondert geklärt.

## 1. Ziele

Den Installer von Bash auf Python umstellen.

Der Installer wird dabei nativ neu aufgebaut (kein Wrapper um die bestehenden Skripte).

Gründe für die Umstellung sind

- bessere Bedienoberfläche,
- Prozesskontrolle und Überwachung der Ein- und Ausgaben
- generischer Aufbau und Wiederverwendbarkeit für weitere Aufgaben (z. B. Systemadministration),
- Die Steuerung soll über  Konfigurationsdateien erfolgen. Die Konfigurationsdateien können als Datei und/ oder Dialog erstellt werden.

## 2. Festlegungen

Festgelegt ist bisher der grundlegende Aufbau sowie einzelne Punkte zur Bereitstellung und Bedienung.

### 2.1 Aufbau

#### 2.1.1 Abstrakte Modul-Klasse.

Die konkreten Module erben von ihr und regeln das Fach- und Modulspezifische, bei Bedarf mit eigenen oder überschriebenen Methoden.


#### 2.1.2 Action-Interface-Klasse

Die konkreten Actions definieren einzelne Aktivitäten — etwa Datei kopieren, Suchen und Ersetzen in Konfigurationsdateien, Dateien erstellen und befüllen, Systemaufrufe usw

#### 2.1.3 Modell

Ein Modul hat eine oder mehrere Actions (Komposition).

Die Actions erhalten ihre Arbeitsumgebung über Context-Objekte (mehrere).

Damit ist die Existenz von Context-Klassen festgelegt. Die Eigenschaften der Context-Klassen sind noch nicht festgelegt. 

Welche Konfiguration ein Modul benötigt, wird im Modul festgelegt. Damit wird das Modul auch zur fachlichen Referenz zur Erstellung der Konfigurationsdatei.

### 2.2 Bereitstellung und Bedienung

Für das UI werden die Python Komponenten Rich und questionary mitgeliefert, damit auf dem Zielserver nichts installiert werden muss.

Der Installer soll über einen Planungsmodus zur Erzeugung von Konfigurationsdateien verfügen.

## 3. Offene Punkte

Diese Fragen sind noch zu entscheiden:

Soll eine Aufgabe nur eine Aktion ausführen oder auch Prüf- und Rollback-Funktionen enthalten?

Welche Context-Klassen werden benötigt und welche Eigenschaften sollen diese haben?

Wie ruft der Installer oder auch ggf. ein anderes Tool die einzelnen Module auf bzw. steuert deren Ablauf? 

Wie ruft ein Modul seine Actions auf? Wie werden Daten an die Actions übergeben?

