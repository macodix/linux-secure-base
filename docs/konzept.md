# Umstellung auf Python — Konzept

**Status:** [in Bearbeitung] · **Stand:** 2026-06-25

Dieses Dokument hält die Ziele und die bisher getroffenen Festlegungen für die Umstellung des Installers von Bash auf Python fest. Es ist ein Arbeitsstand; offene Punkte werden gesondert geklärt.

## 1. Ziele

- Den Installer von Bash auf Python umstellen, nativ neu aufgebaut — kein Wrapper um die bestehenden Skripte. Anlass ist eine bessere Bedienoberfläche für die Installation.
- Prozesskontrolle und die Überwachung der Ein- und Ausgabe sollen zentral verfügbar sein.
- Das Konstrukt aus Modulen und Actions soll generisch sein und sich für weitere Aufgaben (z. B. Systemadministration) erweitern lassen.
- Die Steuerung erfolgt bevorzugt über Konfiguration. Ob die Konfiguration über eine Konfigurationsdatei oder einen Dialog erfolgt, ist offen — bevorzugt beides.

## 2. Festlegungen

Festgelegt ist bisher der grundlegende Aufbau sowie einzelne Punkte zur Bereitstellung und Bedienung.

### 2.1 Aufbau

- Eine abstrakte Modul-Klasse. Die konkreten Module erben von ihr und regeln das Fach- und Modulspezifische, bei Bedarf mit eigenen oder überschriebenen Methoden.
- Ein Action-Interface. Die konkreten Actions definieren einzelne Aktivitäten — etwa Datei kopieren, Suchen und Ersetzen in Konfigurationsdateien, Dateien erstellen und befüllen, Systemaufrufe.
- Ein Modul hat eine oder mehrere Actions (Komposition).
- Die Actions erhalten ihre Arbeitsumgebung über Context-Objekte (mehrere). Damit ist die Existenz von Context-Klassen festgelegt; ihr Zuschnitt ist noch offen.
- Welche Konfiguration ein Modul benötigt, gibt das Modul selbst an.

### 2.2 Bereitstellung und Bedienung

- Rich und questionary werden mitgeliefert, damit auf dem Zielserver nichts installiert werden muss.
- Ein reiner Planungsmodus erzeugt ausschließlich eine Konfigurationsdatei, ohne Änderung am System — etwa zur Vorbereitung eines anderen Servers.

## 3. Offene Punkte

Diese Fragen sind noch zu entscheiden:

- Welche Aufgaben eine Action erfüllen muss. Sicher ist das Ausführen einer Aktivität; ob eine Action auch prüfen und rückgängig machen können soll, ist offen.
- Welche Context-Objekte es gibt und welche Informationen jedes davon enthält.
- Wie der Installer die Module ansteuert und welche Daten er ihnen dabei übergibt.
- Wie ein Modul seine Actions aufruft und mit Daten versorgt.
