# Umstellung auf Python — Architektur

**Status:** [in Bearbeitung] · **Stand:** 2026-06-25

Dieses Dokument hält die Architekturentscheidungen für die Umstellung des Installers von Bash auf Python fest. Es ergänzt das Dokument „Umstellung auf Python — Konzept" um die Festlegungen, die dort im Kapitel „Offene Punkte" noch offen waren. Es ist ein Arbeitsstand.

## 1. Rahmen

Das Projekt ist ein generischer Bausatz. Er besteht aus Modulen, Aktionen, den dafür nötigen abstrakten Klassen und Schnittstellen sowie den Wegen, über die Daten und Meldungen laufen.

Der Installer für die Server-Härtung ist nur ein Nutzer dieses Bausatzes. Er ist nicht das Projekt selbst. Andere Werkzeuge können denselben Bausatz auf dieselbe Weise verwenden.

## 2. Aktion

Eine Aktion ist der kleinste Baustein. Sie ist atomar und erfüllt genau eine Aufgabe. Eine Datei zu erstellen und eine Datei zu löschen sind zwei getrennte Aktionen.

Eine Aktion ist fachneutral. Sie enthält keine fachliche Kenntnis und lässt sich in jedem Modul wiederverwenden.

Eine Aktion nimmt sich nicht selbst zurück. Die Daten, auf die sie wirkt, erhält sie vom Modul. Über den einzelnen Lauf hinaus hält sie keinen Zustand.

Aktionen, die eine Datei erstellen oder ändern, haben eine abschaltbare Sicherung. Ist sie eingeschaltet, sichern sie den vorherigen Stand vor der Änderung. Die Sicherung liegt am Ort der Datei und behält deren Zugriffsrechte. Sie wird nicht an einen anderen Ort kopiert. Die Aktion sichert nur den Stand. Das Zurückspielen ist eine eigene Aktion.

## 3. Modul

Ein Modul ist die fachliche Einheit. Es fasst eine fachliche Aufgabe zusammen und steuert seine Aktionen.

Ein Modul deklariert die Konfiguration, die es benötigt. Diese Deklaration erfüllt drei Zwecke. Sie prüft die eingehenden Werte. Sie ist die Vorlage für die Konfigurationsdatei. Sie steuert den Dialog.

Ein Modul erhält die ungeprüften Werte seines Konfigurationsabschnitts. Es prüft und deutet sie selbst.

Die Rücknahme liegt beim Modul. Sie ist eine Abfolge von Aktionen, die das Modul zusammenstellt. Sie ist nicht zwangsläufig die Umkehrung der Installation. Unterstützt ein Modul keine Rücknahme, meldet es das.

Jedes Modul läuft als eigener Prozess. Die Begründung steht im Kapitel „Ausführung".

## 4. Konfiguration und Daten

Die Daten des Installers stammen aus einer Konfigurationsdatei. Der Dialog und der Planungsmodus erzeugen eine solche Datei. Einen zweiten, eigenen Eingang gibt es nicht.

Die Daten sind nach Modul gegliedert. Je Modul gibt es einen Abschnitt mit benannten Werten. Ein Wert kann auch eine Liste sein.

Eine Klasse `Config` stellt die Daten bereit. Hinter ihr liegen Klassen für die einzelnen Formate, etwa ini oder toml. Jede Format-Klasse liest ihr Format und gibt die Daten als dict zurück. `Config` erhält einen Parameter, den Dateipfad oder das Format, ruft die passende Format-Klasse auf und liefert die gewünschte Form: das vollständige dict, einen Abschnitt als dict, einen Abschnitt als Liste oder die ungeprüften Werte. Der Aufrufer kennt nur die Klasse `Config`.

Das dict hat einen festen, vereinbarten Aufbau aus Abschnitten und benannten Werten. Formate mit geringerem Umfang, etwa ini, bilden in ihrer Format-Klasse auf diesen Aufbau ab.

Die Werte sind zunächst ungeprüft. Geprüft und gedeutet werden sie erst im Modul, gegen dessen Deklaration.

## 5. Kommunikation zwischen Installer und Modul

Der Installer ruft eine Operation des Moduls auf. Möglich sind ausführen, zurücknehmen und planen. Er übergibt dabei die Konfiguration und einen Meldekanal.

Der Rückweg hat zwei getrennte Teile. Über den Meldekanal laufen die Meldungen während der Arbeit. Die Ausgabe der Befehle geht in die Logdatei, der Status und der Fortschritt in die Anzeige. Am Ende der Operation steht das Ergebnis. Es nennt den Ausgang, also gelungen oder gescheitert, und bei einem Fehlschlag den Grund und den Stand der Rücknahme.

Der Meldekanal gehört dem Aufrufer. Das Modul bleibt von der Bedienoberfläche unabhängig.

## 6. Ausführung

Jedes Modul läuft als eigener Prozess. Kommunikation und Steuerung laufen über IPC. Über die Prozessgrenze gehen nur einfache Daten.

Der Installer steuert die Modulprozesse von außen. Er kann sie starten, parallel laufen lassen, anhalten und fortsetzen sowie beenden. Parallel laufen nur Module, die voneinander unabhängig sind. Das Anhalten und Fortsetzen geschieht über die Signale SIGSTOP und SIGCONT.

Ein Fehler mit Abbruch erreicht den Installer nicht als unbehandelte Ausnahme. Die Operation meldet einen Fehlschlag. Der Installer ist zusätzlich gegen unerwartete Ausnahmen abgesichert. Das Modul nimmt sein bereits Getanes zurück und meldet, ob das vollständig, teilweise oder nicht gelang. Was sich nicht zurücknehmen ließ, bleibt in einem bekannten und gekennzeichneten Zustand.

Ein hängendes Modul wird beendet. Ein im Voraus geschätzter Timeout ist dafür nicht nötig und bleibt nur eine Möglichkeit. Der Sonderfall ufw wird darüber gelöst. Der Installer legt den ufw-Modulprozess während des Laufs schlafen und aktiviert ufw erst am Ende der Installation.

## 7. Offene Punkte

Diese Punkte sind noch nicht entschieden.

Das Konfigurationsformat ist bewusst offen gehalten. Festgelegt ist nur, dass die Klasse `Config` das Format kapselt.

Die Sicherung der Dateiänderungen ist im Grundsatz festgelegt, in der Ausgestaltung aber offen.

Der Planungsmodus und der Konfigurator werden später geklärt.

Eine Überwachung gegen hängenden Modulcode über den aufgerufenen Befehl hinaus wird erst bei Bedarf eingeführt.

Ein Kontextobjekt gibt es vorerst nicht. Es lohnt sich erst, wenn mehrere für den ganzen Lauf gleiche Dinge zusammenkommen, etwa der Meldekanal, ein Trockenlauf und die Sicherung.

Die Einordnung des Schalters für den Trocken- oder Planungslauf ist offen.
