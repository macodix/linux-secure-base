# Sicherheitsanforderungen

Dieses Dokument legt die nichtfunktionalen Sicherheitsanforderungen an das gehärtete Linux-Grundsystem fest. Es benennt den Härtungsmaßstab und die Schutzziele, gegen die das Härtungskonzept und die Installationsanleitung geprüft werden.

**Status:** in Bearbeitung — **Stand:** 2026-06-18

## Inhaltsverzeichnis

1 Härtungsmaßstab
2 Defense-in-depth
3 Zwei-Faktor-Pflicht
4 Minimale Angriffsfläche
5 Geheimnis-Trennung
6 Brute-Force-Drosselung

## 1. Härtungsmaßstab

Die Härtung folgt dem BSI-IT-Grundschutz als Referenz für die Auswahl der Maßnahmen. Die technische Konfiguration wird mit dem CIS-Benchmark für Ubuntu Server (Level 1) geprüft. Ein benannter Maßstab macht „gehärtet" prüfbar. Der BSI-Grundschutz passt zum deutschen Rechts- und Datenschutz-Kontext. CIS Level 1 liefert die konkrete, testbare Konfigurations-Checkliste, ohne den Betrieb übermäßig einzuschränken. Level 2 wäre für ein universell einsetzbares Grundsystem zu restriktiv.

Der Maßstab ist verbindlicher Soll-Maßstab. Abweichungen je Maßnahme werden begründet und dokumentiert.

## 2. Defense-in-depth

Sicherheitskritischer Zugriff verlangt mehrere unabhängige Schichten. Prüfbar ist das am SSH-Zugang (Public-Key plus TOTP) und an der Erreichbarkeit interner Dienste (nur über Loopback, nicht von außen).

## 3. Zwei-Faktor-Pflicht

Auslöser ist der interaktive Login (SSH). Reaktion ist der zweite Faktor (TOTP). Sollwert ist, dass kein interaktiver Login ohne zweiten Faktor möglich ist.

## 4. Minimale Angriffsfläche

Eingehend ist im Grundzustand nur SSH offen. Die Web-Ports 80 und 443 öffnen erst mit dem aktiven Webserver, Port 80 nur temporär zur Zertifikatsausstellung. Dienste laufen unter eigenen System-Benutzern ohne Login-Shell und ohne überflüssige Rechte.

## 5. Geheimnis-Trennung

Zugangsdaten, Token und Schlüssel liegen außerhalb des Repos in Dateien mit Mode 600 oder 640 und werden referenziert, nicht eingebettet. Prüfbar ist, dass kein Geheimnis im Repo liegt.

## 6. Brute-Force-Drosselung

Auslöser sind wiederholte Fehlversuche. Reaktion ist die serverweite IP-Sperre durch `fail2ban`. Die Voreinstellungen sind branchenüblich und genügen.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage durch bereinigte Übernahme. |
