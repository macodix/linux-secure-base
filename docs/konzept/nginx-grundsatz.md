# nginx-Grundsatz

Dieses Dokument begründet die Festlegungen für den Webserver des Grundsystems. nginx liefert je Domain statische Inhalte aus und terminiert TLS. Es ist kein Reverse-Proxy und vermittelt keinen Verkehr an interne Dienste. Die Schritt-für-Schritt-Einrichtung steht im Handbuch-Kapitel 13.

**Status:** in Bearbeitung — **Stand:** 2026-06-18

## Inhaltsverzeichnis

1 Geltung und Abgrenzung
2 Multidomain mit getrennten Server-Blöcken
3 TLS je Name über certbot mit HTTP-01
4 Port 443 dauerhaft, Port 80 nur temporär
5 HTTP-zu-HTTPS-Redirect als Absicherung
6 Härtung

## 1. Geltung und Abgrenzung

nginx ist in diesem Grundsystem ein Webserver für statische Inhalte. Je Domain oder Subdomain wird ein Wurzelverzeichnis ausgeliefert (`root`/`try_files`). nginx terminiert TLS und setzt den HTTP-Verkehr auf HTTPS um.

Bewusst nicht Teil dieses Grundsetups sind Reverse-Proxy-Funktionen: kein `proxy_pass`, kein `auth_request`, keine Weitergabe an lokale Anwendungsdienste. Diese Funktionen gehören zu später folgenden Diensten und werden mit ihnen eingerichtet, nicht vorab. Das Grundsystem bleibt damit auf die Auslieferung statischer Inhalte beschränkt und hält die Angriffsfläche klein.

## 2. Multidomain mit getrennten Server-Blöcken

Der Webserver ist multidomain-fähig. Erwartet werden zwei bis vier Domains oder Subdomains. Je Name gibt es einen eigenen `server`-Block mit eigenem `server_name`, eigenem Wurzelverzeichnis und eigenem Zertifikat.

Ein eigener Block je Name hält die Domains voneinander getrennt: jede liefert nur ihr eigenes Wurzelverzeichnis aus, und ein Fehler in einer Konfiguration bleibt auf eine Domain begrenzt. Die Alternative, mehrere Namen in einem Block zu bündeln, lehnen wir ab. Sie macht die Wurzel- und Zertifikatszuordnung unübersichtlich und verhindert eine domänenweise Härtung.

## 3. TLS je Name über certbot mit HTTP-01

Jeder Name erhält ein eigenes Let's-Encrypt-Zertifikat über `certbot` mit der HTTP-01-Challenge. Kein Wildcard-Zertifikat, kein DNS-01-Verfahren.

Die Festlegung folgt aus der Umgebung: Es gibt keine DNS-Provider-API. DNS-01 und Wildcard-Zertifikate setzen voraus, dass certbot einen DNS-TXT-Eintrag automatisiert setzen kann. Ohne Provider-API ist das nicht möglich. HTTP-01 belegt die Kontrolle über einen Namen stattdessen über einen HTTP-Abruf auf Port 80 und kommt ohne DNS-Automatisierung aus. Je Name ein eigenes Zertifikat passt zum getrennten Server-Block je Name (Kapitel 2) und verzichtet auf das Wildcard, das DNS-01 voraussetzte.

## 4. Port 443 dauerhaft, Port 80 nur temporär

Port 443 ist dauerhaft offen, denn über ihn läuft der gesamte Nutzverkehr. Port 80 ist nur temporär offen, zur Ausstellung und Erneuerung der Zertifikate.

Die HTTP-01-Challenge verlangt einen erreichbaren Port 80 während des certbot-Laufs. Außerhalb dieser Läufe gibt es keinen Grund, Port 80 offen zu halten. Ein dauerhaft offener Port 80 vergrößert die Angriffsfläche ohne Nutzen. Die Firewall gibt Port 80 daher nur für die Dauer der Ausstellung und Erneuerung frei (Handbuch-Kapitel 13).

## 5. HTTP-zu-HTTPS-Redirect als Absicherung

Je Name bleibt ein `server`-Block auf Port 80 bestehen, der jeden Abruf per `return 301` auf HTTPS umlenkt.

Im Normalbetrieb ist Port 80 in der Firewall geschlossen, der Redirect-Block wird dann nicht von außen erreicht. Er ist eine Absicherung für den Fall, dass Port 80 versehentlich offen bleibt. Dann landet ein HTTP-Abruf nicht auf nacktem HTTP, sondern wird auf HTTPS umgeleitet. Den Redirect-Block trotz geschlossenem Port zu behalten kostet nichts und schließt diese Lücke.

## 6. Härtung

Global werden die Versions-Anzeige abgeschaltet (`server_tokens off`) und die TLS-Parameter über die von certbot mitgelieferte Datei gesetzt. Der nginx-Dienst erhält systemd-Hardening-Direktiven (Konzept-Dokument Härtungskonzept, Kapitel 6).

nginx ist der einzige von außen erreichbare Anwendungsdienst und damit der exponierte Dienst. Für ihn wird ein eigenes AppArmor-Profil ergänzt, weil weder das `nginx`-Paket noch `apparmor-profiles-extra` auf Ubuntu ein Profil mitliefern. Das Profil wird im Complain-Modus erarbeitet und nach dem Prüflauf auf Enforce gesetzt. Im Enforce-Modus wird es im Härtungs-Prüflauf kontrolliert (Konzept-Dokument Härtungskonzept, Kapitel 7).

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage. |
