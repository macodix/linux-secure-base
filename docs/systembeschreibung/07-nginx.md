# nginx-Grundsatz

Dieses Dokument beschreibt Festlegungen für die Einrichtung des Webserver nginx.


## Inhaltsverzeichnis

1 Multidomain mit getrennten Server-Blöcken
2 TLS je Name über certbot mit HTTP-01
4 Port 443 dauerhaft, Port 80 nur temporär
5 HTTP-zu-HTTPS-Redirect als Absicherung
6 Härtung


## 1. Multidomain mit getrennten Server-Blöcken

Der Webserver ist multidomain-fähig. Je Name gibt es einen eigenen `server`-Block mit eigenem `server_name`, eigenem Wurzelverzeichnis und eigenem Zertifikat.

## 2. TLS je Name über certbot mit HTTP-01

Jede Domain erhält ein eigenes Let's-Encrypt-Zertifikat über `certbot` mit der HTTP-01-Challenge. Kein Wildcard-Zertifikat, kein DNS-01-Verfahren.

## 4. Port 443 dauerhaft, Port 80 nur temporär

Port 443 ist dauerhaft offen, denn über ihn läuft der gesamte Nutzverkehr. Port 80 ist nur temporär offen, z. B. zur Ausstellung und Erneuerung der Zertifikate.

Die HTTP-01-Challenge verlangt einen erreichbaren Port 80 für die Einrichtung und Aktualisierung von `certbot`-Zertifikaten. Für diese Aktionen wird der Port 80 zeitweise an der Firewall (Port 80 eingehend) aktiviert.

## 5. HTTP-zu-HTTPS-Redirect als Absicherung

Die Domain Konfigurationen enthalten einen `server`-Block mit Port 80, der jeden Anfrage mit `return 301` auf HTTPS umlenkt.

Im Normalbetrieb ist Port 80 in der Firewall geschlossen, der Redirect-Block wird dann nicht von außen erreicht. Er ist eine Absicherung für den Fall, dass Port 80 versehentlich offen bleibt.
## 6. Härtung

Global werden die Versions-Anzeige abgeschaltet (`server_tokens off`) und die TLS-Parameter über die von certbot mitgelieferte Datei gesetzt. Der nginx-Dienst erhält systemd-Hardening-Direktiven.

Für ' nginx` wird ein eigenes AppArmor-Profil erstellt, da weder das `nginx`-Paket noch `apparmor-profiles-extra` vonf Ubuntu ein Profil mitliefert.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | Claude | Erstanlage. |
