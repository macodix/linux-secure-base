# linux-secure-base

Gehärtetes Linux-Grundsystem (Ubuntu Server) mit multidomain-fähigem nginx. Eigenständig und unabhängig von weiteren Vorhaben einsetzbar.

## Zweck

Schritt-für-Schritt-Einrichtung eines abgesicherten Linux-Servers: SSH mit Zwei-Faktor (TOTP), Firewall, Brute-Force- und Schadsoftware-Schutz, Protokollierung, automatische Sicherheitsupdates, Datensicherung, Monitoring sowie ein multidomain-fähiger nginx als Webserver (TLS je Domain über Let's Encrypt).

## Aufbau

- `docs/handbuch/` — Installationsanleitung, Schritt für Schritt.
- `docs/konzept/` — Hintergründe: Sicherheitsanforderungen, Systemtopologie, Härtungskonzept.
- `docs/INDEX.md` — Navigation.

## Sicherheit

Privates Repository. Enthält keine serverspezifischen Daten (Hostnamen, IP-Adressen, Zugangsdaten). Diese stehen ausschließlich in gitignorierten `.conf`-Dateien.

Zwei-Datei-Muster: jede Konfiguration als reale `*.conf` (gitignoriert) und `*.conf.example` mit Platzhaltern (eingecheckt).

Der pre-commit-Schutzmechanismus gegen versehentliches Einchecken echter Werte wird vom Betreiber eingerichtet.

## Status

In Aufbau. Die Dokumentation wird aus einem bestehenden Konzept bereinigt übernommen. Die Installationsskripte folgen nach gesonderter Prüfung.
