# Linux Secure Base

Dokumentation und Installations-Scripte für ein gehärtetes Linux Server Grundsystem, optional mit Webserver (nginx), auf der Basis von Ubuntu 26.04 LTS (minimal).

## Zweck

Zur schnellen und einfachen Installation einer sicheren Serverumgebung mit

- einer Schritt-für-Schritt-Anleitung,
- SSH mit Zwei-Faktor (TOTP),
- Firewall,
- Brute-Force- und Schadsoftware-Schutz,
- Protokollierung,
- automatische Sicherheitsupdates,
- Datensicherung,
- Monitoring (via EMail)
- optional nginx Webserver

Die Installation ist so angelegt, dass keine Drittanbieter (z. B. für Monitoring) genutzt werden muss. Alle Benachrichtgungen werden per EMail an eine festzulegende Adresse gesandt.

Die Installations-Scripte werden komplett über Konfigurationsverezichnisse gesteuert.


## Grenzen & Warnung

Aufgrund der Ausgestaltung von Backup und Monitoring ist diese Installation insbesondere für Produktivsystem mit hohen Anforderungen an die Verfügbarkeit und den maximalen Datenverlust nicht geeignet!

**Die Nutzung dieser Anleitung und der Scripte entbindet ausdrücklich NICHT das eigene Hirn vom selbständigen Nachdenken!**

Auch wenn Dokumentation Scripte nach bestem Wissen und Gewissen erstellt wurden, wird für die Anwendung keineerlei Gewährleistung übernommen. Niemand muss diese Anleitung und Scripte nutzen. Und wer für die Beurteilung dieser Dokumente und Scripte nicht hinreichend sachkundig ist, sollte besser die Finger davon lassen!


## Echtheit prüfen (Signatur)

Signierte git-Tags lassen sich mit dem öffentlichen Schlüssel des Projekts daraufhin prüfen, dass ein Stand echt von hier stammt und unterwegs nicht verändert wurde.

- Öffentlicher Schlüssel: [`SIGNING-KEY.asc`](SIGNING-KEY.asc)

- Fingerabdruck: `4B2C 4760 2618 0C67 9598 9C04 E75C 50E9 D42D 066D`

```sh
gpg --import SIGNING-KEY.asc
git tag -v <tag>          # erwartet: "gpg: Good signature ..."
```

Den Fingerabdruck zusätzlich über einen unabhängigen Kanal bestätigen — eine Signatur schützt nur, wenn der Schlüssel nachweislich zum Projekt gehört.

Eine gültige Signatur bestätigt **ausschließlich Herkunft und Unverändertheit**. Sie ist **keine** Aussage über Reife, Qualität oder Eignung für den Produktivbetrieb; es gelten unverändert „Grenzen & Warnung" und der Projektstatus *In Aufbau*.


## Lizenz

Dieses Projekt steht unter der **GNU General Public License v3.0** (GPL-3.0) — siehe [LICENSE](LICENSE). Wer die Scripte verändert und weitergibt, muss den Quellcode ebenfalls unter der GPL offenlegen; so bleiben Änderungen offen und nachprüfbar.

Copyright (C) 2026 macodix / Martin Henkel

Wie in der GPL festgehalten, erfolgt die Bereitstellung ohne jede Gewährleistung (siehe „Grenzen & Warnung" oben und den vollen Lizenztext in [LICENSE](LICENSE)).


## Repository Aufbau

- `docs/anleitung/` — Installationsanleitung, Schritt für Schritt.
- `docs/systembeschreibung/` — Systembeschreibung, Härtungskonzept.
- `docs/INDEX.md` — Navigation.


## Status

In Aufbau.
