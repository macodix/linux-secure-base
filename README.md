# Linux Secure Base

Dokumentation und Installer für ein gehärtetes Linux Server Grundsystem, optional mit Webserver (nginx) und Datenbankserver (PostgreSQL), auf der Basis von Ubuntu 26.04 LTS (minimal).

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
- optional PostgreSQL Datenbankserver

Die Installation ist so angelegt, dass keine Drittanbieter (z. B. für Monitoring) genutzt werden müssen. Alle Benachrichtigungen werden per EMail an eine festzulegende Adresse gesandt.

Die Installation wird vollständig über Konfiguration gesteuert.


## Grenzen & Warnung

Aufgrund der Ausgestaltung von Backup und Monitoring ist diese Installation insbesondere für Produktivsystem mit hohen Anforderungen an die Verfügbarkeit und den maximalen Datenverlust nicht geeignet!

**Die Nutzung dieser Anleitung und der Scripte entbindet ausdrücklich NICHT das eigene Hirn vom selbständigen Nachdenken!**

Auch wenn Dokumentation und Scripte nach bestem Wissen und Gewissen erstellt wurden, wird für die Anwendung keinerlei Gewährleistung übernommen. Niemand muss diese Anleitung und Scripte nutzen. Und wer für die Beurteilung dieser Dokumente und Scripte nicht hinreichend sachkundig ist, sollte besser die Finger davon lassen!


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

Dasselbe Verfahren gilt für das Auslieferungspaket des Python-Installers (`secure-base-installer-<version>.tar.gz`): Es liegt eine abgesetzte Signatur `secure-base-installer-<version>.tar.gz.asc` bei, mit demselben Schlüssel und demselben Fingerabdruck-Abgleich zu prüfen, bevor das Archiv entpackt wird:

```sh
gpg --import SIGNING-KEY.asc
gpg --fingerprint cert@martinhenkel.net   # mit dem Fingerabdruck oben vergleichen
gpg --verify secure-base-installer-<version>.tar.gz.asc secure-base-installer-<version>.tar.gz
```


## Installation in einem Schritt

Der Python-Installer liegt als einzelnes, signiertes Download-Artefakt vor. Es enthält den Installer, den Bausatz pifos und die benötigten Fremdbibliotheken bereits fertig zusammengestellt — kein `pip`, kein Netzzugang und keine vorherige pifos-Einrichtung auf dem Zielsystem nötig.

**Herunterladen:** Archiv und Signatur liegen auf der [Releases-Seite](https://github.com/macodix/linux-secure-base/releases) des Projekts. In der Entwicklungsphase gibt es dort den rollierenden **Testbau** (`testbau`) — er wird bei jedem Entwicklungsstand ersetzt; `secure-base-installer --version` und die Datei `BUILD-INFO` im Paket nennen Commit und Datum des Baus. Versionierte Release-Stände (rc/final) erscheinen erst wieder, wenn ein Stand den Servertest vollständig bestanden hat.

```sh
wget https://github.com/macodix/linux-secure-base/releases/download/testbau/secure-base-installer-0.1.1.tar.gz
wget https://github.com/macodix/linux-secure-base/releases/download/testbau/secure-base-installer-0.1.1.tar.gz.asc
wget https://raw.githubusercontent.com/macodix/linux-secure-base/main/SIGNING-KEY.asc
```

Danach prüfen, entpacken, starten:

```sh
gpg --import SIGNING-KEY.asc
gpg --fingerprint cert@martinhenkel.net   # mit dem Fingerabdruck oben vergleichen
gpg --verify secure-base-installer-<version>.tar.gz.asc secure-base-installer-<version>.tar.gz
tar xzf secure-base-installer-<version>.tar.gz
sudo secure-base-installer-<version>/bin/secure-base-installer install
```

Details zur Bedienung: [`docs/installer/secure-base-installer.md`](docs/installer/secure-base-installer.md).


## Lizenz

Dieses Projekt steht unter der **GNU General Public License v3.0** (GPL-3.0) — siehe [LICENSE](LICENSE). Wer die Scripte verändert und weitergibt, muss den Quellcode ebenfalls unter der GPL offenlegen; so bleiben Änderungen offen und nachprüfbar.

Copyright (C) 2026 macodix / Martin Henkel

Wie in der GPL festgehalten, erfolgt die Bereitstellung ohne jede Gewährleistung (siehe „Grenzen & Warnung" oben und den vollen Lizenztext in [LICENSE](LICENSE)).


## Repository Aufbau

- `docs/systembeschreibung/` — Systembeschreibung, Härtungskonzept.
- `docs/installer/` — Konzept des Installers, der pifos nutzt.
- `docs/anleitung/` — Installationsanleitung, Schritt für Schritt.
- `docs/INDEX.md` — Navigation.


## Umstellung auf Python

Der Installer wurde von Bash auf Python umgestellt, um die Ausgaben und Prozesse der aufgerufenen Befehle besser zu kontrollieren. Grundlage ist der wiederverwendbare Bausatz pifos, der als eigenes Projekt geführt wird: [github.com/macodix/pifos](https://github.com/macodix/pifos).

Auslöser waren Probleme der Bash-Umsetzung mit nebenläufiger Terminal-Ausgabe und externem Befehlsaufruf: `ufw enable` aus dem Installer störte die SSH-Verbindung und die Live-Anzeige, die Statusanzeige über SSH war fragil, und die Trennung von Befehls-Ausgabe und Bedienoberfläche war in Bash umständlich.

Die Python-Fassung trennt stdout und stderr je Befehl sauber über `subprocess`, macht die Statusanzeige robuster und die Fehler- und Ablaufsteuerung klarer.


## Status

In Aufbau.
