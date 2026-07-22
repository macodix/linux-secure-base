# secure-base-installer

Der secure-base-installer richtet ein gehärtetes Linux-Grundsystem in einem Lauf ein. Dieses Dokument beschreibt seine Bedienung und seinen Aufbau: den Aufruf, die Grundlage pifos, den Ablauf eines Laufs, das Modulmuster, die Konfiguration, die Betriebsarten, die Bedienoberfläche und den Installationsbericht. Bezug und Echtheitsprüfung des Pakets stehen in der [README](../../README.md), die eingerichteten Zielzustände in der [Systembeschreibung](../systembeschreibung/INDEX.md).

## Inhaltsverzeichnis
1. Grundlage pifos
2. Aufruf
3. Ablauf eines Laufs
4. Module
5. Konfiguration
6. Betriebsarten
7. Bedienoberfläche
8. Installationsbericht

## 1. Grundlage pifos

Der Installer nutzt den wiederverwendbaren Bausatz pifos (eigenes Projekt [github.com/macodix/pifos](https://github.com/macodix/pifos)). Die Aufruferklasse `LsbInstaller` erbt von `PifosCaller` (`pifos.caller`). pifos übernimmt den Prozessstart je Modul, die Trennung von Standard- und Fehlerausgabe über `subprocess`, die Nachrichten zwischen Modul und Aufrufer sowie das Anlegen der Logdatei mit Rechten 0600. Jedes Härtungsmodul ist eine pifos-`Module`-Klasse.

## 2. Aufruf

```sh
sudo bin/secure-base-installer {install|uninstall|check|test} [MODUL ...] [-c PFAD] [-n] [--force-overwrite]
```

- `install` richtet die ausgewählten Module ein; `uninstall` nimmt die Modul-Änderungen in umgekehrter Reihenfolge zurück; `check` gleicht Ist- und Soll-Zustand ab, ohne zu ändern; `test` prüft die Funktion ohne Änderung (Kapitel 6).
- `MODUL ...` verarbeitet nur die genannten Module (Kurznamen, siehe Kapitel 4); ohne Angabe laufen die in der Konfiguration aktivierten Pflichtmodule.
- `-c PFAD` / `--conf PFAD` gibt eine abweichende Konfigurationsdatei an; ohne Angabe `etc/secure-base/secure-base.conf`.
- `-n` / `--dry-run` listet die Module nur auf und führt nichts aus.
- `--force-overwrite` gibt für einen `install`-Lauf das Überschreiben verwalteter Dateien frei, die vom Soll abweichen (Kapitel 6.1); ohne die Freigabe bricht `install` bei Abweichungen ab, bevor etwas geändert wurde.

Der Installer benötigt Systemrechte (`sudo`) und bricht ohne sie ab, bevor er etwas ändert.

Unterstützt sind Ubuntu und Debian. Die Module setzen deren Paketnamen, Pfade und Archiv-Benennungen voraus. Der Installer stellt die laufende Distribution aus `/etc/os-release` fest und bricht auf jeder anderen mit Code 2 ab, bevor er etwas liest oder ändert.

## 3. Ablauf eines Laufs

Der Einstiegspunkt `bin/secure-base-installer` liest die Kommandozeile und ruft `main` auf. Ein Lauf durchläuft:

1. Distributionsprüfung — auf einer nicht unterstützten Distribution Abbruch mit Code 2, vor jedem anderen Schritt.
2. Rechteprüfung — `install` und `uninstall` ohne Trockenlauf verlangen Systemrechte und brechen sonst mit Code 2 ab, bevor etwas geändert wird; `check` und `test` sind rein lesend.
3. Konfiguration bereitstellen — fehlt die Datei, wird die Vorlage kopiert (Kapitel 5).
4. Modulauswahl — feste Reihenfolge aus der Registratur, gefiltert nach den Aktivierungslisten und der Kommandozeile (Kapitel 4).
5. Fehlende Pflichtwerte klären — dialogische Abfrage, Rückschreiben mit Rechten 0600 (Kapitel 5).
6. Sammel-Prüfung (nur `install`) — alle verwalteten Schreibziele der beauftragten Module werden gegen ihren Soll-Inhalt geprüft, bevor irgendein Modul etwas ändert; unfreigegebene Abweichungen brechen den Lauf mit der vollständigen Konfliktliste ab (Kapitel 6.1).
7. Module ausführen — je Modul Start, Statusmeldungen, Ergebnis (Kapitel 7). `install` und `uninstall` bauen aufeinander auf und brechen nach einem Modulfehler ab; `check` und `test` laufen vollständig durch.
8. Abschluss — bei `install` der Installationsbericht (Kapitel 8) und, nach vollständig erfolgreichem Lauf, die Abfrage zur ufw-Aktivierung (Kapitel 7).

Der Rückgabewert ist 0 bei Erfolg, 1 bei einem Modulfehler, 2 bei einer nicht unterstützten Distribution, fehlenden Rechten, fehlerhafter Auswahl oder ungültiger Konfiguration.

## 4. Module

Jedes Modul ist eine pifos-`Module`-Klasse mit einer `CONFIG`-Liste seiner Konfigurationsschlüssel. Die Registratur (`secure_base.modules.REGISTRY`) hält je Modul einen `ModuleSpec` mit Kurzname, Anzeige-Label, Modulklasse und Optional-Kennzeichen; die Reihenfolge in der Registratur ist die Ausführungsreihenfolge.

Pflichtmodule: `base`, `postfix`, `users`, `ssh`, `ufw`, `fail2ban`, `rkhunter`, `logging`, `unattended`, `restic`, `monit`, `lynis`. Optionale Module: `nginx` und `postgresql`, aktiviert über einen Eintrag in `optional_enabled`.

Ein Modul kann eine Klassenmethode `doc` bereitstellen, die seinen Abschnitt für den Installationsbericht liefert (Kapitel 8).

## 5. Konfiguration

Die Konfiguration folgt dem Zwei-Datei-Muster: die Vorlage `etc/secure-base/secure-base.conf.example` im Paket, die echte `etc/secure-base/secure-base.conf` auf dem Zielsystem (nie eingecheckt, Rechte 0600). Das Format ist INI mit einem Abschnitt je Modul plus `[installer]` und `[general]`.

Fehlt die Datei beim Aufruf, kopiert der Installer die Vorlage mitsamt Abschnitten, Vorgabewerten und Kommentaren. Danach — nach feststehender Modulauswahl — fragt er die leeren Pflichtwerte der ausgewählten Module dialogisch als Freitext ab und schreibt sie mit Rechten 0600 zurück. Pflicht ist jeder in einer Modul-`CONFIG` genannte Schlüssel außer der je Lauf gesetzten Betriebsart und den je Modul als optional erklärten Schlüsseln. Für jedes Modul stellt der Installer aus den datei-weit eindeutigen Schlüsseln genau dessen `CONFIG`-Werte zusammen und ergänzt die Betriebsart.

## 6. Betriebsarten

| Betriebsart | Wirkung | Rechte |
|---|---|---|
| `install` | richtet die Module in Vorwärtsreihenfolge ein | Systemrechte |
| `uninstall` | nimmt die Änderungen in umgekehrter Reihenfolge zurück | Systemrechte |
| `check` | gleicht Ist- und Soll-Zustand ab, ohne zu ändern | rein lesend |
| `test` | prüft die Funktion, ohne zu ändern | rein lesend |

Der Trockenlauf (`-n`) benennt die Module nur und führt nichts aus; Bericht und ufw-Abfrage entfallen. Mit `-c` lässt sich eine abweichende Konfigurationsdatei angeben. Die optionalen Module laufen mit, sobald sie in `optional_enabled` stehen (Kapitel 4).

### 6.1 Schreibverhalten: Soll-Ist-Vergleich und zentrale Sicherungen

Vor jedem Schreiben einer vollständig generierten Datei vergleicht das Modul die vorhandene Datei mit dem Soll-Inhalt aus `secure-base.conf` und Modul-Code (Byte-Vergleich im Speicher; es wird kein Zustand auf dem Server abgelegt):

| Zustand der Datei | Verhalten |
|---|---|
| existiert nicht | schreiben |
| Inhalt = Soll | nichts tun — Meldung „unverändert — übersprungen", keine Sicherung |
| Inhalt ≠ Soll | Konflikt: `install` bricht ab, bevor eine Datei geändert wurde |
| Inhalt ≠ Soll, `--force-overwrite` | schreiben, vorher Sicherung in die zentrale Ablage |

Die Sammel-Prüfung (Ablauf-Schritt 6) meldet alle Konflikte eines Laufs gesammelt — Pfad, Modul, Grund; Dateiinhalte oder Unterschiede werden nie ausgegeben. Ob eine Abweichung von einer Hand-Änderung oder einer geänderten Konfiguration stammt, unterscheidet der Installer nicht — beides erfordert die Freigabe, die je Lauf gilt.

Sicherungen liegen zentral unter `/var/backup/secure-base/<JJJJ-MM-TT-HHMMSS>/` (ein Verzeichnis je Lauf, nur angelegt, wenn tatsächlich gesichert wird), darin die Originale unter ihrem vollen Pfad. Je Datei und Lauf entsteht höchstens eine Sicherung; das gilt auch für Dateien, die der Installer nur zeilenweise ändert (`main.cf`, `sshd_config`, …) — sie werden vor der ersten Änderung eines Laufs einmal zentral gesichert, die einzelnen Zeilen-Aktionen legen keine `.bak` mehr neben die Datei. Überschrieben wird nur nach nachweislich erfolgreicher Sicherung. Dateien mit Geheimniswert (restic-Passphrase, `sasl_passwd`) werden nie in die Ablage kopiert; bei Freigabe wird ihre alte Fassung ersatzlos verworfen, mit Hinweis in der Meldung.

Intern nutzt die Sammel-Prüfung die Modul-Betriebsart `preflight` (rein lesend); `check` meldet zusätzlich je verwalteter Datei, ob sie dem Soll entspricht, fehlt oder abweicht.

## 7. Bedienoberfläche

Der Installer zeigt den Lauf als Statusliste (`StatusView`): je Modul den Zustand (läuft, Erfolg, Fehler), die aktuelle Statusmeldung und den Gesamtstatus. Die Anzeige läuft im alternativen Bildschirm und passt sich der Terminalhöhe an. Meldungen der Module gehen zugleich in die Logdatei.

Die Firewall bleibt nach dem ufw-Modul zunächst inaktiv. Erst am Ende eines vollständig erfolgreichen Installationslaufs bietet der Installer die Aktivierung an — über `/dev/tty` und nur nach ausdrücklicher Zustimmung, damit das Aktivieren die laufende SSH-Sitzung nicht unbemerkt unterbricht. Ohne interaktives Terminal unterbleibt sie.

## 8. Installationsbericht

Nach jedem `install`-Lauf legt der Installer einen Bericht unter `/var/log/secure-base/` ab (Rechte 0600) und sendet ihn an die Administrator Email Adresse (`admin_mail`); der Schalter `install_report` steuert dies. Der Bericht nennt je Modul das Ergebnis und hängt die `doc`-Abschnitte der erfolgreichen Module an. Vor jeder Ablage und jedem Versand prüft ein Selbsttest den Text auf Geheimnisnamen und -werte (`relay_password`, `main_user_password`, `restic_passphrase`); schlägt er an, unterbleiben Ablage und Versand. Ablage und Versand sind fail-soft — ihr Scheitern ändert den Rückgabewert des Laufs nicht.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-07-10 | macodix | Erstanlage des Installer-Konzepts. |
| 0.02 | 2026-07-13 | macodix | Kapitel Aufruf aufgenommen (bisher `installer/README.md`, Verzeichnis entfernt). |
| 0.03 | 2026-07-13 | macodix | Distributionsprüfung als erster Schritt jedes Laufs. |
