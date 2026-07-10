# secure-base-installer

Der secure-base-installer richtet ein gehärtetes Ubuntu-Grundsystem in einem Lauf ein. Dieses Dokument beschreibt seinen Aufbau: die Grundlage pifos, den Ablauf eines Laufs, das Modulmuster, die Konfiguration, die Betriebsarten, die Bedienoberfläche und den Installationsbericht. Bedienung und Bezug stehen in [installer/README.md](../../installer/README.md), die eingerichteten Zielzustände in der [Systembeschreibung](../systembeschreibung/INDEX.md).

## Inhaltsverzeichnis
1. Grundlage pifos
2. Ablauf eines Laufs
3. Module
4. Konfiguration
5. Betriebsarten
6. Bedienoberfläche
7. Installationsbericht

## 1. Grundlage pifos

Der Installer nutzt den wiederverwendbaren Bausatz pifos (eigenes Projekt [github.com/macodix/pifos](https://github.com/macodix/pifos)). Die Aufruferklasse `LsbInstaller` erbt von `PifosCaller` (`pifos.caller`). pifos übernimmt den Prozessstart je Modul, die Trennung von Standard- und Fehlerausgabe über `subprocess`, die Nachrichten zwischen Modul und Aufrufer sowie das Anlegen der Logdatei mit Rechten 0600. Jedes Härtungsmodul ist eine pifos-`Module`-Klasse.

## 2. Ablauf eines Laufs

Der Einstiegspunkt `bin/secure-base-installer` liest die Kommandozeile und ruft `main` auf. Ein Lauf durchläuft:

1. Rechteprüfung — `install` und `uninstall` ohne Trockenlauf verlangen Systemrechte und brechen sonst mit Code 2 ab, bevor etwas geändert wird; `check` und `test` sind rein lesend.
2. Konfiguration bereitstellen — fehlt die Datei, wird die Vorlage kopiert (Kapitel 4).
3. Modulauswahl — feste Reihenfolge aus der Registratur, gefiltert nach den Aktivierungslisten und der Kommandozeile (Kapitel 3).
4. Fehlende Pflichtwerte klären — dialogische Abfrage, Rückschreiben mit Rechten 0600 (Kapitel 4).
5. Module ausführen — je Modul Start, Statusmeldungen, Ergebnis (Kapitel 6). `install` und `uninstall` bauen aufeinander auf und brechen nach einem Modulfehler ab; `check` und `test` laufen vollständig durch.
6. Abschluss — bei `install` der Installationsbericht (Kapitel 7) und, nach vollständig erfolgreichem Lauf, die Abfrage zur ufw-Aktivierung (Kapitel 6).

Der Rückgabewert ist 0 bei Erfolg, 1 bei einem Modulfehler, 2 bei fehlenden Rechten, fehlerhafter Auswahl oder ungültiger Konfiguration.

## 3. Module

Jedes Modul ist eine pifos-`Module`-Klasse mit einer `CONFIG`-Liste seiner Konfigurationsschlüssel. Die Registratur (`secure_base.modules.REGISTRY`) hält je Modul einen `ModuleSpec` mit Kurzname, Anzeige-Label, Modulklasse und Optional-Kennzeichen; die Reihenfolge in der Registratur ist die Ausführungsreihenfolge.

Pflichtmodule: `base`, `postfix`, `users`, `ssh`, `ufw`, `fail2ban`, `rkhunter`, `logging`, `unattended`, `restic`, `monit`, `lynis`. Optionale Module: `nginx` und `postgresql`, aktiviert über einen Eintrag in `optional_enabled`.

Ein Modul kann eine Klassenmethode `doc` bereitstellen, die seinen Abschnitt für den Installationsbericht liefert (Kapitel 7).

## 4. Konfiguration

Die Konfiguration folgt dem Zwei-Datei-Muster: die Vorlage `etc/secure-base/secure-base.conf.example` im Paket, die echte `etc/secure-base/secure-base.conf` auf dem Zielsystem (nie eingecheckt, Rechte 0600). Das Format ist INI mit einem Abschnitt je Modul plus `[installer]` und `[general]`.

Fehlt die Datei beim Aufruf, kopiert der Installer die Vorlage mitsamt Abschnitten, Vorgabewerten und Kommentaren. Danach — nach feststehender Modulauswahl — fragt er die leeren Pflichtwerte der ausgewählten Module dialogisch als Freitext ab und schreibt sie mit Rechten 0600 zurück. Pflicht ist jeder in einer Modul-`CONFIG` genannte Schlüssel außer der je Lauf gesetzten Betriebsart und den je Modul als optional erklärten Schlüsseln. Für jedes Modul stellt der Installer aus den datei-weit eindeutigen Schlüsseln genau dessen `CONFIG`-Werte zusammen und ergänzt die Betriebsart.

## 5. Betriebsarten

| Betriebsart | Wirkung | Rechte |
|---|---|---|
| `install` | richtet die Module in Vorwärtsreihenfolge ein | Systemrechte |
| `uninstall` | nimmt die Änderungen in umgekehrter Reihenfolge zurück | Systemrechte |
| `check` | gleicht Ist- und Soll-Zustand ab, ohne zu ändern | rein lesend |
| `test` | prüft die Funktion, ohne zu ändern | rein lesend |

Der Trockenlauf (`-n`) benennt die Module nur und führt nichts aus; Bericht und ufw-Abfrage entfallen. Mit `-c` lässt sich eine abweichende Konfigurationsdatei angeben. Die optionalen Module laufen mit, sobald sie in `optional_enabled` stehen (Kapitel 3).

## 6. Bedienoberfläche

Der Installer zeigt den Lauf als Statusliste (`StatusView`): je Modul den Zustand (läuft, Erfolg, Fehler), die aktuelle Statusmeldung und den Gesamtstatus. Die Anzeige läuft im alternativen Bildschirm und passt sich der Terminalhöhe an. Meldungen der Module gehen zugleich in die Logdatei.

Die Firewall bleibt nach dem ufw-Modul zunächst inaktiv. Erst am Ende eines vollständig erfolgreichen Installationslaufs bietet der Installer die Aktivierung an — über `/dev/tty` und nur nach ausdrücklicher Zustimmung, damit das Aktivieren die laufende SSH-Sitzung nicht unbemerkt unterbricht. Ohne interaktives Terminal unterbleibt sie.

## 7. Installationsbericht

Nach jedem `install`-Lauf legt der Installer einen Bericht unter `/var/log/secure-base/` ab (Rechte 0600) und sendet ihn an die Administrator Email Adresse (`admin_mail`); der Schalter `install_report` steuert dies. Der Bericht nennt je Modul das Ergebnis und hängt die `doc`-Abschnitte der erfolgreichen Module an. Vor jeder Ablage und jedem Versand prüft ein Selbsttest den Text auf Geheimnisnamen und -werte (`relay_password`, `main_user_password`, `restic_passphrase`); schlägt er an, unterbleiben Ablage und Versand. Ablage und Versand sind fail-soft — ihr Scheitern ändert den Rückgabewert des Laufs nicht.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-07-10 | macodix | Erstanlage des Installer-Konzepts. |
