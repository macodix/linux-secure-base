# Installer

Der Installer richtet ein gehärtetes Ubuntu-Grundsystem ein. Er ist von Bash auf Python umgestellt und nutzt dafür den wiederverwendbaren Bausatz pifos.

## Bezug

Der Installer liegt als einzelnes, signiertes Ein-Schritt-Paket vor (Installer, pifos und Fremdbibliotheken bereits enthalten). Bezug, Echtheitsprüfung und Entpacken: siehe [`../README.md`](../README.md), Abschnitte „Echtheit prüfen (Signatur)" und „Installation in einem Schritt".


## Aufruf

```sh
sudo bin/lsb-installer {install|check} [MODUL ...] [-c PFAD] [-o]
```

- `install` richtet die ausgewählten Module ein; `check` gleicht Ist- und Soll-Zustand ab, ohne zu ändern.
- `MODUL ...` verarbeitet nur die genannten Module (Kurznamen, siehe Konfiguration); ohne Angabe laufen die in der Konfiguration aktivierten Pflichtmodule.
- `-c PFAD` / `--conf PFAD` gibt eine abweichende Konfigurationsdatei an; ohne Angabe `etc/lsb/lsb.conf`.
- `-o` / `--optional` verarbeitet zusätzlich die aktivierten optionalen Module.

Der Installer benötigt Systemrechte (`sudo`) und bricht ohne sie ab, bevor er etwas ändert.

## Konfiguration

Die Konfiguration folgt dem Zwei-Datei-Muster: Die Vorlage [`../etc/lsb/lsb.conf.example`](../etc/lsb/lsb.conf.example) liegt im Repository/Paket, die echte `etc/lsb/lsb.conf` entsteht auf dem Zielsystem und wird nie eingecheckt.

Fehlt die Konfigurationsdatei beim ersten Aufruf ganz, führt der Installer den Konfigurator und legt sie aus den Moduldeklarationen an. Sind einzelne Pflichtwerte leer, fragt er sie dialogisch ab und schreibt sie zurück. Die echte `lsb.conf` erhält dabei die Rechte `0600`.

## Module

Aktuell ist das Referenzmodul `base` umgesetzt (Rechnername, Zeitzone, NTP, sysctl-Härtung, Kernel-Modul-Sperrliste, autofs-Maskierung, AppArmor). Die weiteren Module (`postfix`, `users`, `ssh`, `ufw`, `fail2ban`, `rkhunter`, `logging`, `unattended`, `restic`, `monit`, `lynis`, optional `nginx`) folgen als eigene Pläne, nach demselben Muster.

## Konzept

- Installer: [`../docs/installer/lsb-installer.md`](../docs/installer/lsb-installer.md)
- Bausatz pifos: eigenes Projekt [github.com/macodix/pifos](https://github.com/macodix/pifos)
