# Installer

Der Installer richtet ein gehärtetes Ubuntu-Grundsystem ein. Er ist von Bash auf Python umgestellt und nutzt dafür den wiederverwendbaren Bausatz pifos.

## Bezug

Der Installer liegt als einzelnes, signiertes Ein-Schritt-Paket vor (Installer, pifos und Fremdbibliotheken bereits enthalten). Bezug, Echtheitsprüfung und Entpacken: siehe [`../README.md`](../README.md), Abschnitte „Echtheit prüfen (Signatur)" und „Installation in einem Schritt".


## Aufruf

```sh
sudo bin/secure-base-installer {install|uninstall|check|test} [MODUL ...] [-c PFAD] [-n] [-o]
```

- `install` richtet die ausgewählten Module ein; `uninstall` nimmt die Modul-Änderungen in umgekehrter Reihenfolge zurück; `check` gleicht Ist- und Soll-Zustand ab, ohne zu ändern; `test` prüft die Funktion ohne Änderung.
- `MODUL ...` verarbeitet nur die genannten Module (Kurznamen, siehe Konfiguration); ohne Angabe laufen die in der Konfiguration aktivierten Pflichtmodule.
- `-c PFAD` / `--conf PFAD` gibt eine abweichende Konfigurationsdatei an; ohne Angabe `etc/secure-base/secure-base.conf`.
- `-n` / `--dry-run` listet die Module nur auf und führt nichts aus.
- `-o` / `--optional` verarbeitet zusätzlich die aktivierten optionalen Module.

Der Installer benötigt Systemrechte (`sudo`) und bricht ohne sie ab, bevor er etwas ändert.

## Konfiguration

Die Konfiguration folgt dem Zwei-Datei-Muster: Die Vorlage [`../etc/secure-base/secure-base.conf.example`](../etc/secure-base/secure-base.conf.example) liegt im Repository/Paket, die echte `etc/secure-base/secure-base.conf` entsteht auf dem Zielsystem und wird nie eingecheckt.

Fehlt die Konfigurationsdatei beim ersten Aufruf ganz, führt der Installer den Konfigurator und legt sie aus den Moduldeklarationen an. Sind einzelne Pflichtwerte leer, fragt er sie dialogisch ab und schreibt sie zurück. Die echte `secure-base.conf` erhält dabei die Rechte `0600`.

## Module

Umgesetzt sind die Pflichtmodule `base` (Rechnername, Zeitzone, NTP, sysctl-Härtung, Kernel-Modul-Sperrliste, autofs-Maskierung, AppArmor), `postfix`, `users`, `ssh`, `ufw`, `fail2ban`, `rkhunter`, `logging`, `unattended`, `restic`, `monit` und `lynis` sowie die optionalen Module `nginx` und `postgresql`. Alle folgen demselben Muster.

## Konzept

- Installer: [`../docs/installer/secure-base-installer.md`](../docs/installer/secure-base-installer.md)
- Bausatz pifos: eigenes Projekt [github.com/macodix/pifos](https://github.com/macodix/pifos)
