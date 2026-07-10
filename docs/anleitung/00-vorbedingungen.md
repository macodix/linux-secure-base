# Vorbedingungen

Ausgangspunkt ist die Installation Ubuntu Server 26.04 LTS mit SSH, wie sie typischerweise von vielen VPS Hostern zur Verfügung gestellt wird.

Für die Einrichtung ist `root` Zugang erforderlich.

SSH-Schlüssel (Public-Key-Verfahren) für root und einen Hauptbenutzer sollten verfügbar sein (die Erstellung der Schlüssel ist nicht Bestandteil der Dokumentation und der Scripte).

Für das Backup muss ein über SFTP nutzbarer (externer) Speicherplatz verfügbar sein.

## Konfigurationsdatei anlegen

Alle Module beziehen ihre Werte — Rechnername, Administrator Email Adresse, Modulparameter — aus `etc/secure-base/secure-base.conf`. Die Datei folgt dem Zwei-Datei-Muster: Im Paket liegt die Vorlage `etc/secure-base/secure-base.conf.example` (INI-Format, ein Abschnitt je Modul plus allgemeine Werte), die echte `secure-base.conf` entsteht auf dem Zielsystem und wird nie eingecheckt. Sie erhält die Rechte `0600`.

Zwei Wege, sie anzulegen:

- Von Hand: die Vorlage nach `etc/secure-base/secure-base.conf` kopieren, die leeren Pflichtwerte setzen und die Rechte auf `0600` beschränken.
- Über den Installer: Fehlt die Datei beim ersten Aufruf, legt der Installer sie aus den Moduldeklarationen an. Leere Pflichtwerte fragt er dialogisch ab und schreibt sie zurück; die Rechte `0600` setzt er selbst.

