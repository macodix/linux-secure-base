# Vorhaben: Installer-Umstellung auf Python

**Status:** vorgemerkt — noch nicht begonnen. Arbeit erfolgt in dieser Branch `python-umstellung`, getrennt vom laufenden Bash-Stand auf `main`.

## Ziel

Den `secure-base-installer` (derzeit Bash) auf Python umstellen, um bessere Kontrolle über die Ausgaben und Prozesse der aufgerufenen Befehle zu erhalten.

## Auslöser

Bei der Bash-Umsetzung traten Probleme auf, die mit der nebenläufigen Terminal-Ausgabe und dem Aufruf externer Befehle zusammenhängen:

- `ufw enable` aus dem Installer heraus stört die laufende SSH-Verbindung bzw. die Live-Anzeige; von Hand im Terminal tritt das nicht auf. Vermutung (unbelegt): Unterschied zwischen direktem Aufruf im SSH-Terminal und Aufruf via Skript in einer Subshell.
- Die Live-Statusanzeige und das Schreiben aufs Terminal über die SSH-Verbindung sind fragil.
- Die Trennung von Befehls-Ausgabe (Logfile) und UI-Darstellung ist in Bash umständlich.

Als Interim wurde die ufw-Aktivierung aus dem Installationslauf herausgenommen und als interaktive Abfrage am Ende gelöst (Bash-Stand auf `main`).

## Erwarteter Nutzen

- Saubere Trennung und Kontrolle von stdout/stderr je aufgerufenem Befehl (z. B. `subprocess` mit getrennten Streams).
- Robustere Status-/Terminalanzeige.
- Klarere Fehler- und Ablaufsteuerung.

## Vorgehen

- Beginn erst nach Abschluss der laufenden Bash-Arbeiten.
- Bestehende Konventionen beachten (`~/dev/policies/konv-*`, insbesondere `konv-scripting.md` für Python).
