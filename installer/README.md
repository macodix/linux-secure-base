# secure-base-installer

Installiert und härtet ein Ubuntu-Grundsystem („Linux Secure Base") in 12 Modulen:
- Grundkonfiguration,
- Mail-Versand,
- Hauptbenutzer,
- SSH-Härtung mit TOTP,
- Firewall,
- Brute-Force- und Schadsoftware-Schutz,
- Protokollierung,
- automatische Updates,
- Datensicherung,
- Monitoring und
- monatliche Härtungsprüfung.

Die Reihenfolge der Module ist dabei fest voreingestellt und kann nicht verändert werden.
Jedes Modul ist aber auch einzeln auführbar.

Der ˋsecure-base-installerˋ bietet auch Befehle zur Überorüfung ˋsecure-base-installer checkˋ bzw. zum Test der Installation an (ˋsecure-base-installer testˋ)

---

## Schnellstart

Diese Anleitung führt von einem frischen Server bis zum gehärteten System.
Sie ist bewusst knapp gehalten und in dieser Form vollständig lauffähig — die
Details stehen weiter unten.

### Voraussetzungen

- **Ubuntu Server 26.04 LTS**, frisch installiert mit SSH Zugang
- **root-Zugang** auf dem Zielserver
- ein **SSH-Public-Key** für den künftigen Hauptbenutzer (die Key-Erstellung
  ist nicht Teil dieser Scripts)
- ein über **SFTP erreichbarer Speicherplatz** für das Backup
- ein **SMTP-Smarthost** (Relay) mit Zugangsdaten für den Mail-Versand

### Schritte

Auf dem Zielserver als root:

```sh
# 1. Repository holen — Variante mit git:
apt update && apt install -y git
git clone https://github.com/macodix/linux-secure-base.git

#    ...oder ohne git, nur mit wget und tar:
#    wget -qO- https://github.com/macodix/linux-secure-base/archive/refs/heads/main.tar.gz | tar xz
#    mv linux-secure-base-main linux-secure-base

cd linux-secure-base/installer

# 2. Konfiguration aus der Vorlage anlegen
cp conf/secure-base.conf.example conf/secure-base.conf

# 3. Pflichtwerte eintragen (siehe Tabelle unten — mindestens FQDN,
#    ADMIN_MAIL, MAIN_USER, TIMEZONE, MAIN_USER_PUBKEY, RELAY_*, SFTP_*)
nano conf/secure-base.conf

# 4. Trockenlauf — zeigt die Modul-Reihenfolge, ändert nichts
./secure-base-installer -n install

# 5. Installation starten
./secure-base-installer install
```

> **Aussperr-Schutz — bitte lesen.** Die SSH-Härtung deaktiviert den
> Passwort-Login; ab dann kommst du nur noch per Key **und** TOTP herein.
> Bevor du die laufende root-Sitzung schließt, melde dich in einer **zweiten**
> Sitzung als Hauptbenutzer an und prüfe, dass der Login klappt. Andernfalls
> riskierst du, dich vom Server auszusperren.

Sensible Werte (`RELAY_PASSWORD`, `MAIN_USER_PASSWORD`, `RESTIC_PASSPHRASE`)
lässt du in der conf am besten leer — dann fragt `install` sie zur Laufzeit
ab, ohne Echo und ohne dass sie ins Logfile gelangen.

Das genügt für ein vollständig gehärtetes System. Der Rest dieses Dokuments
ist Nachschlagewerk.

---

## Konfiguration

### Zwei-Datei-Muster

| Datei | Rolle |
|---|---|
| `conf/secure-base.conf.example` | Vorlage im Repo, mit Platzhaltern und Kommentaren |
| `conf/secure-base.conf` | deine echte Konfiguration — `gitignored`, kommt nie ins Repo |

Du legst die echte conf einmal aus der Vorlage an und trägst deine Werte ein.
Alle Module lesen aus dieser einen Datei, gegliedert nach Abschnitten
(`# == <modul> ==`). Jeder Wert ist in der Vorlage kommentiert.

### Pflichtwerte

Ohne diese bricht `install` mit klarer Meldung ab bzw. der Zugang
funktioniert nicht:

| Wert | Abschnitt | Bedeutung |
|---|---|---|
| `FQDN` | Allgemein | vollständiger Hostname des Servers |
| `ADMIN_MAIL` | Allgemein | Zieladresse aller Systembenachrichtigungen |
| `MAIN_USER` | Allgemein | Login des nicht-root-Hauptbenutzers |
| `TIMEZONE` | Allgemein | Zeitzone (tzdata-Schreibweise) |
| `MAIN_USER_PUBKEY` *oder* `MAIN_USER_PUBKEY_FILE` | users | SSH-Public-Key des Hauptbenutzers — **ohne ihn kein SSH-Login** |
| `RELAY_HOST`, `RELAY_PORT`, `RELAY_USER` | postfix | SMTP-Smarthost für den Mail-Versand |
| `SFTP_HOST_ALIAS`, `SFTP_PATH` | restic | SFTP-Ziel für das Backup |

`ALLOW_IN_TCP` (ufw) **muss** Port `22` enthalten, sonst sperrt die Firewall
den SSH-Zugang aus — der Installer bricht in diesem Fall ab.

### Sensible Werte

`RELAY_PASSWORD`, `MAIN_USER_PASSWORD` und `RESTIC_PASSPHRASE` leer lassen →
`install` fragt sie interaktiv ab (ohne Echo). Trägst du sie in die conf ein,
stehen sie dort im Klartext; die Datei ist zwar root-only und `gitignored`,
die interaktive Eingabe ist aber sicherer.

### Module aktivieren

`MODULES_ENABLED` legt fest, **welche** Module laufen. Die **Reihenfolge** ist
fest vorgegeben und unabhängig von dieser Liste. Nicht benötigte Module hier
entfernen oder auskommentieren.

---

## Bedienung

```
secure-base-installer [OPTIONEN] <KOMMANDO> [<modul> ...]
```

### Kommandos

| Kommando | Wirkung |
|---|---|
| `install` | Module installieren und konfigurieren |
| `uninstall` | Modul-Konfiguration zurücknehmen (umgekehrte Reihenfolge) |
| `check` | Soll-Ist-Vergleich, ändert nichts |
| `test` | Scharfer Funktionstest, ändert nichts |

Ohne Modul-Argumente laufen alle in `MODULES_ENABLED` aktivierten Module.
Mit Modul-Argumenten nur die genannten (immer in der kanonischen Reihenfolge):

```sh
./secure-base-installer check              # alle aktivierten Module prüfen
./secure-base-installer check ssh ufw      # nur ssh und ufw prüfen
./secure-base-installer install base       # nur das base-Modul installieren
```

### Optionen

| Option | Wirkung |
|---|---|
| `-c, --conf <pfad>` | alternative Konfigdatei (Default: `conf/secure-base.conf`) |
| `-q, --quiet` | nur WARN und ERROR ausgeben |
| `-v, --verbose` | INFO auch auf der Shell (sonst nur im Logfile) |
| `-n, --dry-run` | Trockenlauf: Statusliste sichtbar, keine Änderungen |
| `-h, --help` | Hilfe ausgeben |

### Logfile

Alle Läufe schreiben nach `/var/log/secure-base/secure-base.log` (Append).
Parallel mitlesen:

```sh
tail -f /var/log/secure-base/secure-base.log
```

### Module einzeln und standalone

Jedes Modul ist ein eigenständiges Skript und kann auch direkt aufgerufen
werden (gleiche Kommandos und Optionen):

```sh
./lib/modules/ssh.sh check
./lib/modules/ssh.sh -c /pfad/zur/test.conf check
```

### Deinstallation

```sh
./secure-base-installer uninstall          # alle Module, umgekehrte Reihenfolge
./secure-base-installer uninstall fail2ban # einzeln
```

---

## Module

In Ausführungsreihenfolge:

| # | Modul | Zweck | conf-Werte |
|---|---|---|---|
| 1 | `base` | Hostname, Zeitzone, Paketquellen | `FQDN`, `TIMEZONE` |
| 2 | `postfix` | Mail-Versand als Satellite an einen Smarthost | `RELAY_*`, `ADMIN_MAIL` |
| 3 | `users` | Hauptbenutzer, `ssh-users`-Gruppe, TOTP-Secret | `MAIN_USER*`, `TOTP_DELIVERY`, `UNINSTALL_REMOVE_USER` |
| 4 | `ssh` | SSH-Härtung mit TOTP, optional Login-Mail | `ENABLE_LOGIN_MAIL`, `ENABLE_CHALLENGE_RESPONSE_AUTH` |
| 5 | `ufw` | Firewall, Default-deny, definierte Port-Listen | `ALLOW_IN_TCP`, `ALLOW_OUT_TCP`, `ALLOW_OUT_UDP` |
| 6 | `fail2ban` | Brute-Force-Schutz für SSH | `IGNOREIP` |
| 7 | `rkhunter` | täglicher Schadsoftware-Scan mit Mail-Bericht | (`ADMIN_MAIL`) |
| 8 | `logging` | journald, logwatch, auditd, logrotate | `JOURNALD_MAX_USE`, `JOURNALD_MAX_RETENTION` |
| 9 | `unattended` | automatische Sicherheitsupdates | `AUTO_REBOOT*`, `APT_DAILY*` |
| 10 | `restic` | Datensicherung auf externen SFTP-Raum | `SFTP_*`, `RESTIC_PASSPHRASE` |
| 11 | `monit` | Monitoring von Platte, Last, Diensten | `MONIT_MAIL_FROM`, `CHECKS_ENABLED` |
| 12 | `lynis` | monatliche Härtungsprüfung (Cron) | `LYNIS_SCHEDULE` |

Ausführliche Beschreibung je Modul: `docs/anleitung/` (Schritt-für-Schritt)
und `docs/systembeschreibung/` (Hintergründe und Festlegungen).

---

## Sicherheitshinweise

- **Aussperr-Schutz:** siehe Schnellstart — Login in zweiter Sitzung
  verifizieren, bevor die root-Sitzung geschlossen wird.
- **TOTP-Zustellung:** Standard ist `TOTP_DELIVERY="terminal"` (QR-Code am
  Bildschirm). `mail` verschickt den QR-Code an `ADMIN_MAIL` und macht das
  Setup vollständig unbeaufsichtigt — schwächt aber die Faktor-Trennung
  (das Secret liegt dann im Postfach). Nur bewusst und mit sofortigem Löschen
  der Mail verwenden.
- **conf-Datei:** Mode root-only, nie ins Repo (`gitignored`). Sensible Werte
  bevorzugt leer lassen und interaktiv eingeben.

---

## Lizenz

GNU General Public License v3.0 (GPL-3.0) — siehe [`LICENSE`](../LICENSE) im
Repository-Wurzelverzeichnis. Bereitstellung ohne Gewährleistung, Einsatz auf
eigene Verantwortung (siehe „Grenzen & Warnung" im Haupt-README).
