# Beschreibung secure-base-installer

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
Jedes Modul ist aber auch einzeln ausführbar.

Der `secure-base-installer` bietet auch Befehle zur Überprüfung `secure-base-installer check` bzw. zum Test der Installation an (`secure-base-installer test`)

Der `secure-base-installer` dient dazu den Prozess der Installation eines gehärteten Server zu standardisieren und zu beschleunigen. Mehr Informationen, auch die Funktionsweise der einzelnen Module, stehen im `docs`-Verzeichnis in diesem Repo.

---
# Inhalt

**Kurzanleitung**

**Konfiguration**

**Bedienung**

**Module**

**Lizenz**

---


# Kurzanleitung

Diese Anleitung führt von einem frischen Server bis zum gehärteten System.
Sie ist bewusst knapp gehalten und in dieser Form vollständig lauffähig — die
Details stehen weiter unten.


## Voraussetzungen

- **Ubuntu Server 26.04 LTS**, minimal mit SSH
- **root-Zugang** auf dem Zielserver
- ein **SSH-Public-Key** für den künftigen Hauptbenutzer (die Key-Erstellung
  ist nicht Teil dieser Scripts)
- ein über **SFTP erreichbarer Speicherplatz** für das Backup
- ein **SMTP-Smarthost** (Relay) mit Zugangsdaten für den Mail-Versand

## In 5 Schritten

### 1. Den Installer herunterladen

**a) Entweder mit `wget`**

```sh
wget -qO- https://github.com/macodix/linux-secure-base/archive/refs/heads/main.tar.gz | tar xz
mv linux-secure-base-main linux-secure-base
```

**b) oder mit `git`**

```sh
apt update && apt install -y git
git clone https://github.com/macodix/linux-secure-base.git
```

### 2. Installer Verzeichnis

```
cd linux-secure-base-main/installer
```

### 3. Beispiel-Konfigurationsdatei kopieren

```
cp conf/secure-base.conf.example conf/secure-base.conf
```

### 4. Konfiguration anpassen (Mindestanforderungen)

Die Konfigurationsdatei `secure-base.conf` mit einem Editor öffnen und mindestens folgende Werte eintragen:

```
# == Allgemein ==
FQDN=""                        # vollständiger Servername mit Domain
ADMIN_MAIL=""                  # die E-Mail-Adresse für administrative Benachrichtigungen (z. B. Monitoring)

# == postfix ==
RELAY_HOST=""                  # Name des SMTP Servers
RELAY_PORT="587"               # *optional*, falls der SMTP-Server nicht auf Port 587 hört
RELAY_USER=""                  # Username (meist E-Mail-Adresse) des SMTP Users von RELAY_HOST
RELAY_PASSWORD=""              # *optional*, wird abgefragt wenn nicht gesetzt 

# == users ==
MAIN_USER=""                   # Benutzernamen des Hauptbenutzers (z. B. für Zugriff via SSH)
MAIN_USER_PASSWORD=""          # *optional*, wird abgefragt wenn nicht gesetzt
MAIN_USER_PUBKEY=""            # *entweder* SSH Public Key (i. d. R. eine Zeile, z. B. "ssh-ed25519 AAAA ..... user@laptop")
MAIN_USER_PUBKEY_FILE=""       # *oder* einen Pfad zu der Datei mit dem Public Key angeben
TOTP_DELIVERY="terminal"       # *optional*, wenn auf 'mail' gesetzt wird Google Authenticator Secret und QR-Code an ADMIN_MAIL geschickt

# == restic ==
SFTP_HOST_ALIAS=""             # der Hostname des Backup SFTP-Servers in der ~/.ssh/config (SFTP Zugang dort konfigurieren)
SFTP_PATH=""                   # Backup-Verzeichnis auf dem Backup Server
RESTIC_PASSPPHRASE=""          # *optional*, Passwort für das verschlüsselte restic-Backup, wird abgefragt wenn nicht gesetzt

# == monit ==
MONIT_MAIL_FROM=""             # Absender Adress für Monitoring Mail Alerts
```

Alle anderen Werte können bei Bedarf natürlich auch angepasst werden.


### 5. Installation

Optional kann ein Testlauf (dry-run) der Installation gestartet werden mit:
```
 ./secure-base-installer -n install
```

Oder direkt die Installation gestartet werden:
```
./secure-base-installer install
```

### H I N W E I S E

>Während der Installation wird SSH Konfiguration geändert. Es wird eindrücklich empfohlen, vor dem Schließen des `root`-Terminals den SSH Zugang des Hauptbenutzers zu testen.
>
>Die Konfigurations-Datei sollte unmittelbar nach der Installation vom Server entfernt oder gelöscht werden
>
>Für mehr Information über den Installationsverlauf kann die Logdatei `/var/log/secure-base/secure-base.log` per `tail -f` in einem zweiten Terminal überwacht werden.

---

# Konfiguration

## Pflichtwerte

Ohne diese bricht `install` mit Meldung ab bzw. der SSH Zugang
funktioniert nicht:

| Wert | Abschnitt | Bedeutung |
|---|---|---|
| `FQDN` | Allgemein | vollständiger Hostname des Servers |
| `ADMIN_MAIL` | Allgemein | Zieladresse aller Systembenachrichtigungen |
| `MAIN_USER` | users | Login des nicht-root-Hauptbenutzers |
| `MAIN_USER_PUBKEY` *oder* `MAIN_USER_PUBKEY_FILE` | users | SSH-Public-Key des Hauptbenutzers — **ohne ihn kein SSH-Login** |
| `RELAY_HOST`, `RELAY_PORT`, `RELAY_USER` | postfix | SMTP-Smarthost für den Mail-Versand |
| `SFTP_HOST_ALIAS`, `SFTP_PATH` | restic | SFTP-Ziel für das Backup |

`ALLOW_IN_TCP` (ufw) **muss** Port `22` enthalten, sonst sperrt die Firewall
den SSH-Zugang aus — der Installer bricht in diesem Fall ab.

## Passwörter

Die Passwort-Einträge `RELAY_PASSWORD`, `MAIN_USER_PASSWORD` und `RESTIC_PASSPHRASE`
können auch leer gelassen werden. In diesem Fall werden bei `secure-base-installer install`
die Passwörter interaktiv abgefragt.

## Module aktivieren

`MODULES_ENABLED` legt fest, **welche** Module installiert werden. Die **Reihenfolge** ist
allerdings fest vorgegeben und unabhängig von dieser Liste. Nicht gewünschte Module können 
hier entfernt werden.


## Weitere Konfigurationseinstellungen

Zur Erklärung weiterer Einstellungen in der Konfigurationsdatei bitte die Kommentare in
der Datei beachten.

---

# Bedienung

```
secure-base-installer [OPTIONEN] <KOMMANDO> [<modul> ...]
```

## Kommandos

| Kommando | Wirkung |
|---|---|
| `install` | Module installieren und konfigurieren |
| `uninstall` | Modul-Konfiguration zurücknehmen (umgekehrte Reihenfolge) |
| `check` | Soll-Ist-Vergleich, ändert nichts |
| `test` | Scharfer Funktionstest, ändert nichts |

Ohne Modul-Argumente laufen alle in `MODULES_ENABLED` aktivierten Module.
Mit den Modul-Argumenten können auch einzelne Module installiert, deinstalliert
oder geprüft (test, check) werden:

```sh
./secure-base-installer check              # alle aktivierten Module prüfen
./secure-base-installer check ssh ufw      # nur ssh und ufw prüfen
./secure-base-installer install base       # nur das base-Modul installieren
```

## Optionen

| Option | Wirkung |
|---|---|
| `-c, --conf <pfad>` | alternative Konfigdatei (Default: `conf/secure-base.conf`) |
| `-q, --quiet` | nur WARN und ERROR ausgeben |
| `-v, --verbose` | INFO auch auf der Shell (sonst nur im Logfile) |
| `-n, --dry-run` | Trockenlauf: Statusliste sichtbar, keine Änderungen |
| `-h, --help` | Hilfe ausgeben |

## Logfile

Alle Läufe schreiben nach `/var/log/secure-base/secure-base.log` (Append).
Parallel mitlesen:

```sh
tail -f /var/log/secure-base/secure-base.log
```

## Module einzeln und standalone

Jedes Modul ist ein eigenständiges Skript und kann auch direkt aufgerufen
werden (gleiche Kommandos und Optionen):

```sh
./lib/modules/ssh.sh check
./lib/modules/ssh.sh -c /pfad/zur/test.conf check
```

## Deinstallation

```sh
./secure-base-installer uninstall          # alle Module, umgekehrte Reihenfolge
./secure-base-installer uninstall fail2ban # einzeln
```

---

# Module

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


# Lizenz

GNU General Public License v3.0 (GPL-3.0) — siehe [`LICENSE`](../LICENSE) im
Repository-Wurzelverzeichnis. Bereitstellung ohne Gewährleistung, Einsatz auf
eigene Verantwortung (siehe „Grenzen & Warnung" im Haupt-README).
