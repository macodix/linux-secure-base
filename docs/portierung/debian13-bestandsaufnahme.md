# Bestandsaufnahme Debian 13: belegte Unterschiede zu Ubuntu 26.04

Grundlage für die geplante Unterstützung von Debian 13 neben Ubuntu 26.04. Dieses Dokument enthält **keine Vermutungen**. Jede Aussage stammt aus den Paketdaten der beiden Distributionen und ist mit dem angegebenen Befehl nachprüfbar.

Stand der Erhebung: 13. Juli 2026.

## 1. Methode

Drei Quellen, alle ohne Systemrechte und ohne Zielsystem auswertbar:

**Archiv-Metadaten** — die `Release`-Dateien der Archive nennen Origin, Label, Suite und Codename. Sie entscheiden, welche Muster `unattended-upgrades` überhaupt treffen kann.

```sh
curl -s http://deb.debian.org/debian/dists/trixie/Release
curl -s http://deb.debian.org/debian-security/dists/trixie-security/Release
curl -s http://archive.ubuntu.com/ubuntu/dists/resolute/Release
curl -s http://archive.ubuntu.com/ubuntu/dists/resolute-security/Release
```

**Paketindizes** — `Packages.xz` je Archiv liefert Existenz, Version und Priorität jedes Pakets. Die Priorität sagt, ob ein Paket zur Standardinstallation gehört.

**Paketinhalte** — die `.deb`-Dateien selbst, gelesen mit `dpkg -c` (Dateiliste) und `dpkg-deb -x` (mitgelieferte Konfigurationsdateien). Damit sind Programmpfade und Vorgabekonfigurationen belegt, nicht geraten.

Ergänzend wurden die Programmpfade auf einem laufenden Ubuntu 26.04 gegengeprüft.

**Codenamen:** Ubuntu 26.04 = `resolute`, Debian 13 = `trixie`.

## 2. Archiv-Metadaten

| Archiv | Origin | Label | Suite | Codename |
|---|---|---|---|---|
| Debian 13, Hauptarchiv | `Debian` | `Debian` | **`stable`** | `trixie` |
| Debian 13, Sicherheit | `Debian` | `Debian-Security` | **`stable-security`** | `trixie-security` |
| Ubuntu 26.04, Hauptarchiv | `Ubuntu` | `Ubuntu` | `resolute` | `resolute` |
| Ubuntu 26.04, Sicherheit | `Ubuntu` | `Ubuntu` | `resolute-security` | `resolute` |

Der Unterschied in der Spalte **Suite** ist die Wurzel des schwersten Befunds (Kapitel 5.1): Debian führt dort `stable`, Ubuntu den Codenamen.

## 3. Pakete: Existenz, Version, Priorität

Priorität `required`, `important` und `standard` bedeutet: gehört zur Standardinstallation. `optional` bedeutet: wird nur auf Anforderung installiert.

| Paket | Debian 13 | Ubuntu 26.04 | Folgerung |
|---|---|---|---|
| `rsyslog` | 8.2504.0 **optional** | 8.2512.0 **important** | **Debian hat kein `/var/log/auth.log`, `syslog`, `mail.log`** |
| `sudo` | 1.9.16 **optional** | 1.9.17 **important** | `/etc/sudoers.d` nicht garantiert vorhanden |
| `cron` | 3.0pl1 **important** | 3.0pl1 **standard** | auf beiden vorhanden |
| `systemd-timesyncd` | 257.13 **standard** | 259.5 optional | Zeitsynchronisation auf beiden möglich |
| `wtmpdb` | 0.73 **standard** | 0.75 optional | Debian führt Anmeldungen in `wtmpdb` |
| `update-notifier-common` | **nicht vorhanden** | 3.207 | siehe Kapitel 5.2 |
| `apparmor` | 4.1.0 optional | 5.0.0~beta1 **standard** | Modul installiert es ohnehin |
| `postgresql` | 17 | 18 | Hauptversion wird zur Laufzeit ermittelt — unkritisch |
| `python3` | 3.13.5 | 3.14.3 | `requires-python = ">=3.13"` erfüllt |
| `unattended-upgrades` | 2.12 | 2.12ubuntu9 | vorhanden |
| `logwatch` | 7.12-3 | 7.12-3ubuntu2 | vorhanden |
| `fail2ban` | 1.1.0-8 | 1.1.0-9 | vorhanden |
| `rkhunter` | 1.4.6-13 | 1.4.6-13 | identisch |
| `monit` | 5.34.3 | 5.35.2 | vorhanden |
| `lynis` | 3.1.4 | 3.1.6 | vorhanden |
| `restic` | 0.18.0 | 0.18.1 | vorhanden |
| `postfix` | 3.10.11 | 3.10.6 | vorhanden |
| `mailutils` | 3.19 | 3.20 | vorhanden |
| `auditd` | 4.0.2 | 4.1.2 | vorhanden |
| `openssh-server` | 10.0p1 | 10.2p1 | vorhanden |
| `libpam-google-authenticator` | 20191231 | 20250213 | vorhanden, Debian deutlich älter |
| `ufw`, `nginx`, `certbot`, `qrencode` | vorhanden | vorhanden | unkritisch |

Kein Paket, das der Installer braucht, fehlt in Debian 13.

## 4. Programmpfade

Alle 54 im Code fest verdrahteten Programmpfade wurden mit den Dateilisten beider Distributionen abgeglichen.

**Ergebnis: 53 von 54 stimmen auf beiden Distributionen.** Weder Debian 13 noch Ubuntu 26.04 führen `/usr/sbin` und `/usr/bin` zusammen — die Trennung gilt auf beiden, und der Code hält sie überall ein.

| Pfad im Code | Debian 13 | Ubuntu 26.04 |
|---|---|---|
| `/usr/bin/logwatch` | **fehlt** — Paket liefert `/usr/sbin/logwatch` | **fehlt** — Paket liefert `/usr/sbin/logwatch` |

Dieser Fehler war **kein Debian-Problem, sondern ein Fehler im ausgelieferten Stand**. Er ist auf `main` behoben (Commit `12e22af`).

Sonderfall `/usr/bin/mail`: Das Paket `mailutils` liefert `mail.mailutils` und registriert `/usr/bin/mail` über `update-alternatives` — auf beiden Distributionen gleich. Der Pfad ist zur Laufzeit vorhanden.

## 5. Mitgelieferte Konfigurationen

### 5.1 unattended-upgrades — der einzige echte Blocker

Die Vorgabedatei der beiden Pakete verwendet **verschiedene Direktiven mit verschiedener Syntax**:

Debian 13:

```
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
};
```

Ubuntu 26.04:

```
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}";
        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
};
```

Das Modul `unattended` schreibt heute die **Ubuntu-Kurzform** `${distro_id}:${distro_codename}-security`. Diese Form vergleicht Origin mit Suite. Debians Suite heißt `stable-security`, nicht `trixie-security` (Kapitel 2) — das Muster trifft nichts.

**Wirkung auf Debian: keine automatischen Sicherheitsupdates, ohne Fehlermeldung.** Das ist der einzige Befund, der die Schutzwirkung des Systems aufhebt.

Derselbe Block steht in `docs/anleitung/09-automatische-sicherheitsupdates.md` und muss mit angepasst werden.

### 5.2 Neustart-Kennzeichen nach Kernel-Updates

`unattended-upgrades` liefert auf **beiden** Distributionen `/etc/kernel/postinst.d/unattended-upgrades` mit, und dieser Hook legt `/var/run/reboot-required` an. Der automatische Neustart nach Kernel-Updates funktioniert auf Debian also.

Der Unterschied liegt bei **anderen** Paketen: Auf Ubuntu melden sie ihren Neustartbedarf über `update-notifier-common` (Paket fehlt in Debian). Auf Debian bleibt das Kennzeichen bei einem Update von etwa `glibc` oder `systemd` aus.

**Wirkung: eingeschränkt, nicht kritisch.** Der Hauptfall (Kernel) ist abgedeckt.

### 5.3 fail2ban

Die Datei `/etc/fail2ban/jail.d/defaults-debian.conf` ist in **beiden** Paketen identisch:

```
[DEFAULT]
banaction = nftables
banaction_allports = nftables[type=allports]

[sshd]
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd
enabled = true
```

Das sshd-Jail liest also auf beiden Distributionen aus dem Journal, nicht aus `/var/log/auth.log`. Das fehlende `rsyslog` unter Debian trifft fail2ban **nicht**.

### 5.4 SSH

Beide Pakete liefern `ssh.service` **und** `ssh.socket` (Ubuntu zusätzlich `sshd.service` als Alias). Beide Vorgabekonfigurationen enthalten `Include /etc/ssh/sshd_config.d/*.conf`. Kein Unterschied.

### 5.5 cron.daily

`logwatch` und `rkhunter` liefern auf beiden Distributionen dieselben Dateien `/etc/cron.daily/00logwatch` bzw. `/etc/cron.daily/rkhunter`. Das Stilllegen des mitgelieferten logwatch-Laufs funktioniert auf Debian unverändert.

## 6. Was widerlegt wurde

Drei Annahmen aus der ersten, gedächtnisbasierten Einschätzung haben der Prüfung **nicht** standgehalten:

- „Auf Debian legt niemand `/var/run/reboot-required` an" — falsch, `unattended-upgrades` bringt den Kernel-Hook selbst mit (5.2).
- „Ohne rsyslog startet das fail2ban-Jail nicht" — falsch, es nutzt auf beiden Distributionen das systemd-Backend (5.3).
- „Debian 13 hat `/usr/sbin` noch nicht zusammengeführt, Ubuntu schon, deshalb bricht der logwatch-Pfad" — falsch in der Begründung: **keine** der beiden Distributionen führt zusammen, der Pfad war schlicht falsch (Kapitel 4).

## 7. Was tatsächlich distributionsabhängig ist

| # | Gegenstand | Fundstelle | Debian 13 |
|---|---|---|---|
| 1 | Origins der automatischen Updates | `unattended.py` `DEBIAN_ORIGINS_BLOCK` | andere Direktive, andere Syntax — **erledigt** |
| 2 | Neustart-Kennzeichen außerhalb des Kernels | `unattended.py` `/var/run/reboot-required` | nur bei Kernel-Updates gesetzt |
| 3 | Systemprotokolle als Dateien | `postfix.py`, `users.py` `MAIL_LOG`; Logwatch-Anhang | ohne `rsyslog` nicht vorhanden |
| 4 | `sudo` und `/etc/sudoers.d` | `logging.py` `SUDOLOG_CONF`, `AUDIT_RULES` | nicht garantiert installiert — **erledigt** |
| 5 | Härtungsmaßstab | Doku, `lynis`-Profil | CIS-Benchmark für Debian statt Ubuntu |

Punkt 3 ist für den Tagesbericht unkritisch: Die Zusammenfassung liest bereits aus dem Journal. Betroffen ist nur der angehängte Logwatch-Bericht, der ohne `rsyslog` kaum noch Quellen hätte.

Punkt 1 ist umgesetzt: Das Modul `unattended` schreibt unter Debian einen `Origins-Pattern`-Block mit Origin, Codename und Label, unter Ubuntu weiterhin die Kurzform `Allowed-Origins`. Welche Distribution läuft, stellt `secure_base.distro` aus `/etc/os-release` fest; auf einer nicht unterstützten Distribution bricht das Modul ab, statt eine der beiden Benennungen zu unterstellen. `check` prüft die Datei am Soll der laufenden Distribution — eine unter Ubuntu geschriebene Datei fällt auf Debian als Abweichung auf.

Punkt 4 ist umgesetzt: Das Modul `logging` richtet die sudo-Protokollierung und die beiden Audit-Regeln auf die sudoers-Pfade nur ein, wenn `sudo` auf dem System vorhanden ist. Maßgeblich sind die Pfade selbst, nicht die Distribution — `auditctl` nimmt eine Überwachung nur an, wenn der überwachte Pfad existiert, und ohne sudoers.d gäbe es kein Ziel für die Protokollierungs-Konfiguration. `sudo` wird dafür nicht nachinstalliert. Administriert wird über `su`, dessen Sitzungen das Journal mit dem aufrufenden Benutzer protokolliert.

## 8. Offen — nur auf einem laufenden Debian 13 zu klären

Diese Punkte lassen sich aus Paketdaten **nicht** beantworten:

- **Audit-Regel auf `/var/log/lastlog`.** In keiner der beiden Distributionen liefert `libpam-modules` noch ein `pam_lastlog`-Modul. Ob die Datei überhaupt noch existiert und `auditd` die Regel annimmt, muss auf dem System geprüft werden — und zwar **auch unter Ubuntu**. Prüfbefehle: `ls -l /var/log/lastlog` und `auditctl -l | grep lastlog`.
- **Verhalten bei aktiver SSH-Socket-Aktivierung.** Beide liefern `ssh.socket` mit. Welche Unit im Auslieferungszustand aktiv ist, entscheidet das Preset des jeweiligen Images. Bei aktiver Socket-Aktivierung läuft kein dauerhafter `sshd`-Prozess — der monit-Check `check process sshd matching "sshd"` würde dann Daueralarm auslösen.
- **Ob `lynis` unter Debian dasselbe Profil und dieselben Tests fährt.** Debian liefert eine ältere Version (3.1.4 gegen 3.1.6).

Ob `sudo` auf dem konkreten Debian-Image installiert ist, hängt vom Image ab und nicht vom Paketindex — der Debian-Installer installiert es, wenn kein Root-Passwort gesetzt wird. Das muss nicht mehr vorab geklärt werden: Das Modul `logging` entscheidet zur Laufzeit anhand der Pfade (Kapitel 7).

## 9. Nächster Schritt

Von den fünf Punkten aus Kapitel 7 sind zwei umgesetzt, darunter der einzige Blocker. Offen sind noch die Systemprotokolle als Dateien (`rsyslog`, Punkt 3) und der Härtungsmaßstab (Punkt 5); Punkt 2 ist reine Dokumentation.

Die Erkennung der Distribution liegt in `secure_base.distro` und wird bisher nur vom Modul `unattended` abgefragt. Der Installer selbst prüft die Distribution noch nicht — er läuft ungeprüft auf jedem System an und bricht erst ab, wenn das erste Modul eine distributionsabhängige Entscheidung trifft.
