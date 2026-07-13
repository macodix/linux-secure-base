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

### 5.4 SSH: Socket-Aktivierung

Beide Pakete liefern `ssh.service` **und** `ssh.socket` mit, und beide Vorgabekonfigurationen enthalten `Include /etc/ssh/sshd_config.d/*.conf`. Welche Unit im Auslieferungszustand aktiv ist, entscheidet aber das `postinst` des Pakets — und dort sind die beiden Distributionen exakt gegenläufig:

| | Debian 13 | Ubuntu 26.04 |
|---|---|---|
| bei Neuinstallation aktiviert | **`ssh.service`** | **`ssh.socket`** |
| nur aktiviert, wenn schon vorher installiert | `ssh.socket` | `ssh.service` |
| Betriebsart | klassischer Daemon | Socket-Aktivierung |

Belegt aus den `postinst`-Skripten beider Pakete: Der Aufruf `deb-systemd-helper --quiet was-enabled <unit>` liefert bei einer Neuinstallation `true` und aktiviert die Unit. Er steht in Debian für `ssh.service`, in Ubuntu für `ssh.socket`. Die jeweils andere Unit steht hinter `deb-systemd-helper debian-installed <unit>` und wird deshalb nur aktiviert, wenn sie aus einer früheren Installation bereits eingerichtet war.

Der Unterschied setzt sich in den Unit-Dateien fort. Ubuntus `ssh.socket` lauscht auf `0.0.0.0:22` und `[::]:22` mit `FreeBind=yes` und trägt `RequiredBy=ssh.service`; dazu liefert Ubuntu einen Generator `sshd-socket-generator`, der die `Port`- und `ListenAddress`-Angaben aus `sshd_config` in ein Drop-in für `ssh.socket` überträgt. Debians `ssh.socket` hat fest `ListenStream=22` und keinen Generator — eine abweichende `Port`-Angabe in `sshd_config` bliebe dort ohne Wirkung. Das deckt sich mit den Vorbehalten, die auf der Debian-Seite gegen die Socket-Aktivierung vorgebracht wurden.

**Folge für secure-base: keine.** Auf Debian läuft `sshd` als dauerhafter Prozess, der monit-Check `check process sshd matching "sshd"` greift also. Auf Ubuntu ändert sich nichts gegenüber heute. Der Port bleibt in beiden Fällen 22.

### 5.5 AppArmor

Beide Distributionen liefern mit dem Paket `apparmor` einen umfangreichen Satz Profile aus, überwiegend für Desktop-Anwendungen. Der Umfang unterscheidet sich (Ubuntu deutlich mehr Profile als Debian), für die von secure-base eingerichteten Dienste ist er jedoch gleich:

| Paket | Profil für `sshd` | Profil für `nginx` |
|---|---|---|
| `openssh-server` | **keines** (Debian wie Ubuntu) | — |
| `nginx-core`, `nginx-common` | — | **keines** (Debian wie Ubuntu) |
| `apparmor-profiles-extra` | keines | **keines** — das Paket ist in beiden Distributionen inhaltsgleich und enthält nur `irssi`, `pidgin`, `totem` und `apt-cacher-ng` |

Die Aussagen der Dokumentation zu den fehlenden Profilen für `sshd` und `nginx` gelten also unverändert, sie waren nur auf Ubuntu festgelegt. Am Vorgehen ändert sich nichts: Für `nginx` wird ein eigenes Profil erzeugt, für `sshd` bewusst keines (Aussperr-Risiko).

### 5.6 Anmeldehistorie: lastlog ist weg

`pam_lastlog.so` ist aus `libpam-modules` entfernt — in **beiden** Distributionen. Auf einem Ubuntu 26.04 existieren weder `/var/log/lastlog` noch `/var/log/wtmp` oder `/var/log/btmp`, und die Programme `last` und `lastlog` sind nicht installiert. Die utmp/wtmp/lastlog-Familie ist abgelöst.

| Nachfolger | Datenbank | Debian 13 | Ubuntu 26.04 |
|---|---|---|---|
| `wtmpdb` | `/var/log/wtmp.db` | **`standard`** — installiert, `sshd` schreibt direkt hinein | `optional` — nicht installiert |
| `lastlog2` | `/var/lib/lastlog/lastlog2.db` | `optional` | `optional` |

Der Pfad der wtmpdb-Datenbank ist ein Debian-Sonderweg: Upstream liegt sie unter `/var/lib/wtmpdb/wtmp.db`, beide Distributionen patchen sie nach `/var/log/wtmp.db` und legen den Upstream-Pfad als Symlink darauf an (belegt aus `libwtmpdb0` und `README.Debian` des Pakets). Als Überwachungsziel taugt nur die echte Datei.

**Folge:** Die Audit-Regel `-w /var/log/lastlog -p wa -k logins` überwacht auf beiden Distributionen eine Datei, die nie entsteht — auch unter Ubuntu, heute. Sie lädt fehlerfrei, weil bei einer Datei das Elternverzeichnis genügt, und liefert dauerhaft null Ereignisse. Der Schlüssel `logins` ist leer, ohne dass irgendetwas darauf hinweist.

Das Modul `logging` installiert deshalb `wtmpdb` und `libpam-wtmpdb` mit und überwacht deren Datenbank. Unter Debian ändert das nichts (beide sind `standard`), unter Ubuntu schließt es die Lücke. Führt ein System wider Erwarten keine Anmeldedatenbank, entfällt die Regel mit Warnung, statt ins Leere zu zeigen.

Die Erfassung ist in beiden Distributionen vollständig und doppelungsfrei, auf verschiedenen Wegen: Debians `openssh-server` hängt von `libwtmpdb0` ab, `sshd` schreibt dort selbst in die Datenbank — die PAM-Vorgabe trägt deshalb `skip_if=sshd`. Ubuntus `openssh-server` hängt nicht von `libwtmpdb0` ab, dafür trägt die Ubuntu-PAM-Vorgabe kein `skip_if`, sodass das PAM-Modul die SSH-Anmeldungen erfasst.

### 5.7 cron.daily

`logwatch` und `rkhunter` liefern auf beiden Distributionen dieselben Dateien `/etc/cron.daily/00logwatch` bzw. `/etc/cron.daily/rkhunter`. Das Stilllegen des mitgelieferten logwatch-Laufs funktioniert auf Debian unverändert.

### 5.8 lynis: ältere Version, gleicher Prüfumfang

Debian liefert `lynis` 3.1.4, Ubuntu 3.1.6. Der Versionsunterschied hat keine Wirkung auf die Härtungsprüfung:

| Gegenstand | Befund |
|---|---|
| Profil `/etc/lynis/default.prf` | in beiden Paketen **byte-identisch**; Debian bringt kein eigenes Profil mit |
| Plugins | in beiden dieselben |
| Testdateien | 43 in beiden |
| registrierte Test-IDs | 473 in beiden, **deckungsgleiche Menge** — keine ID existiert nur in einer Version |
| `include/consts` (Berichtspfad) | identisch — `/var/log/lynis-report.dat` gilt auf beiden |

Inhaltlich unterscheiden sich sieben Testdateien, aber nur in Kleinigkeiten: In `tests_logging` etwa ist der Prozessname des Wazuh-Agenten korrigiert (`wazuh-agent` → `wazuh-agentd`), und ein fehlendes `logrotate` wird in 3.1.6 als „nicht gefunden" statt als Warnung gewertet. Solche Nuancen können den Hardening-Index um wenige Punkte verschieben, ändern aber nichts an Funktion oder Vergleichbarkeit des Prüfnachweises.

Das Modul `lynis` ist ohnehin unempfindlich: Es setzt kein Profil, wertet die Ausgabe nicht aus und pinnt keine Version.

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
| 3 | Systemprotokolle als Dateien | `logging.py` (Paketliste) | ohne `rsyslog` nicht vorhanden — **erledigt** |
| 4 | `sudo` und `/etc/sudoers.d` | `logging.py` `SUDOLOG_CONF`, `AUDIT_RULES` | nicht garantiert installiert — **erledigt** |
| 5 | Härtungsmaßstab | Doku | CIS-Benchmark für Debian statt Ubuntu — **erledigt** |

Punkt 3 ist umgesetzt, und zwar ohne Verzweigung: Das Modul `logging` installiert `rsyslog` mit. Unter Ubuntu ist es ohnehin vorhanden, der Schritt ändert dort nichts. Damit existieren die Protokolldateien unter `/var/log` auf beiden Distributionen, und der angehängte Logwatch-Bericht behält seine Quellen. Beim Rückbau bleibt `rsyslog` bestehen — es schreibt Dateien, die auch Werkzeuge außerhalb von secure-base lesen, und auf einem Teil der Distributionen gehört es zur Standardinstallation.

Für die Zusammenfassung im Tagesbericht war das ohnehin unkritisch: Sie liest aus dem Journal.

Punkt 5 betrifft nur die Dokumentation. Maßgeblich ist jetzt der CIS-Benchmark der eingesetzten Distribution (Level 1) — auf Ubuntu der *CIS Ubuntu Linux Benchmark*, auf Debian der *CIS Debian Linux Benchmark*. Am Code ändert das nichts: `lynis` erkennt die Distribution selbst, und das Modul setzt kein Profil. Die Auswahl der Maßnahmen bleibt für beide Distributionen dieselbe, sie folgt dem BSI-Grundschutz.

Punkt 1 ist umgesetzt: Das Modul `unattended` schreibt unter Debian einen `Origins-Pattern`-Block mit Origin, Codename und Label, unter Ubuntu weiterhin die Kurzform `Allowed-Origins`. Welche Distribution läuft, stellt `secure_base.distro` aus `/etc/os-release` fest; auf einer nicht unterstützten Distribution bricht das Modul ab, statt eine der beiden Benennungen zu unterstellen. `check` prüft die Datei am Soll der laufenden Distribution — eine unter Ubuntu geschriebene Datei fällt auf Debian als Abweichung auf.

Punkt 4 ist umgesetzt: Das Modul `logging` richtet die sudo-Protokollierung und die beiden Audit-Regeln auf die sudoers-Pfade nur ein, wenn `sudo` auf dem System vorhanden ist. Maßgeblich sind die Pfade selbst, nicht die Distribution — `auditctl` nimmt eine Überwachung nur an, wenn der überwachte Pfad existiert, und ohne sudoers.d gäbe es kein Ziel für die Protokollierungs-Konfiguration. `sudo` wird dafür nicht nachinstalliert. Administriert wird über `su`, dessen Sitzungen das Journal mit dem aufrufenden Benutzer protokolliert.

## 8. Offen — nur auf einem laufenden Debian 13 zu klären

Keine mehr. Alle vier Punkte, die hier zunächst standen, sind aus den Paketen selbst beantwortet:

| Ursprüngliche Frage | Antwort |
|---|---|
| Welche SSH-Unit ist im Auslieferungszustand aktiv? | Debian `ssh.service`, Ubuntu `ssh.socket` — belegt aus den `postinst`-Skripten (Kapitel 5.4) |
| Nimmt `auditd` die Regel auf `/var/log/lastlog` an? | Die Datei gibt es nicht mehr; die Regel ist auf die geführte Anmeldedatenbank umgezogen (Kapitel 5.6) |
| Ist `sudo` auf dem Debian-Image installiert? | Muss nicht vorab feststehen — das Modul `logging` entscheidet zur Laufzeit anhand der Pfade (Kapitel 7) |
| Fährt `lynis` unter Debian dieselben Tests? | Ja — gleiches Profil, gleiche 473 Test-IDs (Kapitel 5.8) |

Was ein laufendes Debian 13 noch zeigen muss, ist der Installationslauf selbst: ob alle Module durchlaufen und ihr `check` grün meldet. Das ist ein Praxislauf, keine offene Sachfrage.

## 9. Nächster Schritt

Die fünf Punkte aus Kapitel 7 sind abgearbeitet. Dazu kamen die AppArmor-Aussagen (Kapitel 5.5), die auf Ubuntu festgelegt waren, sachlich aber für beide Distributionen gelten — sie sind jetzt neutral formuliert. Sachfragen sind keine mehr offen (Kapitel 8). Aus steht der Installationslauf auf einem Debian 13.

Die Erkennung der Distribution liegt in `secure_base.distro`. Der Installer fragt sie als ersten Schritt jedes Laufs ab und bricht auf einer nicht unterstützten Distribution mit Code 2 ab, bevor er die Konfiguration liest oder ein Modul startet. Das Modul `unattended` fragt sie zusätzlich ab, weil es zwischen den beiden Benennungen der Paketquellen wählen muss.

Geprüft wird die Kennung (`ID`), nicht die Version. Ubuntu 26.04 und Debian 13 sind die Stände, mit denen der Installer abgeglichen ist; ältere Stände derselben Distribution weist er nicht ab.
