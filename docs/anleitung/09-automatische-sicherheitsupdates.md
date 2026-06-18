# Automatische Sicherheitsupdates (unattended-upgrades)

```
apt install unattended-upgrades
```

In `/etc/apt/apt.conf.d/50unattended-upgrades` setzen:

```
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}:${distro_codename}-updates";
};
[...]
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "23:45";
[...]
Unattended-Upgrade::Mail "<admin@meine-domain.de>";
Unattended-Upgrade::MailReport "only-on-error";
```

`-proposed` und `-backports` bleiben ausgeschlossen: deren Paketstände sind für einen automatischen Reboot ohne Aufsicht nicht ausreichend getestet. Ein einzelnes Backport-Paket wird bei Bedarf manuell installiert (`apt install -t <release>-backports <paket>`). `MailReport "only-on-error"` meldet nur fehlgeschlagene Upgrades. Die Nachvollziehbarkeit erfolgreicher Reboots läuft über `journalctl`/`last` und das Monitoring (Kapitel 11 der Installationsanleitung).

Damit die Updates vor dem Reboot installiert sind, werden die beiden zuständigen systemd-Timer auf feste Nachtzeiten gelegt. Ihr Distro-Default `RandomizedDelaySec=12h` streut die Zeit sonst über zwölf Stunden. Sequenz: 23:15 (Paketlisten), 23:30 (Upgrade), 23:45 (Reboot).

```
systemctl edit apt-daily.timer
```

```
[Timer]
OnCalendar=
OnCalendar=*-*-* 23:15:00
RandomizedDelaySec=0
```

```
systemctl edit apt-daily-upgrade.timer
```

```
[Timer]
OnCalendar=
OnCalendar=*-*-* 23:30:00
RandomizedDelaySec=0
```

Das leere `OnCalendar=` leert zuerst die additive Distro-Default-Liste.

Zusätzlich die periodische Ausführung aktivieren — `/etc/apt/apt.conf.d/20auto-upgrades` mit folgendem Inhalt anlegen bzw. setzen:

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
```

Ohne diese Schalter werden die Einstellungen aus `50unattended-upgrades` geladen, aber nie ausgeführt. Manche Cloud-Images setzen `"0"`.

Konfiguration prüfen:

```
unattended-upgrade --dry-run --debug
```
