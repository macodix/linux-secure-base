# Grundkonfiguration (base)

Das `base`-Modul läuft als erstes und legt den Grundzustand fest: Hostname und Zeitzone, Zeitsynchronisation, Kernel-Härtung sowie das Sperren ungenutzter Schnittstellen. Anschließend wird der Paketstand aktualisiert.

## Hostname und Zeitzone

Aus den Werten `FQDN` und `TIMEZONE` in `secure-base.conf`:

```
hostnamectl set-hostname "$FQDN"
timedatectl set-timezone "$TIMEZONE"
```

## Zeitsynchronisation

```
timedatectl set-ntp true
```

Eine korrekte Systemzeit ist Voraussetzung für nachvollziehbare Protokolle und gültige TLS-Verbindungen.

## Kernel-Härtung (sysctl)

Geschrieben nach `/etc/sysctl.d/60-secure-base.conf` und mit `sysctl --system` angewandt:

```
kernel.randomize_va_space = 2   # ASLR vollständig aktiv
kernel.kptr_restrict = 2        # Kernel-Pointer in /proc verbergen
kernel.dmesg_restrict = 1       # Kernel-Log nur für root
kernel.yama.ptrace_scope = 1    # ptrace auf eigene Kindprozesse beschränken
```

## Wechseldatenträger sperren

Das Kernel-Modul `usb-storage` wird über `/etc/modprobe.d/secure-base-blacklist.conf` deaktiviert:

```
install usb-storage /bin/true
blacklist usb-storage
```

Auf virtuellen Servern ohne USB-Schnittstellen ohne praktische Wirkung, gemäß Härtungsvorgabe dennoch gesetzt.

## Automatisches Einbinden unterbinden

```
systemctl mask autofs
```

## AppArmor

Die Pakete `apparmor` und `apparmor-utils` werden installiert und der Dienst aktiviert; die mitgelieferten Distributions-Profile bleiben im Enforce-Modus. Für `sshd` liefert keine der unterstützten Distributionen ein Profil mit — seine Eindämmung erfolgt über die Firewall und die SSH-Härtung (siehe [Systembeschreibung, Härtung](../systembeschreibung/02-haertung.md)).

## Paketstand

Abschließend werden die Paketquellen aktualisiert und vorhandene Aktualisierungen eingespielt (`apt upgrade`). Verlangt ein Update einen Neustart, bricht das Modul mit Hinweis ab — dann den Server neu starten und die Installation erneut aufrufen.
