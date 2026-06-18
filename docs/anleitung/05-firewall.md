# Firewall (ufw)

Paket installieren und Default-Policy auf „alles verbieten" setzen — eingehend und ausgehend:

```
apt install ufw
ufw default deny incoming
ufw default deny outgoing
```

Eingehend wird im Grundzustand nur SSH erlaubt. Die Web-Ports 80 und 443 öffnen erst mit dem Webserver (Kapitel 13 der Installationsanleitung):

```
ufw allow 22/tcp
```

Ausgehend nur die nötigen Ziel-Ports (Konzept-Dokument Systemtopologie, Kapitel 6):

```
ufw allow out 587/tcp     # Submission/STARTTLS (Postfix-Relay)
ufw allow out 80/tcp      # HTTP (apt, ACME)
ufw allow out 443/tcp     # HTTPS (apt, Git)
ufw allow out 53/tcp      # DNS (TCP)
ufw allow out 53/udp      # DNS (UDP)
ufw allow out 22/tcp      # SSH (Git, restic-SFTP)
```

Die Regeln sind port-, nicht zielhost-gebunden. Auf eine Quell-Netz-Beschränkung für SSH wird verzichtet. `ufw` legt die IPv6-Pendants automatisch an.

Firewall aktivieren und prüfen:

```
ufw enable
ufw status verbose
```

Soll-Bild: `Default: deny (incoming), deny (outgoing)`. Eingehend nur `22/tcp`, ausgehend genau die sechs Regeln oben (jeweils plus v6).
