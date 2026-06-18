# nginx

Einrichtung des multidomain-fähigen nginx als Webserver für statische Inhalte. Je Domain ein eigener Server-Block mit eigenem Let's-Encrypt-Zertifikat. Die Begründung der Festlegungen steht im Konzept-Dokument nginx-Grundsatz.

Die Einrichtung folgt je Domain demselben Ablauf. Die Schritte sind hier für eine Domain `<domain>` beschrieben und für jede weitere Domain zu wiederholen. Erwartet werden zwei bis vier Domains.

## 1. Installation und Grundkonfiguration

```
apt install nginx
```

nginx läuft mit dem Distro-Default-Dienstbenutzer `www-data` (keine Login-Shell, keine administrativen Gruppen). Die Distro-Default-Seite deaktivieren:

```
rm /etc/nginx/sites-enabled/default
```

In `/etc/nginx/nginx.conf` im `http`-Block die Versions-Anzeige abschalten:

```
server_tokens off;
```

## 2. Wurzelverzeichnis je Domain

Je Domain ein Wurzelverzeichnis für die statischen Inhalte anlegen:

```
mkdir -p /var/www/<domain>
chown -R www-data:www-data /var/www/<domain>
```

## 3. Server-Block für den Zertifikatsbezug

Je Domain einen eigenen Server-Block unter `/etc/nginx/sites-available/<domain>` anlegen und per Symlink aktivieren. Für den Zertifikatsbezug genügt zunächst ein minimaler Block auf Port 80:

```
server {
    listen 80;
    listen [::]:80;
    server_name <domain>;
    root /var/www/<domain>;
}
```

```
ln -s /etc/nginx/sites-available/<domain> /etc/nginx/sites-enabled/<domain>
nginx -t && systemctl reload nginx
```

## 4. Port 80 temporär freischalten

Die HTTP-01-Challenge verlangt einen von außen erreichbaren Port 80. Diesen nur für die Dauer der Zertifikatsausstellung freischalten:

```
ufw allow 80/tcp
```

Port 443 dauerhaft freischalten — über ihn läuft der Nutzverkehr:

```
ufw allow 443/tcp
```

Nach der Ausstellung (Abschnitt 6) wird Port 80 wieder geschlossen.

## 5. TLS-Zertifikat je Domain (certbot, HTTP-01)

```
apt install certbot python3-certbot-nginx
```

Je Domain ein eigenes Zertifikat über die HTTP-01-Challenge beziehen. certbot ergänzt den Server-Block aus Abschnitt 3 um den TLS-Teil auf Port 443 und legt für Port 80 einen Block mit Umleitung auf HTTPS an:

```
certbot --nginx -d <domain>
```

Für jede weitere Domain den Befehl mit dem jeweiligen Namen wiederholen. Kein Wildcard, kein DNS-01-Verfahren — die Umgebung hat keine DNS-Provider-API (Konzept-Dokument nginx-Grundsatz, Kapitel 3).

Den HTTP-zu-HTTPS-Redirect-Block, den certbot anlegt, bewusst bestehen lassen. Er bleibt als Absicherung erhalten, falls Port 80 versehentlich offen bleibt (Konzept-Dokument nginx-Grundsatz, Kapitel 5). Der Block auf Port 80 hat die Form:

```
server {
    listen 80;
    listen [::]:80;
    server_name <domain>;
    return 301 https://$host$request_uri;
}
```

Im TLS-Block auf Port 443 die statische Auslieferung sicherstellen:

```
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name <domain>;
    root /var/www/<domain>;

    location / {
        try_files $uri $uri/ =404;
    }

    # ssl_certificate / ssl_certificate_key und include options-ssl-nginx.conf
    # hat certbot ergänzt
}
```

Die TLS-Parameter (Protokolle, Cipher) setzt certbot über die mitgelieferte Datei `options-ssl-nginx.conf`. Abweichungen davon werden in der Betriebsdokumentation festgehalten.

Konfiguration prüfen und übernehmen:

```
nginx -t && systemctl reload nginx
```

## 6. Port 80 wieder schließen

Nach der Ausstellung Port 80 wieder schließen — er wird im Normalbetrieb nicht gebraucht:

```
ufw delete allow 80/tcp
```

Den Ist-Zustand mit der Soll-Port-Liste der Betriebsdokumentation vergleichen (`ss -H -tulpen`, `ufw status verbose`). Eingehend offen bleiben nur `22/tcp` und `443/tcp`. Jeder lauschende Port ohne Eintrag in der Soll-Liste ist ein Befund.

## 7. Zertifikatserneuerung

Die Erneuerung läuft über den mitinstallierten systemd-Timer `certbot.timer`:

```
systemctl status certbot.timer
certbot renew --dry-run
```

Die Erneuerung über HTTP-01 verlangt erneut einen erreichbaren Port 80. Da Port 80 im Normalbetrieb geschlossen ist, wird er für den Erneuerungslauf temporär geöffnet und danach wieder geschlossen. Die konkrete Automatisierung dieses Fensters (Hook am `certbot`-Lauf, der Port 80 öffnet und schließt) wird in der Bauphase erprobt und festgelegt.

## 8. Monitoring-Check ergänzen

Den Prozess-Check für nginx beim Monitoring ergänzen — `/etc/monit/conf.d/nginx`:

```
check process nginx with pidfile /run/nginx.pid
    start program = "/bin/systemctl start nginx"
    stop  program = "/bin/systemctl stop  nginx"
    if 5 restarts within 5 cycles then alert
```

```
monit -t && monit reload
```

## 9. systemd-Härtung

Der nginx-Dienst erhält Hardening-Direktiven über ein Drop-in. Anlegen mit:

```
systemctl edit nginx
```

```
[Service]
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/log/nginx /var/lib/nginx /run
```

Die `ReadWritePaths` erlauben nginx die nötigen Schreibpfade trotz `ProtectSystem=strict`. Der konkrete Satz der Schreibpfade wird beim Aufbau anhand der real genutzten Verzeichnisse geprüft.

```
systemctl daemon-reload && systemctl restart nginx
```

## 10. AppArmor-Profil

nginx ist der einzige von außen erreichbare Anwendungsdienst und damit der exponierte Dienst. Weder das `nginx`-Paket noch `apparmor-profiles-extra` liefern auf Ubuntu ein AppArmor-Profil für nginx mit. Den Stand bestätigen:

```
aa-status | grep -i nginx
```

Liefert der Befund kein Profil, wird ein eigenes über `aa-genprof` im Complain-Modus erarbeitet und nach dem Prüflauf auf Enforce gesetzt. Sein Umfang wird erst nach Festlegung der ausgelieferten Verzeichnisse aller Domains bestimmt. Im Enforce-Modus wird das Profil im Härtungs-Prüflauf (Kapitel 12 der Installationsanleitung) kontrolliert.
