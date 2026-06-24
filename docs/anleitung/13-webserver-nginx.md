# Webserver nginx (optional)

Einrichtung des multidomain-fähigen nginx als Webserver für statische Inhalte. Je Domain ein eigener Server-Block mit eigenem Let's-Encrypt-Zertifikat. Die Begründung der Festlegungen steht im Konzept-Dokument nginx-Grundsatz.

Die Einrichtung folgt je Domain demselben Ablauf. Die Schritte sind hier für eine Domain `<domain>` beschrieben und für jede weitere Domain zu wiederholen. Erwartet werden zwei bis vier Domains.

## 0. Installation über den Installer

nginx ist ein optionales Paket des Installers. Es wird nicht über
`MODULES_ENABLED` aktiviert, sondern über die eigene Konfigurationsdatei
`conf/secure-base-optional.conf` und nur mit dem Schalter `-o` verarbeitet.

Vorbereitung — die Vorlage kopieren und die vhosts eintragen:

```
cp conf/secure-base-optional.conf.example conf/secure-base-optional.conf
```

In `conf/secure-base-optional.conf` nginx aktivieren und mindestens einen
vhost definieren:

```
OPTIONAL_ENABLED=(nginx)
NGINX_VHOSTS=(
    "example.com"
    "shop.example.com|/srv/www/shop"
)
NGINX_CERTBOT_MAIL="admin@example.com"
```

**Erstlauf zuerst im Staging-Modus.** Let's Encrypt begrenzt die Zahl der
Zertifikatsanforderungen pro Domain und Zeitraum scharf (Rate-Limit). Ein
Fehlversuch mit echten Zertifikaten (falscher DNS-Eintrag, Port 80 nicht
erreichbar) kann die Domain für Stunden sperren. Daher den ersten Lauf je
neuer Domain verbindlich im Staging-Modus durchführen, der die echten
Limits nicht berührt:

```
NGINX_CERTBOT_MODE="staging"
```

Erst nach erfolgreichem Staging-Lauf (Zertifikate werden bezogen, nginx lädt,
HTTPS-Abruf funktioniert; das Staging-Zertifikat ist erwartungsgemäß nicht
vertrauenswürdig) auf `NGINX_CERTBOT_MODE="live"` umstellen und erneut
installieren. Die Staging-Zertifikate werden dabei durch echte ersetzt.

Installation als Komplettlauf oder getrennt:

```
secure-base-installer -o install           # Kernsystem und optionale Pakete
```

oder getrennt:

```
secure-base-installer install              # Kernsystem
secure-base-installer -o install nginx     # nginx als optionales Paket
```

Der nginx-Schritt öffnet 443/tcp dauerhaft, 80/tcp nur temporär für den
Zertifikatsbezug, bezieht je Domain ein Let's-Encrypt-Zertifikat, setzt den
HTTP→HTTPS-Redirect und schließt Port 80 anschließend wieder. Für den
Zertifikatsbezug (HTTP-01-Challenge) muss Port 80 von außen erreichbar sein;
das ist unabhängig davon gegeben, ob die Firewall (ufw) bereits aktiv ist:
bei inaktiver Firewall ist der Port ohnehin offen, bei aktiver Firewall öffnet
ihn die nginx-Regel temporär. Der nginx-Schritt läuft daher in jedem Fall
durch; die Firewall wird wie üblich am Ende des Kernlaufs interaktiv aktiviert.

Das Modul richtet zudem ein AppArmor-Basisprofil für nginx im
`complain`-Modus ein: AppArmor protokolliert Verstöße, blockiert aber nichts.
Den Wechsel auf `enforce` (Blockieren) nimmt der Betreiber bewusst vor, sobald
das Profil im Testbetrieb vollständig ist — siehe Abschnitt zum AppArmor-Profil
weiter unten.

Die folgenden Abschnitte beschreiben die Einzelschritte, die der Installer
ausführt — als Hintergrund und für die manuelle Einrichtung.

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

nginx ist der einzige von außen erreichbare Anwendungsdienst und damit der
exponierte Dienst. Weder das `nginx`-Paket noch `apparmor-profiles-extra`
liefern auf Ubuntu ein AppArmor-Profil für nginx mit.

Der Installer richtet daher selbst ein Basis-Profil
(`/etc/apparmor.d/usr.sbin.nginx`) ein: `aa-autodep nginx` erzeugt ein an die
nginx-Binärdatei gebundenes Startprofil, `aa-complain` setzt es in den
`complain`-Modus. In diesem Modus protokolliert AppArmor jeden Zugriff
außerhalb des Profils in das Audit-Log, blockiert aber nichts. Der Webserver
läuft uneingeschränkt, während sich die tatsächlich benötigten Pfade (docroots,
Zertifikatspfade, Logs) im Log ansammeln. Den Stand bestätigen:

```
aa-status | grep -i nginx
```

Enforce wird vom Installer bewusst **nicht** automatisch gesetzt: Ein zu enges
Profil im enforce-Modus würde nginx blockieren (Aussperr-/Funktionsrisiko),
sobald ein konfigurierter Pfad nicht erfasst ist — der Pfadsatz hängt von den
ausgelieferten docroots aller Domains ab. Der Wechsel ist eine bewusste
Betreiber-Entscheidung nach ausreichendem Testbetrieb:

```
# 1. nginx im complain-Modus normal betreiben, alle Domains aufrufen,
#    Zertifikatserneuerung (certbot renew --dry-run) auslösen.
# 2. Protokollierte Zugriffe ins Profil übernehmen:
sudo aa-logprof
# 3. Profil auf enforce setzen:
sudo aa-enforce nginx
# 4. Funktion erneut prüfen; bei Blockaden zurück zu Schritt 1/2.
```

Den aktuellen Modus zeigt `aa-status` (Abschnitte „enforce mode" /
„complain mode"). Der Installer-Check (`secure-base-installer -o check nginx`)
meldet den Modus mit. Im Enforce-Modus wird das Profil im Härtungs-Prüflauf
(Kapitel 12 der Installationsanleitung) kontrolliert.

Nach der nginx-Installation die Härtungsprüfung (lynis) erneut ausführen, da
nginx nach dem Kern-lynis-Lauf installiert wird.
