# Mail-Versand (Postfix als Satellite)

Der Mail-Versand dient ausschließlich Systembenachrichtigungen. Der MTA `postfix` wird als Satellite-System (Smarthost) eingerichtet. Der Versand läuft über einen externen SMTP-Server des Hosters. Postfix lauscht nur auf `loopback`, nicht von außen.

Für den Mailversand wird hier per default der Port 587 genutzt und muss in den Firewall-Einstellungen ausgehend offens ein.

## 1. Installation und Grundkonfiguration

```
apt install postfix mailutils libsasl2-modules ca-certificates
```

Eingaben bei der Installation (`configure`):

- **General type:** Satellite system
- **System mail name:** FQDN-Hostname
- **SMTP relay host:** leer lassen (wird in der Konfigurationsdatei gesetzt)

## 2. Einrichtung in `main.cf`

In `/etc/postfix/main.cf` folgende Zeilen eintragen bzw. prüfen:

```
# Smarthost (Relay)
relayhost = [smtp.hoster.example]:587

# SASL-Auth gegenüber dem Relay
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_tls_security_options = noanonymous

# STARTTLS verlangen, Hoster-Zertifikat verifizieren
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_tls_loglevel = 1

# Nur ausgehend — kein lokaler smtpd-Empfang nötig
inet_interfaces = loopback-only
mydestination = $myhostname, localhost.$mydomain, localhost

# Alle ausgehenden Mails an die Admin-Adresse umlenken
recipient_canonical_maps = regexp:/etc/postfix/recipient_canonical
```

Eckige Klammern um den Relay-Hostnamen verhindern den MX-Lookup. Der Hoster gibt genau diesen Host vor. `smtp_tls_security_level = encrypt` erzwingt STARTTLS auf Port 587.

## 3. SASL-Zugangsdaten

In `/etc/postfix/sasl_passwd` (existiert noch nicht) folgenden Eintrag anlegen:

```
[smtp.hoster.example]:587 versand@meine-domain.de:<SMTP-PASSWORT>
```

Die Zugangsdaten für Postfix bekannt machen und die Berechtigungen einschränken:

```
postmap /etc/postfix/sasl_passwd
chmod 600 /etc/postfix/sasl_passwd*
```

Die Datei mit echtem Passwort gehört in keine Versionsverwaltung. Bei Bedarf vorher `umask 077` setzen.

## 4. Mail-Umleitung an die Admin-Adresse

In `/etc/aliases` die Zieladresse als Alias festlegen und bekannt machen:

```
# /etc/aliases
postmaster: root
root:       <admin@meine-domain.de>
```

```
newaliases
```

Cron, systemd und mailto-Direktiven landen damit bei der Admin-Adresse. Damit darüber hinaus jede ausgehende Mail unabhängig vom Empfänger dort landet, in `/etc/postfix/recipient_canonical` (existiert noch nicht) eine Zieladresse vorgeben — die zugehörige Direktive in `main.cf` ist bereits gesetzt (Abschnitt 2):

```
# /etc/postfix/recipient_canonical
/.+/   admin@meine-domain.de
```

Abschließend die Änderungen aktivieren:

```
systemctl reload postfix
```

Nach jeder Änderung an `main.cf` oder einer der Map-Dateien (`sasl_passwd`, `recipient_canonical`, `/etc/aliases`) muss Postfix die Konfiguration neu einlesen.
