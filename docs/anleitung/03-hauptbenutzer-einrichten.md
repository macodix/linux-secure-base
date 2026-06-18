# Hauptbenutzer einrichten (SSH-Key + TOTP)

Vor Einrichtung des Hauptbenutzers das TOTP-Paket installieren:

```
apt install libpam-google-authenticator
```

Für die Berechtigung zum SSH-Login wird eine eigene Gruppe eingerichtet:

```
groupadd ssh-users
```

Den Hauptbenutzer mit `useradd` anlegen — kein Mitglied administrativer Gruppen, Home-Verzeichnis vorhanden, Standard-Shell `/bin/bash`, Mitglied der Gruppe `ssh-users`:

```
useradd -m -s /bin/bash -G ssh-users <hauptbenutzer>
passwd <hauptbenutzer>
```

Der öffentliche SSH-Schlüssel wird auf dem Server als `~/.ssh/authorized_keys` des Hauptbenutzers hinterlegt:

```
su - <hauptbenutzer>
mkdir -p ~/.ssh
chmod 700 ~/.ssh
( umask 077; cat > ~/.ssh/authorized_keys )
<Public-Key einfügen, mit Strg-D abschließen>
exit
```

Als Hauptbenutzer das TOTP-Geheimnis erzeugen — `google-authenticator` stellt Fragen, die für SSH so beantwortet werden:

```
su - <hauptbenutzer>
google-authenticator
```

- „Do you want authentication tokens to be time-based?" — **yes**
- QR-Code mit der Authenticator-App scannen, Notfall-Codes sicher hinterlegen.
- „Do you want me to update your `~/.google_authenticator` file?" — **yes**
- „Disallow multiple uses of the same authentication token?" — **yes**
- „Increase the rate-limit window?" — **no** (Standard 30 s beibehalten)
- „Enable rate-limiting?" — **yes**

Administrative Tätigkeiten laufen über den Wechsel zum Root-Konto per `su`. Das vorinstallierte `sudo` bleibt erhalten, wird aber nicht genutzt — der Hauptbenutzer ist nicht Mitglied der Gruppe `sudo`. Ein `root`-Passwort muss gesetzt sein.
