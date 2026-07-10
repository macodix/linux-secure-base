# SSH-Härtung mit TOTP

Die SSH-Härtung umfasst die Grundkonfiguration, den Login mit TOTP, die E-Mail-Benachrichtigung bei Login und die Aktivierung der Konfiguration.

## 1. Grundkonfiguration

In `/etc/ssh/sshd_config` folgende Werte setzen bzw. prüfen:

```
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0

AllowGroups ssh-users
```

Überprüfung mit den Soll-Werten:

```
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|permitemptypasswords|maxauthtries|logingracetime|clientaliveinterval|clientalivecountmax|allowgroups'
```

Die zugelassenen KEX-, Cipher- und MAC-Algorithmen werden in der Betriebsdokumentation festgelegt und bei Abweichung vom Distro-Default in `sshd_config` gesetzt.

## 2. SSH-Login mit TOTP

Das Paket `libpam-google-authenticator` ist bereits installiert (Kapitel 3 der Installationsanleitung). In `/etc/pam.d/sshd` folgende Einträge setzen:

```
[...]
# Standard Un*x authentication.
#@include common-auth
[...]
# Google Authenticator
auth required pam_google_authenticator.so
```

In `/etc/ssh/sshd_config` den Faktor-Stack setzen:

```
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes
UsePAM yes
AuthenticationMethods publickey,keyboard-interactive
```

`KbdInteractiveAuthentication` ist die aktuelle Direktive. `ChallengeResponseAuthentication` ist nur noch ein veralteter Alias darauf und wird vorsorglich mitgesetzt, damit die Härtung auch gegenüber abweichenden OpenSSH-Versionen greift. Auf aktuellen Ubuntu-Versionen ist die Zeile redundant, aber unschädlich.

## 3. E-Mail-Benachrichtigung bei SSH-Login

Jeder SSH-Login löst eine Mail an die Administrator Email Adresse aus. Unter `/etc/ssh/login-mail-notification.sh` folgendes Skript anlegen:

```
#!/bin/sh
# Aufruf ueber pam_exec (session open_session) als root.
if [ "$PAM_TYPE" = "open_session" ]; then
    ADMINMAIL="<admin@meine-domain.de>"
    TEXT="SSH-Login auf dem Server: $(hostname -f) \nBenutzer: $PAM_USER \nZeitpunkt: $(date) \nClient-IP: $PAM_RHOST"
    echo -e "$TEXT" | mail -s "SSH Login Info: $PAM_USER" "$ADMINMAIL"
fi
```

Dem Skript die minimal erforderlichen Rechte geben — es läuft als root:

```
chmod 700 /etc/ssh/login-mail-notification.sh
```

Der Aufruf erfolgt über `pam_exec`, nicht über `/etc/ssh/sshrc`. Ein `sshrc`-Hook liefe im Kontext des einloggenden Benutzers und scheiterte am Mode `0700 root:root`. Zudem sind die PAM-Umgebungsvariablen (`PAM_TYPE`, `PAM_USER`, `PAM_RHOST`) nur unter `pam_exec` gesetzt. In `/etc/pam.d/sshd` dazu eine Session-Zeile ergänzen:

```
session optional pam_exec.so seteuid /etc/ssh/login-mail-notification.sh
```

`optional` sorgt dafür, dass ein Mail-Fehler den Login nicht blockiert.

## 4. Konfiguration aktivieren

Nach allen Änderungen an `/etc/ssh/sshd_config` und `/etc/pam.d/sshd` den SSH-Dienst neu laden (`reload` statt `restart` — laufende Sitzungen bleiben erhalten):

```
systemctl reload ssh
```

Vor dem Trennen der bestehenden SSH-Sitzung in einer zweiten Sitzung den Login einmal verifizieren (Public-Key + TOTP) — sonst Gefahr, sich auszusperren.
