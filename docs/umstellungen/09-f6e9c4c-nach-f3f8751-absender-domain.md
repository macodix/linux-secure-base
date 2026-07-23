# Anpassung Produktivsysteme f6e9c4c → f3f8751: Absender-Domain für Systemmails

Anleitung für einen bereits laufenden Server. Auf einem neu aufgesetzten Server erledigt der Installer alles.

**Ausführung:** alle Befehle als `root` (Wechsel per `su`).

## 1. Geltungsbereich

Gilt für Server, die mit einem Stand **bis einschließlich Commit `f6e9c4c`** eingerichtet wurden. Den neuen Stand bringt Commit `f3f8751`.

Betroffen ist jeder Server mit eingerichtetem Modul `postfix`. Symptom: Systemmails (cron, Fehler-Mails der Backup-/Dump-Skripte, Installationsbericht) gehen mit dem Absender `root@<fqdn>` raus (z. B. `root@srv001.example.com`); Hoster-Relays lehnen solche Absender als Spam ab.

## 2. Was sich ändert

In `/etc/postfix/main.cf` kommt eine Direktive hinzu:

```
myorigin = $mydomain
```

Unqualifizierte lokale Absender („root" ohne Domain) werden damit zu `root@<domain>` vervollständigt statt — über den bisherigen Ubuntu-Default `myorigin = /etc/mailname` — zu `root@<fqdn>`. `$mydomain` leitet Postfix selbst aus `myhostname` ab (alles nach dem ersten Punkt). `/etc/mailname` bleibt unverändert und ist danach ohne Wirkung auf den Absender.

## 3. main.cf anpassen

```
postconf -e 'myorigin = $mydomain'
systemctl reload postfix
```

`postconf -e` ersetzt eine vorhandene `myorigin`-Zeile bzw. ergänzt sie am Dateiende.

## 4. Prüfen

Testmail schicken und den Absender im Log kontrollieren:

```
echo "Absendertest" | mail -s "Absendertest" root
grep "from=<" /var/log/mail.log | tail -1
```

Erwartung: `from=<root@<domain>>` (z. B. `root@example.com`), nicht `root@<fqdn>`; Zustellstatus `status=sent`.
