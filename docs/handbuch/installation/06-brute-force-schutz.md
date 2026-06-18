# Brute-Force-Schutz (fail2ban)

`fail2ban` sperrt die Quell-IP nach wiederholten SSH-Fehlversuchen. Die Voreinstellungen genügen. Sie werden über eine `jail.local` gegen Überschreiben bei Updates geschützt:

```
apt install fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
systemctl enable --now fail2ban
```

Das `sshd`-Jail ist in der Standardkonfiguration aktiv. Überprüfung: `fail2ban-client status sshd` zeigt das aktive Jail.
