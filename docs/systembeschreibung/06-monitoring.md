# Monitoring

Dieses Dokument beschreibt das Monitoring des Grundsystems: 
- die überwachten Größen,
- den Verfügbarkeitsnachweis und
- die Benachrichtigung


## Inhaltsverzeichnis

1. Überwachte Größen
2. Verfügbarkeitsnachweis
3. Benachrichtigung

## 1. Überwachte Größen

`monit` überwacht Plattenplatz, Systemlast, Speicher und kritische Dienste und alarmiert per Mail an die Administrator Email Adresse. Der Status ist mit `monit status` als `root` abrufbar. Der Prüfzyklus beträgt 60 s (`set daemon 60`). Bei Ausfall eines überwachten Dienst-Prozesses versucht das Monitoring den Diest neu zu starten (`systemctl`)  und sendet ein EMail an die Administrator Email Adresse.

| Prüfgegenstand | Schwellwert/Bedingung | Reaktion |
|---|---|---|
| Systemlast (1 min / 5 min) | über 4 / über 2 | Alarm |
| Speicher | über 90 % | Alarm |
| CPU (user) | über 90 % für 5 Zyklen | Alarm |
| Wurzel-Dateisystem | Platz oder Inodes über 85 % | Alarm |
| Kritische Dienst-Prozesse | Prozess fehlt | Neustart und Alarm |
| Schadsoftware-Scan | Log älter als 25 h | Alarm |
| Backup | Erfolgs-Kennzeichen älter als 26 h | Alarm |

Kritische Dienst sind im Grundzustand SSH, Postfix, Brute-Force-Schutz (`fail2ban`), Firewall (`ufw`) und cron. Die Firewall hat keinen Daemon und wird über `systemctl is-active --quiet ufw` per Exit-Code geprüft (kein Parsen einer Ausgabe). Ein Dienst-Ausfall wird innerhalb von 60 Sekunden erkannt. Jeder Check liegt als eigene Datei unter `/etc/monit/conf.d/`.

## 2. Verfügbarkeitsnachweis

Auf einem Einzelserver ohne Hochverfügbarkeit kann das lokale Monitoring einen Totalausfall des Wirts nicht selbst protokollieren, weil es dann mit ausfällt. Ist ein Verfügbarkeitsnachweis erforderlich, muss ein anderes bzw. externe Mintoring-Werkzeug verwendet werden.

## 3. Benachrichtigung

Das System ist so angelegt, dass im Alarmfall eine Mail an die Administrator Email Adresse versandt wird. Auslöser einer Mail sind SSH-Login, Backup-Fehlschlag, Ressourcen-Alarm des Monitorings, fehlgeschlagenes automatisches Update und der tägliche Log-Bericht.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage durch bereinigte Übernahme. |
