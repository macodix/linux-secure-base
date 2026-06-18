# Monitoring

Dieses Dokument beschreibt das Monitoring des Grundsystems: die überwachten Größen, den Verfügbarkeitsnachweis und die Benachrichtigung des Betreibers.

**Status:** in Bearbeitung — **Stand:** 2026-06-18

## Inhaltsverzeichnis

1 Überwachte Größen
2 Verfügbarkeitsnachweis
3 Benachrichtigung

## 1. Überwachte Größen

`monit` überwacht Plattenplatz, Systemlast, Speicher und kritische Dienste und alarmiert per Mail über das lokale Postfix. Es bindet nur an Loopback (`set httpd port 2812 ... allow localhost`). Der Status ist mit `monit status` als root abrufbar. Der Prüfzyklus beträgt 60 s (`set daemon 60`). Bei Ausfall eines überwachten Dienst-Prozesses startet das Monitoring ihn über `systemctl` neu und alarmiert.

| Prüfgegenstand | Schwellwert/Bedingung | Reaktion |
|---|---|---|
| Systemlast (1 min / 5 min) | über 4 / über 2 | Alarm |
| Speicher | über 90 % | Alarm |
| CPU (user) | über 90 % für 5 Zyklen | Alarm |
| Wurzel-Dateisystem | Platz oder Inodes über 85 % | Alarm |
| Kritische Dienst-Prozesse | Prozess fehlt | Neustart und Alarm |
| Schadsoftware-Scan | Log älter als 25 h | Alarm |
| Backup | Erfolgs-Kennzeichen älter als 26 h | Alarm |

Kritische Dienst-Prozesse sind im Grundzustand SSH, Postfix, Brute-Force-Schutz (`fail2ban`), Firewall (`ufw`) und cron. Mit dem Webserver wird ein Prozess-Check für nginx ergänzt. Die Firewall hat keinen Dauer-Daemon und wird über `systemctl is-active --quiet ufw` per Exit-Code geprüft (kein Parsen einer Ausgabe). Ein Prozess-Ausfall wird innerhalb eines Zyklus (60 s) erkannt. Jeder Check liegt als eigene Datei unter `/etc/monit/conf.d/`.

## 2. Verfügbarkeitsnachweis

Auf einem Einzelserver ohne Hochverfügbarkeit kann das lokale Monitoring einen Totalausfall des Wirts nicht selbst protokollieren, weil es dann mit ausfällt. Der Verfügbarkeitsnachweis verlangt daher eine vom Wirt unabhängige Messung.

Festgelegt ist: In der derzeitigen Ausbaustufe wird keine kontinuierliche, wirt-unabhängige Messung eingerichtet. Ausfälle werden nachträglich aus Reboot- und Dienst-Logs nachvollzogen (Ausfall-Buchführung). Dieser Nachweis ist bei einem Totalausfall des Wirts lückenhaft, was als Einschränkung bewusst akzeptiert wird. Eine externe Messung (Uptime-Prüfdienst auf den öffentlichen HTTPS-Endpunkt) wird eingeführt, sobald mehrere Instanzen betrieben werden. Die interne Selbstüberwachung durch `monit` bleibt davon unberührt und deckt Teilausfälle ab.

## 3. Benachrichtigung

Der Betreiber wird per Mail informiert und muss nicht permanent überwachen. Der Versand läuft über das Postfix (Konzept-Dokument Mail-Versand). Auslöser einer Mail sind SSH-Login, Backup-Fehlschlag, Ressourcen-Alarm des Monitorings, fehlgeschlagenes automatisches Update und der tägliche Log-Bericht.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---|---|---|---|
| 0.01 | 2026-06-18 | macodix | Erstanlage durch bereinigte Übernahme. |
