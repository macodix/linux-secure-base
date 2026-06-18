# Vorbedingungen

Ausgangspunkt ist eine minimale Server-Installation Ubuntu Server LTS ohne grafische Oberfläche. Die Einrichtung erfolgt als `root` über die initiale Konsole des Anbieters oder den initialen SSH-Zugang. Die VPS-Konsole bleibt als Rückfallweg gegen Aussperren bestehen. Der SSH-Public-Key des Betreibers liegt am Arbeitsplatz vor.

Die Reihenfolge der Kapitel ist die Aufbau-Reihenfolge: zuerst der Mail-Versand, damit alle folgenden Komponenten benachrichtigen können. Dann Benutzer und SSH-Härtung. Dann die Schutzmechanismen. Abschließend Protokollierung, Updates, Datensicherung, Monitoring, Härtungsprüfung und der Webserver.

Vorab zu prüfen: Hostname/FQDN gesetzt (`hostnamectl`), Zeitsynchronisation aktiv — `timedatectl show -p NTPSynchronized --value` liefert `yes` (Distro-Default `systemd-timesyncd`).

Platzhalter in diesem Dokument (`<admin@meine-domain.de>`, `<smtp.hoster.example>`, `<hauptbenutzer>`, SFTP-Ziel, `<domain>`) sind umgebungsspezifisch und in der Betriebsdokumentation belegt.
