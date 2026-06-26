# pifos — Diagramme

**Status:** [in Bearbeitung] · **Stand:** 2026-06-26

Dieses Dokument visualisiert den Aufbau und die Abläufe des Bausatzes pifos (python infrastructure for operational services), um das Verständnis zu erleichtern. Maßgeblich ist `docs/pifos/konzept.md`, ergänzend `docs/pifos/anforderungen.md`. Die Diagramme bilden nur ab, was dort festgelegt ist. Auf dieser Ebene werden konkrete Klassen- und Dateinamen aus dem Konzept verwendet (`PifosCaller`, `pifos_caller.py`, `ConfigItem`, `config.py`).

Format ist Mermaid in Markdown; GitHub rendert es nativ.

## Inhaltsverzeichnis

1. Klassendiagramm
2. Komponenten- und Datenflussdiagramm
3. Sequenzdiagramm: Aufruf und Steuerung über IPC
4. Zustandsdiagramm: Modulprozess

## 1. Klassendiagramm

Das Klassendiagramm zeigt die drei Bausteine von pifos und ihre Beziehungen: die Basisklassen für Aktionen und Module, die Konfiguration mit Config-Objekt und formatspezifischen Klassen sowie die Aufrufer-Basisklasse mit einem konkreten Aufrufer.

Ein Modul nutzt Aktionen über Komposition (`Module` HAT `Action`). Konkrete Aktionen und Module erben von ihrer jeweiligen Basisklasse. Ein konkreter Aufrufer wie der Installer erbt von `PifosCaller`. Die abstrakten Methoden der Basisklassen sind kursiv dargestellt; alle Klassenvariablen besitzen laut Anforderung ÜBR-04 getter und setter, im Diagramm aus Übersicht nicht je Variable ausgeführt.

```mermaid
classDiagram
    direction LR

    class Action {
        <<abstract>>
        +status
        +stdout
        +stderr
        +safe_mode
        +backup_location
        +run()*
        +get_status()
        +get_stdout()
        +get_stderr()
    }

    class CopyFileAction {
        +run()
    }
    class SysCmdAction {
        +command
        +run()
    }

    Action <|-- CopyFileAction
    Action <|-- SysCmdAction
    note for SysCmdAction "generische Aktion fuer Systembefehle (AKT-08)"

    class Module {
        <<abstract>>
        +CONFIG : list~ConfigItem~
        +loglevel
        +start()*
        +run_action()
        +control_action()
        +send_message()
        +receive_message()
    }

    class InstModule {
        +check()
        +rollback()
    }

    Module <|-- InstModule
    note for InstModule "systemveraenderndes Modul: Ueberpruefungsmodus + Rollback (MOD-12, MOD-13)"

    Module o-- "0..*" Action : Komposition

    class Config {
        +get_value()
        +get_section()
        +get_list()
        +load_dict()
        +load_raw()
        +check_pattern()
    }

    class ConfigItem {
        <<dataclass>>
        +name
        +required
        +default
        +check
        +description
    }

    class IniConfig {
        +to_dict()
    }
    class TomlConfig {
        +to_dict()
    }
    class JsonConfig {
        +to_dict()
    }

    Config ..> ConfigItem : nutzt
    Config <-- IniConfig : liefert dict/raw
    Config <-- TomlConfig : liefert dict/raw
    Config <-- JsonConfig : liefert dict/raw
    Module ..> Config : erhaelt beim Start
    Module ..> ConfigItem : deklariert in CONFIG

    class PifosCaller {
        <<abstract>>
        +loglevel
        +start_module()
        +stop_module()
        +terminate_module()
        +send_command()
        +receive_result()
        +write_log()
    }

    class LsbInstaller {
        +ui
        +run()
    }

    PifosCaller <|-- LsbInstaller
    PifosCaller ..> Module : startet/steuert via IPC
    PifosCaller ..> Config : instanziiert und uebergibt
```

## 2. Komponenten- und Datenflussdiagramm

Das Komponentendiagramm zeigt, wie die Teile zur Laufzeit zusammenwirken und wohin Daten fließen. Der Aufrufer instanziiert die Konfiguration aus einer Konfigurationsquelle, startet darüber Modulprozesse und führt als einziger das Logfile.

Die Trennung der Verantwortung folgt dem Konzept: Aktionen erfassen Status und Ausgaben, das Modul reicht ausgewählte Meldungen per IPC nach oben, und nur der Aufrufer schreibt das Logfile (LOG-01, LOG-02).

```mermaid
flowchart TB
    src[("Konfigurationsquelle<br>ini / toml / json")]
    log[(Logfile)]

    subgraph caller[Aufrufer z. B. LsbInstaller]
        ui[Oberflaeche + Fachlogik]
        base["PifosCaller<br>IPC + Logger"]
    end

    subgraph modproc[Modulprozess]
        mod[Module]
        act1[Action]
        act2[Action]
    end

    src -->|liest ueber Config| base
    base -->|Config-Objekt + Befehle via IPC| mod
    mod -->|Meldungen, Ergebnisse via IPC| base
    ui --- base
    mod -->|steuert / Komposition| act1
    mod --> act2
    act1 -->|Status, stdout, stderr| mod
    act2 -->|Status, stdout, stderr| mod
    base -->|schreibt| log
```

## 3. Sequenzdiagramm: Aufruf und Steuerung über IPC

Das Sequenzdiagramm zeigt den zeitlichen Ablauf zwischen Aufrufer und Modul über IPC: der Aufrufer beschafft die Konfiguration, startet den Modulprozess, sendet Befehle hinab und erhält Meldungen und Ergebnisse hinauf. Das Modul steuert dabei seine Aktionen und entscheidet, welche Meldungen es weiterreicht.

Der Ablauf folgt den Anforderungen STR-01 bis STR-04 (Start über IPC, Übergabe der Konfiguration, bidirektionale Nachrichten) sowie LOG-02 (Modul wählt aus, was es meldet; Aufrufer wählt aus, was er protokolliert).

```mermaid
sequenceDiagram
    participant C as Aufrufer (PifosCaller)
    participant Cfg as Config
    participant M as Module (Modulprozess)
    participant A as Action

    C->>Cfg: instanziieren, Quelle laden
    Cfg-->>C: Config-Objekt
    C->>M: Modulprozess starten (IPC), Config uebergeben
    M->>M: CONFIG pruefen, Werte in Klassenvariablen ablegen

    C->>M: Befehl (Aktivitaet ausfuehren)
    M->>A: Aktion ausfuehren, Optionen setzen
    A-->>M: Status, stdout, stderr
    M-->>C: Meldung (INFO/WARN), nicht-logging-relevante Nachricht
    C-->>M: Antwort / Daten anfordern (Variablenwerte)
    M-->>C: angeforderte Daten

    M-->>C: Ergebnis der Aktivitaet
    C->>C: ausgewaehlte Meldungen ins Logfile schreiben
    C->>M: Modulprozess beenden (IPC)
```

## 4. Zustandsdiagramm: Modulprozess

Das Zustandsdiagramm zeigt die Zustände eines Modulprozesses aus Sicht des Aufrufers. Das Konzept (Kapitel 3.3, Standardaufrufer) legt fest, dass die Aufrufer-Basisklasse Modulprozesse starten, anhalten und beenden kann; daraus ergeben sich die Übergänge.

```mermaid
stateDiagram-v2
    [*] --> Gestartet : start_module()
    Gestartet --> Angehalten : stop_module()
    Angehalten --> Gestartet : fortsetzen
    Gestartet --> Beendet : terminate_module()
    Angehalten --> Beendet : terminate_module()
    Gestartet --> Beendet : Modul beendet sich (CRITICAL)
    Beendet --> [*]
```

Der Übergang „Modul beendet sich (CRITICAL)" bildet EXC-03 ab: Stuft ein Modul einen Fehler als CRITICAL ein und beendet sich, stellt es vorher sicher, dass die Ausnahme-Meldungen den Aufrufer noch erreichen.

## Versionshistorie

| Version | Datum | Wer | Änderung |
|---------|-------|-----|----------|
| 0.01 | 2026-06-26 | macodix | Erstanlage: Klassen-, Komponenten-/Datenfluss-, Sequenz- und Zustandsdiagramm in Mermaid, abgeleitet aus `docs/pifos/konzept.md` und `docs/pifos/anforderungen.md`. |
</content>
