# Anioł stróż autostartu :)

Monitor automatycznego uruchamiania aplikacji w Windows: enumeracja źródeł autostartu,
wykrywanie nowych/zmienionych wpisów względem baselinu, powiadamianie. Blokowanie (driver)
w osobnym, późniejszym etapie.

Pierwsza wersja: PowerShell (opcjonalnie kompilacja do `.exe` przez PS2EXE).

---

## 1. Źródła autostartu

Sześć kategorii. Każda ma inny tryb odczytu, ale wszystkie zwracają ten sam wspólny obiekt,
dzięki czemu diff i allowlist pozostają jednolite.

### 1.1 Rejestr - klucze Run  `(tryb: enumeruj wszystkie wartości)`

```
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
...\RunOnce
...\RunOnceEx
...\Policies\Explorer\Run
...\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
...\RunServices
...\RunServicesOnce
```

Najczęstsze miejsca. Wpis to nazwa + ścieżka do programu. HKCU dotyczy użytkownika,
HKLM całego systemu. RunOnce - uruchamia się raz i kasuje wpis. RunOnceEx, RunServices,
RunServicesOnce - starsze warianty, wciąż używane przez malware, bo bywają pomijane.
Wow6432Node - klucze dla aplikacji 32-bit w 64-bitowym systemie. Policies - środowiska z GPO.
Każdą ścieżkę poprzedzamy `Test-Path` (nie wszystkie istnieją); HKLM wymaga uprawnień admina.

### 1.2 Relokacja folderu Startup (Shell Folders)  `(tryb: wskaźnik → porównaj + doskanuj)`

```
HKCU:\...\Explorer\User Shell Folders
HKCU:\...\Explorer\Shell Folders
HKLM:\...\Explorer\User Shell Folders
HKLM:\...\Explorer\Shell Folders
```

Nie przechowują wpisów autostartu - wskazują, gdzie znajduje się folder Startup.
Trik atakującego: zamiast wrzucać plik do Startupu, podmienia tu ścieżkę (wartości
`Startup` i `Common Startup`), żeby ominąć skanery patrzące tylko na domyślną lokalizację.
Sprawdzamy, czy wartość nadal wskazuje domyślny folder - jeśli nie, alert i skanujemy nową ścieżkę.

### 1.3 Rejestr - pojedyncze wartości  `(tryb: oczekiwana vs rzeczywista)`

```
HKLM:\...\Winlogon → Shell                     (oczek.: explorer.exe)
HKLM:\...\Winlogon → Userinit                  (oczek.: ...\userinit.exe,)
HKCU:\...\NT\CurrentVersion\Windows → load     (oczek.: puste)
HKCU:\Environment → UserInitMprLogonScript     (oczek.: brak)
HKLM:\System\...\Session Manager → BootExecute (oczek.: autocheck autochk *)
```

Tu nie enumerujemy - pilnujemy jednej, konkretnej wartości i jej poprawnej zawartości.
`Shell` i `Userinit` decydują, co startuje po zalogowaniu; `load` oraz `UserInitMprLogonScript`
uruchamiają program/skrypt dla użytkownika (normalnie nieustawione); `BootExecute` działa
bardzo wcześnie, jeszcze przed startem systemu. Cokolwiek odbiega od oczekiwanej wartości = alert.

### 1.4 Foldery Startup  `(tryb: skanuj wszystkie pliki)`

```
%AppData%\...\Start Menu\Programs\Startup
%ProgramData%\...\Start Menu\Programs\Startup
```

Wszystko, co trafi do tych folderów, uruchamia się przy logowaniu - osobno dla użytkownika
i dla wszystkich. Nie tylko skróty `.lnk`: również pliki `.exe`, skrypty (`.bat`, `.cmd`,
`.vbs`, `.js`) oraz inne pliki otwierane domyślnym programem. Dlatego skanujemy wszystkie pliki.
Dla `.lnk` dodatkowo odczytujemy cel skrótu - bo istotna jest ścieżka docelowa, nie nazwa skrótu.

### 1.5 Usługi (Services)  `(tryb: enumeruj, StartMode = Auto)`

```
HKLM:\SYSTEM\CurrentControlSet\Services
odczyt: Get-CimInstance Win32_Service   (StartMode = Auto)
```

Usługi z trybem startu „Automatic" uruchamiają się przy starcie systemu, jeszcze przed
zalogowaniem - głębiej niż klucze Run. Czytamy przez CIM/WMI, bo od razu dostajemy `PathName`
(plik + argumenty), konto (`StartName`) i stan. Tu chowają się też sterowniki (typ `KernelDriver`)
- w pierwszej wersji skupiamy się na zwykłych usługach. Usług są setki i większość jest legalna,
więc baseline + allowlist są tu kluczowe.

### 1.6 Harmonogram Zadań (Scheduled Tasks)  `(tryb: enumeruj, trigger logon/boot)`

```
C:\Windows\System32\Tasks   (zadania jako pliki XML)
odczyt: Get-ScheduledTask    (trigger: logon / boot)
```

Zadania wyzwalane przy logowaniu lub starcie systemu - popularny mechanizm trwałości,
bo omija klucze Run. Czytamy przez moduł `ScheduledTasks`; interesują nas triggery logon/boot
(realny autostart), a z akcji wyciągamy plik i argumenty. Zadania czysto czasowe oznaczamy
osobną kategorią. Systemowe wpisy w `\Microsoft\Windows\...` filtrujemy lub traktujemy jako znane.
Sygnał wart uwagi: akcja będąca skryptem (`powershell.exe -enc ...`).

---

## 2. Mapowanie na MITRE ATT&CK

| Kategoria | Technika MITRE |
|---|---|
| Rejestr - klucze Run | T1547.001 |
| Relokacja Shell Folders | T1547.001 |
| Winlogon (Shell / Userinit) | T1547.004 |
| load, UserInitMprLogonScript | T1037.001 |
| Foldery Startup | T1547.001 |
| Usługi | T1543.003 |
| Harmonogram Zadań | T1053.005 |

**Świadomie pomijamy** (zbyt czasochłonne / dużo szumu): T1547.002 (Authentication Packages),
T1547.003 (Time Providers), T1547.005 (Security Support Providers), AppInit_DLLs,
Image File Execution Options, Active Setup, BHO / rozszerzenia powłoki.

---

## 3. Format baselinu (`baseline.json`)

Każda kategoria ma własną tablicę (`runKeys`, `shellFolders`, `singleValues`, `startupFolders`,
`services`, `scheduledTasks`). Wpisy mają jeden z trzech kształtów:

- **Enumerowane** (`runKeys`, `startupFolders`, `services`, `scheduledTasks`) - `command`,
  `targetPath`, `sha256`, `signature`.
- **Wskaźnik** (`shellFolders`) - `valueName` + `expected` vs `actual` ścieżka.
- **Pojedyncza wartość** (`singleValues`) - `valueName` + `expected` vs `actual` zawartość.

### Pola

| Pole | Znaczenie |
|---|---|
| `id` | Stabilna tożsamość: `źródło\|lokalizacja\|nazwa`. Po tym diffujemy istnienie wpisu. |
| `source` | Typ źródła (RunKey, StartupFolder, Service, ScheduledTask, ShellFolder, SingleValue). |
| `location` | Konkretny klucz / folder / ścieżka zadania. |
| `name` | Nazwa wartości / pliku / usługi / zadania. |
| `command` | Pełna komenda (surowa, z argumentami). |
| `targetPath` | Sam plik wyłuskany z komendy (do hasha i podpisu). |
| `sha256` | Hash pliku docelowego; `null` gdy plik nie istnieje (sam w sobie sygnał). |
| `signature` | Podmiot podpisujący albo `"Unsigned"`. |
| `firstSeen` | Kiedy wpis pierwszy raz zobaczyliśmy. |
| `displayName`, `startMode`, `account` | Tylko usługi. |
| `trigger`, `account` | Tylko zadania. |
| `valueName`, `expected`, `actual` | Tylko `shellFolders` i `singleValues`. |

### Przykład

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-10-10T20:00:00+02:00",
  "hostname": "DESKTOP-WK",

  "runKeys": [
    {
      "id": "RunKey|HKCU:\\...\\Run|OneDrive",
      "source": "RunKey",
      "location": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "name": "OneDrive",
      "command": "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background",
      "targetPath": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
      "sha256": "9F2A1C...E4",
      "signature": "Microsoft Corporation",
      "firstSeen": "2026-10-10T20:00:00+02:00"
    }
  ],

  "startupFolders": [
    {
      "id": "StartupFolder|user|Spotify.lnk",
      "source": "StartupFolder",
      "location": "C:\\Users\\wk\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
      "name": "Spotify.lnk",
      "command": "C:\\Users\\wk\\AppData\\Roaming\\Spotify\\Spotify.exe",
      "targetPath": "C:\\Users\\wk\\AppData\\Roaming\\Spotify\\Spotify.exe",
      "sha256": "11BE77...A0",
      "signature": "Spotify AB",
      "firstSeen": "2026-10-10T20:00:00+02:00"
    }
  ],

  "services": [
    {
      "id": "Service|Spooler",
      "source": "Service",
      "location": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Spooler",
      "name": "Spooler",
      "displayName": "Print Spooler",
      "command": "C:\\Windows\\System32\\spoolsv.exe",
      "targetPath": "C:\\Windows\\System32\\spoolsv.exe",
      "startMode": "Auto",
      "account": "LocalSystem",
      "sha256": "C3D4...9B",
      "signature": "Microsoft Windows",
      "firstSeen": "2026-10-10T20:00:00+02:00"
    }
  ],

  "scheduledTasks": [
    {
      "id": "ScheduledTask|\\MyApp\\Updater",
      "source": "ScheduledTask",
      "location": "\\MyApp\\Updater",
      "name": "Updater",
      "command": "C:\\Program Files\\MyApp\\updater.exe --silent",
      "targetPath": "C:\\Program Files\\MyApp\\updater.exe",
      "trigger": "Logon",
      "account": "SYSTEM",
      "sha256": "77AA...1F",
      "signature": "MyApp Sp. z o.o.",
      "firstSeen": "2026-10-10T20:00:00+02:00"
    }
  ],

  "shellFolders": [
    {
      "id": "ShellFolder|HKCU|Startup",
      "source": "ShellFolder",
      "location": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
      "valueName": "Startup",
      "expected": "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
      "actual": "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
      "firstSeen": "2026-10-10T20:00:00+02:00"
    }
  ],

  "singleValues": [
    {
      "id": "SingleValue|Winlogon|Shell",
      "source": "SingleValue",
      "location": "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
      "valueName": "Shell",
      "expected": "explorer.exe",
      "actual": "explorer.exe",
      "firstSeen": "2026-10-10T20:00:00+02:00"
    }
  ]
}
```

---

## 4. Allowlist (`allowlist.json`)

Osobny, prosty plik - lista zatwierdzonych `id` (+ opcjonalnie `sha256` dla ochrony przed
podmianą pliku pod tą samą nazwą).

```json
{
  "allowed": [
    { "id": "RunKey|HKCU:\\...\\Run|OneDrive", "sha256": "9F2A1C...E4", "note": "Microsoft OneDrive" },
    { "id": "Service|Spooler", "matchBy": "id", "note": "Usługa systemowa" }
  ]
}
```

- `matchBy: "sha256"` (domyślnie) - podmiana pliku = alert (trzeba aktualizować po update programu).
- `matchBy: "id"` - zatwierdzenie tylko po tożsamości, dla często aktualizowanych programów.

---

## 5. Format alertów (`alerts/`)

Alert powstaje **tylko gdy wykryto zmianę** - czysty skan nie tworzy pliku.
Jeden plik na uruchomienie, w którym coś wykryto; nazwa = timestamp uruchomienia.

```
alerts/
  alert_2026-10-10_20-21-05.json
  alert_2026-10-11_09-03-12.json
```

Format: strukturalny diff w JSON (spójny z baselinem, maszynowo czytelny - folder `alerts/`
jest punktem integracji dla powiadomień i, później, drivera).

### Typy zmian

- **`new`** - nowa tożsamość (`id`), której nie było w baseline → niesie `current`.
- **`changed`** - ta sama `id`, zmienił się `sha256`/`command` lub `actual` → niesie `before` + `after`.
- **`removed`** - `id` był w baseline, zniknął → niesie `previous`.

### Przykład `alert_2026-10-10_20-21-05.json`

```json
{
  "scanTime": "2026-10-10T20:21:05+02:00",
  "hostname": "DESKTOP-WK",
  "baselineTime": "2026-10-09T18:00:00+02:00",
  "changeCount": 2,
  "changes": [
    {
      "type": "new",
      "category": "runKeys",
      "id": "RunKey|HKCU:\\...\\Run|svc_update",
      "current": {
        "location": "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "name": "svc_update",
        "command": "C:\\Users\\Public\\svc_update.exe",
        "targetPath": "C:\\Users\\Public\\svc_update.exe",
        "sha256": "A17F...3C",
        "signature": "Unsigned"
      }
    },
    {
      "type": "changed",
      "category": "singleValues",
      "id": "SingleValue|Winlogon|Shell",
      "field": "actual",
      "before": "explorer.exe",
      "after": "explorer.exe, C:\\Users\\Public\\x.exe"
    }
  ]
}
```

Nagłówek (`scanTime`, `baselineTime`, `changeCount`) daje kontekst: kiedy program działał
i względem jakiego baselinu liczył różnicę. Alert jest niezmiennym zapisem chwili - niezależnie
od tego, czy baseline zostanie potem zaktualizowany.

Opcjonalnie: jedna linia do `alerts.log` dla czytania gołym okiem
(`[2026-10-10 20:21] 2 zmiany: +1 new, ~1 changed`).

---

## 6. Pliki projektu

```
baseline.json      - aktualny stan prawdy (snapshot wszystkich źródeł)
allowlist.json     - zatwierdzone wpisy
alerts/            - strukturalne diffy, tworzone tylko przy zmianach
  alert_<timestamp>.json
alerts.log         - opcjonalny, czytelny log jednoliniowy
```

---

## 7. Zakres etapów

1. **Monitoring (tryb użytkownika, PowerShell)** - enumeracja 6 źródeł, baseline, diff, alerty,
   powiadomienia. Wersja pierwsza; może być kompilowana do `.exe` (PS2EXE).
2. **Driver (tryb jądra, później)** - blokowanie: przechwytywanie tworzenia procesów,
   zatrzymanie podejrzanego programu. Czyta ten sam folder `alerts/`.
