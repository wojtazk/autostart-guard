# Testy ręczne na maszynie wirtualnej

Scenariusze do przeklikania „na żywo" — uzupełniają automatyczny plan z
[`testy.md`](testy.md). Każdy zaczyna i kończy się na **snapshocie VM**.

## Przygotowanie (wspólne)

1. VM z Windows 10/11, **zrób snapshot** przed testami.
2. Skopiuj repo na VM (np. `C:\ag-src`). Folder roboczy na dane: `C:\ag`.
3. PowerShell **jako administrator** (pełny odczyt HKLM / usług / zadań).
4. Przejdź do narzędzi:
   ```powershell
   cd C:\ag-src\tools
   ```

Polecenia używają `-DataPath C:\ag`, więc:
`C:\ag\baseline.json`, `C:\ag\allowlist.json`, `C:\ag\alerts\`.

---

## Scenariusz 1 — wykrycie nowego autostartu (instalacja Chrome)

**Cel:** pokazać, że po zrobieniu baseline'u instalacja programu, który dopisuje
się do autostartu, zostaje wykryta jako nowe wpisy. Nie wymaga drivera.

1. **Baseline** (stan czysty, przed instalacją):
   ```powershell
   .\AutostartGuard.ps1 -Action Baseline -DataPath C:\ag
   ```
   Oczekiwane: `Zapisano baseline: C:\ag\baseline.json`, podsumowanie liczby
   wpisów w 6 kategoriach.

2. **Zainstaluj Chrome** (dopisuje usługi `gupdate`/`gupdatem` i zadania
   `GoogleUpdateTaskMachine*`):
   ```powershell
   winget install --id Google.Chrome -e --silent --accept-package-agreements --accept-source-agreements
   ```
   (albo ręcznie z pobranego instalatora, jeśli brak winget)

3. **Skan**:
   ```powershell
   .\AutostartGuard.ps1 -Action Scan -DataPath C:\ag
   ```
   Oczekiwane: `WYKRYTO zmiany (...)`, powstaje `C:\ag\alerts\alert_<timestamp>.json`.

4. **Obejrzyj alert**:
   ```powershell
   Get-Content (Get-ChildItem C:\ag\alerts\alert_*.json | Select-Object -Last 1).FullName -Raw
   ```
   Oczekiwane: wpisy `type=new` w `scheduledTasks` i/lub `services` wskazujące
   Google Update (z `targetPath`, `signature=Google LLC`).

5. **(opcjonalnie) Allowlist** — zatwierdź jeden z wpisów i potwierdź, że
   znika z kolejnego skanu:
   ```powershell
   # skopiuj "id" wykrytego wpisu z alertu i wstaw poniżej
   @{ allowed = @( @{ id = '<WKLEJ_ID>'; matchBy = 'id'; note = 'Google Update' } ) } |
     ConvertTo-Json -Depth 5 | Set-Content C:\ag\allowlist.json -Encoding UTF8
   .\AutostartGuard.ps1 -Action Scan -DataPath C:\ag
   ```
   Oczekiwane: ten wpis nie generuje już alertu (reszta nowych — nadal tak).

6. **Sprzątanie:** przywróć snapshot.

**Co to pokazuje:** diff względem baseline, wykrycie realnego autostartu,
działanie allowlisty.

---

## Scenariusz 2 — wykrycie + BLOKADA (end-to-end, driver)

**Cel:** pełny łańcuch: skaner wykrywa „malware", klient wgrywa regułę, driver
blokuje uruchomienie. Wymaga drivera i trybu test signing.

### 2a. Przygotowanie drivera (raz na VM)

Instalatorem z Release **albo** ręcznie:
```powershell
bcdedit /set testsigning on
Restart-Computer        # po restarcie dalej jako administrator
# po restarcie:
sc.exe create AutostartGuard type= kernel start= demand binPath= C:\ag-src\x64\Release\process_filter.sys
sc.exe start AutostartGuard
sc.exe query AutostartGuard      # STATE powinno być RUNNING
```
> Jeśli `start` zwróci błąd 577 — test signing nie jest aktywny (restart).
> Driver startuje w trybie `audit` (nic nie blokuje).

### 2b. Test

1. **Baseline:**
   ```powershell
   .\AutostartGuard.ps1 -Action Baseline -DataPath C:\ag
   ```

2. **Udawany „malware"** (kopia Notatnika) + wpis w autostarcie:
   ```powershell
   Copy-Item C:\Windows\System32\notepad.exe C:\Users\Public\svc_update.exe
   New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
     -Name 'svc_update' -Value 'C:\Users\Public\svc_update.exe' -PropertyType String -Force
   ```

3. **Potwierdź, że się uruchamia** (przed blokadą):
   ```powershell
   Start-Process C:\Users\Public\svc_update.exe   # Notatnik się otwiera — zamknij go
   ```

4. **Skan** → alert:
   ```powershell
   .\AutostartGuard.ps1 -Action Scan -DataPath C:\ag
   ```
   Oczekiwane: alert `type=new`, `runKeys`, `signature=Unsigned`, ścieżka w `C:\Users\Public`.

5. **Wgraj reguły do drivera i włącz blokowanie:**
   ```powershell
   .\AutostartGuardCtl.ps1 -Action Load  -AlertsPath C:\ag\alerts
   .\AutostartGuardCtl.ps1 -Action Mode  -Mode enforce -Force
   ```

6. **Próba uruchomienia — teraz odmowa:**
   ```powershell
   Start-Process C:\Users\Public\svc_update.exe
   ```
   Oczekiwane: błąd odmowy dostępu (proces nie wstaje).

7. **Liczniki:**
   ```powershell
   .\AutostartGuardCtl.ps1 -Action Status
   ```
   Oczekiwane: `Blocked` rośnie. W DebugView (Capture Kernel) linia
   `[AutostartGuard] ZABLOKOWANO ...`.

8. **Sprzątanie:**
   ```powershell
   .\AutostartGuardCtl.ps1 -Action Mode -Mode audit
   .\AutostartGuardCtl.ps1 -Action Clear
   ```
   następnie przywróć snapshot.

**Co to pokazuje:** etap 1 i etap 2 spięte razem — wykrycie kończy się realną
blokadą przy próbie uruchomienia.

---

## Scenariusz 3 — podmiana wartości (hijack Winlogon Shell)

**Cel:** pokazać wykrywanie zmiany pojedynczej wartości (nie enumeracji).
**OSTROŻNIE:** modyfikujemy `Winlogon\Shell` — zła wartość potrafi zepsuć
logowanie. Robić **tylko na VM ze snapshotem** i od razu przywracać.

1. **Baseline:**
   ```powershell
   .\AutostartGuard.ps1 -Action Baseline -DataPath C:\ag
   ```

2. **Symulacja hijacku** (dopisanie obcego pliku do `Shell`):
   ```powershell
   $wl = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
   $orig = (Get-ItemProperty $wl -Name Shell).Shell          # zapamiętaj oryginał
   Set-ItemProperty $wl -Name Shell -Value 'explorer.exe, C:\Users\Public\x.exe'
   ```

3. **Skan** → alert:
   ```powershell
   .\AutostartGuard.ps1 -Action Scan -DataPath C:\ag
   ```
   Oczekiwane: alert `type=changed`, `singleValues`, `id=SingleValue|Shell`,
   z `before=explorer.exe` i `after=explorer.exe, C:\Users\Public\x.exe`.

4. **Natychmiast przywróć** (zanim się wylogujesz/zrestartujesz):
   ```powershell
   Set-ItemProperty $wl -Name Shell -Value $orig
   ```

5. **Sprzątanie:** przywróć snapshot.

**Co to pokazuje:** tryb „oczekiwana vs rzeczywista" dla wartości, które mają
znaną poprawną zawartość (Winlogon, load, BootExecute, ...).

---

## Przypadki brzegowe (szybkie)

| Test | Jak | Oczekiwane |
|---|---|---|
| Brak admina | `-Action Baseline` jako zwykły user | HKLM/usługi/zadania w `skipped`, bez wysypki |
| Brak zmian | `-Action Scan` od razu po baseline | „Brak zmian", żaden plik w `alerts/` nie powstaje |
| Uszkodzony alert | wrzuć zły JSON do `C:\ag\alerts` i `AutostartGuardCtl.ps1 -Action Load -DryRun` | plik pominięty z ostrzeżeniem `Pomijam ...` |
| Plik nie istnieje | wpis Run do nieistniejącej ścieżki, skan | w alercie `sha256=null`, `signature=FileMissing` |
