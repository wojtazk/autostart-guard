# Anioł stróż autostartu - etap 2: driver blokujący

Sterownik trybu jądra, który blokuje uruchamianie programów wskazanych przez
etap 1 projektu (monitoring autostartu w PowerShellu).

> **To PoC na zajęcia, nie produkt.** Tryb `enforce` faktycznie uniemożliwia
> uruchamianie procesów. Testuj na maszynie wirtualnej ze snapshotem.

---

## 1. Dlaczego driver nie czyta `alerts/` sam

README etapu 1 zakłada, że driver „czyta ten sam folder `alerts/`". Odstąpiliśmy
od tego świadomie. Tryb jądra nie ma biblioteki JSON, a otwieranie plików
z kontekstu callbacku tworzenia procesu to ryzyko zakleszczenia (callback
działa w kontekście wątku tworzącego proces, który może być w środku operacji
na systemie plików).

Zamiast tego klasyczny podział: **polityka w user mode, egzekucja w jądrze**.

```
alerts/*.json
      │
      │  AutostartGuardCtl.ps1  (parsowanie JSON, wyciąganie targetPath)
      ▼
\\.\AutostartGuard              (DeviceIoControl, IOCTL_AG_ADD_RULE)
      │
      ▼
process_filter.sys              (płaska lista ścieżek w pamięci jądra)
      │
      │  PsSetCreateProcessNotifyRoutineEx
      ▼
CreateInfo->CreationStatus = STATUS_ACCESS_DENIED
```

Efekt dla projektu jest ten sam, a kod jądra zostaje na tyle mały, że da się go
przeczytać w całości.

---

## 2. Pliki

| Plik                          | Rola                                                       |
| ----------------------------- | ---------------------------------------------------------- |
| `driver.c`                    | cały sterownik: `DriverEntry`, callback, obsługa IOCTL     |
| `agctl.h`                     | kontrakt kernel ↔ user mode: kody IOCTL, struktury, limity |
| `tools/AutostartGuardCtl.ps1` | klient: czyta `alerts/`, wgrywa reguły, czyta liczniki     |
| `tools/sample-alerts/`        | przykładowy alert do testu parsowania bez drivera          |

Brak pliku `.inf` jest celowy - to sterownik niePnP, instalowany jako usługa
jądra przez `sc.exe create`. INF powodował błąd `InfVerif 1297`
(„does not install on any devices").

---

## 3. Tryby pracy

| Tryb          | Zachowanie                                               |
| ------------- | -------------------------------------------------------- |
| `off` (0)     | callback nic nie robi                                    |
| `audit` (1)   | loguje trafienia, **przepuszcza** proces - tryb startowy |
| `enforce` (2) | loguje i **blokuje** tworzenie procesu                   |

Driver startuje w `audit`. Przejście do `enforce` wymaga w skrypcie flagi
`-Force`.

### Bezpiecznik

Driver ma wbudowaną listę krytycznych procesów systemowych (`smss.exe`,
`csrss.exe`, `services.exe`, `lsass.exe`, `svchost.exe`, `explorer.exe`,
`winlogon.exe` i kilka dalszych). Trafienie w nie zostanie **zalogowane, ale
nigdy nie zablokowane**, nawet w trybie `enforce`. Bez tego jedna zła reguła
potrafi zablokować logowanie i zostawić maszynę nie do użytku. Skrypt
user mode odsiewa te same nazwy już przy wgrywaniu.

---

## 4. Dopasowywanie ścieżek

Jądro widzi ścieżki w formacie NT, user mode w formacie DOS:

```
jądro:   \Device\HarddiskVolume3\Users\Public\svc_update.exe
reguła:  C:\Users\Public\svc_update.exe
```

Driver obcina prefiks `C:` i sprawdza, czy ścieżka z jądra **kończy się** regułą,
bez czułości na wielkość liter.

Konsekwencje, o których trzeba wiedzieć:

- reguła `svc_update.exe` (sama nazwa) zablokuje ten plik w **każdym** katalogu;
- dopasowanie jest po ścieżce, nie po hashu - zmiana nazwy pliku obchodzi regułę.
  Blokowanie po SHA-256 wymagałoby liczenia hasha w jądrze, co wykracza poza PoC;
- limit długości reguły to 259 znaków, limit liczby reguł to 64 (`agctl.h`).

---

## 5. Build

Wymagania: Visual Studio 2022 z komponentem C++ oraz WDK z integracją MSBuild.

Projekt przypina wersję SDK, bo bez tego `WindowsTargetPlatformVersion` rozwija
się do samego `10.0`, `KM_IncludePath` zostaje puste i plik kompiluje się
nagłówkami user mode (`ntddk.h` nie zostanie znaleziony). Sprawdź, dla której
wersji masz WDK:

```powershell
Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\build"
```

Jeśli to nie `10.0.22621.0`, popraw `WindowsTargetPlatformVersion`
w `process_filter.vcxproj`.

Build:

```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild .\process_filter.vcxproj /t:Rebuild /p:Configuration=Debug /p:Platform=x64
```

Wynik: `x64\Debug\process_filter.sys`, test-podpisany certyfikatem
wygenerowanym przez WDK (`process_filter.cer`).

### `/INTEGRITYCHECK`

`PsSetCreateProcessNotifyRoutineEx` wymaga, by obraz miał w nagłówku PE flagę
`IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`. Bez niej rejestracja callbacku
zwraca `STATUS_ACCESS_DENIED` (`0xC0000022`) i driver nie wstanie. Projekt
dodaje do linkera `/INTEGRITYCHECK`. Weryfikacja:

```powershell
dumpbin /headers x64\Debug\process_filter.sys | Select-String "DLL characteristics"
```

W wyniku musi być ustawiony bit `0x0080` (np. `41E0`).

Źródła: [/INTEGRITYCHECK](https://learn.microsoft.com/en-us/cpp/build/reference/integritycheck-require-signature-check),
[PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex).
Treść przeredagowana zgodnie z wymogami licencyjnymi źródeł.

---

## 6. Instalacja (maszyna testowa)

Driver jest podpisany certyfikatem testowym, więc maszyna musi być w trybie
test signing. Wymaga restartu:

```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

Potem, z konsoli **jako administrator**:

```powershell
# Uwaga: "sc" w PowerShellu to alias Set-Content. Trzeba pisać sc.exe
sc.exe create AutostartGuard type= kernel binPath= C:\ag\process_filter.sys
sc.exe start AutostartGuard
sc.exe query AutostartGuard
```

Jeśli `start` zwróci błąd 577 (nie można zweryfikować podpisu), test signing
nie jest aktywny. Jeśli driver wstaje i natychmiast się wyładowuje, sprawdź
log z DebugView - najpewniej `/INTEGRITYCHECK`.

Odinstalowanie:

```powershell
sc.exe stop AutostartGuard
sc.exe delete AutostartGuard
```

---

## 7. Użycie

Logi drivera: **DebugView** z włączonymi _Capture Kernel_ i _Enable Verbose
Kernel Output_. Wszystkie wpisy mają prefiks `[AutostartGuard]`.

```powershell
cd tools

# Stan drivera: tryb, liczba reguł, liczniki
.\AutostartGuardCtl.ps1 -Action Status

# Co zostałoby wgrane z alertów - działa bez drivera i bez admina
.\AutostartGuardCtl.ps1 -Action Load -AlertsPath ..\..\autostart-guard\alerts -DryRun

# Wgranie reguł (czyści poprzednie)
.\AutostartGuardCtl.ps1 -Action Load -AlertsPath ..\..\autostart-guard\alerts

# Włączenie blokowania
.\AutostartGuardCtl.ps1 -Action Mode -Mode enforce -Force

# Powrót do obserwacji / wyczyszczenie
.\AutostartGuardCtl.ps1 -Action Mode -Mode audit
.\AutostartGuardCtl.ps1 -Action Clear
```

---

## 8. Scenariusz demonstracyjny

Na maszynie wirtualnej ze snapshotem:

```powershell
# 1. Fałszywy "malware" - kopia Notatnika
Copy-Item C:\Windows\System32\notepad.exe C:\Users\Public\svc_update.exe

# 2. Potwierdzenie, że się uruchamia
Start-Process C:\Users\Public\svc_update.exe        # okno się otwiera, zamknij je

# 3. Reguła na tę ścieżkę (przykładowy alert zawiera dokładnie ten plik)
cd tools
.\AutostartGuardCtl.ps1 -Action Load -AlertsPath .\sample-alerts
.\AutostartGuardCtl.ps1 -Action Mode -Mode enforce -Force

# 4. Próba ponownego uruchomienia - teraz odmowa dostępu
Start-Process C:\Users\Public\svc_update.exe

# 5. Potwierdzenie w licznikach
.\AutostartGuardCtl.ps1 -Action Status
```

W punkcie 4 oczekiwany jest błąd odmowy dostępu, a `Blocked` w punkcie 5 rośnie.
Równolegle w DebugView pojawia się linia `[AutostartGuard] ZABLOKOWANO ...`.

---

## 9. Ograniczenia

Świadome uproszczenia, warte wymienienia w sekcji „wnioski i propozycje
ulepszeń" dokumentacji projektu:

- **Dopasowanie po ścieżce, nie po hashu.** Zmiana nazwy pliku obchodzi regułę.
- **Brak trwałości reguł.** Lista żyje w pamięci jądra; po restarcie trzeba ją
  wgrać ponownie (w praktyce: zadanie w Harmonogramie przy starcie systemu).
- **Kontrola dostępu tylko domyślna.** Urządzenie dostaje standardowy
  deskryptor bezpieczeństwa, który daje prawo zapisu administratorom i koncie
  SYSTEM. Wersja produkcyjna powinna ustawiać własny SDDL i weryfikować, czy
  wołający to zaufany proces - inaczej dowolny proces z prawami admina może
  wyczyścić reguły.
- **Brak samoochrony.** Nic nie broni usługi drivera przed zatrzymaniem przez
  administratora (prawdziwe EDR-y używają do tego procesów chronionych i ELAM).
- **Limity statyczne.** 64 reguły, 259 znaków ścieżki - tablica jest alokowana
  statycznie, żeby uniknąć zarządzania pamięcią w jądrze.
- **`FileOpenNameAvailable`.** Gdy jądro nie potrafi podać pełnej nazwy obrazu,
  `ImageFileName` jest przybliżeniem. Driver nie sprawdza tej flagi.
- **Brak obsługi ARM64 w testach.** Konfiguracje ARM64 są w projekcie, ale
  budowany i sprawdzany był tylko x64.

---

## 10. Mapowanie na wymagania projektu

Etap 2 odpowiada punktowi „blokowanie" z README etapu 1 i realizuje
przeciwdziałanie technikom trwałości z tabeli MITRE: T1547.001, T1547.004,
T1037.001, T1543.003, T1053.005. Niezależnie od tego, w którym źródle
autostartu znalazł się wpis, blokada działa w jednym miejscu - przy próbie
uruchomienia procesu.
