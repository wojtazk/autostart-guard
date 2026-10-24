# Anioł stróż autostartu (AutostartGuard)

[![build-driver](https://github.com/wojtazk/autostart-guard/actions/workflows/build-driver.yml/badge.svg)](https://github.com/wojtazk/autostart-guard/actions/workflows/build-driver.yml)

Narzędzie monitorujące automatyczne uruchamianie aplikacji w Windows i blokujące
podejrzane wpisy. Projekt dzieli się na dwa etapy:

- **Etap 1 — monitoring (PowerShell).** Enumeruje punkty autostartu, buduje
  baseline, wykrywa nowe/zmienione/usunięte wpisy i zapisuje strukturalny diff
  do `alerts/`. Działa samodzielnie.
- **Etap 2 — blokowanie (driver trybu jądra).** Sterownik przechwytuje tworzenie
  procesów i w trybie `enforce` odmawia uruchomienia plików z reguł. Reguły
  pochodzą z alertów etapu 1, wgrywane przez klienta user mode.

> **To projekt na zajęcia, nie produkt.** Tryb `enforce` realnie blokuje
> uruchamianie procesów — testować wyłącznie na maszynie wirtualnej ze snapshotem.

---

## Jak to się spina

```
┌─ ETAP 1 (user mode) ──────────────┐     ┌─ ETAP 2 (kernel) ───────────┐
│ AutostartGuard.ps1                │     │ process_filter.sys          │
│   enumeracja 6 źródeł             │     │   callback na tworzenie     │
│   → baseline.json                 │     │   procesu                   │
│   → diff → alerts/*.json          │     │   płaska lista reguł        │
└───────────────┬───────────────────┘     └──────────────▲──────────────┘
                │ alerts/*.json                          │ IOCTL (DeviceIoControl)
                │                                        │
                └──────────► AutostartGuardCtl.ps1 ──────┘
                             czyta alerty, wyciąga targetPath,
                             wgrywa reguły do drivera
```

Driver świadomie **nie** czyta `alerts/` ani nie parsuje JSON-a (tryb jądra nie
ma do tego bibliotek, a operacje na plikach z kontekstu callbacku grożą
zakleszczeniem). Polityka żyje w user mode, egzekucja w jądrze.

---

## Źródła autostartu (etap 1)

Sześć kategorii, każda zwraca ten sam wspólny obiekt:

| Kategoria | Co obejmuje | MITRE ATT&CK |
|---|---|---|
| `runKeys` | klucze Run/RunOnce/RunServices/Policies (HKCU+HKLM, Wow6432Node) | T1547.001 |
| `shellFolders` | relokacja folderu Startup (User Shell Folders) | T1547.001 |
| `singleValues` | Winlogon Shell/Userinit, load, UserInitMprLogonScript, BootExecute | T1547.004, T1037.001 |
| `startupFolders` | pliki w folderach Startup (nie tylko `.lnk`) | T1547.001 |
| `services` | usługi z `StartMode=Auto` | T1543.003 |
| `scheduledTasks` | zadania z triggerem logon/boot | T1053.005 |

Szczegółowy opis kluczy, formatów `baseline.json` / `allowlist.json` / alertów:
[`docs/reference.md`](docs/reference.md). Schemat działania: [`docs/schemat.svg`](docs/schemat.svg).

---

## Szybki start

### Etap 1 — monitoring (wystarczy PowerShell 5.1+ / 7+, do pełnego skanu admin)

```powershell
cd tools

# 1. Zbuduj baseline (stan odniesienia)
.\AutostartGuard.ps1 -Action Baseline

# 2. Skanuj — alert powstaje tylko, jeśli coś się zmieniło
.\AutostartGuard.ps1 -Action Scan
#    → ..\autostart-guard\alerts\alert_<timestamp>.json
```

Folder roboczy (`baseline.json`, `allowlist.json`, `alerts/`) domyślnie
`.\autostart-guard`; zmienia go `-DataPath`.

### Etap 2 — blokowanie (VM w trybie test signing, jako administrator)

Gotowy driver + instalator pobierzesz z [**Releases**](../../releases) (budowane
automatycznie — patrz niżej). Build lokalny, instalacja i pełny scenariusz
demonstracyjny: [`docs/DRIVER.md`](docs/DRIVER.md).

```powershell
cd tools

# podgląd, co zostałoby wgrane (bez drivera, bez admina)
.\AutostartGuardCtl.ps1 -Action Load -AlertsPath ..\autostart-guard\alerts -DryRun

# wgranie reguł i włączenie blokowania
.\AutostartGuardCtl.ps1 -Action Load -AlertsPath ..\autostart-guard\alerts
.\AutostartGuardCtl.ps1 -Action Mode -Mode enforce -Force
```

---

## Testy

```powershell
pwsh -File tools/tests/AutostartGuard.Tests.ps1
```

Testy jednostkowe i integracyjne (logika, format alertów) — przenośne, działają
też na Linux/macOS w CI, bez Windows. Plan testów i scenariusze systemowe na VM:
[`docs/testy.md`](docs/testy.md).

---

## Automatyczny build i Releases (GitHub Actions)

Driver budowany jest automatycznie na runnerze Windows: instalacja WDK,
kompilacja (`Release|x64`), podpis certyfikatem testowym, instalator i upload do
Releases. Workflow: [`.github/workflows/build-driver.yml`](.github/workflows/build-driver.yml),
szczegóły: [`docs/CI.md`](docs/CI.md).

Wydanie wersji:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Release dostaje: instalator `AutostartGuard-Setup-<wersja>.exe`, wersję portable
`.zip` oraz `process_filter.cer`. Driver jest podpisany **certyfikatem testowym**
— maszyna docelowa musi mieć włączony tryb test signing (robi to instalator).
Testować wyłącznie na VM ze snapshotem.

---

## Układ repozytorium

```
.
├── README.md                       # ten plik
├── .github/workflows/
│   └── build-driver.yml            # CI: build drivera + Release
├── installer/
│   └── process_filter.iss          # instalator Inno Setup
├── docs/
│   ├── reference.md                # źródła, formaty JSON, mapowanie MITRE
│   ├── schemat.svg                 # schemat przepływu (etap 1 + etap 2)
│   ├── testy.md                    # plan testów i wyniki
│   ├── CI.md                       # opis pipeline, test signing, plan B (EWDK)
│   └── DRIVER.md                   # etap 2: build, instalacja, użycie drivera
├── tools/
│   ├── AutostartGuard.ps1          # skaner (launcher)
│   ├── AutostartGuard.Core.ps1     # skaner (funkcje, testowalne osobno)
│   ├── AutostartGuardCtl.ps1       # klient drivera (most etap 1 ↔ etap 2)
│   ├── sample-alerts/              # przykładowy alert do testu bez drivera
│   └── tests/
│       └── AutostartGuard.Tests.ps1
├── driver.c                        # sterownik (cały)
├── agctl.h                         # kontrakt kernel ↔ user mode
├── process_filter.sln
├── process_filter.vcxproj
└── process_filter.vcxproj.filters
```

Build sterownika wymaga Visual Studio 2022 + WDK; artefakty (`x64/`, `*.sys`,
`*.obj`, `*.pdb`) nie są wersjonowane — patrz `.gitignore`.

---

## Ograniczenia (świadome uproszczenia PoC)

- Dopasowanie reguł w driverze po ścieżce, nie po hashu — zmiana nazwy pliku
  obchodzi regułę.
- Brak trwałości reguł po restarcie (w praktyce: zadanie w Harmonogramie).
- Driver: domyślny deskryptor bezpieczeństwa, brak samoochrony, limity statyczne
  (64 reguły / 259 znaków).

Pełna lista: `docs/DRIVER.md`, sekcja „Ograniczenia".
