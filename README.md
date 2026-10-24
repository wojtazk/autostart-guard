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
│ AutostartGuard.ps1 (Watch)        │     │ process_filter.sys          │
│   enumeracja 6 źródeł             │     │   callback na tworzenie     │
│   → baseline.json                 │     │   procesu                   │
│   → diff → alerts/*.json          │     │   płaska lista reguł        │
│   → decyzja + blocked-paths.txt   │     │                             │
└───────────────┬───────────────────┘     └──────────────▲──────────────┘
                │ blocked-paths.txt                      │ IOCTL (DeviceIoControl)
                │                                        │
                └──────────► AutostartGuardCtl.ps1 ──────┘
                             Sync: czyści reguły, wgrywa listę
                             blokad do drivera i włącza enforce
```

Driver świadomie **nie** czyta plików ani nie parsuje JSON-a (tryb jądra nie
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

## Jak to działa przy autostarcie

Po zainstalowaniu i zbudowaniu baseline cały scenariusz dzieje się sam:

1. **Przy starcie systemu** — driver ładuje się jako usługa jądra, a zadanie
   `Sync` wgrywa zapisaną listę blokad i włącza **enforce** (blokowanie aktywne
   jeszcze przed logowaniem).
2. **Przy logowaniu** — zadanie `Watch` skanuje autostart względem baseline
   i allowlisty. **Każdy nowy wpis (spoza baseline i allowlisty) jest domyślnie
   blokowany**, a Ty dostajesz okno z wyborem:
   - **Zablokuj** — zostaje zablokowany (reguła trafia do drivera),
   - **Uruchom** — dodaj do allowlisty i uruchom teraz (nie będzie już blokowany);
     domyślnie przypięte do **sha256**, więc podmiana pliku pod tą samą nazwą
     znów zaalarmuje (`-AllowMode id`, gdy program często się aktualizuje),
   - **Pokaż** — otwiera plik różnicy (`alert_*.json`) w Notatniku.

   Okna nie da się zamknąć bez decyzji. Wpisy z **ważnym podpisem Microsoftu**
   (np. svchost) są auto-zezwalane bez pytania.

Driver egzekwuje decyzje: blokuje tworzenie procesu dla ścieżek z listy blokad.

## Szybki start

### Zainstaluj i zbuduj baseline (VM w trybie test signing, jako administrator)

Pobierz instalator z [**Releases**](../../releases) i uruchom. Instalator sam
rejestruje usługę sterownika oraz zadania (logowanie / start systemu), a dane
trzyma w `<folder programu>\data`. Został jeden krok — **baseline**:

```powershell
cd "C:\Program Files\AutostartGuard\tools"
.\AutostartGuard.ps1 -Action Baseline
sc.exe start AutostartGuard
```

Od teraz działa automatycznie (patrz „Jak to działa przy autostarcie").
Build lokalny drivera i scenariusz demonstracyjny: [`docs/DRIVER.md`](docs/DRIVER.md).

### Ręcznie / do testów

```powershell
cd tools

# jednorazowy skan z powiadomieniem (to samo, co robi zadanie Watch)
.\AutostartGuard.ps1 -Action Watch -Notify

# tylko wykrywanie, bez blokowania
.\AutostartGuard.ps1 -Action Scan

# rejestracja zadań ręcznie (gdy nie używasz instalatora)
.\Install-Tasks.ps1
```

Folder roboczy (`baseline.json`, `allowlist.json`, `alerts/`, `blocked-paths.txt`)
domyślnie `<folder programu>\data`; zmienia go `-DataPath`.

---

## Testy

```powershell
pwsh -File tools/tests/AutostartGuard.Tests.ps1
```

Testy jednostkowe i integracyjne (logika, format alertów) — przenośne, działają
też na Linux/macOS w CI, bez Windows. Plan testów i scenariusze systemowe na VM:
[`docs/testy.md`](docs/testy.md), ręczne scenariusze: [`docs/testy-reczne.md`](docs/testy-reczne.md).

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
│   ├── testy-reczne.md             # scenariusze testów ręcznych na VM
│   ├── CI.md                       # opis pipeline, test signing, plan B (EWDK)
│   └── DRIVER.md                   # etap 2: build, instalacja, użycie drivera
├── tools/
│   ├── AutostartGuard.ps1          # skaner + Watch (launcher)
│   ├── AutostartGuard.Core.ps1     # funkcje skanera + GUI decyzji (testowalne)
│   ├── AutostartGuardCtl.ps1       # klient drivera (Load / Sync / Mode / Status)
│   ├── Install-Tasks.ps1           # rejestracja zadań: Watch (logon) + Sync (boot)
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

<!-- ## Ograniczenia (świadome uproszczenia PoC)

- Dopasowanie reguł w driverze po ścieżce, nie po hashu — zmiana nazwy pliku
  obchodzi regułę.
- Blokowanie opiera się na podpisie binarki, nie argumentów — technika
  "living off the land" (podpisany svchost z wrogimi parametrami) przechodzi.
- Brak trwałości reguł po restarcie (w praktyce: zadanie w Harmonogramie).
- Driver: domyślny deskryptor bezpieczeństwa, brak samoochrony, limity statyczne
  (64 reguły / 259 znaków).

Pełna lista: `docs/DRIVER.md`, sekcja „Ograniczenia".
-->
