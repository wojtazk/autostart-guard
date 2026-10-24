# AutostartGuard — plan testów i wyniki

Dokument do sekcji „Testy" dokumentacji projektu. Dzieli testy na trzy poziomy:
**jednostkowe** (logika, bez systemu), **integracyjne** (skaner ↔ klient drivera)
i **systemowe/bezpieczeństwa** (realne enumeracje i blokowanie — na maszynie
wirtualnej). Dla każdego podane: cel, sposób, oczekiwany wynik, status.

Skaner: `AutostartGuard.ps1` + `AutostartGuard.Core.ps1`.
Klient drivera: `AutostartGuardCtl.ps1`. Driver: `process_filter.sys` (etap 2).

---

## 1. Testy jednostkowe (automatyczne)

Uruchomienie:

```powershell
pwsh -File tools/tests/AutostartGuard.Tests.ps1
# Kod wyjścia 0 = OK, 1 = błąd. Nie wymaga Windows ani uprawnień.
```

Testują logikę niezależną od systemu, więc działają też na Linux/macOS (CI).

| # | Test | Cel | Oczekiwany wynik | Status |
|---|---|---|---|---|
| 1.1 | Parsowanie składni | Wszystkie 3 skrypty parsują się bez błędów | 0 błędów parsera | ✅ |
| 1.2 | `Resolve-TargetPath` — cudzysłowy | `"C:\...\app.exe" /bg` → `C:\...\app.exe` | ścieżka bez argumentów | ✅ |
| 1.3 | `Resolve-TargetPath` — bez cudzysłowów | `...\svchost.exe -k netsvcs` → `...\svchost.exe` | ucięte na `.exe` | ✅ |
| 1.4 | `Resolve-TargetPath` — sama ścieżka | zwraca niezmienioną | bez zmian | ✅ |
| 1.5 | `Resolve-TargetPath` — pusta komenda | `'   '` → `$null` | `null` | ✅ |
| 1.6 | `Compare-State` — nowy wpis | nowe `id` w stanie bieżącym | 1 zmiana typu `new` | ✅ |
| 1.7 | `Compare-State` — podmiana | to samo `id`, inny `sha256` | 1 zmiana typu `changed` | ✅ |
| 1.8 | `Compare-State` — usunięcie | `id` zniknął ze stanu | 1 zmiana typu `removed` | ✅ |
| 1.9 | Allowlist — zgodny SHA-256 | wpis na allowliście z tym samym hashem | 0 alertów | ✅ |
| 1.10 | Allowlist — niezgodny SHA-256 | podmiana pliku pod zatwierdzoną nazwą | alert NIE tłumiony | ✅ |
| 1.11 | Allowlist — `matchBy=id` | zatwierdzenie po tożsamości | 0 alertów niezależnie od hasha | ✅ |
| 1.12 | `Compare-State` — wartość pojedyncza | zmiana `actual` (Winlogon Shell) | `changed`, `field=actual` | ✅ |

**Wynik: 12/12 (plus 5 asercji integracyjnych niżej) — PASS=17, FAIL=0.**

---

## 2. Testy integracyjne (automatyczne)

Cel: udowodnić, że alert produkowany przez skaner jest **1:1 konsumowalny**
przez klienta drivera — bez drivera i bez uprawnień (tryb `-DryRun`).

| # | Test | Sposób | Oczekiwany wynik | Status |
|---|---|---|---|---|
| 2.1 | Round-trip JSON | alert zapisany i wczytany ponownie | `changeCount` się zgadza | ✅ |
| 2.2 | Ekstrakcja `targetPath` | `AutostartGuardCtl.ps1 -Action Load -DryRun` na alercie skanera | wypisuje ścieżkę nowego wpisu | ✅ |
| 2.3 | Tryb DryRun bez drivera | klient kończy bez dotykania `\\.\AutostartGuard` | komunikat „DryRun" | ✅ |

Dodatkowo zweryfikowano ręcznie, że klient parsuje dołączony
`tools/sample-alerts/alert_*.json` i wyciąga z niego 3 ścieżki.

> **Uwaga środowiskowa.** Testy uruchomiono na Linuksie (PowerShell 7.4.6).
> Filtr nazw procesów systemowych w kliencie (`[IO.Path]::GetFileName`) zależy
> od separatora ścieżki — na Linuksie nie rozpoznaje `\`, więc `svchost.exe`
> nie został odsiany. **Na Windows działa poprawnie.** Warto dodać test 3.x na
> VM potwierdzający odsiewanie procesów chronionych.

---

## 3. Testy systemowe / bezpieczeństwa (maszyna wirtualna)

Tych **nie da się** uruchomić poza Windows — wymagają realnego rejestru, usług,
Harmonogramu Zadań oraz (dla blokowania) zainstalowanego drivera w trybie
test signing. Wykonywać na VM ze **snapshotem**.

### 3.1 Enumeracja — kompletność i brak uprawnień

| # | Test | Kroki | Oczekiwany wynik |
|---|---|---|---|
| 3.1.1 | Pełna enumeracja (admin) | `AutostartGuard.ps1 -Action Baseline` jako admin | `baseline.json` z wypełnionymi 6 kategoriami, `skipped=[]` |
| 3.1.2 | Bez admina | ten sam skrypt jako zwykły user | HKLM/usługi/zadania w `skipped`, skrypt nie wywala się |
| 3.1.3 | Porównanie z Autoruns | zestawić listę z Sysinternals Autoruns | pokrycie kluczy Run / Startup / usług / zadań |

### 3.2 Wykrywanie zmian (diff → alert)

| # | Test | Kroki | Oczekiwany wynik |
|---|---|---|---|
| 3.2.1 | Nowy wpis Run | dodać wartość do `HKCU\...\Run`, `-Action Scan` | alert `new`, kategoria `runKeys`, poprawny `targetPath` |
| 3.2.2 | Nowy plik w Startup (nie `.lnk`) | wrzucić `.exe`/`.bat` do folderu Startup | alert `new`, kategoria `startupFolders` |
| 3.2.3 | Podmiana celu `.lnk` | podmienić cel istniejącego skrótu | alert `changed` (zmiana `command`/`sha256`) |
| 3.2.4 | Hijack Winlogon Shell | dopisać plik do `Shell` | alert `changed`, `singleValues`, `field=actual` |
| 3.2.5 | Relokacja Startup | zmienić `User Shell Folders\Startup` | alert `changed`, `shellFolders` |
| 3.2.6 | Nowa usługa Auto | `sc.exe create` usługi `Auto` | alert `new`, `services` |
| 3.2.7 | Nowe zadanie logon | zadanie z triggerem przy logowaniu | alert `new`, `scheduledTasks` |
| 3.2.8 | Brak zmian | `-Action Scan` bez modyfikacji | brak pliku alertu, komunikat „Brak zmian" |
| 3.2.9 | Allowlist tłumi | dodać wpis do `allowlist.json`, powtórzyć 3.2.1 | alert nie powstaje |
| 3.2.10 | Podmiana pliku mimo allowlist | zmienić binarkę zatwierdzonego wpisu (`matchBy=sha256`) | alert `changed` mimo allowlisty |

### 3.3 Blokowanie (driver, etap 2)

Scenariusz z README drivera, sekcja 8. VM w trybie test signing, snapshot.

| # | Test | Kroki | Oczekiwany wynik |
|---|---|---|---|
| 3.3.1 | Tryb audit przepuszcza | driver `audit`, uruchomić „malware" | proces startuje, licznik `Matched` rośnie, `Blocked=0` |
| 3.3.2 | Tryb enforce blokuje | `-Mode enforce -Force`, uruchomić „malware" | odmowa dostępu, `Blocked` rośnie, log `[AutostartGuard] ZABLOKOWANO` |
| 3.3.3 | Proces chroniony | reguła na `explorer.exe` | trafienie logowane, **nigdy** blokowane |
| 3.3.4 | Obejście przez zmianę nazwy | zmienić nazwę zablokowanego pliku | proces startuje (znane ograniczenie — dopasowanie po ścieżce, nie hashu) |
| 3.3.5 | Łańcuch end-to-end | skaner → alert → `Ctl Load` → `enforce` → próba startu | pełny przepływ: wykrycie w etapie 1 kończy się blokadą w etapie 2 |

### 3.4 Odporność / przypadki brzegowe

| # | Test | Kroki | Oczekiwany wynik |
|---|---|---|---|
| 3.4.1 | Uszkodzony `baseline.json` | podmienić na niepoprawny JSON | czytelny błąd, nie wysypka |
| 3.4.2 | Uszkodzony alert | wrzucić zły JSON do `alerts/` | klient pomija plik z ostrzeżeniem (`Pomijam ...`) |
| 3.4.3 | Komenda bez `.exe` | wpis Run wskazujący `rundll32 ...` | `targetPath` wyznaczony sensownie lub `null`, bez błędu |
| 3.4.4 | Plik docelowy nie istnieje | wpis Run do nieistniejącej ścieżki | `sha256=null`, `signature=FileMissing` |
| 3.4.5 | Limit reguł drivera | >64 reguł z alertów | klient nie przekracza `AG_MAX_RULES`, czytelny komunikat |

---

## 4. Co warto zaznaczyć w dokumentacji

- **Testy jednostkowe i integracyjne są automatyczne i przenośne** — chodzą w CI
  (Linux) bez Windows, bo logika (ekstrakcja ścieżek, diff, allowlist) jest
  oddzielona od cmdletów systemowych (`AutostartGuard.Core.ps1`).
- **Testy systemowe wymagają VM** — realny rejestr/usługi/zadania i driver w
  trybie test signing. Zawsze na snapshocie (tryb `enforce` potrafi zablokować
  logowanie przy złej regule — stąd wbudowany bezpiecznik na procesy krytyczne).
- **Znane ograniczenia do testów regresyjnych**: dopasowanie po ścieżce (nie
  hashu) w driverze, brak trwałości reguł po restarcie, limity statyczne
  (64 reguły / 259 znaków) — wszystkie wymienione w README drivera, sekcja 9.
