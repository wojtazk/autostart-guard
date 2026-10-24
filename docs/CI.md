# CI / build automatyczny (GitHub Actions)

Workflow: [`.github/workflows/build-driver.yml`](../.github/workflows/build-driver.yml).

Buduje sterownik (etap 2) na runnerze Windows, podpisuje certyfikatem testowym,
pakuje instalator i — przy tagu `vX.Y.Z` — wrzuca wszystko do GitHub Releases.

---

## Kiedy się uruchamia

| Wyzwalacz | Co robi |
|---|---|
| `push` taga `v*` (np. `v1.0.0`) | pełny build + **utworzenie Release** z artefaktami |
| ręczne „Run workflow" (workflow_dispatch) | build + artefakty w zakładce Actions (bez Release) |

### Jak wydać wersję

```bash
git tag v1.0.0
git push origin v1.0.0
```

Workflow zbuduje i opublikuje Release `AutostartGuard v1.0.0`.

---

## Co produkuje (artefakty / assety Release)

| Plik | Opis |
|---|---|
| `AutostartGuard-Setup-<wersja>.exe` | instalator Inno Setup (kopiuje pliki, importuje cert, rejestruje usługę) |
| `AutostartGuard-<wersja>-portable.zip` | wersja „portable": `.sys`, `.cer`, skrypty, dokumentacja |
| `process_filter.cer` | certyfikat testowy, którym podpisano ten build |

---

## Kroki pipeline

1. **Testy etapu 1** — `tools/tests/AutostartGuard.Tests.ps1` jako gate (pwsh jest na runnerze).
2. **Setup MSBuild** — `microsoft/setup-msbuild`.
3. **Instalacja WDK 10.0.22621** — `choco install windowsdriverkit11` (z integracją VS, czyli toolset `WindowsKernelModeDriver10.0`).
4. **Build** — `msbuild process_filter.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off`.
5. **Podpis testowy** — generujemy certyfikat (`New-SelfSignedCertificate`), podpisujemy `.sys` (`signtool`), eksportujemy `.cer`.
6. **Instalator** — `ISCC.exe installer\process_filter.iss`.
7. **Portable zip** + **upload artefaktów**.
8. **Release** (tylko na tagu) — `softprops/action-gh-release`.

---

## Podpis testowy — co to znaczy

Driver jest podpisany **certyfikatem testowym generowanym przy każdym buildzie**
(inny przy każdym Release). To wystarcza do PoC, ale:

- maszyna docelowa musi być w trybie **test signing**:
  `bcdedit /set testsigning on` + restart (instalator robi to jako opcję),
- certyfikat trzeba **zaufać** — instalator importuje `.cer` do `Root`
  i `TrustedPublisher`; wersja portable wymaga ręcznego `certutil -addstore`.

To NIE jest podpis produkcyjny (brak EV / atestacji Microsoftu). Driver nie
załaduje się na normalnej maszynie bez test signing — i tak ma być, to projekt
na zajęcia. **Testować wyłącznie na maszynie wirtualnej ze snapshotem.**

---

## Dostrajanie wersji WDK/SDK

`WindowsTargetPlatformVersion` w `process_filter.vcxproj` jest przypięte do
`10.0.22621.0`. Workflow instaluje WDK w tej samej wersji i przekazuje ją do
`msbuild`. Jeśli zmienisz wersję WDK:

- zaktualizuj `WindowsTargetPlatformVersion` w `.vcxproj`,
- zaktualizuj `env.SDK_VERSION` w workflow,
- upewnij się, że paczka choco instaluje odpowiedni WDK.

---

## Plan B: EWDK (gdy integracja VS zawiedzie)

Jeśli `choco install windowsdriverkit11` nie zintegruje toolsetu z Visual
Studio (build zgłosi brak `WindowsKernelModeDriver10.0`), alternatywą jest
**EWDK** — samodzielne, przenośne środowisko build (ISO z kompletem narzędzi,
nie wymaga instalacji VS). Szkic kroku:

```yaml
      - name: Build via EWDK
        shell: cmd
        run: |
          curl -L -o ewdk.iso "<link do EWDK ISO z Microsoft>"
          powershell -c "Mount-DiskImage -ImagePath ewdk.iso"
          call E:\LaunchBuildEnv.cmd
          msbuild process_filter.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off
```

Minus: ISO EWDK jest duże (kilkanaście GB) — trzeba sprawdzić, czy mieści się
na dysku runnera. Dlatego domyślnie używamy lżejszej ścieżki choco.

---

## Lokalny build (bez CI)

Wymagania: Visual Studio 2022 (C++) + WDK 10.0.22621.

```powershell
msbuild process_filter.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64
```

Pełna instrukcja, instalacja i scenariusz demo: [`DRIVER.md`](DRIVER.md).
