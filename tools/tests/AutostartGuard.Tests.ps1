<#
    Testy skanera AutostartGuard (bez Pester - czyste asercje).

    Co jest testowane TUTAJ (dziala na kazdej platformie):
      - parsowanie skladni wszystkich skryptow,
      - Resolve-TargetPath (ekstrakcja .exe z komendy),
      - Compare-State (new/changed/removed + allowlist),
      - kompatybilnosc formatu alertu z klientem drivera (AutostartGuardCtl.ps1).

    Czego NIE da sie przetestowac tutaj (wymaga Windows): realny odczyt rejestru,
    uslug i zadan - opisane w tests/README-testy.md jako testy na VM.

    Uruchomienie:  pwsh -File AutostartGuard.Tests.ps1
    Kod wyjscia 0 = wszystko OK, 1 = co najmniej jeden test nie przeszedl.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$toolsDir = Split-Path -Parent $PSScriptRoot
. (Join-Path $toolsDir 'AutostartGuard.Core.ps1')

$script:pass = 0; $script:fail = 0
function Assert($cond, $name) {
    if ($cond) { $script:pass++; Write-Host "  [OK]   $name" }
    else { $script:fail++; Write-Host "  [FAIL] $name" -ForegroundColor Red }
}

# --- 1. Parsowanie skladni ---------------------------------------- #
Write-Host "`n[1] Parsowanie skladni skryptow"
foreach ($f in 'AutostartGuard.ps1', 'AutostartGuard.Core.ps1', 'AutostartGuardCtl.ps1') {
    $path = Join-Path $toolsDir $f
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
    Assert ($errors.Count -eq 0) "$f parsuje sie bez bledow ($($errors.Count) bledow)"
}

# --- 2. Resolve-TargetPath ---------------------------------------- #
Write-Host "`n[2] Resolve-TargetPath"
Assert ((Resolve-TargetPath '"C:\Program Files\App\app.exe" /background') -eq 'C:\Program Files\App\app.exe') 'sciezka w cudzyslowach z argumentem'
Assert ((Resolve-TargetPath 'C:\Windows\System32\svchost.exe -k netsvcs') -eq 'C:\Windows\System32\svchost.exe') 'sciezka bez cudzyslowow z argumentem'
Assert ((Resolve-TargetPath 'C:\Users\Public\svc_update.exe') -eq 'C:\Users\Public\svc_update.exe') 'sama sciezka'
Assert ($null -eq (Resolve-TargetPath '   ')) 'pusta komenda -> null'

# --- 3. Compare-State --------------------------------------------- #
Write-Host "`n[3] Compare-State"

function New-MockEnum($id, $sha, $cmd = 'C:\x.exe') {
    [pscustomobject]@{ id = $id; command = $cmd; sha256 = $sha; targetPath = $cmd }
}
function New-MockState($runKeys = @(), $singleValues = @()) {
    [pscustomobject]@{
        runKeys = @($runKeys); startupFolders = @(); services = @(); scheduledTasks = @()
        shellFolders = @(); singleValues = @($singleValues)
    }
}

$base = New-MockState -runKeys @(New-MockEnum 'RunKey|HKCU|OneDrive' 'AAA')
$cur = New-MockState -runKeys @(
    (New-MockEnum 'RunKey|HKCU|OneDrive' 'AAA'),
    (New-MockEnum 'RunKey|HKCU|svc_update' 'BBB' 'C:\Users\Public\svc_update.exe')
)
$ch = @(Compare-State -Baseline $base -Current $cur -Allow @())
Assert ($ch.Count -eq 1 -and $ch[0].type -eq 'new' -and $ch[0].id -eq 'RunKey|HKCU|svc_update') 'wykrycie nowego wpisu'

# podmiana hasha (changed)
$cur2 = New-MockState -runKeys @(New-MockEnum 'RunKey|HKCU|OneDrive' 'ZZZ')
$ch2 = @(Compare-State -Baseline $base -Current $cur2 -Allow @())
Assert ($ch2.Count -eq 1 -and $ch2[0].type -eq 'changed') 'wykrycie podmiany (zmiana sha256)'

# usuniecie (removed)
$ch3 = @(Compare-State -Baseline $base -Current (New-MockState) -Allow @())
Assert ($ch3.Count -eq 1 -and $ch3[0].type -eq 'removed') 'wykrycie zniknietego wpisu'

# allowlist po sha256 - tlumi nowy wpis
$allowSha = @([pscustomobject]@{ id = 'RunKey|HKCU|svc_update'; sha256 = 'BBB' })
$ch4 = @(Compare-State -Baseline $base -Current $cur -Allow $allowSha)
Assert ($ch4.Count -eq 0) 'allowlist (sha256 zgodny) tlumi alert'

# allowlist po sha256 - inny hash NIE tlumi (podmiana pliku)
$allowShaBad = @([pscustomobject]@{ id = 'RunKey|HKCU|svc_update'; sha256 = 'XXX' })
$ch5 = @(Compare-State -Baseline $base -Current $cur -Allow $allowShaBad)
Assert ($ch5.Count -eq 1) 'allowlist (sha256 niezgodny) NIE tlumi alertu'

# allowlist matchBy=id - tlumi niezaleznie od hasha
$allowById = @([pscustomobject]@{ id = 'RunKey|HKCU|svc_update'; matchBy = 'id' })
$ch6 = @(Compare-State -Baseline $base -Current $cur -Allow $allowById)
Assert ($ch6.Count -eq 0) 'allowlist (matchBy=id) tlumi alert niezaleznie od sha256'

# singleValues - zmiana actual (np. hijack Winlogon Shell)
$baseSV = New-MockState -singleValues @([pscustomobject]@{ id = 'SingleValue|Winlogon|Shell'; actual = 'explorer.exe' })
$curSV = New-MockState -singleValues @([pscustomobject]@{ id = 'SingleValue|Winlogon|Shell'; actual = 'explorer.exe, C:\Users\Public\x.exe' })
$ch7 = @(Compare-State -Baseline $baseSV -Current $curSV -Allow @())
Assert ($ch7.Count -eq 1 -and $ch7[0].type -eq 'changed' -and $ch7[0].field -eq 'actual') 'wykrycie podmiany wartosci (Winlogon Shell)'

# --- 4. Kompatybilnosc formatu alertu z klientem drivera ---------- #
Write-Host "`n[4] Integracja: alert skanera -> klient drivera (DryRun)"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("agtest_" + [guid]::NewGuid().ToString('N'))
$alertsDir = Join-Path $tmp 'alerts'
New-Item -ItemType Directory -Path $alertsDir -Force | Out-Null

# Budujemy alert DOKLADNIE tak jak launcher: new (runKey) + changed (singleValue).
$curInt = New-MockState -runKeys @(New-MockEnum 'RunKey|HKCU|svc_update' 'BBB' 'C:\Users\Public\svc_update.exe') `
    -singleValues @([pscustomobject]@{ id = 'SingleValue|Winlogon|Shell'; actual = 'explorer.exe, C:\Users\Public\x.exe' })
$baseInt = New-MockState -singleValues @([pscustomobject]@{ id = 'SingleValue|Winlogon|Shell'; actual = 'explorer.exe' })
$changesInt = @(Compare-State -Baseline $baseInt -Current $curInt -Allow @())

$alert = [ordered]@{
    scanTime = (Get-Date).ToString('o'); hostname = 'TESTVM'
    baselineTime = (Get-Date).ToString('o'); changeCount = $changesInt.Count; changes = $changesInt
}
$alertFile = Join-Path $alertsDir 'alert_2026-10-13_09-00-00.json'
$alert | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $alertFile -Encoding UTF8

# Walidacja: plik jest poprawnym JSON-em i da sie wczytac z powrotem.
$reloaded = Get-Content -LiteralPath $alertFile -Raw | ConvertFrom-Json
Assert ($reloaded.changeCount -eq $changesInt.Count) 'alert to poprawny JSON (round-trip)'

# Uruchamiamy REALNEGO klienta drivera w trybie DryRun (bez admina, bez drivera).
$ctl = Join-Path $toolsDir 'AutostartGuardCtl.ps1'
$out = & pwsh -NoLogo -NoProfile -File $ctl -Action Load -AlertsPath $alertsDir -DryRun 2>&1 | Out-String

Assert ($out -match 'svc_update\.exe') 'klient drivera wyciaga targetPath nowego wpisu z alertu skanera'
Assert ($out -match 'DryRun') 'klient konczy w trybie DryRun (bez drivera)'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue

# --- Podsumowanie ------------------------------------------------- #
Write-Host "`n==================================="
Write-Host "Testy: PASS=$script:pass FAIL=$script:fail"
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
