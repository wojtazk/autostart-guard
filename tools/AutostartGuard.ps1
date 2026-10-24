<#
.SYNOPSIS
    AutostartGuard - skaner autostartu (etap 1) + orkiestracja blokowania (etap 2).

.DESCRIPTION
    Enumeruje punkty automatycznego uruchamiania w Windows, buduje baseline,
    porownuje stan biezacy z baseline'em i zapisuje strukturalny diff do alerts/.

    Akcja Watch (uruchamiana przy logowaniu) realizuje docelowy scenariusz:
    kazdy NOWY wpis (poza baseline i allowlista) jest domyslnie BLOKOWANY,
    a uzytkownik dostaje okno z wyborem Zablokuj / Uruchom / Pokaz. Decyzje sa
    egzekwowane przez driver (enforce wlaczany automatycznie).

    Zrodla: runKeys, shellFolders, singleValues, startupFolders, services,
    scheduledTasks. MITRE: T1547.001, T1547.004, T1037.001, T1543.003, T1053.005.

.PARAMETER Action
    Baseline - zbiera stan i zapisuje baseline.json (nadpisuje)
    Scan     - porownuje z baseline.json, zapisuje alert gdy sa zmiany
    Watch    - jak Scan + blokuje nowe wpisy i pyta uzytkownika (logowanie)
    Show     - wypisuje zebrany stan (nic nie zapisuje)

.PARAMETER DataPath
    Folder roboczy (baseline.json, allowlist.json, alerts/, blocked-paths.txt).
    Domyslnie <folder programu>\data (obok folderu tools).

.PARAMETER Notify
    Pokazuje interakcje z uzytkownikiem (okno decyzji w Watch, dymek w Scan).

.EXAMPLE
    .\AutostartGuard.ps1 -Action Baseline
    .\AutostartGuard.ps1 -Action Watch -Notify

.NOTES
    Pelen odczyt HKLM/uslug/zadan oraz blokowanie wymaga uprawnien administratora.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Baseline', 'Scan', 'Watch', 'Show')]
    [string] $Action,

    # Domyslnie <app>\data - obok folderu tools, w ktorym lezy ten skrypt.
    [string] $DataPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\data')),

    [switch] $Notify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AutostartGuard.Core.ps1')

if (-not (Test-Path -LiteralPath $DataPath)) { New-Item -ItemType Directory -Path $DataPath -Force | Out-Null }
$baselineFile = Join-Path $DataPath 'baseline.json'
$allowFile    = Join-Path $DataPath 'allowlist.json'
$alertsDir    = Join-Path $DataPath 'alerts'
$blockedFile  = Join-Path $DataPath 'blocked-paths.txt'
$ctlScript    = Join-Path $PSScriptRoot 'AutostartGuardCtl.ps1'

if (-not (Test-Admin)) {
    Write-Warning 'Uruchomiono bez uprawnien administratora - czesc HKLM / uslug / zadan moze zostac pominieta, a blokowanie nie zadziala.'
}

Write-Host 'Zbieram stan autostartu...'
$current = Get-CurrentState

$counts = (($EnumCategories + $ValueCategories) | ForEach-Object { "$_=$(@($current.$_).Count)" }) -join ', '
Write-Host "Zebrano: $counts"
if (@($current.skipped).Count -gt 0) {
    Write-Warning "Pominieto $(@($current.skipped).Count) zrodel (brak uprawnien/dostepu)."
}

function Get-Baseline {
    if (-not (Test-Path -LiteralPath $baselineFile)) {
        throw "Brak baseline.json w $DataPath. Uruchom najpierw: -Action Baseline"
    }
    return Get-Content -LiteralPath $baselineFile -Raw | ConvertFrom-Json
}

switch ($Action) {

    'Show' { $current | ConvertTo-Json -Depth 6 }

    'Baseline' {
        $current | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $baselineFile -Encoding UTF8
        Write-Host "Zapisano baseline: $baselineFile"
    }

    'Scan' {
        $baseline = Get-Baseline
        $allow = @(Get-AgAllowed -AllowFile $allowFile)
        $changes = @(Compare-State -Baseline $baseline -Current $current -Allow $allow)

        if ($changes.Count -eq 0) { Write-Host 'Brak zmian wzgledem baseline. Alert nie powstaje.'; return }

        $alertFile = Write-AgAlert -Changes $changes -Current $current -Baseline $baseline -AlertsDir $alertsDir -DataPath $DataPath
        $byType = $changes | Group-Object type | ForEach-Object { "$($_.Name)=$($_.Count)" }
        Write-Host "WYKRYTO zmiany ($($changes.Count)): $($byType -join ', ')"
        Write-Host "Alert zapisany: $alertFile"

        if ($Notify) {
            $new = @($changes | Where-Object { $_.type -eq 'new' })
            $msg = "Wykryto $($changes.Count) zmian w autostarcie ($($byType -join ', '))."
            if ($new.Count -gt 0) {
                $names = @($new | ForEach-Object { $_.id -replace '.*\|', '' }) | Select-Object -First 3
                $msg += "`nNowe: " + ($names -join ', ')
            }
            $msg += "`nSzczegoly: $alertFile"
            Show-AgNotification -Title 'AutostartGuard - zmiany w autostarcie' -Message $msg
        }
    }

    'Watch' {
        # Docelowy scenariusz: nowe wpisy blokowane domyslnie, uzytkownik decyduje.
        $baseline = Get-Baseline
        $allow = @(Get-AgAllowed -AllowFile $allowFile)
        $changes = @(Compare-State -Baseline $baseline -Current $current -Allow $allow)

        # Lista blokowanych sciezek - zrodlo prawdy dla drivera (plik tekstowy).
        $blocked = @()
        if (Test-Path -LiteralPath $blockedFile) {
            $blocked = @(Get-Content -LiteralPath $blockedFile | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
        }

        $new = @($changes | Where-Object { $_.type -eq 'new' })

        if ($changes.Count -gt 0) {
            $alertFile = Write-AgAlert -Changes $changes -Current $current -Baseline $baseline -AlertsDir $alertsDir -DataPath $DataPath
            Write-Host "WYKRYTO $($changes.Count) zmian; nowych wpisow: $($new.Count)"

            foreach ($c in $new) {
                $target = Get-ChangeTarget -Change $c
                $name = $c.id -replace '.*\|', ''

                # Domyslnie blokuj (dopisz sciezke do listy blokad).
                if ($target -and ($blocked -notcontains $target)) { $blocked += $target }

                $choice = if ($Notify) { Show-AgDecision -EntryName $name -TargetPath $target -AlertFile $alertFile } else { 'block' }

                if ($choice -eq 'run') {
                    if ($target) { $blocked = @($blocked | Where-Object { $_ -ne $target }) }
                    Add-AgAllowEntry -AllowFile $allowFile -Id $c.id -Note 'Zatwierdzone przez uzytkownika (Uruchom)'
                    Write-Host "  [URUCHOM]  $name -> dodano do allowlisty"
                    if ($target -and (Test-Path -LiteralPath $target)) {
                        try { Start-Process -FilePath $target } catch { Write-Warning "Nie udalo sie uruchomic: $target" }
                    }
                }
                else {
                    Write-Host "  [ZABLOKUJ] $name"
                }
            }
        }
        else {
            Write-Host 'Brak nowych wpisow.'
        }

        # Zapisz liste blokad (zrodlo prawdy) i zsynchronizuj z driverem (enforce).
        $blocked = @($blocked | Select-Object -Unique)
        Set-Content -LiteralPath $blockedFile -Encoding UTF8 -Value (@('# Sciezki blokowane przez AutostartGuard (zarzadzane automatycznie)') + $blocked)

        if (Test-Path -LiteralPath $ctlScript) {
            try {
                & $ctlScript -Action Sync -BlockedFile $blockedFile
            }
            catch { Write-Warning "Synchronizacja z driverem nieudana (czy driver dziala?): $($_.Exception.Message)" }
        }
        else {
            Write-Warning "Nie znaleziono $ctlScript - pominieto synchronizacje z driverem."
        }
    }
}
