<#
.SYNOPSIS
    AutostartGuard - skaner autostartu (etap 1 projektu).

.DESCRIPTION
    Enumeruje punkty automatycznego uruchamiania w Windows, buduje baseline,
    porownuje stan biezacy z baseline'em i zapisuje strukturalny diff do
    folderu alerts/. Pliki alert_*.json sa konsumowane przez klienta drivera
    (AutostartGuardCtl.ps1, etap 2), ktory wyciaga z nich targetPath.

    Zrodla: runKeys, shellFolders, singleValues, startupFolders, services,
    scheduledTasks. Mapowanie MITRE: T1547.001, T1547.004, T1037.001,
    T1543.003, T1053.005.

    Funkcje skanera zyja w AutostartGuard.Core.ps1 (dot-source ponizej), zeby
    dalo sie je testowac osobno.

.PARAMETER Action
    Baseline - zbiera stan i zapisuje baseline.json (nadpisuje)
    Scan     - porownuje z baseline.json, zapisuje alert gdy sa zmiany
    Show     - wypisuje zebrany stan (nic nie zapisuje)

.PARAMETER DataPath
    Folder roboczy: baseline.json, allowlist.json, alerts/ (domyslnie .\autostart-guard).

.EXAMPLE
    .\AutostartGuard.ps1 -Action Baseline
    .\AutostartGuard.ps1 -Action Scan

.NOTES
    Pelen odczyt HKLM, uslug i zadan wymaga uprawnien administratora. Bez nich
    niedostepne zrodla trafiaja do pola "skipped", zamiast byc po cichu pomijane.
    Cmdlety sa Windows-only.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Baseline', 'Scan', 'Show')]
    [string] $Action,

    [string] $DataPath = (Join-Path (Get-Location) 'autostart-guard')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'AutostartGuard.Core.ps1')

if (-not (Test-Path -LiteralPath $DataPath)) { New-Item -ItemType Directory -Path $DataPath -Force | Out-Null }
$baselineFile = Join-Path $DataPath 'baseline.json'
$allowFile = Join-Path $DataPath 'allowlist.json'
$alertsDir = Join-Path $DataPath 'alerts'

if (-not (Test-Admin)) {
    Write-Warning 'Uruchomiono bez uprawnien administratora - czesc HKLM / uslug / zadan moze zostac pominieta (pole "skipped").'
}

Write-Host 'Zbieram stan autostartu...'
$current = Get-CurrentState

$counts = (($EnumCategories + $ValueCategories) | ForEach-Object { "$_=$(@($current.$_).Count)" }) -join ', '
Write-Host "Zebrano: $counts"
if (@($current.skipped).Count -gt 0) {
    Write-Warning "Pominieto $(@($current.skipped).Count) zrodel (brak uprawnien/dostepu)."
}

switch ($Action) {

    'Show' { $current | ConvertTo-Json -Depth 6 }

    'Baseline' {
        $current | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $baselineFile -Encoding UTF8
        Write-Host "Zapisano baseline: $baselineFile"
    }

    'Scan' {
        if (-not (Test-Path -LiteralPath $baselineFile)) {
            throw "Brak baseline.json w $DataPath. Uruchom najpierw: -Action Baseline"
        }
        $baseline = Get-Content -LiteralPath $baselineFile -Raw | ConvertFrom-Json

        $allow = @()
        if (Test-Path -LiteralPath $allowFile) {
            try {
                $allowJson = Get-Content -LiteralPath $allowFile -Raw | ConvertFrom-Json
                if (@($allowJson.PSObject.Properties.Name) -contains 'allowed') { $allow = @($allowJson.allowed) }
            }
            catch { Write-Warning "Niepoprawny allowlist.json - pomijam: $($_.Exception.Message)" }
        }

        $changes = @(Compare-State -Baseline $baseline -Current $current -Allow $allow)

        if ($changes.Count -eq 0) {
            Write-Host 'Brak zmian wzgledem baseline. Alert nie powstaje.'
            return
        }

        $now = Get-Date
        $alert = [ordered]@{
            scanTime     = $now.ToString('o')
            hostname     = $current.hostname
            baselineTime = $baseline.generatedAt
            changeCount  = $changes.Count
            changes      = $changes
        }

        if (-not (Test-Path -LiteralPath $alertsDir)) { New-Item -ItemType Directory -Path $alertsDir -Force | Out-Null }
        $stamp = $now.ToString('yyyy-MM-dd_HH-mm-ss')
        $alertFile = Join-Path $alertsDir "alert_$stamp.json"
        $alert | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $alertFile -Encoding UTF8

        $byType = $changes | Group-Object type | ForEach-Object { "$($_.Name)=$($_.Count)" }
        Write-Host "WYKRYTO zmiany ($($changes.Count)): $($byType -join ', ')"
        Write-Host "Alert zapisany: $alertFile"

        $logLine = "[$($now.ToString('yyyy-MM-dd HH:mm:ss'))] $($changes.Count) zmian: $($byType -join ', ')"
        Add-Content -LiteralPath (Join-Path $DataPath 'alerts.log') -Value $logLine
    }
}
