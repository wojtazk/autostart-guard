<#
.SYNOPSIS
    Rejestruje zadania AutostartGuard w Harmonogramie (zwykle wywolywany przez
    instalator, mozna tez recznie).

.DESCRIPTION
    Tworzy dwa zadania:

      1. "AutostartGuard Watch (logon)"  - przy KAZDYM logowaniu, w kontekscie
         zalogowanego uzytkownika z najwyzszymi uprawnieniami. Uruchamia
         AutostartGuard.ps1 -Action Watch -Notify: wykrywa nowe wpisy, blokuje
         je domyslnie i pokazuje okno Zablokuj / Uruchom / Pokaz.

      2. "AutostartGuard Sync (boot)"    - przy starcie systemu, jako SYSTEM.
         Uruchamia AutostartGuardCtl.ps1 -Action Sync: wgrywa zapisana liste
         blokad do drivera i wlacza enforce JESZCZE przed zalogowaniem, zeby
         znane zle wpisy byly blokowane juz przy starcie.

    Sciezki sa wyliczane z polozenia tego skryptu (folder tools), wiec instalator
    nie musi nic podawac. Dane: <app>\data.

.PARAMETER DataPath
    Folder danych. Domyslnie <app>\data (obok folderu tools).

.EXAMPLE
    .\Install-Tasks.ps1

.NOTES
    Uruchom jako administrator. Usuniecie obu zadan:
        Unregister-ScheduledTask -TaskName 'AutostartGuard Watch (logon)' -Confirm:$false
        Unregister-ScheduledTask -TaskName 'AutostartGuard Sync (boot)'  -Confirm:$false
#>

[CmdletBinding()]
param(
    [string] $DataPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\data'))
)

$ErrorActionPreference = 'Stop'

$scanner = Join-Path $PSScriptRoot 'AutostartGuard.ps1'
$ctl     = Join-Path $PSScriptRoot 'AutostartGuardCtl.ps1'
foreach ($f in $scanner, $ctl) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Nie znaleziono $f" }
}

if (-not (Test-Path -LiteralPath $DataPath)) { New-Item -ItemType Directory -Path $DataPath -Force | Out-Null }
$blockedFile = Join-Path $DataPath 'blocked-paths.txt'

if (-not (Test-Path -LiteralPath (Join-Path $DataPath 'baseline.json'))) {
    Write-Warning "Brak baseline.json w $DataPath. Zrob najpierw: .\AutostartGuard.ps1 -Action Baseline"
}

# --- 1. Zadanie przy logowaniu: Watch (wykryj + blokuj + zapytaj) --- #
$watchArg = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Action Watch -DataPath "{1}" -Notify' -f $scanner, $DataPath
$watchAction  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $watchArg
$watchTrigger = New-ScheduledTaskTrigger -AtLogOn
$watchPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$watchSettings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName 'AutostartGuard Watch (logon)' -Action $watchAction -Trigger $watchTrigger `
    -Principal $watchPrincipal -Settings $watchSettings -Force | Out-Null
Write-Host "Zarejestrowano: 'AutostartGuard Watch (logon)'"

# --- 2. Zadanie przy starcie systemu: Sync (enforce wczesnie) ------- #
$syncArg = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Action Sync -BlockedFile "{1}"' -f $ctl, $blockedFile
$syncAction  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $syncArg
$syncTrigger = New-ScheduledTaskTrigger -AtStartup
$syncPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$syncSettings  = New-ScheduledTaskSettingsSet -StartWhenAvailable
Register-ScheduledTask -TaskName 'AutostartGuard Sync (boot)' -Action $syncAction -Trigger $syncTrigger `
    -Principal $syncPrincipal -Settings $syncSettings -Force | Out-Null
Write-Host "Zarejestrowano: 'AutostartGuard Sync (boot)'"

Write-Host ''
Write-Host 'Gotowe. Test bez restartu:'
Write-Host "  Start-ScheduledTask -TaskName 'AutostartGuard Watch (logon)'"
