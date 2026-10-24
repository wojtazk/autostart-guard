<#
.SYNOPSIS
    Klient user mode dla drivera AutostartGuard (etap 2 projektu).

.DESCRIPTION
    Most miedzy etapem 1 (monitoring w PowerShellu, folder alerts/) a etapem 2
    (blokowanie w trybie jadra). Tutaj dzieje sie cala "brudna" robota:
    parsowanie JSON-a, chodzenie po dysku, normalizacja sciezek. Driver dostaje
    tylko gotowa, plaska liste sciezek przez DeviceIoControl.

    Taki podzial jest celowy - parsowanie JSON-a w trybie jadra to proszenie
    sie o BSOD-a, a kernel nie ma do tego zadnych bibliotek.

.PARAMETER Action
    Status  - wypisuje tryb pracy, liczbe regul i liczniki z drivera
    Load    - czyta alerts/*.json i wgrywa targetPath jako reguly
    Clear   - usuwa wszystkie reguly z drivera
    Mode    - ustawia tryb pracy (-Mode off|audit|enforce)

.PARAMETER AlertsPath
    Folder z plikami alert_*.json (domyslnie .\alerts).

.PARAMETER Mode
    off | audit | enforce

.PARAMETER Force
    Wymagane do wlaczenia trybu enforce - tryb ten faktycznie blokuje
    uruchamianie programow.

.EXAMPLE
    .\AutostartGuardCtl.ps1 -Action Status

.EXAMPLE
    .\AutostartGuardCtl.ps1 -Action Load -AlertsPath C:\ag\alerts
    .\AutostartGuardCtl.ps1 -Action Mode -Mode enforce -Force

.NOTES
    Wymaga uprawnien administratora - urzadzenie drivera ma domyslny
    deskryptor bezpieczenstwa, ktory daje prawo zapisu tylko administratorom
    i koncie SYSTEM.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Status', 'Load', 'Clear', 'Mode', 'Sync')]
    [string] $Action,

    [string] $AlertsPath = (Join-Path (Get-Location) 'alerts'),

    [ValidateSet('off', 'audit', 'enforce')]
    [string] $Mode,

    # Dla akcji Sync: plik z blokowanymi sciezkami (jedna na linie, # = komentarz).
    [string] $BlockedFile,

    [switch] $Force,

    [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ #
#  Kontrakt z driverem - musi sie zgadzac z agctl.h
# ------------------------------------------------------------------ #

$DevicePath = '\\.\AutostartGuard'

# CTL_CODE(0x8123, fn, METHOD_BUFFERED, access)
#   = (0x8123 << 16) | (access << 14) | (fn << 2) | 0
# Sufiks L (Int64) + rzut na [uint32]: Windows PowerShell 5.1 parsuje 8-cyfrowy
# literał hex z ustawionym najwyższym bitem jako UJEMNY Int32, a [uint32] na
# wartości ujemnej rzuca wyjątek. L wymusza dodatni Int64 przed rzutem.
$IOCTL_AG_SET_MODE = [uint32] 0x8123A000L  # fn 0x800, FILE_WRITE_ACCESS
$IOCTL_AG_CLEAR_RULES = [uint32] 0x8123A004L  # fn 0x801, FILE_WRITE_ACCESS
$IOCTL_AG_ADD_RULE = [uint32] 0x8123A008L  # fn 0x802, FILE_WRITE_ACCESS
$IOCTL_AG_GET_STATS = [uint32] 0x8123600CL  # fn 0x803, FILE_READ_ACCESS

$AG_MAX_PATH = 260                # znaki WCHAR
$AG_RULE_SIZE = $AG_MAX_PATH * 2   # 520 bajtow
$AG_STATS_SIZE = 32

$ModeNames = @{ 0 = 'DISABLED'; 1 = 'AUDIT'; 2 = 'ENFORCE' }
$ModeValues = @{ 'off' = 0; 'audit' = 1; 'enforce' = 2 }

# Te same nazwy, ktore driver chroni na twardo. Odfiltrowujemy je juz tutaj,
# zeby nie zasmiecac listy regul wpisami, ktore nigdy nie zadzialaja.
$ProtectedNames = @(
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe',
    'dwm.exe', 'userinit.exe', 'fontdrvhost.exe', 'lsaiso.exe',
    'conhost.exe', 'sihost.exe', 'logonui.exe', 'dllhost.exe'
)

# ------------------------------------------------------------------ #
#  P/Invoke
# ------------------------------------------------------------------ #

if (-not ('AgNative.Io' -as [type])) {
    Add-Type -Namespace 'AgNative' -Name 'Io' -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern System.IntPtr CreateFileW(
    string lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    System.IntPtr lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    System.IntPtr hTemplateFile);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool DeviceIoControl(
    System.IntPtr hDevice,
    uint dwIoControlCode,
    byte[] lpInBuffer,
    uint nInBufferSize,
    byte[] lpOutBuffer,
    uint nOutBufferSize,
    out uint lpBytesReturned,
    System.IntPtr lpOverlapped);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(System.IntPtr hObject);
'@
}

# ------------------------------------------------------------------ #
#  Funkcje pomocnicze
# ------------------------------------------------------------------ #

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Open-AgDevice {
    $GENERIC_READ = [uint32] 0x80000000L   # L: patrz uwaga przy stałych IOCTL (PS 5.1)
    $GENERIC_WRITE = [uint32] 0x40000000
    $OPEN_EXISTING = [uint32] 3

    $handle = [AgNative.Io]::CreateFileW(
        $DevicePath,
        ($GENERIC_READ -bor $GENERIC_WRITE),
        [uint32] 0,
        [IntPtr]::Zero,
        $OPEN_EXISTING,
        [uint32] 0,
        [IntPtr]::Zero)

    if ($handle -eq [IntPtr]::new(-1)) {
        $err = [ComponentModel.Win32Exception]::new(
            [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        throw "Nie udalo sie otworzyc $DevicePath : $($err.Message). " +
        'Czy driver jest uruchomiony (sc.exe query AutostartGuard)?'
    }

    return $handle
}

function Invoke-AgIoctl {
    param(
        [Parameter(Mandatory)] [IntPtr] $Handle,
        [Parameter(Mandatory)] [uint32] $Code,
        [byte[]] $InBuffer = $null,
        [int]    $OutSize = 0
    )

    $outBuffer = if ($OutSize -gt 0) { New-Object byte[] $OutSize } else { $null }
    $inSize = if ($InBuffer) { $InBuffer.Length } else { 0 }
    $returned = [uint32] 0

    $ok = [AgNative.Io]::DeviceIoControl(
        $Handle, $Code,
        $InBuffer, [uint32] $inSize,
        $outBuffer, [uint32] $OutSize,
        [ref] $returned, [IntPtr]::Zero)

    if (-not $ok) {
        $err = [ComponentModel.Win32Exception]::new(
            [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        throw "DeviceIoControl 0x$($Code.ToString('X8')) nie powiodlo sie: $($err.Message)"
    }

    return $outBuffer
}

function Get-AgStats {
    param([Parameter(Mandatory)] [IntPtr] $Handle)

    $raw = Invoke-AgIoctl -Handle $Handle -Code $IOCTL_AG_GET_STATS -OutSize $AG_STATS_SIZE

    return [pscustomobject] @{
        Mode      = $ModeNames[[int][BitConverter]::ToUInt32($raw, 0)]
        RuleCount = [BitConverter]::ToUInt32($raw, 4)
        Evaluated = [BitConverter]::ToUInt64($raw, 8)
        Matched   = [BitConverter]::ToUInt64($raw, 16)
        Blocked   = [BitConverter]::ToUInt64($raw, 24)
    }
}

function Add-AgRule {
    param(
        [Parameter(Mandatory)] [IntPtr] $Handle,
        [Parameter(Mandatory)] [string] $Path
    )

    $bytes = [Text.Encoding]::Unicode.GetBytes($Path)
    if ($bytes.Length -gt ($AG_RULE_SIZE - 2)) {
        throw "Sciezka za dluga (limit $($AG_MAX_PATH - 1) znakow): $Path"
    }

    # Reszta bufora zostaje zerami, czyli string jest zakonczony NUL-em.
    $buffer = New-Object byte[] $AG_RULE_SIZE
    [Array]::Copy($bytes, $buffer, $bytes.Length)

    Invoke-AgIoctl -Handle $Handle -Code $IOCTL_AG_ADD_RULE -InBuffer $buffer | Out-Null
}

<#
    Wyciaga sciezki do zablokowania z plikow alert_*.json.

    Format alertu (patrz README etapu 1): changes[] z polami current / after /
    previous. Interesuja nas wpisy typu "new" i "changed", bo tylko one
    reprezentuja cos, co pojawilo sie w systemie.
#>
function Get-TargetPathsFromAlerts {
    param([Parameter(Mandatory)] [string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Folder z alertami nie istnieje: $Path"
    }

    # @() wymusza tablice nawet przy jednym pliku - bez tego .Count wywala sie
    # pod Set-StrictMode.
    $files = @(Get-ChildItem -LiteralPath $Path -Filter 'alert_*.json' -File)
    if ($files.Count -eq 0) {
        Write-Warning "Brak plikow alert_*.json w $Path"
        return @()
    }

    $found = [Collections.Generic.List[string]]::new()

    foreach ($file in $files) {
        try {
            $alert = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        }
        catch {
            Write-Warning "Pomijam $($file.Name) - niepoprawny JSON: $($_.Exception.Message)"
            continue
        }

        # Pod StrictMode odwolanie do nieistniejacej wlasciwosci rzuca wyjatek,
        # wiec kazde pole trzeba najpierw sprawdzic na liscie wlasciwosci.
        if (@($alert.PSObject.Properties.Name) -notcontains 'changes') { continue }

        foreach ($change in $alert.changes) {
            $changeFields = @($change.PSObject.Properties.Name)

            if ($changeFields -contains 'type' -and $change.type -eq 'removed') {
                continue  # wpis zniknal z systemu, nie ma czego blokowac
            }

            foreach ($field in 'current', 'after') {
                if ($changeFields -notcontains $field) { continue }

                $node = $change.$field
                if ($null -eq $node) { continue }

                # Dla "changed" pole after bywa zwyklym stringiem, nie obiektem -
                # wtedy po prostu nie ma targetPath i wpis pomijamy.
                if (@($node.PSObject.Properties.Name) -notcontains 'targetPath') { continue }

                $target = $node.targetPath
                if ([string]::IsNullOrWhiteSpace($target)) { continue }

                $found.Add($target.Trim().Trim('"'))
            }
        }
    }

    return @($found | Select-Object -Unique)
}

# ------------------------------------------------------------------ #
#  Main
# ------------------------------------------------------------------ #

if ($Action -eq 'Mode' -and -not $Mode) {
    throw 'Akcja Mode wymaga parametru -Mode (off|audit|enforce).'
}

if ($Action -eq 'Mode' -and $Mode -eq 'enforce' -and -not $Force) {
    throw 'Tryb enforce faktycznie blokuje uruchamianie programow. ' +
    'Dodaj -Force, zeby potwierdzic. Testuj na maszynie wirtualnej.'
}

# Dla akcji Load parsujemy pliki ZANIM dotkniemy drivera. Dzieki temu bledny
# JSON albo pusty folder wychodza od razu, a -DryRun da sie uruchomic bez
# zaladowanego drivera i bez uprawnien administratora.
$pendingRules = $null

if ($Action -eq 'Load') {
    $targets = @(Get-TargetPathsFromAlerts -Path $AlertsPath)

    # Odsiewamy procesy systemowe - driver i tak ich nie zablokuje.
    $pendingRules = @()
    foreach ($t in $targets) {
        $leaf = [IO.Path]::GetFileName($t)
        if ($ProtectedNames -contains $leaf.ToLowerInvariant()) {
            Write-Warning "Pomijam proces systemowy: $t"
            continue
        }
        $pendingRules += $t
    }

    if ($pendingRules.Count -eq 0) {
        Write-Host 'Brak sciezek do wgrania.'
        return
    }

    Write-Host "Znaleziono $($pendingRules.Count) sciezek:"
    $pendingRules | ForEach-Object { Write-Host "  $_" }

    if ($DryRun) {
        Write-Host 'DryRun - nic nie wgrano.'
        return
    }
}

if (-not (Test-Admin)) {
    throw 'Ten skrypt wymaga uruchomienia jako administrator.'
}

$handle = Open-AgDevice
try {
    switch ($Action) {

        'Status' {
            Get-AgStats -Handle $handle | Format-List
        }

        'Clear' {
            Invoke-AgIoctl -Handle $handle -Code $IOCTL_AG_CLEAR_RULES | Out-Null
            Write-Host 'Reguly wyczyszczone.'
        }

        'Mode' {
            $value = $ModeValues[$Mode]
            $buffer = [BitConverter]::GetBytes([uint32] $value)
            Invoke-AgIoctl -Handle $handle -Code $IOCTL_AG_SET_MODE -InBuffer $buffer | Out-Null
            Write-Host "Tryb ustawiony na $($Mode.ToUpper())."
        }

        'Load' {
            # Lista zostala przygotowana i zwalidowana wyzej.
            Invoke-AgIoctl -Handle $handle -Code $IOCTL_AG_CLEAR_RULES | Out-Null
            foreach ($t in $pendingRules) {
                Add-AgRule -Handle $handle -Path $t
            }

            Write-Host ''
            Write-Host 'Wgrano. Stan drivera:'
            Get-AgStats -Handle $handle | Format-List
        }

        'Sync' {
            # Zrodlo prawdy = plik blocked-paths.txt. Czyscimy driver, wgrywamy
            # cala liste i WLACZAMY enforce (blokowanie domyslnie wlaczone).
            if (-not $BlockedFile) { $BlockedFile = Join-Path (Get-Location) 'blocked-paths.txt' }

            $paths = @()
            if (Test-Path -LiteralPath $BlockedFile) {
                $paths = @(Get-Content -LiteralPath $BlockedFile |
                        ForEach-Object { $_.Trim() } |
                        Where-Object { $_ -and -not $_.StartsWith('#') } |
                        Select-Object -Unique)
            }

            # Odsiewamy procesy chronione (driver i tak ich nie zablokuje).
            $final = @()
            foreach ($p in $paths) {
                $leaf = [IO.Path]::GetFileName($p)
                if ($leaf -and $ProtectedNames -contains $leaf.ToLowerInvariant()) {
                    Write-Warning "Pomijam proces systemowy: $p"; continue
                }
                if ($final.Count -ge $AG_MAX_RULES) { Write-Warning "Limit $AG_MAX_RULES regul - reszta pominieta."; break }
                $final += $p
            }

            Invoke-AgIoctl -Handle $handle -Code $IOCTL_AG_CLEAR_RULES | Out-Null
            foreach ($t in $final) { Add-AgRule -Handle $handle -Path $t }

            # Enforce - o to chodzi w Watch (blokowanie domyslnie aktywne).
            $buffer = [BitConverter]::GetBytes([uint32] $ModeValues['enforce'])
            Invoke-AgIoctl -Handle $handle -Code $IOCTL_AG_SET_MODE -InBuffer $buffer | Out-Null

            Write-Host "Zsynchronizowano $($final.Count) regul, tryb ENFORCE."
            Get-AgStats -Handle $handle | Format-List
        }
    }
}
finally {
    [AgNative.Io]::CloseHandle($handle) | Out-Null
}
