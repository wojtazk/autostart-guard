<#
    AutostartGuard.Core.ps1 - konfiguracja zrodel + funkcje skanera.

    Sam w sobie nic nie wykonuje (brak param, brak Main) - jest dot-source'owany
    przez AutostartGuard.ps1 oraz przez testy (tests/AutostartGuard.Tests.ps1).

    Dzieki rozdzieleniu funkcje czyste (Resolve-TargetPath, Compare-State) da sie
    testowac bez cmdletow Windows-only.
#>

Set-StrictMode -Version Latest

# ------------------------------------------------------------------ #
#  Konfiguracja zrodel
# ------------------------------------------------------------------ #

$script:RunKeyPaths = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices'
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
)

$script:SingleValues = @(
    @{ Id = 'Winlogon|Shell';    Path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'Shell';    Expected = '^explorer\.exe$' }
    @{ Id = 'Winlogon|Userinit'; Path = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name = 'Userinit'; Expected = 'userinit\.exe,?$' }
    @{ Id = 'Windows|load';      Path = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows';  Name = 'load';     Expected = '^$' }
    @{ Id = 'Env|UserInitMprLogonScript'; Path = 'HKCU:\Environment'; Name = 'UserInitMprLogonScript'; Expected = '^$' }
    @{ Id = 'SessionManager|BootExecute'; Path = 'HKLM:\System\CurrentControlSet\Control\Session Manager'; Name = 'BootExecute'; Expected = '^autocheck autochk \*$' }
)

$script:ShellFolderChecks = @(
    @{ Id = 'HKCU|Startup';        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'; Name = 'Startup' }
    @{ Id = 'HKLM|Common Startup'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'; Name = 'Common Startup' }
)

$script:EnumCategories  = @('runKeys', 'startupFolders', 'services', 'scheduledTasks')
$script:ValueCategories = @('shellFolders', 'singleValues')

# ------------------------------------------------------------------ #
#  Funkcje czyste (testowalne na kazdej platformie)
# ------------------------------------------------------------------ #

function Resolve-TargetPath {
    param([string] $Command)

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $cmd = [Environment]::ExpandEnvironmentVariables($Command.Trim())

    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 1) { return $cmd.Substring(1, $end - 1) }
    }
    $m = [regex]::Match($cmd, '^(.*?\.exe)\b', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($cmd -split '\s+')[0]
}

function Test-AgAllowed {
    param($AllowMap, [string] $Id, [string] $Sha)
    if (-not $AllowMap.ContainsKey($Id)) { return $false }
    $rule = $AllowMap[$Id]
    return ($rule -eq '*' -or $rule -eq $Sha)
}

function ConvertTo-AllowMap {
    param($Allow)
    $map = @{}
    foreach ($a in @($Allow)) {
        $names = @($a.PSObject.Properties.Name)
        $byId = ($names -contains 'matchBy' -and $a.matchBy -eq 'id')
        $sha = if (-not $byId -and $names -contains 'sha256') { $a.sha256 } else { '*' }
        $map[$a.id] = $sha
    }
    return $map
}

function Compare-State {
    param($Baseline, $Current, $Allow)

    $changes = [Collections.Generic.List[object]]::new()
    $allowMap = ConvertTo-AllowMap -Allow $Allow

    foreach ($cat in $script:EnumCategories) {
        $baseById = @{}; foreach ($e in @($Baseline.$cat)) { $baseById[$e.id] = $e }
        $curById = @{}; foreach ($e in @($Current.$cat)) { $curById[$e.id] = $e }

        foreach ($id in $curById.Keys) {
            $cur = $curById[$id]
            if (-not $baseById.ContainsKey($id)) {
                if (Test-AgAllowed $allowMap $id $cur.sha256) { continue }
                $changes.Add([pscustomobject]@{ type = 'new'; category = $cat; id = $id; current = $cur })
            }
            else {
                $base = $baseById[$id]
                if ($cur.sha256 -ne $base.sha256 -or $cur.command -ne $base.command) {
                    if (Test-AgAllowed $allowMap $id $cur.sha256) { continue }
                    $changes.Add([pscustomobject]@{ type = 'changed'; category = $cat; id = $id; before = $base; after = $cur })
                }
            }
        }
        foreach ($id in $baseById.Keys) {
            if (-not $curById.ContainsKey($id)) {
                $changes.Add([pscustomobject]@{ type = 'removed'; category = $cat; id = $id; previous = $baseById[$id] })
            }
        }
    }

    foreach ($cat in $script:ValueCategories) {
        $baseById = @{}; foreach ($e in @($Baseline.$cat)) { $baseById[$e.id] = $e }
        foreach ($cur in @($Current.$cat)) {
            if (-not $baseById.ContainsKey($cur.id)) {
                $changes.Add([pscustomobject]@{ type = 'new'; category = $cat; id = $cur.id; current = $cur })
                continue
            }
            $base = $baseById[$cur.id]
            if ($cur.actual -ne $base.actual) {
                $changes.Add([pscustomobject]@{ type = 'changed'; category = $cat; id = $cur.id; field = 'actual'; before = $base.actual; after = $cur.actual })
            }
        }
    }
    return $changes
}

# ------------------------------------------------------------------ #
#  Pomocnicze zalezne od Windows (uzywane tylko przy realnym skanie)
# ------------------------------------------------------------------ #

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { return $false }
}

# Powiadomienie na pulpicie (dymek w zasobniku; na Win10/11 wyświetla się jako
# toast). Działa tylko w interaktywnej sesji użytkownika - dlatego zadanie w
# Harmonogramie musi być "przy logowaniu", w kontekście użytkownika, nie SYSTEM.
# Nigdy nie wywala skanu - przy braku GUI po prostu nic nie pokazuje.
function Show-AgNotification {
    param([string] $Title, [string] $Message)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $ni = New-Object System.Windows.Forms.NotifyIcon
        $ni.Icon = [System.Drawing.SystemIcons]::Warning
        $ni.Visible = $true
        $ni.ShowBalloonTip(10000, $Title, $Message, [System.Windows.Forms.ToolTipIcon]::Warning)
        Start-Sleep -Seconds 8
        $ni.Dispose()
    }
    catch {
        Write-Warning "Nie udalo sie pokazac powiadomienia: $($_.Exception.Message)"
    }
}

# Interaktywne okno decyzji dla nowego wpisu autostartu.
# Zwraca: 'block' (Zablokuj) albo 'run' (Uruchom).
# Okna NIE da się zamknąć bez wyboru - X / Alt+F4 są blokowane, dopóki
# użytkownik nie kliknie Zablokuj albo Uruchom (pętla). Przycisk 'Pokaż'
# otwiera plik alertu w Notatniku i NIE kończy decyzji.
# Brak GUI (sesja bez pulpitu) -> zwraca 'block' (nie ma kogo zapytać).
function Show-AgDecision {
    param([string] $EntryName, [string] $TargetPath, [string] $AlertFile)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    }
    catch { return 'block' }

    $script:agChoice = $null     # dopóki null -> brak decyzji, okno się nie zamknie

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'AutostartGuard - nowy wpis autostartu'
    $form.Size = New-Object System.Drawing.Size(540, 230)
    $form.StartPosition = 'CenterScreen'
    $form.TopMost = $true
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false; $form.MinimizeBox = $false
    $form.ControlBox = $false    # bez przycisku X w pasku tytułu

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Location = New-Object System.Drawing.Point(16, 16)
    $lbl.Size = New-Object System.Drawing.Size(500, 120)
    $lbl.Text = "Wykryto NOWY wpis autostartu (poza baseline i allowlistą):`r`n`r`n$EntryName`r`n$TargetPath`r`n`r`nWybierz - okna nie da się zamknąć bez decyzji."
    $form.Controls.Add($lbl)

    $bBlock = New-Object System.Windows.Forms.Button
    $bBlock.Text = 'Zablokuj'; $bBlock.Location = New-Object System.Drawing.Point(20, 150); $bBlock.Size = New-Object System.Drawing.Size(150, 34)
    $bBlock.Add_Click({ $script:agChoice = 'block'; $form.Close() })

    $bRun = New-Object System.Windows.Forms.Button
    $bRun.Text = 'Uruchom'; $bRun.Location = New-Object System.Drawing.Point(185, 150); $bRun.Size = New-Object System.Drawing.Size(150, 34)
    $bRun.Add_Click({ $script:agChoice = 'run'; $form.Close() })

    $bShow = New-Object System.Windows.Forms.Button
    $bShow.Text = 'Pokaż'; $bShow.Location = New-Object System.Drawing.Point(350, 150); $bShow.Size = New-Object System.Drawing.Size(150, 34)
    $bShow.Add_Click({ if ($AlertFile -and (Test-Path -LiteralPath $AlertFile)) { Start-Process notepad.exe $AlertFile } }.GetNewClosure())

    # Blokuj zamknięcie (Alt+F4 itp.), dopóki nie ma decyzji.
    $form.Add_FormClosing({ param($s, $e) if ($null -eq $script:agChoice) { $e.Cancel = $true } })

    $form.Controls.AddRange(@($bBlock, $bRun, $bShow))
    $form.AcceptButton = $bBlock
    [void]$form.ShowDialog()
    $form.Dispose()
    if ($null -eq $script:agChoice) { return 'block' }   # na wszelki wypadek
    return $script:agChoice
}

# --- Allowlist (odczyt/zapis) -------------------------------------- #

function Get-AgAllowed {
    param([string] $AllowFile)
    if (-not (Test-Path -LiteralPath $AllowFile)) { return @() }
    try {
        $j = Get-Content -LiteralPath $AllowFile -Raw | ConvertFrom-Json
        if (@($j.PSObject.Properties.Name) -contains 'allowed') { return @($j.allowed) }
    }
    catch { Write-Warning "Niepoprawny allowlist.json - ignoruję: $($_.Exception.Message)" }
    return @()
}

function Add-AgAllowEntry {
    param([string] $AllowFile, [string] $Id, [string] $Note = '')
    $existing = @(Get-AgAllowed -AllowFile $AllowFile)
    if ($existing | Where-Object { $_.id -eq $Id }) { return }
    $existing += [pscustomobject]@{ id = $Id; matchBy = 'id'; note = $Note }
    @{ allowed = $existing } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $AllowFile -Encoding UTF8
}

# --- Zapis alertu (wspólny dla Scan i Watch) ----------------------- #

function Write-AgAlert {
    param($Changes, $Current, $Baseline, [string] $AlertsDir, [string] $DataPath)
    if (-not (Test-Path -LiteralPath $AlertsDir)) { New-Item -ItemType Directory -Path $AlertsDir -Force | Out-Null }
    $now = Get-Date
    $alert = [ordered]@{
        scanTime     = $now.ToString('o')
        hostname     = $Current.hostname
        baselineTime = $Baseline.generatedAt
        changeCount  = @($Changes).Count
        changes      = $Changes
    }
    $stamp = $now.ToString('yyyy-MM-dd_HH-mm-ss')
    $file = Join-Path $AlertsDir "alert_$stamp.json"
    $alert | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $file -Encoding UTF8
    $byType = @($Changes) | Group-Object type | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Add-Content -LiteralPath (Join-Path $DataPath 'alerts.log') -Value "[$($now.ToString('yyyy-MM-dd HH:mm:ss'))] $(@($Changes).Count) zmian: $($byType -join ', ')"
    return $file
}

# Wyłuskuje targetPath ze zmiany typu 'new' (bezpiecznie, pod StrictMode).
function Get-ChangeTarget {
    param($Change)
    if (@($Change.PSObject.Properties.Name) -notcontains 'current') { return $null }
    $cur = $Change.current
    if ($null -eq $cur) { return $null }
    if (@($cur.PSObject.Properties.Name) -notcontains 'targetPath') { return $null }
    return $cur.targetPath
}

function Get-FileFacts {
    param([string] $TargetPath)
    $result = [ordered]@{ sha256 = $null; signature = 'Unknown' }
    if ([string]::IsNullOrWhiteSpace($TargetPath)) { return $result }
    if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) { $result.signature = 'FileMissing'; return $result }

    try { $result.sha256 = (Get-FileHash -LiteralPath $TargetPath -Algorithm SHA256).Hash } catch { $result.sha256 = $null }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $TargetPath
        if ($sig.Status -eq 'Valid' -and $sig.SignerCertificate) {
            $cn = ($sig.SignerCertificate.Subject -split ',' | Where-Object { $_.Trim().StartsWith('CN=') } | Select-Object -First 1)
            $result.signature = if ($cn) { $cn.Trim().Substring(3) } else { 'Signed' }
        }
        else { $result.signature = 'Unsigned' }
    }
    catch { $result.signature = 'Unknown' }
    return $result
}

function New-Entry {
    param($Source, $Location, $Name, $Command, [hashtable] $Extra = @{})
    $target = Resolve-TargetPath -Command $Command
    $facts = Get-FileFacts -TargetPath $target
    $obj = [ordered]@{
        id = "$Source|$Location|$Name"; source = $Source; location = $Location; name = $Name
        command = $Command; targetPath = $target; sha256 = $facts.sha256; signature = $facts.signature
        firstSeen = (Get-Date).ToString('o')
    }
    foreach ($k in $Extra.Keys) { $obj[$k] = $Extra[$k] }
    return [pscustomobject] $obj
}

function New-ValueEntry {
    param($Source, $Location, $ValueName, $Expected, $Actual)
    return [pscustomobject] [ordered]@{
        id = "$Source|$ValueName"; source = $Source; location = $Location
        valueName = $ValueName; expected = $Expected; actual = $Actual; firstSeen = (Get-Date).ToString('o')
    }
}

function Get-RunKeyEntries {
    param([ref] $Skipped)
    $out = [Collections.Generic.List[object]]::new()
    foreach ($path in $script:RunKeyPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try { $props = Get-ItemProperty -LiteralPath $path }
        catch { $Skipped.Value.Add("runKeys: $path ($($_.Exception.Message))"); continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $out.Add((New-Entry -Source 'RunKey' -Location $path -Name $p.Name -Command ([string]$p.Value)))
        }
    }
    return $out
}

function Get-StartupFolderEntries {
    $out = [Collections.Generic.List[object]]::new()
    $shell = $null
    $folders = @(
        @{ Scope = 'user';   Path = [Environment]::GetFolderPath('Startup') }
        @{ Scope = 'common'; Path = [Environment]::GetFolderPath('CommonStartup') }
    )
    foreach ($f in $folders) {
        if ([string]::IsNullOrWhiteSpace($f.Path) -or -not (Test-Path -LiteralPath $f.Path)) { continue }
        Get-ChildItem -LiteralPath $f.Path -File | ForEach-Object {
            $command = $_.FullName
            if ($_.Extension -ieq '.lnk') {
                try {
                    if (-not $shell) { $shell = New-Object -ComObject WScript.Shell }
                    $command = $shell.CreateShortcut($_.FullName).TargetPath
                }
                catch { $command = $_.FullName }
            }
            $out.Add((New-Entry -Source 'StartupFolder' -Location $f.Path -Name $_.Name -Command $command -Extra @{ scope = $f.Scope }))
        }
    }
    return $out
}

function Get-ServiceEntries {
    param([ref] $Skipped)
    $out = [Collections.Generic.List[object]]::new()
    try { $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object { $_.StartMode -eq 'Auto' } }
    catch { $Skipped.Value.Add("services: $($_.Exception.Message)"); return $out }
    foreach ($svc in $services) {
        $out.Add((New-Entry -Source 'Service' -Location $svc.Name -Name $svc.Name -Command ([string]$svc.PathName) `
                    -Extra @{ displayName = $svc.DisplayName; startMode = $svc.StartMode; account = $svc.StartName }))
    }
    return $out
}

function Get-ScheduledTaskEntries {
    param([ref] $Skipped)
    $out = [Collections.Generic.List[object]]::new()
    try { $tasks = Get-ScheduledTask -ErrorAction Stop }
    catch { $Skipped.Value.Add("scheduledTasks: $($_.Exception.Message)"); return $out }
    foreach ($task in $tasks) {
        # Typ triggera czytamy z PSTypeNames (zawsze istnieje), a NIE z .CimClass:
        # pod StrictMode odwołanie do .CimClass na triggerze, który jej nie wystawia,
        # rzuca wyjątek. TypeNames CIM zawierają np. ...MSFT_TaskLogonTrigger.
        $trig = $null
        foreach ($t in @($task.Triggers)) {
            if ($null -eq $t) { continue }
            $names = @($t.PSObject.TypeNames) -join ';'
            if     ($names -match 'LogonTrigger') { $trig = 'Logon'; break }
            elseif ($names -match 'BootTrigger')  { $trig = 'Boot';  break }
        }
        if (-not $trig) { continue }   # tylko realny autostart: logon / boot

        $account = if (@($task.PSObject.Properties.Name) -contains 'Principal' -and $task.Principal) { $task.Principal.UserId } else { $null }

        foreach ($act in @($task.Actions)) {
            if (@($act.PSObject.Properties.Name) -notcontains 'Execute') { continue }
            $exe = [string]$act.Execute
            if ([string]::IsNullOrWhiteSpace($exe)) { continue }
            $arguments = if (@($act.PSObject.Properties.Name) -contains 'Arguments') { [string]$act.Arguments } else { '' }
            $full = ("$exe $arguments").Trim()
            $loc = ($task.TaskPath + $task.TaskName)
            $out.Add((New-Entry -Source 'ScheduledTask' -Location $loc -Name $task.TaskName -Command $full `
                        -Extra @{ trigger = $trig; account = $account }))
        }
    }
    return $out
}

function Get-ShellFolderEntries {
    param([ref] $Skipped)
    $out = [Collections.Generic.List[object]]::new()
    $default = @{
        'Startup'        = '%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        'Common Startup' = '%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    foreach ($c in $script:ShellFolderChecks) {
        if (-not (Test-Path -LiteralPath $c.Path)) { continue }
        try { $val = (Get-ItemProperty -LiteralPath $c.Path -Name $c.Name -ErrorAction Stop).$($c.Name) }
        catch { $Skipped.Value.Add("shellFolders: $($c.Path)\$($c.Name)"); continue }
        $exp = if ($default.ContainsKey($c.Name)) { $default[$c.Name] } else { '' }
        $out.Add((New-ValueEntry -Source 'ShellFolder' -Location $c.Path -ValueName $c.Name -Expected $exp -Actual ([string]$val)))
    }
    return $out
}

function Get-SingleValueEntries {
    param([ref] $Skipped)
    $out = [Collections.Generic.List[object]]::new()
    foreach ($sv in $script:SingleValues) {
        $actual = ''
        if (Test-Path -LiteralPath $sv.Path) {
            try { $actual = [string]((Get-ItemProperty -LiteralPath $sv.Path -Name $sv.Name -ErrorAction Stop).$($sv.Name)) }
            catch { $actual = '' }
        }
        $out.Add((New-ValueEntry -Source 'SingleValue' -Location $sv.Path -ValueName $sv.Name -Expected $sv.Expected -Actual $actual))
    }
    return $out
}

function Get-CurrentState {
    $skipped = [Collections.Generic.List[string]]::new()
    return [pscustomobject] [ordered]@{
        schemaVersion  = 1
        generatedAt    = (Get-Date).ToString('o')
        hostname       = $env:COMPUTERNAME
        isAdmin        = (Test-Admin)
        runKeys        = @(Get-RunKeyEntries -Skipped ([ref]$skipped))
        shellFolders   = @(Get-ShellFolderEntries -Skipped ([ref]$skipped))
        singleValues   = @(Get-SingleValueEntries -Skipped ([ref]$skipped))
        startupFolders = @(Get-StartupFolderEntries)
        services       = @(Get-ServiceEntries -Skipped ([ref]$skipped))
        scheduledTasks = @(Get-ScheduledTaskEntries -Skipped ([ref]$skipped))
        skipped        = @($skipped)
    }
}
