; Instalator AutostartGuard (etap 2: driver) - Inno Setup 6.
;
; Kompilacja (w workflow): ISCC.exe /DMyAppVersion=1.0.0 /DSrcDir=dist installer\process_filter.iss
;
; Instalator LABOWY. Robi:
;   - kopiuje process_filter.sys + skrypty narzędziowe do Program Files,
;   - importuje testowy certyfikat do magazynów Root i TrustedPublisher,
;   - rejestruje usługę jądra (sc create AutostartGuard type= kernel),
;   - opcjonalnie włącza tryb test signing (wymaga restartu).
; NIE uruchamia sterownika automatycznie - wymaga to aktywnego test signing i
; restartu. Instrukcja startu pokazywana na końcu. Używać na maszynie wirtualnej.

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif
#ifndef SrcDir
  #define SrcDir "dist"
#endif

[Setup]
AppName=AutostartGuard
AppVersion={#MyAppVersion}
AppPublisher=Projekt na zajęcia (PoC)
DefaultDirName={autopf}\AutostartGuard
DefaultGroupName=AutostartGuard
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64
OutputDir=Output
OutputBaseFilename=AutostartGuard-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=AutostartGuard (driver PoC)

[Languages]
Name: "pl"; MessagesFile: "compiler:Languages\Polish.isl"

[Tasks]
Name: "testsigning"; \
  Description: "Włącz tryb test signing (WYMAGA restartu - driver testowy inaczej się nie załaduje)"; \
  GroupDescription: "Konfiguracja systemu:"; Flags: checkedonce

[Dirs]
; Folder danych - baseline.json, allowlist.json, alerts/, blocked-paths.txt.
Name: "{app}\data"

[Files]
Source: "{#SrcDir}\process_filter.sys"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\process_filter.cer"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SrcDir}\README.md";          DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "{#SrcDir}\tools\*";            DestDir: "{app}\tools"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SrcDir}\docs\*";             DestDir: "{app}\docs";  Flags: ignoreversion recursesubdirs createallsubdirs

[Run]
; 1. Zaufaj certyfikatowi testowemu (główny + wydawca), żeby podpis sterownika był uznany.
Filename: "{sys}\certutil.exe"; Parameters: "-f -addstore Root ""{app}\process_filter.cer"""; \
  StatusMsg: "Importowanie certyfikatu (Root)..."; Flags: runhidden
Filename: "{sys}\certutil.exe"; Parameters: "-f -addstore TrustedPublisher ""{app}\process_filter.cer"""; \
  StatusMsg: "Importowanie certyfikatu (TrustedPublisher)..."; Flags: runhidden

; 2. Zarejestruj usługę jądra (start automatyczny - rezydentny przy starcie systemu).
Filename: "{sys}\sc.exe"; Parameters: "create AutostartGuard type= kernel start= auto binPath= ""{app}\process_filter.sys"""; \
  StatusMsg: "Rejestrowanie usługi sterownika..."; Flags: runhidden

; 3. Zarejestruj zadania: Watch (przy logowaniu) i Sync (przy starcie systemu).
Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\Install-Tasks.ps1"" -DataPath ""{app}\data"""; \
  StatusMsg: "Rejestrowanie zadań (logowanie / start systemu)..."; Flags: runhidden

; 4. Opcjonalnie włącz test signing.
Filename: "{sys}\bcdedit.exe"; Parameters: "/set testsigning on"; Tasks: testsigning; \
  StatusMsg: "Włączanie trybu test signing..."; Flags: runhidden

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -Command ""Unregister-ScheduledTask -TaskName 'AutostartGuard Watch (logon)' -Confirm:$false -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'AutostartGuard Sync (boot)' -Confirm:$false -ErrorAction SilentlyContinue"""; Flags: runhidden; RunOnceId: "DelAgTasks"
Filename: "{sys}\sc.exe"; Parameters: "stop AutostartGuard";   Flags: runhidden; RunOnceId: "StopAgSvc"
Filename: "{sys}\sc.exe"; Parameters: "delete AutostartGuard"; Flags: runhidden; RunOnceId: "DelAgSvc"

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  Msg: string;
begin
  if CurStep = ssPostInstall then
  begin
    Msg := 'Instalacja zakończona.' + #13#10#13#10;
    Msg := Msg + 'Zarejestrowano: usługę sterownika oraz zadania Watch (logowanie) i Sync (start systemu).' + #13#10#13#10;
    if WizardIsTaskSelected('testsigning') then
      Msg := Msg + 'Włączono test signing - URUCHOM PONOWNIE komputer, aby zaczął obowiązywać.' + #13#10#13#10;
    Msg := Msg + 'POZOSTAŁ JEDEN KROK - zbuduj baseline (jako administrator):' + #13#10 +
           '  cd "' + ExpandConstant('{app}') + '\tools"' + #13#10 +
           '  .\AutostartGuard.ps1 -Action Baseline' + #13#10#13#10 +
           'Od teraz przy każdym logowaniu nowe wpisy autostartu (spoza baseline' + #13#10 +
           'i allowlisty) są domyślnie blokowane, z oknem Zablokuj / Uruchom / Pokaż.' + #13#10#13#10 +
           'UWAGA: enforce realnie blokuje procesy. Testuj na maszynie wirtualnej ze snapshotem.';
    MsgBox(Msg, mbInformation, MB_OK);
  end;
end;
