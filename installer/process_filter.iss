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

; 2. Zarejestruj usługę jądra (nie startujemy jej - wymaga test signing + restartu).
Filename: "{sys}\sc.exe"; Parameters: "create AutostartGuard type= kernel start= demand binPath= ""{app}\process_filter.sys"""; \
  StatusMsg: "Rejestrowanie usługi sterownika..."; Flags: runhidden

; 3. Opcjonalnie włącz test signing.
Filename: "{sys}\bcdedit.exe"; Parameters: "/set testsigning on"; Tasks: testsigning; \
  StatusMsg: "Włączanie trybu test signing..."; Flags: runhidden

[UninstallRun]
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
    if WizardIsTaskSelected('testsigning') then
      Msg := Msg + 'Włączono test signing - URUCHOM PONOWNIE komputer, aby zaczął obowiązywać.' + #13#10#13#10;
    Msg := Msg + 'Po restarcie, z konsoli jako administrator:' + #13#10 +
           '  sc.exe start AutostartGuard' + #13#10#13#10 +
           'Wgranie reguł z alertów i tryb blokowania:' + #13#10 +
           '  cd "' + ExpandConstant('{app}') + '\tools"' + #13#10 +
           '  .\AutostartGuardCtl.ps1 -Action Load -AlertsPath <folder z alertami>' + #13#10 +
           '  .\AutostartGuardCtl.ps1 -Action Mode -Mode enforce -Force' + #13#10#13#10 +
           'UWAGA: tryb enforce realnie blokuje procesy. Testuj na maszynie wirtualnej ze snapshotem.';
    MsgBox(Msg, mbInformation, MB_OK);
  end;
end;
