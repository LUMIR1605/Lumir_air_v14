#define AppName "Lumir SHIELD"
#define AppVersion "RC6"
#define AppPublisher "Lumir SHIELD"
#define AppExeName "LumirShield.exe"

[Setup]
AppId={{7E4B7C7D-0C3C-4DCD-9E26-1DF4F349F5F3}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={localappdata}\Lumir SHIELD
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\release
OutputBaseFilename=LumirShield-Setup-RC6
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
UninstallDisplayName={#AppName}

[Files]
Source: "..\dist\LumirShield.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\Lumir SHIELD"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{group}\Lumir SHIELD"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{group}\Odinstaluj Lumir SHIELD"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Uruchom Lumir SHIELD"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if not UninstallSilent then begin
    if MsgBox('Jesli Lumir SHIELD jest otwarty, zostanie teraz zamkniety przed odinstalowaniem.',
      mbConfirmation, MB_YESNO) <> IDYES then begin
      Result := False;
      exit;
    end;
  end;

  Exec('taskkill.exe', '/IM "LumirShield.exe" /T', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
  Exec('taskkill.exe', '/IM "LumirShield.exe" /T /F', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
end;
