#define AppName "Lumir SHIELD RC7"
#define AppVersion "RC7"
#define AppPublisher "Lumir SHIELD RC7"
#define AppExeName "LumirShield-RC7.exe"

[Setup]
AppId={{A6C33580-FF95-4A2F-B0BF-BB99CA75C217}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={localappdata}\Lumir SHIELD RC7
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\..\..\outputs\RC7
OutputBaseFilename=LumirShield-Setup-RC7
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
UninstallDisplayName={#AppName}

[Files]
Source: "..\..\..\outputs\RC7\LumirShield-RC7.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\Lumir SHIELD RC7"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{group}\Lumir SHIELD RC7"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{group}\Odinstaluj Lumir SHIELD RC7"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Uruchom Lumir SHIELD RC7"; Flags: nowait postinstall skipifsilent

