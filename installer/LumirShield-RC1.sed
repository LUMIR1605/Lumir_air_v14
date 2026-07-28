[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=1
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=
DisplayLicense=
FinishMessage=Instalacja Lumir SHIELD zostala zakonczona.
TargetName=C:\Users\lukas\Lumir_air_v14\dist\LumirShield-Setup.exe
FriendlyName=Lumir SHIELD RC1
AppLaunched=powershell.exe -ExecutionPolicy Bypass -File Install_Lumir_SHIELD.ps1
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
SourceFiles=SourceFiles
[SourceFiles]
SourceFiles0=C:\Users\lukas\Lumir_air_v14\installer\payload
[SourceFiles0]
%FILE0%=
%FILE1%=
[SourceFiles0.Files]
%FILE0%="Install_Lumir_SHIELD.ps1"
%FILE1%="LumirShield.exe"
[Strings]
FILE0="Install_Lumir_SHIELD.ps1"
FILE1="LumirShield.exe"
