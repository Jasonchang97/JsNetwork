[Setup]
AppName=JsNetwork
AppVersion=1.0.2
AppPublisher=JsNetwork
AppPublisherURL=https://github.com/jsnetwork
DefaultDirName={autopf}\JsNetwork
DefaultGroupName=JsNetwork
AllowNoIcons=yes
OutputDir=Output
OutputBaseFilename=JsNetwork-v1.0.2-win32-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x86compatible
ArchitecturesInstallIn64BitMode=

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1

[Files]
Source: "staging\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\JsNetwork"; Filename: "{app}\JsNetwork.exe"
Name: "{group}\{cm:UninstallProgram,JsNetwork}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\JsNetwork"; Filename: "{app}\JsNetwork.exe"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\JsNetwork"; Filename: "{app}\JsNetwork.exe"; Tasks: quicklaunchicon

[Run]
Filename: "{app}\JsNetwork.exe"; Description: "{cm:LaunchProgram,JsNetwork}"; Flags: nowait postinstall skipifsilent

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  // Kill any running JsNetwork instance
  Exec('taskkill', '/F /IM JsNetwork.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Stop WinDivert kernel driver service so the .sys file can be replaced
  Exec('sc', 'stop WinDivert', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('sc', 'delete WinDivert', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Give the driver a moment to unload
  Sleep(1000);

  Result := '';
end;

function NeedRestart(): Boolean;
begin
  // If WinDivert driver was loaded, a reboot ensures the old driver is fully unloaded
  Result := False;
end;

[UninstallRun]
