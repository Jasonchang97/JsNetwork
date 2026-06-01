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

[UninstallRun]
Filename: "{app}\lsp_installer.exe"; Parameters: "uninstall"; Flags: runhidden
