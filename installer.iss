[Setup]
AppName=JsNetwork
AppVersion=1.0.1
AppPublisher=JsNetwork
AppPublisherURL=https://github.com/jsnetwork
DefaultDirName={autopf}\JsNetwork
DefaultGroupName=JsNetwork
AllowNoIcons=yes
OutputDir=D:\JsNetwork\JsNetwork\dist
OutputBaseFilename=JsNetwork-v1.0.1-win32-setup
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
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\JsNetwork.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\Qt5CoreKso.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\Qt5GuiKso.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\Qt5NetworkKso.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\Qt5SqlKso.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\Qt5WidgetsKso.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\platforms\qwindows.dll"; DestDir: "{app}\platforms"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\wpcap.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\Packet.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\jsnetwork_lsp.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-win2\Release\lsp_installer.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-lsp64\Release\jsnetwork_lsp.dll"; DestDir: "{app}\x64"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\build-lsp64\Release\lsp_installer64.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "D:\JsNetwork\JsNetwork\docs\UserGuide.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\JsNetwork"; Filename: "{app}\JsNetwork.exe"
Name: "{group}\{cm:UninstallProgram,JsNetwork}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\JsNetwork"; Filename: "{app}\JsNetwork.exe"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\JsNetwork"; Filename: "{app}\JsNetwork.exe"; Tasks: quicklaunchicon

[Run]
; Import CA certificate into system trust store (certutil fails silently if file missing)
Filename: "certutil"; Parameters: "-addstore ""Root"" ""{app}\ca.cer"""; StatusMsg: "Installing CA certificate..."; Flags: runhidden
; Install LSP provider via 64-bit installer (handles both 32/64 catalogs)
Filename: "{app}\lsp_installer64.exe"; Parameters: "install ""{app}\x64\jsnetwork_lsp.dll"" ""{app}\jsnetwork_lsp.dll"""; StatusMsg: "Installing network interceptor..."; Flags: runhidden
Filename: "{app}\JsNetwork.exe"; Description: "{cm:LaunchProgram,JsNetwork}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove LSP providers (64-bit first, then 32-bit)
Filename: "{app}\lsp_installer64.exe"; Parameters: "uninstall"; Flags: runhidden
Filename: "{app}\lsp_installer.exe"; Parameters: "uninstall"; Flags: runhidden
; Remove CA certificate from trust store
Filename: "certutil"; Parameters: "-delstore ""Root"" ""JsNetwork CA"""; Flags: runhidden

[Registry]
; Register as system proxy handler (optional)
Root: HKCU; Subkey: "Software\JsNetwork"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
