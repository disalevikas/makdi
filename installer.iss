; ============================================================
; Makdi — Inno Setup installer script  (Release Guide step B4)
; Every release: update MyAppVersion below, then Build → Compile.
; Output: Output\MakdiSetup-<version>.exe
; ============================================================

#define MyAppName "Makdi"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Vikas Disale"
#define MyAppURL "https://vikasdisale.com/makdi"
#define MyAppExeName "Makdi.exe"

[Setup]
AppId={{8F4A2C1D-7B3E-4E9A-9C5D-MAKDI0100000}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=LICENSE
OutputDir=Output
OutputBaseFilename=MakdiSetup-{#MyAppVersion}
SetupIconFile=makdi.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; PyInstaller --onedir output: the whole dist\Makdi folder
Source: "dist\Makdi\*"; DestDir: "{app}"; \
  Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Makdi website"; Filename: "{#MyAppURL}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
  Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent

; Crawl history & logs live in Documents\Makdi — never deleted by uninstall,
; so users keep their data across reinstalls/updates.
