; Inno Setup script for PreScan (Windows). Packages the PyInstaller --onedir bundle
; from dist\PreScan. Qt DLLs are copied as separate replaceable files next to
; prescan.exe (LGPL §4d, §11.2 row 4) -- never packed into one file. The executable
; and shortcuts use prescan.ico. Build with:  ISCC packaging\prescan.iss

#define AppName "PreScan"
#define AppVersion "0.0.0"
#define AppExe "prescan.exe"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=PreScan
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=..\dist
OutputBaseFilename=PreScan-Setup-{#AppVersion}
SetupIconFile=..\src\prescan\resources\icons\prescan.ico
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequiredOverridesAllowed=dialog

[Files]
; Recurse the whole --onedir bundle; every Qt6*.dll stays a separate file here.
Source: "..\dist\PreScan\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; IconFilename: "{app}\{#AppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch PreScan"; Flags: nowait postinstall skipifsilent
