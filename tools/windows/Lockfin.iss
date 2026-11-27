#ifndef AppVersion
  #error AppVersion must be supplied by build_windows.py
#endif
#ifndef BundleDir
  #error BundleDir must be supplied by build_windows.py
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by build_windows.py
#endif
#ifndef LicensePath
  #error LicensePath must be supplied by build_windows.py
#endif
[Setup]
AppId={{9A8C49BC-F617-4B90-A2D9-F676D8AB9ED2}
AppName=Lockfin
AppVersion={#AppVersion}
AppPublisher=SERPIERO
DefaultDirName={localappdata}\Programs\Lockfin
DefaultGroupName=Lockfin
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=Lockfin-{#AppVersion}-Windows-Setup
LicenseFile={#LicensePath}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\Lockfin.exe
[Files]
Source: "{#BundleDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\Lockfin"; Filename: "{app}\Lockfin.exe"
Name: "{group}\Uninstall Lockfin"; Filename: "{uninstallexe}"
