; EFRISConnect - Windows installer (Inno Setup 6).
; Build with installer\build.ps1, which stages the files, bundles Node.js and
; passes /DAppVersion and /DStageDir to the compiler.
;
; One setup for three kinds of computer:
;   This computer only : Manager Desktop on one PC (relay on localhost).
;   Shop server        : relay for the shop network, optionally Manager Server.
;   Till               : trusts the shop server's certificate; installs nothing else.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef StageDir
  #define StageDir "..\build\stage"
#endif

[Setup]
AppId={{80D0D693-F8E2-479E-A372-C4229D53FEB2}
AppName=EFRISConnect
AppVersion={#AppVersion}
AppVerName=EFRISConnect {#AppVersion}
AppPublisher=The Tukei Hope Initiative
AppPublisherURL=https://github.com/The-Tukei-Hope-Initiative/EFRISConnect
DefaultDirName={autopf}\EFRISConnect
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\build
OutputBaseFilename=EFRISConnect-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile={#StageDir}\LICENSE
UninstallDisplayName=EFRISConnect
SetupLogging=yes
; The relay is stopped by our own code before files are replaced.
CloseApplications=no

[Files]
; Server and single-PC installs: everything (relay, extension, bundled Node.js).
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion createallsubdirs; Check: not IsTill
; Till installs: only the helper that trusts the server certificate.
Source: "{#StageDir}\windows\install-helper.ps1"; DestDir: "{app}\windows"; Flags: ignoreversion; Check: IsTill
Source: "{#StageDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion; Check: IsTill

[Registry]
Root: HKLM; Subkey: "Software\EFRISConnect"; ValueType: string; ValueName: "InstallMode"; ValueData: "{code:ModeName}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\EFRISConnect"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"

[Icons]
Name: "{autoprograms}\EFRISConnect\EFRISConnect tray icon"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\windows\tray.vbs"""; Check: not IsTill
Name: "{commonstartup}\EFRISConnect tray icon"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\windows\tray.vbs"""; Check: not IsTill

[INI]
Filename: "{autoprograms}\EFRISConnect\Open EFRISConnect.url"; Section: "InternetShortcut"; Key: "URL"; String: "https://localhost:5443/extension"; Check: not IsTill
Filename: "{autoprograms}\EFRISConnect\Open Manager.url"; Section: "InternetShortcut"; Key: "URL"; String: "https://localhost:{code:MgrHttpsPort}"; Check: IsServer
Filename: "{commondesktop}\Manager (shop).url"; Section: "InternetShortcut"; Key: "URL"; String: "{code:TillManagerUrl}"; Check: IsTill

[UninstallDelete]
Type: files; Name: "{autoprograms}\EFRISConnect\Open EFRISConnect.url"
Type: files; Name: "{autoprograms}\EFRISConnect\Open Manager.url"
Type: files; Name: "{commondesktop}\Manager (shop).url"
Type: dirifempty; Name: "{autoprograms}\EFRISConnect"

[Run]
Filename: "{sys}\wscript.exe"; Parameters: """{app}\windows\tray.vbs"""; Description: "Show the EFRISConnect icon next to the clock"; Flags: postinstall nowait runasoriginaluser; Check: not IsTill
Filename: "https://localhost:5443/extension"; Description: "Open EFRISConnect now to create the owner account"; Flags: postinstall shellexec nowait runasoriginaluser unchecked; Check: not IsTill
Filename: "{code:TillManagerUrl}"; Description: "Open Manager on the shop server"; Flags: postinstall shellexec nowait runasoriginaluser; Check: IsTill

[Code]
var
  ModePage: TInputOptionWizardPage;
  ManagerPage: TInputFileWizardPage;
  PortPage: TInputQueryWizardPage;
  KeyPage: TInputFileWizardPage;
  TillCertPage: TInputFileWizardPage;
  TillServerPage: TInputQueryWizardPage;
  SetupOk: Boolean;

function IsSingle: Boolean; begin Result := ModePage.SelectedValueIndex = 0; end;
function IsServer: Boolean; begin Result := ModePage.SelectedValueIndex = 1; end;
function IsTill: Boolean;   begin Result := ModePage.SelectedValueIndex = 2; end;

function ModeName(Param: String): String;
begin
  if IsServer then Result := 'server'
  else if IsTill then Result := 'till'
  else Result := 'single';
end;

function MgrPort(Param: String): String;
begin
  if IsTill then Result := Trim(TillServerPage.Values[1]) else Result := Trim(PortPage.Values[0]);
  if Result = '' then Result := '5000';
end;

// Tills open Manager over HTTPS: the relay serves it on Manager's port + 1.
function MgrHttpsPort(Param: String): String;
begin
  Result := IntToStr(StrToIntDef(MgrPort(''), 5000) + 1);
end;

function TillManagerUrl(Param: String): String;
begin
  Result := 'https://' + Trim(TillServerPage.Values[0]) + ':' + MgrHttpsPort('');
end;

function FindManagerServer: String;
begin
  Result := '';
  if FileExists(ExpandConstant('{commonpf64}\Manager Server\ManagerServer.exe')) then
    Result := ExpandConstant('{commonpf64}\Manager Server\ManagerServer.exe')
  else if FileExists(ExpandConstant('{localappdata}\Programs\Manager Server\ManagerServer.exe')) then
    Result := ExpandConstant('{localappdata}\Programs\Manager Server\ManagerServer.exe');
end;

function IsPort(S: String): Boolean;
var N: Integer;
begin
  N := StrToIntDef(Trim(S), -1);
  Result := (N >= 1) and (N <= 65535);
end;

procedure InitializeWizard;
var PrevMode: String;
begin
  ModePage := CreateInputOptionPage(wpLicense,
    'How will this computer be used?', 'You can run Setup again later to change this.',
    'Choose one, then click Next.', True, False);
  ModePage.Add('This computer only - Manager Desktop on this PC, one person issuing receipts');
  ModePage.Add('Shop server - other computers (tills, laptops) in the shop connect to this one');
  ModePage.Add('Till - connect this computer to a shop server that already runs EFRISConnect');
  ModePage.SelectedValueIndex := 0;
  // Upgrade or re-run: start from the mode chosen last time.
  if RegQueryStringValue(HKLM, 'Software\EFRISConnect', 'InstallMode', PrevMode) then begin
    if PrevMode = 'server' then ModePage.SelectedValueIndex := 1
    else if PrevMode = 'till' then ModePage.SelectedValueIndex := 2;
  end;

  ManagerPage := CreateInputFilePage(ModePage.ID,
    'Manager Server', 'Tills open Manager from this computer.',
    'If Manager Server Edition is installed here, select ManagerServer.exe. EFRISConnect then starts it ' +
    'when you sign in to Windows. Leave it empty if you start Manager Server yourself or it runs elsewhere.');
  ManagerPage.Add('ManagerServer.exe:', 'ManagerServer.exe|ManagerServer.exe|Programs (*.exe)|*.exe', '.exe');
  ManagerPage.Values[0] := FindManagerServer;

  PortPage := CreateInputQueryPage(ManagerPage.ID,
    'Manager Server port', 'Tills reach Manager encrypted at https://' + Lowercase(GetComputerNameString) + ':PORT+1',
    'Use the port Manager Server listens on. 5000 is the usual one.');
  PortPage.Add('Port:', False);
  PortPage.Values[0] := '5000';

  KeyPage := CreateInputFilePage(PortPage.ID,
    'EFRIS private key (optional)', 'The key URA issued for this business.',
    'Select the .pem file to copy it into EFRISConnect''s protected data folder. ' +
    'Leave it empty to set the key later in EFRISConnect Settings.');
  KeyPage.Add('Private key (.pem):', 'Key files (*.pem;*.key)|*.pem;*.key|All files|*.*', '.pem');

  TillCertPage := CreateInputFilePage(ModePage.ID,
    'Shop server certificate', 'So this computer trusts the shop server.',
    'Select https_cert.cer from the till kit. On the shop server it is in ' +
    'C:\ProgramData\EFRISConnect\data\till-kit (copy that folder to a USB stick or share).');
  TillCertPage.Add('https_cert.cer:', 'Certificate (*.cer;*.crt)|*.cer;*.crt', '.cer');
  if FileExists(ExpandConstant('{src}\https_cert.cer')) then
    TillCertPage.Values[0] := ExpandConstant('{src}\https_cert.cer');

  TillServerPage := CreateInputQueryPage(TillCertPage.ID,
    'Shop server', 'Where Manager runs in this shop.',
    'Type the shop server''s computer name (or IP address) and Manager Server''s port on that server ' +
    '(usually 5000). The desktop shortcut opens Manager encrypted, on the next port (5001).');
  TillServerPage.Add('Server name or IP:', False);
  TillServerPage.Add('Manager Server port:', False);
  TillServerPage.Values[1] := '5000';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if (PageID = ManagerPage.ID) or (PageID = PortPage.ID) then Result := not IsServer
  else if PageID = KeyPage.ID then Result := IsTill
  else if (PageID = TillCertPage.ID) or (PageID = TillServerPage.ID) then Result := not IsTill
  else if PageID = wpSelectDir then Result := IsTill;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = ManagerPage.ID) and (Trim(ManagerPage.Values[0]) <> '') and not FileExists(ManagerPage.Values[0]) then begin
    MsgBox('ManagerServer.exe was not found at that path.', mbError, MB_OK); Result := False;
  end else if (CurPageID = PortPage.ID) and not IsPort(PortPage.Values[0]) then begin
    MsgBox('Enter a port number between 1 and 65535.', mbError, MB_OK); Result := False;
  end else if (CurPageID = KeyPage.ID) and (Trim(KeyPage.Values[0]) <> '') and not FileExists(KeyPage.Values[0]) then begin
    MsgBox('The key file was not found.', mbError, MB_OK); Result := False;
  end else if (CurPageID = TillCertPage.ID) and not FileExists(TillCertPage.Values[0]) then begin
    MsgBox('Select https_cert.cer from the shop server''s till kit.', mbError, MB_OK); Result := False;
  end else if CurPageID = TillServerPage.ID then begin
    if Trim(TillServerPage.Values[0]) = '' then begin
      MsgBox('Enter the shop server''s computer name or IP address.', mbError, MB_OK); Result := False;
    end else if not IsPort(TillServerPage.Values[1]) then begin
      MsgBox('Enter a port number between 1 and 65535.', mbError, MB_OK); Result := False;
    end;
  end;
end;

function Helper(Args: String): Boolean;
var Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\windows\install-helper.ps1') + '" ' + Args,
    '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

function Q(S: String): String; begin Result := '"' + Trim(S) + '"'; end;

procedure CurStepChanged(CurStep: TSetupStep);
var Args: String;
begin
  // Upgrade: stop the running relay and tray first, so their files can be replaced.
  if (CurStep = ssInstall) and FileExists(ExpandConstant('{app}\windows\install-helper.ps1')) then
    Helper('-Action stop');

  if CurStep = ssPostInstall then begin
    if IsTill then begin
      WizardForm.StatusLabel.Caption := 'Trusting the shop server certificate ...';
      SetupOk := Helper('-Action till -CertFile ' + Q(TillCertPage.Values[0]));
    end else begin
      WizardForm.StatusLabel.Caption := 'Setting up EFRISConnect: certificate, firewall, startup task ...';
      Args := '-Action setup -Mode ' + ModeName('') +
              ' -User ' + Q(GetEnv('USERDOMAIN') + '\' + GetUserNameString);
      if IsServer then begin
        Args := Args + ' -ManagerPort ' + MgrPort('');
        if Trim(ManagerPage.Values[0]) <> '' then Args := Args + ' -ManagerExe ' + Q(ManagerPage.Values[0]);
      end;
      if Trim(KeyPage.Values[0]) <> '' then Args := Args + ' -KeyFile ' + Q(KeyPage.Values[0]);
      SetupOk := Helper(Args);
    end;
    if not SetupOk then
      MsgBox('Part of the setup did not finish. The details are in' + #13#10 +
             'C:\ProgramData\EFRISConnect\install.log' + #13#10#13#10 +
             'You can run Setup again after fixing the problem.', mbError, MB_OK);
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
var Host: String;
begin
  if CurPageID <> wpFinished then Exit;
  Host := Lowercase(GetComputerNameString);
  if IsTill then
    WizardForm.FinishedLabel.Caption :=
      'This computer now trusts the shop server.' + #13#10#13#10 +
      'Open Manager from the desktop shortcut "Manager (shop)" and use the EFRISConnect buttons as usual.'
  else if IsServer then
    WizardForm.FinishedLabel.Caption :=
      'EFRISConnect starts with Windows and serves the shop network.' + #13#10#13#10 +
      'Manager custom button URL (every EFRISConnect button):' + #13#10 +
      '    https://' + Host + ':5443/extension' + #13#10 +
      'Tills open Manager (encrypted) at:' + #13#10 +
      '    https://' + Host + ':' + MgrHttpsPort('') + #13#10#13#10 +
      'Tills: copy C:\ProgramData\EFRISConnect\data\till-kit to a USB stick and run this Setup on each till ' +
      '(choose "Till"), or run "Trust EFRISConnect server.bat" from the kit.' + #13#10#13#10 +
      'The icon next to the clock shows the status and has Restart, Logs and Copy URL.'
  else
    WizardForm.FinishedLabel.Caption :=
      'EFRISConnect starts with Windows.' + #13#10#13#10 +
      'Manager custom button URL (every EFRISConnect button):' + #13#10 +
      '    https://localhost:5443/extension' + #13#10#13#10 +
      'The icon next to the clock shows the status and has Restart, Logs and Copy URL.';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var Mode, Args: String; Code: Integer;
begin
  if CurUninstallStep <> usUninstall then Exit;
  if not RegQueryStringValue(HKLM, 'Software\EFRISConnect', 'InstallMode', Mode) then Mode := 'single';
  Args := '-Action uninstall';
  if Mode = 'till' then begin
    if MsgBox('Stop trusting the shop server''s certificate on this computer?', mbConfirmation, MB_YESNO) = IDYES then
      Args := Args + ' -RemoveCert';
  end else begin
    if MsgBox('Also delete EFRISConnect''s data on this computer?' + #13#10#13#10 +
              'This removes the credential vault, users, logs, receipt history and the HTTPS certificate. ' +
              'Choose No to keep them for a reinstall or upgrade.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      Args := Args + ' -RemoveData -RemoveCert';
  end;
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\windows\install-helper.ps1') + '" ' + Args,
    '', SW_HIDE, ewWaitUntilTerminated, Code);
end;
