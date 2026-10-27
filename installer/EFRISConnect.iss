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
AppPublisherURL=https://tukeihopeinitiative.org/
AppSupportURL=https://github.com/The-Tukei-Hope-Initiative/EFRISConnect
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
SetupIconFile=efrisconnect.ico
; Branded pictures (made by make-wizard-images.ps1) at the modern wizard's sizes, sharp at 100-200%.
WizardImageFile=wizard-large-100.bmp,wizard-large-125.bmp,wizard-large-150.bmp,wizard-large-175.bmp,wizard-large-200.bmp
WizardSmallImageFile=wizard-small-100.bmp,wizard-small-125.bmp,wizard-small-150.bmp,wizard-small-175.bmp,wizard-small-200.bmp
DisableWelcomePage=no
UninstallDisplayIcon={app}\efrisconnect.ico
; The relay is stopped by our own code before files are replaced.
CloseApplications=no

[Files]
; Server and single-PC installs: everything (relay, extension, bundled Node.js).
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion createallsubdirs; Check: not IsTill
; Till installs: only the helper that trusts the server certificate.
Source: "{#StageDir}\windows\install-helper.ps1"; DestDir: "{app}\windows"; Flags: ignoreversion; Check: IsTill
Source: "{#StageDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion; Check: IsTill
; The EFRISConnect icon, for the shortcuts, the tray and Apps & features (every mode).
Source: "efrisconnect.ico"; DestDir: "{app}"; Flags: ignoreversion
; The logo for the side panel Setup draws as text (used by Setup only, not installed).
Source: "logo-tile.bmp"; Flags: dontcopy
; The brand word mark (Inter, white on green), from brand/EFRISConnect-logos.
Source: "wordmark-panel.bmp"; Flags: dontcopy

[Messages]
WelcomeLabel1=Welcome to EFRISConnect
WelcomeLabel2=EFRISConnect connects Manager.io to URA EFRIS. It fiscalises your receipts, invoices and credit notes, registers your goods with URA, keeps URA stock in step with Manager, and prints documents with the URA QR code.%n%nSales still work when the internet is down: they are saved and sent to URA later, or issued by the URA Offline Enabler.%n%nBefore you start: Manager open on this computer, and your URA EFRIS TIN, device number, password and private key.%n%nFree and open source (MIT licence).

[Tasks]
Name: "desktopicon"; Description: "A desktop shortcut to EFRISConnect"; Check: not IsTill
Name: "trayicon"; Description: "The EFRISConnect icon next to the clock, from when you sign in to Windows"; Check: not IsTill

[Registry]
Root: HKLM; Subkey: "Software\EFRISConnect"; ValueType: string; ValueName: "InstallMode"; ValueData: "{code:ModeName}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\EFRISConnect"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"

[Icons]
Name: "{commondesktop}\EFRISConnect"; Filename: "{code:AppBrowserExe}"; Parameters: "--app=https://localhost:5443/extension"; IconFilename: "{app}\efrisconnect.ico"; Comment: "Open EFRISConnect"; Tasks: desktopicon; Check: (not IsTill) and HasAppBrowser
Name: "{commondesktop}\EFRISConnect"; Filename: "{win}\explorer.exe"; Parameters: "https://localhost:5443/extension"; IconFilename: "{app}\efrisconnect.ico"; Comment: "Open EFRISConnect"; Tasks: desktopicon; Check: (not IsTill) and (not HasAppBrowser)
Name: "{commondesktop}\EFRISConnect Control Centre"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\windows\relay-window.vbs"""; IconFilename: "{app}\efrisconnect.ico"; Tasks: desktopicon; Check: not IsTill
Name: "{autoprograms}\EFRISConnect\EFRISConnect Control Centre"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\windows\relay-window.vbs"""; IconFilename: "{app}\efrisconnect.ico"; Comment: "Start, stop and switch on or off everything EFRISConnect runs"; Check: not IsTill
Name: "{autoprograms}\EFRISConnect\EFRISConnect tray icon"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\windows\tray.vbs"""; IconFilename: "{app}\efrisconnect.ico"; AppUserModelID: "TukeiHope.EFRISConnect"; Check: not IsTill
Name: "{commonstartup}\EFRISConnect tray icon"; Filename: "{sys}\wscript.exe"; Parameters: """{app}\windows\tray.vbs"""; IconFilename: "{app}\efrisconnect.ico"; Tasks: trayicon; Check: not IsTill

[INI]
; Web shortcuts carry the EFRISConnect icon (IconFile + IconIndex in the .url file).
Filename: "{autoprograms}\EFRISConnect\EFRISConnect.url"; Section: "InternetShortcut"; Key: "URL"; String: "https://localhost:5443/extension"; Check: not IsTill
Filename: "{autoprograms}\EFRISConnect\EFRISConnect.url"; Section: "InternetShortcut"; Key: "IconFile"; String: "{app}\efrisconnect.ico"; Check: not IsTill
Filename: "{autoprograms}\EFRISConnect\EFRISConnect.url"; Section: "InternetShortcut"; Key: "IconIndex"; String: "0"; Check: not IsTill
Filename: "{autoprograms}\EFRISConnect\Open Manager.url"; Section: "InternetShortcut"; Key: "URL"; String: "https://localhost:{code:MgrHttpsPort}"; Check: IsServer
Filename: "{commondesktop}\Manager (shop).url"; Section: "InternetShortcut"; Key: "URL"; String: "{code:TillManagerUrl}"; Check: IsTill

[InstallDelete]
; The shortcut was renamed in 1.0.8.
Type: files; Name: "{autoprograms}\EFRISConnect\Open EFRISConnect.url"
; 1.0.13: the desktop shortcut is a real shortcut (.lnk) that shows its icon, and the
; Relay window became the Control Centre.
Type: files; Name: "{commondesktop}\EFRISConnect.url"
Type: files; Name: "{autoprograms}\EFRISConnect\EFRISConnect Relay.lnk"

[UninstallDelete]
Type: files; Name: "{autoprograms}\EFRISConnect\Open EFRISConnect.url"
Type: files; Name: "{autoprograms}\EFRISConnect\EFRISConnect.url"
Type: files; Name: "{commondesktop}\EFRISConnect.url"
Type: files; Name: "{autoprograms}\EFRISConnect\Open Manager.url"
Type: files; Name: "{commondesktop}\Manager (shop).url"
Type: dirifempty; Name: "{autoprograms}\EFRISConnect"

[Run]
Filename: "{sys}\wscript.exe"; Parameters: """{app}\windows\tray.vbs"""; Description: "Show the EFRISConnect icon next to the clock"; Flags: postinstall nowait runasoriginaluser; Tasks: trayicon; Check: not IsTill
Filename: "https://localhost:5443/extension"; Description: "Open EFRISConnect now to create the owner account"; Flags: postinstall shellexec nowait runasoriginaluser unchecked; Check: (not IsTill) and (not WasInstalled)
Filename: "https://localhost:5443/extension"; Description: "Open EFRISConnect now"; Flags: postinstall shellexec nowait runasoriginaluser unchecked; Check: (not IsTill) and WasInstalled
Filename: "{code:TillManagerUrl}"; Description: "Open Manager on the shop server"; Flags: postinstall shellexec nowait runasoriginaluser; Check: IsTill

[Code]
var
  ModePage: TInputOptionWizardPage;
  ManagerPage: TInputFileWizardPage;
  PortPage: TInputQueryWizardPage;
  DataPage: TInputDirWizardPage;
  CopyDataBox: TNewCheckBox;
  CopyNote: TNewStaticText;
  TillCertPage: TInputFileWizardPage;
  TillServerPage: TInputQueryWizardPage;
  SetupOk: Boolean;
  Upgrading: Boolean;

// An earlier EFRISConnect on this computer (an upgrade or a re-run, not a first install).
function WasInstalled: Boolean; begin Result := Upgrading; end;

// The browser that opens EFRISConnect in its own app window: Google Chrome, else
// Microsoft Edge (installed for all users, so the shortcut works for everyone).
function AppBrowserExe(Param: String): String;
begin
  Result := ExpandConstant('{commonpf64}\Google\Chrome\Application\chrome.exe');
  if not FileExists(Result) then Result := ExpandConstant('{commonpf32}\Google\Chrome\Application\chrome.exe');
  if not FileExists(Result) then Result := ExpandConstant('{commonpf32}\Microsoft\Edge\Application\msedge.exe');
  if not FileExists(Result) then Result := ExpandConstant('{commonpf64}\Microsoft\Edge\Application\msedge.exe');
end;
function HasAppBrowser: Boolean; begin Result := FileExists(AppBrowserExe('')); end;

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

// The ManagerServer.exe chosen at the last install (saved in the data folder), when it
// is still there; else Manager Server's usual install folders.
function FindManagerServer: String;
var Saved: AnsiString;
begin
  Result := '';
  if LoadStringFromFile(ExpandConstant('{commonappdata}\EFRISConnect\data\manager-server-path.txt'), Saved) and FileExists(Trim(String(Saved))) then
    Result := Trim(String(Saved))
  else if FileExists(ExpandConstant('{commonpf64}\Manager Server\ManagerServer.exe')) then
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

procedure OpenWebsite(Sender: TObject);
var Code: Integer;
begin
  ShellExec('open', 'https://tukeihopeinitiative.org/', '', '', SW_SHOWNORMAL, ewNoWait, Code);
end;

// The green side panel of the Welcome and Finish pages, drawn as text (sharp at any
// display scale, read by screen readers) over the place of the wizard picture.
// Colours as in the extension: header green, light green, gold; Uganda's colours as
// a thin rule. TColor is $BBGGRR.
function SideText(Parent: TWinControl; Text: String; L, T, W, H: Integer; Size: Integer; Bold: Boolean; Color: TColor; Centre: Boolean): TLabel;
begin
  Result := TLabel.Create(WizardForm);
  Result.Parent := Parent;
  Result.AutoSize := False;
  Result.WordWrap := True;
  Result.Transparent := True;
  Result.SetBounds(L, T, W, H);
  Result.Font.Name := 'Segoe UI';
  Result.Font.Size := Size;
  Result.Font.Color := Color;
  if Bold then Result.Font.Style := [fsBold];
  if Centre then Result.Alignment := taCenter;
  Result.ShowAccelChar := False;   // show '&' as itself, not as a shortcut-key underline
  Result.Caption := Text;
end;

procedure SideBar(Parent: TWinControl; L, T, W, H: Integer; Color: TColor);
var P: TPanel;
begin
  P := TPanel.Create(WizardForm);
  P.Parent := Parent;
  P.BevelOuter := bvNone;
  P.ParentBackground := False;
  P.Color := Color;
  P.SetBounds(L, T, W, H);
end;

procedure SidePanel(Pic: TBitmapImage);
var P: TPanel; Logo, WordMark: TBitmapImage; Org: TLabel; Pad, W, Y, I, Seg: Integer; Points: array[0..2] of String;
begin
  Pic.Visible := False;
  P := TPanel.Create(WizardForm);
  P.Parent := Pic.Parent;
  P.BevelOuter := bvNone;
  P.ParentBackground := False;
  P.Color := $205E1B;
  P.SetBounds(Pic.Left, Pic.Top, Pic.Width, Pic.Height);
  Pad := ScaleX(18); W := P.Width - 2 * Pad;

  Logo := TBitmapImage.Create(WizardForm);
  Logo.Parent := P;
  Logo.Stretch := True;
  Logo.SetBounds(Pad, ScaleY(22), ScaleX(44), ScaleY(44));
  Logo.Bitmap.LoadFromFile(ExpandConstant('{tmp}\logo-tile.bmp'));

  // The name as the brand word mark (480 x 53 px picture), not typed text, so Setup
  // matches the logo pack.
  WordMark := TBitmapImage.Create(WizardForm);
  WordMark.Parent := P;
  WordMark.Stretch := True;
  I := W; if I > ScaleX(176) then I := ScaleX(176);
  WordMark.SetBounds(Pad, ScaleY(76), I, I * 53 div 480);
  WordMark.Bitmap.LoadFromFile(ExpandConstant('{tmp}\wordmark-panel.bmp'));
  SideText(P, 'URA EFRIS e-receipts and e-invoices for Manager.io', Pad, ScaleY(100), W, ScaleY(32), 9, False, $C9E6C8, False);
  SideBar(P, Pad, ScaleY(136), ScaleX(28), ScaleY(3), $25A8F9);

  Points[0] := 'Receipts, invoices and credit notes';
  Points[1] := 'Keeps selling when the internet is down';
  Points[2] := 'Your data stays on your computer';
  Y := ScaleY(148);
  for I := 0 to 2 do begin
    SideText(P, #$2713, Pad, Y, ScaleX(16), ScaleY(18), 10, True, $25A8F9, False);
    SideText(P, Points[I], Pad + ScaleX(18), Y, W - ScaleX(18), ScaleY(30), 9, False, $FFFFFF, False);
    Y := Y + ScaleY(32);
  end;

  // Foot: Uganda's colours as a thin rule, then the credit as in the extension's footer.
  // Anchored to the bottom, but never over the points (the panel is shorter on some screens).
  I := Y + ScaleY(6);
  Y := P.Height - ScaleY(114);
  if Y < I then Y := I;
  Seg := W div 3;
  SideBar(P, Pad, Y, Seg, ScaleY(3), $000000);
  SideBar(P, Pad + Seg, Y, Seg, ScaleY(3), $04DCFC);
  SideBar(P, Pad + 2 * Seg, Y, W - 2 * Seg, ScaleY(3), $0000D9);
  Y := Y + ScaleY(9);
  SideText(P, 'EFRISConnect - Free & Open Source', ScaleX(4), Y, P.Width - ScaleX(8), ScaleY(16), 8, True, $FFFFFF, True);
  SideText(P, 'A project of', ScaleX(4), Y + ScaleY(16), P.Width - ScaleX(8), ScaleY(15), 8, False, $C9E6C8, True);
  Org := SideText(P, 'The Tukei Hope Initiative', ScaleX(4), Y + ScaleY(31), P.Width - ScaleX(8), ScaleY(15), 8, True, $25A8F9, True);
  Org.Font.Style := [fsBold, fsUnderline];
  Org.Cursor := crHand;
  Org.OnClick := @OpenWebsite;
  SideText(P, 'Community Based Organisation, Entebbe, Uganda', ScaleX(4), Y + ScaleY(46), P.Width - ScaleX(8), ScaleY(28), 8, False, $C9E6C8, True);
  SideText(P, 'Registration No. EMC/CBO/025' + #13#10 + 'Your Hope, Our Mission', ScaleX(4), Y + ScaleY(74), P.Width - ScaleX(8), ScaleY(30), 8, False, $C9E6C8, True);
end;

procedure InitializeWizard;
var PrevMode, PrevVersion: String; SavedData: AnsiString; Site, Ask, AskHint: TNewStaticText;
begin
  Upgrading := RegQueryStringValue(HKLM, 'Software\EFRISConnect', 'Version', PrevVersion);
  ExtractTemporaryFile('logo-tile.bmp');
  ExtractTemporaryFile('wordmark-panel.bmp');
  SidePanel(WizardForm.WizardBitmapImage);
  SidePanel(WizardForm.WizardBitmapImage2);
  // Long lines in the "Ready to Install" summary wrap instead of running off the edge.
  WizardForm.ReadyMemo.WordWrap := True;
  WizardForm.ReadyMemo.ScrollBars := ssVertical;

  // Under the welcome text: a call to support the work, with the organisation's name
  // as the link to its website (ways to give, contact details).
  WizardForm.AdjustLabelHeight(WizardForm.WelcomeLabel2);
  Ask := TNewStaticText.Create(WizardForm);
  Ask.Parent := WizardForm.WelcomePage;
  Ask.AutoSize := False;
  Ask.WordWrap := True;
  Ask.Left := WizardForm.WelcomeLabel2.Left;
  Ask.Width := WizardForm.WelcomeLabel2.Width;
  Ask.Top := WizardForm.WelcomeLabel2.Top + WizardForm.WelcomeLabel2.Height + ScaleY(10);
  Ask.Height := ScaleY(30);
  Ask.Caption := 'EFRISConnect is free. You can help keep it that way by supporting the work of';
  Site := TNewStaticText.Create(WizardForm);
  Site.Parent := WizardForm.WelcomePage;
  Site.Caption := 'The Tukei Hope Initiative';
  Site.Cursor := crHand;
  Site.Font.Color := clBlue;
  Site.Font.Style := [fsUnderline, fsBold];
  Site.OnClick := @OpenWebsite;
  Site.Left := Ask.Left;
  Site.Top := Ask.Top + Ask.Height;
  AskHint := TNewStaticText.Create(WizardForm);
  AskHint.Parent := WizardForm.WelcomePage;
  AskHint.Caption := 'Click the name to donate or to get in touch.';
  AskHint.Left := Ask.Left;
  AskHint.Top := Site.Top + Site.Height + ScaleY(2);

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
    'If Manager Server Edition is installed here, select ManagerServer.exe. EFRISConnect then runs it ' +
    'in the background from Windows start-up, with no window. Leave it empty if you start Manager Server yourself or it runs elsewhere.');
  ManagerPage.Add('ManagerServer.exe:', 'ManagerServer.exe|ManagerServer.exe|Programs (*.exe)|*.exe', '.exe');
  ManagerPage.Values[0] := FindManagerServer;

  PortPage := CreateInputQueryPage(ManagerPage.ID,
    'Manager Server port', 'Tills reach Manager encrypted at https://' + Lowercase(GetComputerNameString) + ':PORT+1',
    'Use the port Manager Server listens on. 5000 is the usual one.');
  PortPage.Add('Port:', False);
  PortPage.Values[0] := '5000';
  // The port chosen at the last install.
  if LoadStringFromFile(ExpandConstant('{commonappdata}\EFRISConnect\data\lan-manager-port.txt'), SavedData) and IsPort(Trim(String(SavedData))) then
    PortPage.Values[0] := Trim(String(SavedData));

  // Manager Server's data in a local folder, not Documents (often synced by OneDrive).
  DataPage := CreateInputDirPage(PortPage.ID,
    'Manager Server data folder', 'Where Manager Server keeps the businesses.',
    'Use a local folder on this computer. Avoid OneDrive or Google Drive folders: they sync the ' +
    'business file while Manager Server writes to it. Back up with Manager''s own backup instead.',
    False, '');
  DataPage.Add('Data folder:');
  DataPage.Values[0] := ExpandConstant('{commonappdata}\Manager.io');
  if LoadStringFromFile(ExpandConstant('{commonappdata}\EFRISConnect\data\manager-server-data.txt'), SavedData) and (Trim(String(SavedData)) <> '') then
    DataPage.Values[0] := Trim(String(SavedData));
  CopyDataBox := TNewCheckBox.Create(DataPage);
  CopyDataBox.Parent := DataPage.Surface;
  CopyDataBox.Top := DataPage.Edits[0].Top + DataPage.Edits[0].Height + ScaleY(16);
  CopyDataBox.Width := DataPage.SurfaceWidth;
  CopyDataBox.Height := ScaleY(20);
  CopyDataBox.Caption := 'Copy my current Manager data into this folder if it is empty';
  CopyDataBox.Checked := True;
  // The detail on its own wrapping line (a tick box caption does not wrap).
  CopyNote := TNewStaticText.Create(DataPage);
  CopyNote.Parent := DataPage.Surface;
  CopyNote.Top := CopyDataBox.Top + CopyDataBox.Height + ScaleY(4);
  CopyNote.Left := ScaleX(18);
  CopyNote.AutoSize := False;
  CopyNote.WordWrap := True;
  CopyNote.Width := DataPage.SurfaceWidth - ScaleX(18);
  CopyNote.Height := ScaleY(32);
  CopyNote.Caption := 'From Documents\Manager.io. Close Manager first. The original is kept as a backup.';

  // No page for the EFRIS private key: it is pasted in EFRISConnect (Settings >
  // EFRIS Credentials), where it is stored encrypted, never as a plain file.

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
  else if PageID = DataPage.ID then Result := (not IsServer) or (Trim(ManagerPage.Values[0]) = '')
  else if (PageID = TillCertPage.ID) or (PageID = TillServerPage.ID) then Result := not IsTill
  else if PageID = wpSelectDir then Result := IsTill;
end;

function EnablerInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\TcsTomcat') and RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\TcsData');
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := 'This computer:' + NewLine + Space;
  if IsTill then Result := Result + 'Till (trusts the shop server, nothing runs here)'
  else if IsServer then Result := Result + 'Shop server (other computers connect to it)'
  else Result := Result + 'This computer only';
  if IsServer then begin
    Result := Result + NewLine + NewLine + 'Manager Server:' + NewLine + Space;
    if Trim(ManagerPage.Values[0]) = '' then Result := Result + 'started by you (not by EFRISConnect)'
    else Result := Result + ManagerPage.Values[0] + NewLine + Space + 'Data folder: ' + DataPage.Values[0] +
      NewLine + Space + 'Runs in the background from Windows start-up (no window)';
    Result := Result + NewLine + Space + 'Port: ' + MgrPort('') + ' (tills use https://' + Lowercase(GetComputerNameString) + ':' + MgrHttpsPort('') + ')';
  end;
  if MemoDirInfo <> '' then Result := Result + NewLine + NewLine + MemoDirInfo;
  if MemoTasksInfo <> '' then Result := Result + NewLine + NewLine + MemoTasksInfo;
  if not IsTill then begin
    Result := Result + NewLine + NewLine + 'Starts with Windows:' + NewLine + Space + 'EFRISConnect runs in the background from start-up, so receipts work before anyone signs in.';
    Result := Result + NewLine + NewLine + 'URA Offline Enabler:' + NewLine + Space;
    if EnablerInstalled then Result := Result + 'found on this computer; it will start with Windows (its database first) and restart if it stops.'
    else Result := Result + 'not found. Optional: install it from URA only if you must issue receipts with no internet at all.';
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = ManagerPage.ID) and (Trim(ManagerPage.Values[0]) <> '') and not FileExists(ManagerPage.Values[0]) then begin
    MsgBox('ManagerServer.exe was not found at that path.', mbError, MB_OK); Result := False;
  end else if (CurPageID = PortPage.ID) and not IsPort(PortPage.Values[0]) then begin
    MsgBox('Enter a port number between 1 and 65535.', mbError, MB_OK); Result := False;
  end else if (CurPageID = DataPage.ID) and (Trim(DataPage.Values[0]) = '') then begin
    MsgBox('Choose a folder for Manager Server''s data.', mbError, MB_OK); Result := False;
  end else if (CurPageID = DataPage.ID) and ((Pos('onedrive', Lowercase(DataPage.Values[0])) > 0) or (Pos('google drive', Lowercase(DataPage.Values[0])) > 0)) then begin
    Result := MsgBox('That folder looks like a OneDrive or Google Drive folder. Syncing it while Manager Server writes to it can damage the business file.' + #13#10#13#10 +
      'Use it anyway?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
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
        if Trim(ManagerPage.Values[0]) <> '' then begin
          Args := Args + ' -ManagerExe ' + Q(ManagerPage.Values[0]) + ' -ManagerData ' + Q(DataPage.Values[0]);
          if CopyDataBox.Checked then Args := Args + ' -CopyManagerData';
        end;
      end;
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
      'For each till: copy C:\ProgramData\EFRISConnect\data\till-kit to a USB stick and run this Setup there (choose "Till").'
  else
    WizardForm.FinishedLabel.Caption :=
      'EFRISConnect starts with Windows.' + #13#10#13#10 +
      'Manager custom button URL (every EFRISConnect button):' + #13#10 +
      '    https://localhost:5443/extension' + #13#10#13#10 +
      'The icon next to the clock shows the status and has Restart, Logs and Copy URL.';
  // Size the text to its lines and put the options below it (they covered the last lines).
  WizardForm.AdjustLabelHeight(WizardForm.FinishedLabel);
  WizardForm.RunList.Top := WizardForm.FinishedLabel.Top + WizardForm.FinishedLabel.Height + ScaleY(12);
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
