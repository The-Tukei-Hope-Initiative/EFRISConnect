# EFRISConnect - turn off "QuickEdit" in the current console window.
# With QuickEdit on, a click inside the relay window starts a text selection and
# Windows pauses the relay until it ends: every till then waits. Run by the
# launcher just before it starts the relay (the setting belongs to the window).
$sig = @'
[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int h);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out int m);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, int m);
'@
try {
  $k = Add-Type -Name ConsoleMode -Namespace EFRISConnect -MemberDefinition $sig -PassThru
  $h = $k::GetStdHandle(-10)   # console input
  $m = 0
  if ($k::GetConsoleMode($h, [ref]$m)) {
    # Clear ENABLE_QUICK_EDIT_MODE (0x40); ENABLE_EXTENDED_FLAGS (0x80) makes it stick.
    [void]$k::SetConsoleMode($h, (($m -band (-bnot 0x40)) -bor 0x80))
  }
} catch {}
