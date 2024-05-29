# PSDetour-Hooks

This is a collection of hooks that can be used with the PowerShell module [PSDetour](https://github.com/jborean93/PSDetour).
They are sorted by dll and are designed for auditing the calls at runtime.

The functions are designed to work with the `Trace-PSDetourProcess` cmdlet.

```powershell
# The keys correspond to the filenames in this repository which in turn are the
# dlls that contain the functions defined in them. The value is a list of
# methods hook in those names. It supports matching through simple pattern
# matching using the -like operator.
$desiredHooks = @{
    Kernel32 = 'OpenProcess', 'GetProcessId'
    Secur32 = '*Message'
    BCrypt = 'BCrypt*'
}

. ./Trace-Process $desiredHooks -OutputFormat Yaml -Id 1234
```

Make sure the following modules have been installed.

```powershell
Install-Module -Name PSDetour, Yayaml -Force -Scope AllUsers
```

_note: using AllUsers is needed for the hooked processes to see the modules._

See [Windows API Sets](https://learn.microsoft.com/en-us/uwp/win32-and-com/win32-apis) to find out if an API should be loaded through the DLL name or the API set name.
