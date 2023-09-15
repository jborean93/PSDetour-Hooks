using System;
using System.Runtime.InteropServices;

namespace PSDetourHooks;

public static class Methods
{
    [DllImport("Kernel32.dll")]
    public static extern int GetCurrentThreadId();
}
