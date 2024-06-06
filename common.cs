using System;
using System.Runtime.InteropServices;

namespace PSDetourHooks;

public static class Methods
{
    [DllImport("Kernel32.dll")]
    public static extern int GetCurrentThreadId();

    [DllImport("Kernel32.dll")]
    public static extern nint LocalFree(
        nint hMem);

    [DllImport("Advapi32.dll")]
    public static extern int GetSecurityDescriptorLength(
        nint pSecurityDescriptor
    );

    [DllImport("Advapi32.dll")]
    public static extern int LsaNtStatusToWinError(
        int Status);
}
