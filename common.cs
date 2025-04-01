using System;
using System.Runtime.InteropServices;

namespace PSDetourHooks;

public static class Methods
{
    public const int CERT_STORE_LOCALIZED_NAME_PROP_ID = 0x1000;

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

    [DllImport("Crypt32.dll")]
    public static extern bool CertGetStoreProperty(
        nint hCertStore,
        int dwPropId,
        nint pvData,
        ref int pcbData);
}
