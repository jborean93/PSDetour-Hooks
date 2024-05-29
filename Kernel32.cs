using System;
using System.Runtime.InteropServices;

namespace Kernel32;

[Flags]
public enum ConsoleFill
{
    None = 0x00000000,
    FOREGROUND_BLUE = 0x00000001,
    FOREGROUND_GREEN = 0x00000002,
    FOREGROUND_RED = 0x00000004,
    FOREGROUND_INTENSITY = 0x00000008,
    BACKGROUND_BLUE = 0x00000010,
    BACKGROUND_GREEN = 0x00000020,
    BACKGROUND_RED = 0x00000040,
    BACKGROUND_INTENSITY = 0x00000080,
}

[Flags]
public enum ExtendedProcessCreationFlags
{
    EXTENDED_PROCESS_CREATION_FLAG_ELEVATION_HANDLED = 0x00000001,
    EXTENDED_PROCESS_CREATION_FLAG_FORCELUA = 0x00000002,
    EXTENDED_PROCESS_CREATION_FLAG_FORCE_BREAKAWAY = 0x00000004,
}

[Flags]
public enum LogonFlags
{
    None = 0x00000000,
    LOGON_WITH_PROFILE = 0x00000001,
    LOGON_NETCREDENTIALS_ONLY = 0x00000002,
}

[Flags]
public enum ProcessAccessMask
{
    PROCESS_TERMINATE = 0x00000001,
    PROCESS_CREATE_THREAD = 0x00000002,
    PROCESS_VM_OPERATION = 0x00000008,
    PROCESS_VM_READ = 0x00000010,
    PROCESS_VM_WRITE = 0x00000020,
    PROCESS_DUP_HANDLE = 0x00000040,
    PROCESS_CREATE_PROCESS = 0x00000080,
    PROCESS_SET_QUOTA = 0x00000100,
    PROCESS_SET_INFORMATION = 0x00000200,
    PROCESS_QUERY_INFORMATION = 0x00000400,
    PROCESS_SUSPEND_RESUME = 0x00000800,
    PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,

    DELETE = 0x00010000,
    READ_CONTROL = 0x00020000,
    WRITE_DAC = 0x00040000,
    WRITE_OWNER = 0x00080000,
    SYNCHRONIZE = 0x00100000,
    ACCESS_SYSTEM_SECURITY = 0x01000000,

    STANDARD_RIGHTS_ALL = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE,
    STANDARD_RIGHTS_EXECUTE = READ_CONTROL,
    STANDARD_RIGHTS_READ = READ_CONTROL,
    STANDARD_RIGHTS_REQUIED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
    STANDARD_RIGHTS_WRITE = READ_CONTROL,

    GENERIC_ALL = 0x10000000,
    GENERIC_EXECUTE = 0x20000000,
    GENERIC_WRITE = 0x40000000,
    GENERIC_READ = unchecked((int)0x800000000),

    PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIED | SYNCHRONIZE | 0x1FFF,
}

[Flags]
public enum ProcessCreationFlags
{
    None = 0x00000000,
    DEBUG_PROCESS = 0x00000001,
    DEBUG_ONLY_THIS_PROCESS = 0x00000002,
    CREATE_SUSPENDED = 0x00000004,
    DETACHED_PROCESS = 0x00000008,
    CREATE_NEW_CONSOLE = 0x00000010,
    NORMAL_PRIORITY_CLASS = 0x00000020,
    IDLE_PRIORITY_CLASS = 0x00000040,
    HIGH_PRIORITY_CLASS = 0x00000080,
    REALTIME_PRIORITY_CLASS = 0x00000100,
    CREATE_NEW_PROCESS_GROUP = 0x00000200,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    CREATE_SEPARATE_WOW_VDM = 0x00000800,
    CREATE_SHARED_WOW_VDM = 0x00001000,
    CREATE_FORCEDOS = 0x00002000,
    BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
    ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
    INHERIT_PARENT_AFFINITY = 0x00010000,
    INHERIT_CALLER_PRIORITY = 0x00020000,
    CREATE_PROTECTED_PROCESS = 0x00040000,
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
    PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
    PROCESS_MODE_BACKGROUND_END = 0x00200000,
    CREATE_SECURE_PROCESS = 0x00400000,
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
    CREATE_DEFAULT_ERROR_MODE = 0x04000000,
    CREATE_NO_WINDOW = 0x08000000,
    PROFILE_USER = 0x10000000,
    PROFILE_KERNEL = 0x20000000,
    PROFILE_SERVER = 0x40000000,
    CREATE_IGNORE_SYSTEM_DEFAULT = unchecked((int)0x80000000),
}

[Flags]
public enum ProcessThreadAttributeFlags
{
    PROC_THREAD_ATTRIBUTE_NUMBER = 0x0000FFFF,
    PROC_THREAD_ATTRIBUTE_THREAD = 0x00010000,  // Attribute may be used with thread creation
    PROC_THREAD_ATTRIBUTE_INPUT = 0x00020000,  // Attribute is input only
    PROC_THREAD_ATTRIBUTE_ADDITIVE = 0x00040000,  // Attribute may be "accumulated," e.g. bitmasks, counters, etc.
}

public enum ProcessThreadAttribute
{
    ProcThreadAttributeParentProcess = 0,
    ProcThreadAttributeExtendedFlags = 1,
    ProcThreadAttributeHandleList = 2,
    ProcThreadAttributeGroupAffinity = 3,
    ProcThreadAttributePreferredNode = 4,
    ProcThreadAttributeIdealProcessor = 5,
    ProcThreadAttributeUmsThread = 6,
    ProcThreadAttributeMitigationPolicy = 7,
    ProcThreadAttributePackageFullName = 8,
    ProcThreadAttributeSecurityCapabilities = 9,
    ProcThreadAttributeConsoleReference = 10,
    ProcThreadAttributeProtectionLevel = 11,
    ProcThreadAttributeOsMaxVersionTested = 12,
    ProcThreadAttributeJobList = 13,
    ProcThreadAttributeChildProcessPolicy = 14,
    ProcThreadAttributeAllApplicationPackagesPolicy = 15,
    ProcThreadAttributeWin32kFilter = 16,
    ProcThreadAttributeSafeOpenPromptOriginClaim = 17,
    ProcThreadAttributeDesktopAppPolicy = 18,
    ProcThreadAttributeBnoIsolation = 19,
    ProcThreadAttributePseudoConsole = 22,
    ProcThreadAttributeIsolationManifest = 23,
    ProcThreadAttributeMitigationAuditPolicy = 0x0002420018,
    ProcThreadAttributeMachineType = 25,
    ProcThreadAttributeComponentFilter = 26,
    ProcThreadAttributeEnableOptionalXStateFeatures = 27,
    ProcThreadAttributeCreateStore = 28,
    ProcThreadAttributeTrustedApp = 29,
}

[Flags]
public enum StartupInfoFlags : int
{
    None = 0x00000000,
    STARTF_USESHOWWINDOW = 0x00000001,
    STARTF_USESIZE = 0x00000002,
    STARTF_USEPOSITION = 0x00000004,
    STARTF_USECOUNTCHARS = 0x00000008,
    STARTF_USEFILLATTRIBUTE = 0x00000010,
    STARTF_RUNFULLSCREEN = 0x00000020,
    STARTF_FORCEONFEEDBACK = 0x00000040,
    STARTF_FORCEOFFFEEDBACK = 0x00000080,
    STARTF_USESTDHANDLES = 0x00000100,
    STARTF_USEHOTKEY = 0x00000200,
    STARTF_TITLEISLINKNAME = 0x00000800,
    STARTF_TITLEISAPPID = 0x00001000,
    STARTF_PREVENTPINNING = 0x00002000,
    STARTF_UNTRUSTEDSOURCE = 0x00008000,
}

public enum WindowStyle : short
{
    SW_HIDE = 0x0000,
    SW_SHOWNORMAL = 0x0001,
    SW_NORMAL = SW_SHOWNORMAL,
    SW_SHOWMINIMIZED = 0x0002,
    SW_SHOWMAXIMIZED = 0x0003,
    SW_MAXIMIZE = SW_SHOWMAXIMIZED,
    SW_SHOWNOACTIVATE = 0x0004,
    SW_SHOW = 0x0005,
    SW_MINIMIZE = 0x0006,
    SW_SHOWMINNOACTIVE = 0x0007,
    SW_SHOWNA = 0x0008,
    SW_RESTORE = 0x0009,
    SW_SHOWDEFAULT = 0x0010,
    SW_FORCEMINIMIZE = 0x0011,
}

// The PROC_THREAD_ATTRIBUTE_* structs are undocumented so this is a best guess.
// http://www.rohitab.com/discuss/topic/38601-proc-thread-attribute-list-structure-documentation/
// https://github.com/winsiderss/phnt/blob/master/ntpsapi.h
[StructLayout(LayoutKind.Sequential)]
public struct PROC_THREAD_ATTRIBUTE_ENTRY
{
    public nint Attribute;
    public nint Size;
    public nint Value;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROC_THREAD_ATTRIBUTE_LIST
{
    public int dwFlags;
    public int dwMaximumCount;
    public int dwActualCount;
    public int dwUnknown1;
    public nint ExtendedFlagsAttribute; // Pointer to PROC_THREAD_ATTRIBUTE_ENTRY of ProcThreadAttributeExtendedFlags if present
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public PROC_THREAD_ATTRIBUTE_ENTRY[] Entries;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public nint hProcess;
    public nint hThread;
    public int dwProcessId;
    public int dwThreadId;
}


[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
    public int nLength;
    public nint lpSecurityDescriptor;
    public bool bInheritHandle;
}

[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFOW
{
    public int cb;
    public nint lpReserved;
    public nint lpDesktop;
    public nint lpTitle;
    public int dwX;
    public int dwY;
    public int dwXSize;
    public int dwYSize;
    public int dwXCountChars;
    public int dwYCountChars;
    public int dwFillAttribute;
    public int dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public nint lpReserved2;
    public nint hStdInput;
    public nint hStdOutput;
    public nint hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFOEXW
{
    public STARTUPINFOW StartupInfo;
    public nint lpAttributeList;
}

public static class Methods
{
    [DllImport("Kernel32.dll")]
    public static extern int GetProcessId(
        nint Process
    );
}
