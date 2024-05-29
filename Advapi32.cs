using System;
using System.Runtime.InteropServices;

namespace Advapi32;

public enum CryptGetProvParam
{
    PP_ENUMALGS = 1,
    PP_ENUMCONTAINERS = 2,
    PP_IMPTYPE = 3,
    PP_NAME = 4,
    PP_VERSION = 5,
    PP_CONTAINER = 6,
    PP_CHANGE_PASSWORD = 7,
    PP_KEYSET_SEC_DESCR = 8,
    PP_CERTCHAIN = 9,
    PP_KEY_TYPE_SUBTYPE = 10,
    PP_PROVTYPE = 16,
    PP_KEYSTORAGE = 17,
    PP_APPLI_CERT = 18,
    PP_SYM_KEYSIZE = 19,
    PP_SESSION_KEYSIZE = 20,
    PP_UI_PROMPT = 21,
    PP_ENUMALGS_EX = 22,
    PP_ENUMMANDROOTS = 25,
    PP_ENUMELECTROOTS = 26,
    PP_KEYSET_TYPE = 27,
    PP_ADMIN_PIN = 31,
    PP_KEYEXCHANGE_PIN = 32,
    PP_SIGNATURE_PIN = 33,
    PP_SIG_KEYSIZE_INC = 34,
    PP_KEYX_KEYSIZE_INC = 35,
    PP_UNIQUE_CONTAINER = 36,
    PP_SGC_INFO = 37,
    PP_USE_HARDWARE_RNG = 38,
    PP_KEYSPEC = 39,
    PP_ENUMEX_SIGNING_PROT = 40,
    PP_CRYPT_COUNT_KEY_USE = 41,
    PP_USER_CERTSTORE = 42,
    PP_SMARTCARD_READER = 43,
    PP_SMARTCARD_GUID = 45,
    PP_ROOT_CERTSTORE = 46,
    PP_SMARTCARD_READER_ICON = 47,
}

public enum SeObjectType
{
    SE_UNKNOWN_OBJECT_TYPE,
    SE_FILE_OBJECT,
    SE_SERVICE,
    SE_PRINTER,
    SE_REGISTRY_KEY,
    SE_LMSHARE,
    SE_KERNEL_OBJECT,
    SE_WINDOW_OBJECT,
    SE_DS_OBJECT,
    SE_DS_OBJECT_ALL,
    SE_PROVIDER_DEFINED_OBJECT,
    SE_WMIGUID_OBJECT,
    SE_REGISTRY_WOW64_32KEY,
    SE_REGISTRY_WOW64_64KEY
}

[Flags]
public enum SecurityInformation
{
    OWNER_SECURITY_INFORMATION = 0x00000001,
    GROUP_SECURITY_INFORMATION = 0x00000002,
    DACL_SECURITY_INFORMATION = 0x00000004,
    SACL_SECURITY_INFORMATION = 0x00000008,
    LABEL_SECURITY_INFORMATION = 0x00000010,
    ATTRIBUTE_SECURITY_INFORMATION = 0x00000020,
    SCOPE_SECURITY_INFORMATION = 0x00000040,
    PROCESS_TRUST_LABEL_SECURITY_INFORMATION = 0x00000080,
    ACCESS_FILTER_SECURITY_INFORMATION = 0x00000100,
    BACKUP_SECURITY_INFORMATION = 0x00010000,
    PROTECTED_DACL_SECURITY_INFORMATION = unchecked((int)0x80000000),
    PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
    UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
    UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
}

[StructLayout(LayoutKind.Sequential)]
public struct GENERIC_MAPPING
{
    public int GenericRead;
    public int GenericWrite;
    public int GenericExecute;
    public int GenericAll;

}

public static class Methods
{
    [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
        nint SecurityDescriptor,
        int RequestedStringSDRevision,
        int SecurityInformation,
        out nint StringSecurityDescriptor,
        out int StringSecurityDescriptorLen);
}
