using System;
using System.Runtime.InteropServices;

namespace Wintrust;

[StructLayout(LayoutKind.Sequential)]
public struct WINTRUST_DATA
{
    public int cbStruct;
    public nint pPolicyCallbackData;
    public nint pSIPClientData;
    public int dwUIChoice;
    public int fdwRevocationChecks;
    public int dwUnionChoice;
    public nint unionData;
    public int dwStateAction;
    public nint hWVTStateData;
    public nint pwszURLReference;
    public int dwProvFlags;
    public int dwUIContext;
    public nint pSignatureSettings;
}

[StructLayout(LayoutKind.Sequential)]
public struct WINTRUST_FILE_INFO
{
    public int cbStruct;
    public nint pcwszFilePath;
    public nint hFile;
    public nint pgKnownSubject;
}

[StructLayout(LayoutKind.Sequential)]
public struct WINTRUST_CATALOG_INFO
{
    public int cbStruct;
    public int dwCatalogVersion;
    public nint pcwszCatalogFilePath;
    public nint pcwszMemberTag;
    public nint pcwszMemberFilePath;
    public nint hMemberFile;
    public nint pbCalculatedFileHash;
    public int cbCalculatedFileHash;
    public nint pcCatalogContext;
    public nint hCatAdmin;
}

[StructLayout(LayoutKind.Sequential)]
public struct WINTRUST_BLOB_INFO
{
    public int cbStruct;
    public Guid gSubject;
    public nint pcwszDisplayName;
    public int cbMemObject;
    public nint pbMemObject;
    public int cbMemSignedMsg;
    public nint pbMemSignedMsg;
}

public enum TrustDataUIChoice
{
    WTD_UI_ALL = 1,
    WTD_UI_NONE = 2,
    WTD_UI_NOBAD = 3,
    WTD_UI_NOGOOD = 4,
}

[Flags]
public enum TrustDataRevocationChecks
{
    WTD_REVOKE_NONE = 0x00000000,
    WTD_REVOKE_WHOLECHAIN = 0x00000001,
}

public enum TrustDataUnionChoice
{
    WTD_CHOICE_FILE = 1,
    WTD_CHOICE_CATALOG = 2,
    WTD_CHOICE_BLOB = 3,
    WTD_CHOICE_SIGNER = 4,
    WTD_CHOICE_CERT = 5,
}

[Flags]
public enum TrustDataStateAction
{
    WTD_STATEACTION_IGNORE = 0x00000000,
    WTD_STATEACTION_VERIFY = 0x00000001,
    WTD_STATEACTION_CLOSE = 0x00000002,
    WTD_STATEACTION_AUTO_CACHE = 0x00000003,
    WTD_STATEACTION_AUTO_CACHE_FLUSH = 0x00000004,
}

[Flags]
public enum TrustDataProvFlags
{
    WTD_PROV_FLAGS_MASK = 0x0000FFFF,
    WTD_USE_IE4_TRUST_FLAG = 0x00000001,
    WTD_NO_IE4_CHAIN_FLAG = 0x00000002,
    WTD_NO_POLICY_USAGE_FLAG = 0x00000004,
    WTD_REVOCATION_CHECK_NONE = 0x00000010,
    WTD_REVOCATION_CHECK_END_CERT = 0x00000020,
    WTD_REVOCATION_CHECK_CHAIN = 0x00000040,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000080,
    WTD_SAFER_FLAG = 0x00000100,
    WTD_HASH_ONLY_FLAG = 0x00000200,
    WTD_USE_DEFAULT_OSVER_CHECK = 0x00000400,
    WTD_LIFETIME_SIGNING_FLAG = 0x00000800,
    WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000,
    WTD_DISABLE_MD2_MD4 = 0x00002000,
    WTD_MOTW = 0x00004000,
    WTD_CODE_INTEGRITY_DRIVER_MODE = 0x00008000,
}

public enum TrustDataUIContext
{
    WTD_UICONTEXT_EXECUTE = 0,
    WTD_UICONTEXT_INSTALL = 1,
}
