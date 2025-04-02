using System;
using System.Runtime.InteropServices;

namespace Secur32;

[StructLayout(LayoutKind.Sequential)]
public struct CERT_CONTEXT
{
    public int dwCertEncodingType;
    public nint pbCertEncoded;
    public int cbCertEncoded;
    public nint pCertInfo;
    public nint hCertStore;
}

[StructLayout(LayoutKind.Sequential)]
public struct CREDSSP_CRED
{
    public int Type;
    public nint pSchannelCred;
    public nint pSpnegoCred;
}

[StructLayout(LayoutKind.Sequential)]
public struct CREDSSP_CRED_EX
{
    public int Type;
    public int Version;
    public int Flags;
    public int Reserved;
    public CREDSSP_CRED Cred;
}

[StructLayout(LayoutKind.Sequential)]
public struct LUID
{
    public int LowPart;
    public int HighPart;
}

[StructLayout(LayoutKind.Sequential)]
public struct LSA_STRING
{
    public short Length;
    public short MaximumLength;
    public nint Buffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct QUOTA_LIMITS
{
    public nint PagedPoolLimit;
    public nint NonPagedPoolLimit;
    public nint MinimumWorkingSetSize;
    public nint MaximumWorkingSetSize;
    public nint PagefileLimit;
    public long TimeLimit;
}

[StructLayout(LayoutKind.Sequential)]
public struct SCHANNEL_CRED
{
    public int dwVersion;
    public int cCreds;
    public nint paCred;
    public nint hRootStore;
    public int cMappers;
    public nint aphMappers;
    public int cSupportedAlgs;
    public nint palgSupportedAlgs;
    public int grbitEnabledProtocols;
    public int dwMinimumCipherStrength;
    public int dwMaximumCipherStrength;
    public int dwSessionLifespan;
    public int dwFlags;
    public int dwCredFormat;
}

[StructLayout(LayoutKind.Sequential)]
public struct SCH_CREDENTIALS
{
    public int dwVersion;
    public SchannelCredFormat dwCredFormat;
    public int cCreds;
    public nint paCred;
    public nint hRootStore;
    public int cMappers;
    public nint aphMappers;
    public int dwSessionLifespan;
    public SchannelCredFlags dwFlags;
    public int cTlsParameters;
    public nint pTlsParameters;
}

[StructLayout(LayoutKind.Sequential)]
public struct SEC_WINNT_AUTH_IDENTITY
{
    public nint User;
    public int UserLength;
    public nint Domain;
    public int DomainLength;
    public nint Password;
    public int PasswordLength;
    public int Flags;
}

[StructLayout(LayoutKind.Sequential)]
public struct SEC_WINNT_AUTH_IDENTITY_EX
{
    public int Version;
    public int Length;
    public nint User;
    public int UserLength;
    public nint Domain;
    public int DomainLength;
    public nint Password;
    public int PasswordLength;
    public int Flags;
    public nint PackageList;
    public int PackageListLength;
}


[StructLayout(LayoutKind.Sequential)]
public struct SEC_WINNT_AUTH_IDENTITY_EX2
{
    public int Version;
    public short cbHeaderLength;
    public int sbStructureLength;
    public int UserOffset;
    public short UserLength;
    public int DomainOffset;
    public short DomainLength;
    public int PackedCredentialsOffset;
    public short PackedCredentialsLength;
    public int Flags;
    public int PackageListOffset;
    public short PackageListLength;
}

[StructLayout(LayoutKind.Sequential)]
public struct SecBufferDesc
{
    public int ulVersion;
    public int cBuffer;
    public nint pBuffers;
}

[StructLayout(LayoutKind.Sequential)]
public struct SecBuffer
{
    public int cbBuffer;
    public int BufferType;
    public nint pvBuffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct SID_AND_ATTRIBUTES
{
    public nint Sid;
    public int Attributes;
}

[StructLayout(LayoutKind.Sequential)]
public struct TOKEN_GROUPS
{
    public int GroupCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public SID_AND_ATTRIBUTES[] Groups;
}

[StructLayout(LayoutKind.Sequential)]
public struct TOKEN_SOURCE
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public char[] SourceName;
    public LUID SourceIdentifier;
}

public enum AlgorithmId
{
    // Algorithm Classes
    ALG_CLASS_ANY = 0,
    ALG_CLASS_SIGNATURE = 1 << 13,
    ALG_CLASS_MSG_ENCRYPT = 2 << 13,
    ALG_CLASS_DATA_ENCRYPT = 3 << 13,
    ALG_CLASS_HASH = 4 << 13,
    ALG_CLASS_KEY_EXCHANGE = 5 << 13,
    ALG_CLASS_ALL = 7 << 13,

    // Algorithm Types
    ALG_TYPE_ANY = 0,
    ALG_TYPE_DSS = 1 << 9,
    ALG_TYPE_RSA = 2 << 9,
    ALG_TYPE_BLOCK = 3 << 9,
    ALG_TYPE_STREAM = 4 << 9,
    ALG_TYPE_DH = 5 << 9,
    ALG_TYPE_SECURECHANNEL = 6 << 9,
    ALG_TYPE_ECDH = 7 << 9,
    ALG_TYPE_THIRDPARTY = 8 << 9,

    // Algorithm Sub Ids
    ALG_SID_ANY = 0,

    // Generic ThirdParty sub-ids
    ALG_SID_THIRDPARTY_ANY = 0,

    // Some RSA sub-ids
    ALG_SID_RSA_ANY = 0,
    ALG_SID_RSA_PKCS = 1,
    ALG_SID_RSA_MSATWORK = 2,
    ALG_SID_RSA_ENTRUST = 3,
    ALG_SID_RSA_PGP = 4,

    // Some DSS sub-ids
    ALG_SID_DSS_ANY = 0,
    ALG_SID_DSS_PKCS = 1,
    ALG_SID_DSS_DMS = 2,
    ALG_SID_ECDSA = 3,

    // Block cipher sub ids
    ALG_SID_DES = 1,
    ALG_SID_3DES = 3,
    ALG_SID_DESX = 4,
    ALG_SID_IDEA = 5,
    ALG_SID_CAST = 6,
    ALG_SID_SAFERSK64 = 7,
    ALG_SID_SAFERSK128 = 8,
    ALG_SID_3DES_112 = 9,
    ALG_SID_CYLINK_MEK = 12,
    ALG_SID_RC5 = 13,
    ALG_SID_AES_128 = 14,
    ALG_SID_AES_192 = 15,
    ALG_SID_AES_256 = 16,
    ALG_SID_AES = 17,

    // Fortezza sub-ids
    ALG_SID_SKIPJACK = 10,
    ALG_SID_TEK = 11,

    // RC2 sub-ids
    ALG_SID_RC2 = 2,

    // Stream cipher sub-ids
    ALG_SID_RC4 = 1,
    ALG_SID_SEAL = 2,

    // Diffie-Hellman sub-ids
    ALG_SID_DH_SANDF = 1,
    ALG_SID_DH_EPHEM = 2,
    ALG_SID_AGREED_KEY_ANY = 3,
    ALG_SID_KEA = 4,
    ALG_SID_ECDH = 5,
    ALG_SID_ECDH_EPHEM = 6,

    // Hash sub ids
    ALG_SID_MD2 = 1,
    ALG_SID_MD4 = 2,
    ALG_SID_MD5 = 3,
    ALG_SID_SHA = 4,
    ALG_SID_SHA1 = 4,
    ALG_SID_MAC = 5,
    ALG_SID_RIPEMD = 6,
    ALG_SID_RIPEMD160 = 7,
    ALG_SID_SSL3SHAMD5 = 8,
    ALG_SID_HMAC = 9,
    ALG_SID_TLS1PRF = 10,
    ALG_SID_HASH_REPLACE_OWF = 11,
    ALG_SID_SHA_256 = 12,
    ALG_SID_SHA_384 = 13,
    ALG_SID_SHA_512 = 14,
    ALG_SID_SSL3_MASTER = 1,
    ALG_SID_SCHANNEL_MASTER_HASH = 2,
    ALG_SID_SCHANNEL_MAC_KEY = 3,
    ALG_SID_PCT1_MASTER = 4,
    ALG_SID_SSL2_MASTER = 5,
    ALG_SID_TLS1_MASTER = 6,
    ALG_SID_SCHANNEL_ENC_KEY = 7,
    ALG_SID_ECMQV = 1,

    CALG_MD2 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD2,
    CALG_MD4 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD4,
    CALG_MD5 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MD5,
    CALG_SHA = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA,
    CALG_SHA1 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA1,
    CALG_MAC = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_MAC,
    CALG_RSA_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_RSA | ALG_SID_RSA_ANY,
    CALG_DSS_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_DSS_ANY,
    CALG_NO_SIGN = ALG_CLASS_SIGNATURE | ALG_TYPE_ANY | ALG_SID_ANY,
    CALG_RSA_KEYX = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY,
    CALG_DES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DES,
    CALG_3DES_112 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES_112,
    CALG_3DES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_3DES,
    CALG_DESX = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_DESX,
    CALG_RC2 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC2,
    CALG_RC4 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_RC4,
    CALG_SEAL = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_STREAM | ALG_SID_SEAL,
    CALG_DH_SF = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_SANDF,
    CALG_DH_EPHEM = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_DH_EPHEM,
    CALG_AGREEDKEY_ANY = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_AGREED_KEY_ANY,
    CALG_KEA_KEYX = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_KEA,
    CALG_HUGHES_MD5 = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_MD5,
    CALG_SKIPJACK = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_SKIPJACK,
    CALG_TEK = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_TEK,
    CALG_CYLINK_MEK = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_CYLINK_MEK,
    CALG_SSL3_SHAMD5 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SSL3SHAMD5,
    CALG_SSL3_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL3_MASTER,
    CALG_SCHANNEL_MASTER_HASH = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MASTER_HASH,
    CALG_SCHANNEL_MAC_KEY = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_MAC_KEY,
    CALG_SCHANNEL_ENC_KEY = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SCHANNEL_ENC_KEY,
    CALG_PCT1_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_PCT1_MASTER,
    CALG_SSL2_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_SSL2_MASTER,
    CALG_TLS1_MASTER = ALG_CLASS_MSG_ENCRYPT | ALG_TYPE_SECURECHANNEL | ALG_SID_TLS1_MASTER,
    CALG_RC5 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_RC5,
    CALG_HMAC = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HMAC,
    CALG_TLS1PRF = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_TLS1PRF,
    CALG_HASH_REPLACE_OWF = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_REPLACE_OWF,
    CALG_AES_128 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_128,
    CALG_AES_192 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_192,
    CALG_AES_256 = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES_256,
    CALG_AES = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_AES,
    CALG_SHA_256 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256,
    CALG_SHA_384 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384,
    CALG_SHA_512 = ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512,
    CALG_ECDH = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH | ALG_SID_ECDH,
    CALG_ECDH_EPHEM = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ECDH | ALG_SID_ECDH_EPHEM,
    CALG_ECMQV = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | ALG_SID_ECMQV,
    CALG_ECDSA = ALG_CLASS_SIGNATURE | ALG_TYPE_DSS | ALG_SID_ECDSA,
    CALG_NULLCIPHER = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_ANY | 0,
    CALG_THIRDPARTY_KEY_EXCHANGE = ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_THIRDPARTY | ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_SIGNATURE = ALG_CLASS_SIGNATURE | ALG_TYPE_THIRDPARTY | ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_CIPHER = ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_THIRDPARTY | ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_HASH = ALG_CLASS_HASH | ALG_TYPE_THIRDPARTY | ALG_SID_THIRDPARTY_ANY,
}

[Flags]
public enum AscReq
{
    ASC_REQ_NONE = 0x00000000,
    ASC_REQ_DELEGATE = 0x00000001,
    ASC_REQ_MUTUAL_AUTH = 0x00000002,
    ASC_REQ_REPLAY_DETECT = 0x00000004,
    ASC_REQ_SEQUENCE_DETECT = 0x00000008,
    ASC_REQ_CONFIDENTIALITY = 0x00000010,
    ASC_REQ_USE_SESSION_KEY = 0x00000020,
    ASC_REQ_SESSION_TICKET = 0x00000040,
    ASC_REQ_ALLOCATE_MEMORY = 0x00000100,
    ASC_REQ_USE_DCE_STYLE = 0x00000200,
    ASC_REQ_DATAGRAM = 0x00000400,
    ASC_REQ_CONNECTION = 0x00000800,
    ASC_REQ_CALL_LEVEL = 0x00001000,
    ASC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
    ASC_REQ_EXTENDED_ERROR = 0x00008000,
    ASC_REQ_STREAM = 0x00010000,
    ASC_REQ_INTEGRITY = 0x00020000,
    ASC_REQ_LICENSING = 0x00040000,
    ASC_REQ_IDENTIFY = 0x00080000,
    ASC_REQ_ALLOW_NULL_SESSION = 0x00100000,
    ASC_REQ_ALLOW_NON_USER_LOGONS = 0x00200000,
    ASC_REQ_ALLOW_CONTEXT_REPLAY = 0x00400000,
    ASC_REQ_FRAGMENT_TO_FIT = 0x00800000,
    ASC_REQ_NO_TOKEN = 0x01000000,
    ASC_REQ_PROXY_BINDINGS = 0x04000000,
    SSP_REQ_REAUTHENTICATION = 0x08000000,
    ASC_REQ_ALLOW_MISSING_BINDINGS = 0x10000000,
}

[Flags]
public enum AscRet
{
    ASC_RET_DELEGATE = 0x00000001,
    ASC_RET_MUTUAL_AUTH = 0x00000002,
    ASC_RET_REPLAY_DETECT = 0x00000004,
    ASC_RET_SEQUENCE_DETECT = 0x00000008,
    ASC_RET_CONFIDENTIALITY = 0x00000010,
    ASC_RET_USE_SESSION_KEY = 0x00000020,
    ASC_RET_SESSION_TICKET = 0x00000040,
    ASC_RET_ALLOCATED_MEMORY = 0x00000100,
    ASC_RET_USED_DCE_STYLE = 0x00000200,
    ASC_RET_DATAGRAM = 0x00000400,
    ASC_RET_CONNECTION = 0x00000800,
    ASC_RET_CALL_LEVEL = 0x00002000,
    ASC_RET_THIRD_LEG_FAILED = 0x00004000,
    ASC_RET_EXTENDED_ERROR = 0x00008000,
    ASC_RET_STREAM = 0x00010000,
    ASC_RET_INTEGRITY = 0x00020000,
    ASC_RET_LICENSING = 0x00040000,
    ASC_RET_IDENTIFY = 0x00080000,
    ASC_RET_NULL_SESSION = 0x00100000,
    ASC_RET_ALLOW_NON_USER_LOGONS = 0x00200000,
    ASC_RET_ALLOW_CONTEXT_REPLAY = 0x00400000,
    ASC_RET_FRAGMENT_ONLY = 0x00800000,
    ASC_RET_NO_TOKEN = 0x01000000,
    ASC_RET_NO_ADDITIONAL_TOKEN = 0x02000000,
    ASP_RET_REAUTHENTICATION = 0x08000000,
}

[Flags]
public enum CertEncodingType
{
    X509_ASN_ENCODING = 0x00000001,
    X509_NDR_ENCODING = 0x00000002,
    PKCS_7_ASN_ENCODING = 0x00010000,
    PKCS_7_NDR_ENCODING = 0x00020000,
}

[Flags]
public enum CredentialUse
{
    SECPKG_CRED_INBOUND = 0x00000001,
    SECPKG_CRED_OUTBOUND = 0x00000002,
    SECPKG_CRED_BOTH = 0x00000003,
    SECPKG_CRED_DEFAULT = 0x00000004,
    SECPKG_CRED_AUTOLOGON_RESTRICTED = 0x00000010,
    SECPKG_CRED_PROCESS_POLICY_ONLY = 0x00000020,
    SECPKG_CRED_RESERVED = unchecked((int)0xF0000000),
}

public enum CredSspSubmitType
{
    CredsspPasswordCreds = 2,
    CredsspSchannelCreds = 4,
    CredsspCertificateCreds = 13,
    CredsspSubmitBufferBoth = 50,
    CredsspSubmitBufferBothOld = 51,
    CredsspCredEx = 100,
}

[Flags]
public enum CredSspFlags
{
    None = 0x00000000,
    CREDSSP_FLAG_REDIRECT = 0x00000001,
}

public enum CredSspVersion
{
    CREDSSP_CRED_EX_VERSION = 0,
}

[Flags]
public enum IscReq
{
    ISC_REQ_DELEGATE = 0x00000001,
    ISC_REQ_MUTUAL_AUTH = 0x00000002,
    ISC_REQ_REPLAY_DETECT = 0x00000004,
    ISC_REQ_SEQUENCE_DETECT = 0x00000008,
    ISC_REQ_CONFIDENTIALITY = 0x00000010,
    ISC_REQ_USE_SESSION_KEY = 0x00000020,
    ISC_REQ_PROMPT_FOR_CREDS = 0x00000040,
    ISC_REQ_USE_SUPPLIED_CREDS = 0x00000080,
    ISC_REQ_ALLOCATE_MEMORY = 0x00000100,
    ISC_REQ_USE_DCE_STYLE = 0x00000200,
    ISC_REQ_DATAGRAM = 0x00000400,
    ISC_REQ_CONNECTION = 0x00000800,
    ISC_REQ_CALL_LEVEL = 0x00001000,
    ISC_REQ_FRAGMENT_SUPPLIED = 0x00002000,
    ISC_REQ_EXTENDED_ERROR = 0x00004000,
    ISC_REQ_STREAM = 0x00008000,
    ISC_REQ_INTEGRITY = 0x00010000,
    ISC_REQ_IDENTIFY = 0x00020000,
    ISC_REQ_NULL_SESSION = 0x00040000,
    ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000,
    ISC_REQ_RESERVED1 = 0x00100000,
    ISC_REQ_FRAGMENT_TO_FIT = 0x00200000,
    ISC_REQ_FORWARD_CREDENTIALS = 0x00400000,
    ISC_REQ_NO_INTEGRITY = 0x00800000,
    ISC_REQ_USE_HTTP_STYLE = 0x01000000,
    ISC_REQ_UNVERIFIED_TARGET_NAME = 0x20000000,
    ISC_REQ_CONFIDENTIALITY_ONLY = 0x40000000,
}

[Flags]
public enum IscRet
{
    ISC_RET_DELEGATE = 0x00000001,
    ISC_RET_MUTUAL_AUTH = 0x00000002,
    ISC_RET_REPLAY_DETECT = 0x00000004,
    ISC_RET_SEQUENCE_DETECT = 0x00000008,
    ISC_RET_CONFIDENTIALITY = 0x00000010,
    ISC_RET_USE_SESSION_KEY = 0x00000020,
    ISC_RET_USED_COLLECTED_CREDS = 0x00000040,
    ISC_RET_USED_SUPPLIED_CREDS = 0x00000080,
    ISC_RET_ALLOCATED_MEMORY = 0x00000100,
    ISC_RET_USED_DCE_STYLE = 0x00000200,
    ISC_RET_DATAGRAM = 0x00000400,
    ISC_RET_CONNECTION = 0x00000800,
    ISC_RET_INTERMEDIATE_RETURN = 0x00001000,
    ISC_RET_CALL_LEVEL = 0x00002000,
    ISC_RET_EXTENDED_ERROR = 0x00004000,
    ISC_RET_STREAM = 0x00008000,
    ISC_RET_INTEGRITY = 0x00010000,
    ISC_RET_IDENTIFY = 0x00020000,
    ISC_RET_NULL_SESSION = 0x00040000,
    ISC_RET_MANUAL_CRED_VALIDATION = 0x00080000,
    ISC_RET_RESERVED1 = 0x00100000,
    ISC_RET_FRAGMENT_ONLY = 0x00200000,
    ISC_RET_FORWARD_CREDENTIALS = 0x00400000,
    ISC_RET_USED_HTTP_STYLE = 0x01000000,
    ISC_RET_NO_ADDITIONAL_TOKEN = 0x02000000,
    ISC_RET_REAUTHENTICATION = 0x08000000,
    ISC_RET_CONFIDENTIALITY_ONLY = 0x40000000,
}

public enum SchannelCredVersion
{
    SCH_CRED_V1 = 0x00000001,
    SCH_CRED_V2 = 0x00000002,
    SCH_CRED_VERSION = 0x00000002,
    SCH_CRED_V3 = 0x00000003,
    SCHANNEL_CRED_VERSION = 0x00000004,
    SCH_CREDENTIALS_VERSION = 0x00000005,
}

public enum SchannelCryptoUsage
{
    KeyExchange,
    Signature,
    Cipher,
    Digest,
    CertSig,
}

[Flags]
public enum SchannelCredFlags
{
    None = 0,
    SCH_CRED_NO_SYSTEM_MAPPER = 0x00000002,
    SCH_CRED_NO_SERVERNAME_CHECK = 0x00000004,
    SCH_CRED_MANUAL_CRED_VALIDATION = 0x00000008,
    SCH_CRED_NO_DEFAULT_CREDS = 0x00000010,
    SCH_CRED_AUTO_CRED_VALIDATION = 0x00000020,
    SCH_CRED_USE_DEFAULT_CREDS = 0x00000040,
    SCH_CRED_DISABLE_RECONNECTS = 0x00000080,
    SCH_CRED_REVOCATION_CHECK_END_CERT = 0x00000100,
    SCH_CRED_REVOCATION_CHECK_CHAIN = 0x00000200,
    SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x00000400,
    SCH_CRED_IGNORE_NO_REVOCATION_CHECK = 0x00000800,
    SCH_CRED_IGNORE_REVOCATION_OFFLINE = 0x00001000,
    SCH_CRED_RESTRICTED_ROOTS = 0x00002000,
    SCH_CRED_REVOCATION_CHECK_CACHE_ONLY = 0x00004000,
    SCH_CRED_CACHE_ONLY_URL_RETRIEVAL = 0x00008000,
    SCH_CRED_MEMORY_STORE_CERT = 0x00010000,
    SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE = 0x00020000,
    SCH_SEND_ROOT_CERT = 0x00040000,
    SCH_CRED_SNI_CREDENTIAL = 0x0008000,
    SCH_CRED_SNI_ENABLE_OCSP = 0x00100000,
    SCH_SEND_AUX_RECORD = 0x00200000,
    SCH_USE_STRONG_CRYPTO = 0x00400000,
    SCH_USE_PRESHAREDKEY_ONLY = 0x00800000,
    SCH_USE_DTLS_ONLY = 0x01000000,
    SCH_ALLOW_NULL_ENCRYPTION = 0x02000000,
    SCH_CRED_DEFERRED_CRED_VALIDATION = 0x04000000,
}

public enum SchannelCredFormat
{
    SCH_CRED_FORMAT_CERT_CONTEXT = 0x00000000,
    SCH_CRED_FORMAT_CERT_HASH = 0x00000001,
    SCH_CRED_FORMAT_CERT_HASH_STORE = 0x00000002,
}

[Flags]
public enum SchannelProtocols
{
    SP_PROT_NONE = 0,

    SP_PROT_PCT1_SERVER = 0x00000001,
    SP_PROT_PCT1_CLIENT = 0x00000002,
    SP_PROT_PCT1 = SP_PROT_PCT1_SERVER | SP_PROT_PCT1_CLIENT,

    SP_PROT_SSL2_SERVER = 0x00000004,
    SP_PROT_SSL2_CLIENT = 0x00000008,
    SP_PROT_SSL2 = SP_PROT_SSL2_SERVER | SP_PROT_SSL2_CLIENT,

    SP_PROT_SSL3_SERVER = 0x00000010,
    SP_PROT_SSL3_CLIENT = 0x00000020,
    SP_PROT_SSL3 = SP_PROT_SSL3_SERVER | SP_PROT_SSL3_CLIENT,

    SP_PROT_TLS1_SERVER = 0x00000040,
    SP_PROT_TLS1_CLIENT = 0x00000080,
    SP_PROT_TLS1 = SP_PROT_TLS1_SERVER | SP_PROT_TLS1_CLIENT,

    SP_PROT_SSL3TLS1_CLIENTS = SP_PROT_TLS1_CLIENT | SP_PROT_TLS1_CLIENT,
    SP_PROT_SSL3TLS1_SERVERS = SP_PROT_TLS1_SERVER | SP_PROT_SSL3_SERVER,
    SP_PROT_SSL3TLS1 = SP_PROT_SSL3 | SP_PROT_TLS1,

    SP_PROT_TLS1_0_SERVER = SP_PROT_TLS1_SERVER,
    SP_PROT_TLS1_0_CLIENT = SP_PROT_TLS1_CLIENT,
    SP_PROT_TLS1_0 = SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_0_CLIENT,

    SP_PROT_TLS1_1_SERVER = 0x00000100,
    SP_PROT_TLS1_1_CLIENT = 0x00000200,
    SP_PROT_TLS1_1 = SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_1_CLIENT,

    SP_PROT_TLS1_2_SERVER = 0x00000400,
    SP_PROT_TLS1_2_CLIENT = 0x00000800,
    SP_PROT_TLS1_2 = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_2_CLIENT,

    SP_PROT_TLS1_3_SERVER = 0x00001000,
    SP_PROT_TLS1_3_CLIENT = 0x00002000,
    SP_PROT_TLS1_3 = SP_PROT_TLS1_3_SERVER | SP_PROT_TLS1_3_CLIENT,

    SP_PROT_DTLS_SERVER = 0x00010000,
    SP_PROT_DTLS_CLIENT = 0x00020000,
    SP_PROT_DTLS = SP_PROT_DTLS_SERVER | SP_PROT_DTLS_CLIENT,

    SP_PROT_DTLS1_0_SERVER = SP_PROT_DTLS_SERVER,
    SP_PROT_DTLS1_0_CLIENT = SP_PROT_DTLS_CLIENT,
    SP_PROT_DTLS1_0 = SP_PROT_DTLS1_0_SERVER | SP_PROT_DTLS1_0_CLIENT,

    SP_PROT_DTLS1_2_SERVER = 0x00040000,
    SP_PROT_DTLS1_2_CLIENT = 0x00080000,
    SP_PROT_DTLS1_2 = SP_PROT_DTLS1_2_SERVER | SP_PROT_DTLS1_2_CLIENT,

    SP_PROT_UNI_SERVER = 0x40000000,
    SP_PROT_UNI_CLIENT = unchecked((int)0x80000000),
    SP_PROT_UNI = SP_PROT_UNI_SERVER | SP_PROT_UNI_CLIENT,

    SP_PROT_ALL = unchecked((int)0xFFFFFFFF),
    SP_PROT_CLIENTS = SP_PROT_PCT1_CLIENT | SP_PROT_SSL2_CLIENT | SP_PROT_SSL3_CLIENT | SP_PROT_UNI_CLIENT | SP_PROT_TLS1_CLIENT,
    SP_PROT_SERVERS = SP_PROT_PCT1_SERVER | SP_PROT_SSL2_SERVER | SP_PROT_SSL3_SERVER | SP_PROT_UNI_SERVER | SP_PROT_TLS1_SERVER,
}

public enum SecBufferType
{
    SECBUFFER_EMPTY = 0,
    SECBUFFER_DATA = 1,
    SECBUFFER_TOKEN = 2,
    SECBUFFER_PKG_PARAMS = 3,
    SECBUFFER_MISSING = 4,
    SECBUFFER_EXTRA = 5,
    SECBUFFER_STREAM_TRAILER = 6,
    SECBUFFER_STREAM_HEADER = 7,
    SECBUFFER_NEGOTIATION_INFO = 8,
    SECBUFFER_PADDING = 9,
    SECBUFFER_STREAM = 10,
    SECBUFFER_MECHLIST = 11,
    SECBUFFER_MECHLIST_SIGNATURE = 12,
    SECBUFFER_TARGET = 13,
    SECBUFFER_CHANNEL_BINDINGS = 14,
    SECBUFFER_CHANGE_PASS_RESPONSE = 15,
    SECBUFFER_TARGET_HOST = 16,
    SECBUFFER_ALERT = 17,
    SECBUFFER_APPLICATION_PROTOCOLS = 18,
    SECBUFFER_SRTP_PROTECTION_PROFILES = 19,
    SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = 20,
    SECBUFFER_TOKEN_BINDING = 21,
    SECBUFFER_PRESHARED_KEY = 22,
    SECBUFFER_PRESHARED_KEY_IDENTITY = 23,
    SECBUFFER_DTLS_MTU = 24,
    SECBUFFER_SEND_GENERIC_TLS_EXTENSION = 25,
    SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION = 26,
    SECBUFFER_FLAGS = 27,
    SECBUFFER_TRAFFIC_SECRETS = 28,
    SECBUFFER_CERTIFICATE_REQUEST_CONTEXT = 29,
}

[Flags]
public enum SecBufferFlags
{
    SECBUFFER_NONE = 0,
    SECBUFFER_ATTRMASK = unchecked((int)0xF0000000),
    SECBUFFER_READONLY = unchecked((int)0x80000000),
    SECBUFFER_READONLY_WITH_CHECKSUM = unchecked((int)0x10000000),
    SECBUFFER_RESERVED = unchecked((int)0x60000000),
}

public enum SecurityLogonType
{
    UndefinedLogonType = 0,
    Interactive = 2,
    Network,
    Batch,
    Service,
    Proxy,
    Unlock,
    NetworkCleartext,
    NewCredentials,
    RemoteInteractive,
    CachedInteractive,
    CachedRemoteInteractive,
    CachedUnlock
}

public enum TargetDataRep
{
    SECURITY_NATIVE_DREP = 0x00000010,
    SECURITY_NETWORK_DREP = 0x00000000,
}

[Flags]
public enum TokenGroupAttributes
{
    SE_GROUP_MANDATORY = 0x00000001,
    SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002,
    SE_GROUP_ENABLED = 0x00000004,
    SE_GROUP_OWNER = 0x00000008,
    SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010,
    SE_GROUP_INTEGRITY = 0x00000020,
    SE_GROUP_INTEGRITY_ENABLED = 0x00000040,
    SE_GROUP_LOGON_ID = unchecked((int)0xC0000000),
    SE_GROUP_RESOURCE = 0x20000000,
}

[Flags]
public enum WinNTAuthIdentityFlags
{
    SEC_WINNT_AUTH_IDENTITY_ANSI = 0x00000001,
    SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x00000002,
    SEC_WINNT_AUTH_IDENTITY_MARSHALLED = 0x00000004,
    SEC_WINNT_AUTH_IDENTITY_ONLY = 0x00000008,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_PROCESS_ENCRYPTED = 0x00000010,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_PROTECTED = 0x00000020,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_USER_PROTECTED = 0x00000040,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SYSTEM_ENCRYPTED = 0x00000080,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_RESERVED = 0x00010000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_USER = 0x00020000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_NULL_DOMAIN = 0x00040000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_ID_PROVIDER = 0x00080000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_LOAD = 0x10000000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_NO_CHECKBOX = 0x20000000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_SAVE_CRED_CHECKED = 0x40000000,
    SEC_WINNT_AUTH_IDENTITY_FLAGS_SSPIPFC_CREDPROV_DO_NOT_SAVE = unchecked((int)0x80000000),
}

public enum WinNTAuthIdentityVersion
{
    SEC_WINNT_AUTH_IDENTITY_VERSION = 0x200,
    SEC_WINNT_AUTH_IDENTITY_VERSION_2 = 0x201,
}
