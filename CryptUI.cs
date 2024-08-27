using System;
using System.Runtime.InteropServices;

namespace CryptUI;

public enum CertEncodingType
{
    X509_ASN_ENCODING = 0x00000001,
    X509_NDR_ENCODING = 0x00000002,
}

public enum CertMessageEncodingType
{
    PKCS_7_ASN_ENCODING = 0x00010000,
    PKCS_7_NDR_ENCODING = 0x00020000,
}

public enum DigitalSignInfoAdditionalCertChoice
{
    NONE = 0x00000000,
    CRYPTUI_WIZ_DIGITAL_SIGN_ADD_CHAIN = 0x00000001,
    CRYPTUI_WIZ_DIGITAL_SIGN_ADD_CHAIN_NO_ROOT = 0x00000002,
}

public enum DigitalSignInfoExtendedInfoFlags
{
    CRYPTUI_WIZ_DIGITAL_SIGN_COMMERCIAL = 0x0001,
    CRYPTUI_WIZ_DIGITAL_SIGN_INDIVIDUAL = 0x0002,
}

public enum DigitalSignInfoSigningCertChoice
{
    CRYPTUI_WIZ_DIGITAL_SIGN_CERT = 1,
    CRYPTUI_WIZ_DIGITAL_SIGN_STORE = 2,
    CRYPTUI_WIZ_DIGITAL_SIGN_PVK = 3,
}

public enum DigitalSignInfoSubjectChoice
{
    CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE = 1,
    CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_BLOB = 2,
}

[Flags]
public enum CryptUIWizFlags
{
    NONE = 0,
    CRYPTUI_WIZ_NO_UI = 0x0001,
}

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
public struct CRYPT_ATTRIBUTES
{
    public int cAttr;
    public nint rgAttr;
}

[StructLayout(LayoutKind.Sequential)]
public struct CRYPT_ATTRIBUTE
{
    public nint pszObjId;
    public int cValue;
    public nint rgValue;
}

[StructLayout(LayoutKind.Sequential)]
public struct CRYPT_INTEGER_BLOB
{
    public int cbData;
    public nint pbData;
}

[StructLayout(LayoutKind.Sequential)]
public struct CRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO
{
    public int dwSize;
    public nint pGuidSubject;
    public int cbBlob;
    public nint pbBlob;
    public nint pwszDisplayName;
}

[StructLayout(LayoutKind.Sequential)]
public struct CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT
{
    public int dwSize;
    public int cbBlob;
    public nint pbBlob;
}

[StructLayout(LayoutKind.Sequential)]
public struct CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO
{
    public int dwSize;
    public DigitalSignInfoExtendedInfoFlags dwAttrFlags;
    public nint pwszDescription;
    public nint pwszMoreInfoLocation;
    public nint pszHashAlg;
    public nint pwszSigningCertDisplayString;
    public nint hAdditionalCertStore;
    public nint psAuthenticated;
    public nint psUnauthenticated;
}

[StructLayout(LayoutKind.Sequential)]
public struct CRYPTUI_WIZ_DIGITAL_SIGN_INFO
{
    public int dwSize;
    public DigitalSignInfoSubjectChoice dwSubjectChoice;
    public nint SubjectUnion;
    public DigitalSignInfoSigningCertChoice dwSigningCertChoice;
    public nint SigningCertUnion;
    public nint pwszTimestampURL;
    public DigitalSignInfoAdditionalCertChoice dwAdditionalCertChoice;
    public nint pSignExtInfo;
}
