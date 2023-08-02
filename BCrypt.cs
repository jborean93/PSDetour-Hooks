using System;
using System.Runtime.InteropServices;

namespace BCrypt;

[StructLayout(LayoutKind.Sequential)]
public struct BCryptBufferDesc
{
    public int ulVersion;
    public int cBuffer;
    public nint pBuffers;
}

[StructLayout(LayoutKind.Sequential)]
public struct BCryptBuffer
{
    public int cbBuffer;
    public int BufferType;
    public nint pvBuffer;
}

public enum BCryptBufferType
{
    KDF_HASH_ALGORITHM = 0x0,
    KDF_SECRET_PREPEND = 0x1,
    KDF_SECRET_APPEND = 0x2,
    KDF_HMAC_KEY = 0x3,
    KDF_TLS_PRF_LABEL = 0x4,
    KDF_TLS_PRF_SEED = 0x5,
    KDF_SECRET_HANDLE = 0x6,
    KDF_TLS_PRF_PROTOCOL = 0x7,
    KDF_ALGORITHMID = 0x8,
    KDF_PARTYUINFO = 0x9,
    KDF_PARTYVINFO = 0xA,
    KDF_SUPPPUBINFO = 0xB,
    KDF_SUPPPRIVINFO = 0xC,
    KDF_LABEL = 0xD,
    KDF_CONTEXT = 0xE,
    KDF_SALT = 0xF,
    KDF_ITERATION_COUNT = 0x10,
    KDF_GENERIC_PARAMETER = 0x11,
    KDF_KEYBITLENGTH = 0x12,
    KDF_HKDF_SALT = 0x13,
    KDF_HKDF_INFO = 0x14,
}

[Flags]
public enum GenRandomFlags
{
    None = 0x00000000,
    BCRYPT_RNG_USE_ENTROPY_IN_BUFFER = 0x00000001,
    BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002,
}

[Flags]
public enum DeriveKeyFlags
{
    None = 0x0,
    KDF_USE_SECRET_AS_HMAC_KEY_FLAG = 0x1,
}

[Flags]
public enum ImportKeyFlags
{
    None = 0x00000000,
    BCRYPT_NO_KEY_VALIDATION = 0x00000008,
}

public static class Methods
{
    [DllImport("Bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptDeriveKey(
        nint hSharedSecret,
        [MarshalAs(UnmanagedType.LPWStr)] string pwszKDF,
        nint pParameterList,
        nint pbDerivedKey,
        int cbDerivedKey,
        nint pcbResult,
        int dwFlags);
}
