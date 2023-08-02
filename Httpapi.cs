using System;
using System.Runtime.InteropServices;

namespace Httpapi;

[StructLayout(LayoutKind.Sequential)]
public struct HTTP_BYTE_RANGE
{
    public long StartingOffset;
    public long Length;
}

[StructLayout(LayoutKind.Sequential)]
public struct HTTP_DATA_CHUNK_FRAGMENT_CACHE_EX
{
    public HTTP_DATA_CHUNK_TYPE DataChunkType;
    public HTTP_BYTE_RANGE ByteRange;
    public nint pFragmentName;
}

[StructLayout(LayoutKind.Sequential)]
public struct HTTP_DATA_CHUNK_MEMORY
{
    public HTTP_DATA_CHUNK_TYPE DataChunkType;
    public nint pBuffer;
    public int BufferLength;
}

[StructLayout(LayoutKind.Sequential)]
public struct HTTP_KNOWN_HEADER
{
    public short RawValueLength;
    public nint pRawValue;
}

[StructLayout(LayoutKind.Sequential)]
public struct HTTP_RESPONSE_HEADERS
{
    public short UnknownHeaderCount;
    public nint pUnknownHeaders;
    public short TrailerCount;
    public nint pTrailers;
    // [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)] public HTTP_KNOWN_HEADER[] KnownHeaders;
    public HTTP_KNOWN_HEADER HeaderCacheControl;
    public HTTP_KNOWN_HEADER HeaderConnection;
    public HTTP_KNOWN_HEADER HeaderDate;
    public HTTP_KNOWN_HEADER HeaderKeepAlive;
    public HTTP_KNOWN_HEADER HeaderPragma;
    public HTTP_KNOWN_HEADER HeaderTrailer;
    public HTTP_KNOWN_HEADER HeaderTransferEncoding;
    public HTTP_KNOWN_HEADER HeaderUpgrade;
    public HTTP_KNOWN_HEADER HeaderVia;
    public HTTP_KNOWN_HEADER HeaderWarning;
    public HTTP_KNOWN_HEADER HeaderAllow;
    public HTTP_KNOWN_HEADER HeaderContentLength;
    public HTTP_KNOWN_HEADER HeaderContentType;
    public HTTP_KNOWN_HEADER HeaderContentEncoding;
    public HTTP_KNOWN_HEADER HeaderContentLanguage;
    public HTTP_KNOWN_HEADER HeaderContentLocation;
    public HTTP_KNOWN_HEADER HeaderMd5;
    public HTTP_KNOWN_HEADER HeaderRange;
    public HTTP_KNOWN_HEADER HeaderExpires;
    public HTTP_KNOWN_HEADER HeaderLastModified;
    public HTTP_KNOWN_HEADER HeaderAcceptRanges;
    public HTTP_KNOWN_HEADER HeaderAge;
    public HTTP_KNOWN_HEADER HeaderEtag;
    public HTTP_KNOWN_HEADER HeaderLocation;
    public HTTP_KNOWN_HEADER HeaderProxyAuthenticate;
    public HTTP_KNOWN_HEADER HeaderRetryAfter;
    public HTTP_KNOWN_HEADER HeaderServer;
    public HTTP_KNOWN_HEADER HeaderSetCookie;
    public HTTP_KNOWN_HEADER HeaderVary;
    public HTTP_KNOWN_HEADER HeaderWwwAuthenticate;
}

[StructLayout(LayoutKind.Sequential)]
public struct HTTP_RESPONSE_V1
{
    public HTTP_RESPONSE_FLAG Flags;
    public HTTP_VERSION Version;
    public short StatusCode;
    public short ReasonLength;
    public nint pReason;
    public HTTP_RESPONSE_HEADERS Headers;
    public short EntityChunkCount;
    public nint pEntityChunks;
}

[StructLayout(LayoutKind.Sequential)]
public struct HTTP_VERSION
{
    public short MajorVersion;
    public short MinorVersion;
}

public enum HTTP_DATA_CHUNK_TYPE
{
    HttpDataChunkFromMemory = 0,
    HttpDataChunkFromFileHandle = 1,
    HttpDataChunkFromFragmentCache = 2,
    HttpDataChunkFromFragmentCacheEx = 3,
    HttpDataChunkTrailers = 4,
}

[Flags]
public enum HTTP_RESPONSE_FLAG
{
    HTTP_RESPONSE_FLAG_NONE = 0,
    HTTP_RESPONSE_FLAG_MULTIPLE_ENCODINGS_AVAILABLE = 0x00000001,
    HTTP_RESPONSE_FLAG_MORE_ENTITY_BODY_EXISTS = 0x00000002
}

[Flags]
public enum HTTP_SEND_RESPONSE_FLAG
{
    HTTP_SEND_RESPONSE_FLAG_NONE = 0x00000000,
    HTTP_SEND_RESPONSE_FLAG_DISCONNECT = 0x00000001,
    HTTP_SEND_RESPONSE_FLAG_MORE_DATA = 0x00000002,
    HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA = 0x00000004,
    HTTP_SEND_RESPONSE_FLAG_ENABLE_NAGLING = 0x00000008,
    HTTP_SEND_RESPONSE_FLAG_PROCESS_RANGES = 0x00000020,
    HTTP_SEND_RESPONSE_FLAG_OPAQUE = 0x00000040,
    HTTP_SEND_RESPONSE_FLAG_GOAWAY = 0x00000100,
}
