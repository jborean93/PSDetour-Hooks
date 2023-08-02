New-PSDetourHook -DllName KdsCli.dll -MethodName SIDKeyUnprotect {
    [OutputType([Int64])]
    param (
        [IntPtr]$KeyRequest,
        [IntPtr]$DpapiContext,
        [IntPtr]$Data,
        [IntPtr]$DataLength,
        [int]$Flags
    )

    <#
    int64 SIDKeyUnprotect(
        RPC_KEY_REQUEST *keyRequest,
        DPAPI_CTX *dpapiCtx,
        byte **data, // blank
        int *dataLength, // blank
        int flags
    );

    // 0x131F60050D0
    typedef struct RPC_KEY_REQUEST
    {
        int version; // 3
        int padding1;
        int field1; // 4
        int padding2;
        int keyInfoLength; // 132
        int padding3;
        KEY_INFO *keyInfo; // 0x0131f5b1421d
        void *field2; // 0
        KEY_PROTECTOR *keyProtector; // 0x0131f6005170
        int keyEncAlgoAsnLength; // 11
        int padding4;
        byte *keyEncAlgoAsn; // 0x0131f5b142f8 2.16.840.1.101.3.4.1.45 (aes256-wrap)
        void *field3; // 0
        ENCRYPTION_CIPHER_INFO *registeredCiphers; // 0x7ffb23f65828
        int encryptedCekLength; // 40
        int padding5;
        byte *encryptedCek; // 0x0131f5b14305
        void *field4; // 0
    } RPC_KEY_REQUEST, *PRPC_KEY_REQUEST;

    typedef struct KEY_INFO
    {
        int version;
        int magic;
        int flags;
        int l0Index;
        int l1Index;
        int l2Index;
        GUID rootKeyIdentifier;
        int unknownLength;
        int domainLength;
        int forestLength;
        // unknown
        // domain
        // forest
    } KEY_INFO, *PKEY_INFO;

    typedef struct KEY_PROTECTOR
    {
        int identifierLength; // 11
        int padding1;
        byte *identifierAsn; // 0x0131f5b142a3
        int valueLength; // 72
        int padding2;
        byte *valueAsn; // 0x0131f5b142ae
    } KEY_PROTECTOR, *PKEY_PROTECTOR;

    typedef struct ENCRYPTION_CIPHER_INFO
    {
        wchar_t *name; // 0x7ffb23f6b158 AES256wrap
        int nameLength; // 24
        int padding1;
        wchar_t *oidString; // 7ffb23f6b170 2.16.840.1.101.3.4.1.45
        int field1; // 2
        int padding2;
        int oidLength; // 11
        int padding3;
        byte *oid; // 0x7ffb23f6b188 2.16.840.1.101.3.4.1.45 (aes256-wrap)
        void *field3; // 0
        void *field4; // 80 D0 CE A0 00 00 00 00
    } ENCRYPTION_CIPHER_INFO, *PENCRYPTION_CIPHER_INFO;

    typedef struct DPAPI_CTX
    {
        size_t field1; // 24
        void *allocFunc; // dpapisrv.dll SSAlloc(unsigned __int63) - 0x00004220
        void *freeFunc; // dpapisrv.dll MIDL_user_free(void *a1) - 0x00003F30
        wchar_t *rpcName; // dpapisrv.dll ncalrpc.SidKey Local End Point
        wchar_t *storage; // dpapisrv.dll protected_storage
        wchar_t *rpcProto1; // dpapisrv.dll ncacn_np
        wchar_t *rpcPipe1; // dpapisrv.dll \PIPE\protected_storage
        wchar_t *rpcProto2; // dpapisrv.dll ncacn_np
        wchar_t *rpcPipe2; // dpapisrv.dll \PIPE\ntsvcs
    } DPAPI_CTX, *PDPAPI_CTX;
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        KeyRequest = Format-Pointer $KeyRequest
        DpapiCtx = Format-Pointer $DpapiContext
        Data = Format-Pointer $Data
        DataLength = Format-Pointer $DataLength
        Flags = Format-Enum $Flags
    })
    $res = $this.Invoke($KeyRequest, $DpapiContext, $Data, $DataLength, $Flags)

    $cekLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($DataLength)
    $cek = [byte[]]::new($cekLength)
    $returnDataPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Data)
    [System.Runtime.InteropServices.Marshal]::Copy($returnDataPtr, $cek, 0, $cek.Length)
    Write-FunctionResult -Result $res ([Ordered]@{
        CEK = [System.Convert]::ToHexString($cek)
    })

    $res
}

New-PSDetourHook -DllName KdsCli.dll -MethodName CNG_AesKeyUnwrap -Address 0xD530 -AddressIsoffset {
    [OutputType([Int64])]
    param (
        [IntPtr]$EncryptedData,
        [int]$EncryptedDataLength,
        [IntPtr]$Key,
        [IntPtr]$Unknown,  # Seems to be set to 1 but not used in the decompiled code.
        [IntPtr]$OutData,
        [IntPtr]$OutDataLength
    )

    $encryptedCekBytes = [byte[]]::new($EncryptedDataLength)
    [System.Runtime.InteropServices.Marshal]::Copy($EncryptedData, $encryptedCekBytes, 0, $encryptedCekBytes.Length)

    $secretBytes = [byte[]]::new(32)
    [System.Runtime.InteropServices.Marshal]::Copy($Key, $secretBytes, 0, $secretBytes.Length)

    Write-FunctionCall -Arguments ([Ordered]@{
        EncryptedData = [Ordered]@{
            Raw = Format-Pointer $EncryptedData
            Value = [System.Convert]::ToHexString($encryptedCekBytes)
        }
        EncryptedDataLength = $EncryptedDataLength
        Key = [Ordered]@{
            Raw = Format-Pointer $Key
            Value = [System.Convert]::ToHexString($secretBytes)
        }
        Unknown = Format-Pointer $Unknown
        OutData = Format-Pointer $OutData
        OutDataLength = Format-Pointer $OutDataLength
    })

    $res = $this.Invoke($EncryptedData, $EncryptedDataLength, $Key, $Unknown, $OutData, $OutDataLength)

    $cekLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($OutDataLength)
    $cek = [byte[]]::new($cekLength)
    $cekPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($OutData)
    [System.Runtime.InteropServices.Marshal]::Copy($cekPtr, $cek, 0, $cek.Length)
    Write-FunctionResult -Result $res ([Ordered]@{
        CEK = [System.Convert]::ToHexString($cek)
    })

    $res
}

New-PSDetourHook -DllName KdsCli.dll -MethodName GetSIDKeyFileName -Address 0x6B60 -AddressIsOffset {
    [OutputType([Int64])]
    param (
        [IntPtr]$Unknown1,
        [int]$Unknown2,
        [int]$Unknown3,
        [IntPtr]$Unknown4,
        [IntPtr]$Path
    )

    Write-FunctionCall -Arguments ([Ordered]@{
        Unknown1 = Format-Pointer $Unknown1
        Unknown2 = $Unknown2
        Unknown3 = $Unknown3
        Unknown4 = Format-Pointer $Unknown4
        Path = Format-Pointer $Path 'LPWSTR'
    })
    $res = $this.Invoke($Unknown1, $Unknown2, $Unknown3, $Unknown4, $Path)

    $pathPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Path)
    $pathStr = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pathPtr)
    Write-FunctionResult -Result $res ([Ordered]@{
        Path = $pathStr
    })

    $res
}

New-PSDetourHook -DllName KdsCli.dll -MethodName GenerateSIDKey -Address 0xF0D4 -AddressIsOffset {
    [OutputType([Int64])]
    param (
        [IntPtr]$GroupKeyEnvelope,
        [IntPtr]$GKELength,  # 854
        [IntPtr]$PasswordId,
        [int]$Unknown4,  # 2
        [IntPtr]$Unknown5,
        [IntPtr]$Unknown6,
        [IntPtr]$OutData
    )

    <#
    typedef struct GROUP_KEY_ENVELOPE
    {
        int version;
        int magic;
        int flags;
        int l0Index;
        int l1Index;
        int l2Index;
        GUID rootKeyIdentifier;
        int kdfAlgoLength;
        int kdfParamLength;
        int secretAlgoLength;
        int secretParamLength;
        int pubKeyLength;
        int privateKeyLength;
        int l1KeyLength;
        int l2KeyLength;
        int domainLength;
        int forestLength;
    } GROUP_KEY_ENVELOPE, *PGROUP_KEY_ENVELOPE;
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        GroupKeyEnvelope = Format-Pointer $GroupKeyEnvelope
        GKELength = [Int64]$GKELength
        PasswordId = Format-Pointer $PasswordId
        Unknown4 = $Unknown4
        Unknown5 = Format-Pointer $Unknown5
        Unknown6 = Format-Pointer $Unknown6
        OutData = Format-Pointer $OutData
    })

    $res = $this.Invoke($GroupKeyEnvelope, $GKELength, $PasswordId, $Unknown4, $Unknown5, $Unknown6, $OutData)

    $kek = [byte[]]::new(32)
    [System.Runtime.InteropServices.Marshal]::Copy($OutData, $kek, 0, $kek.Length)
    Write-FunctionResult -Result $res ([Ordered]@{
        KEK = [System.Convert]::ToHexString($kek)
    })

    $res
}
