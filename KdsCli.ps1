$kdscli = [System.Runtime.InteropServices.NativeLibrary]::Load("$env:SystemRoot\System32\KdsCli.dll")
$CNG_AesKeyUnwrap = [IntPtr]::Add($kdsCli, 0xD530)
$GetSpecifiedKey = [IntPtr]::Add($kdsCli, 0xFB94)
$GetSIDKeyFileName = [IntPtr]::Add($kdsCli, 0x6B60)
$GenerateSIDKey = [IntPTr]::Add($kdsCli, 0xF0D4)

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

    $this.State.Writer.WriteLine(
        'SIDKeyUnprotect(KeyRequest: 0x{0:X8}, DpapiCtx: 0x{1:X8}, Data: 0x{2:X8}, DataLength: 0x{3:X8}, Flags: 0x{4:X8})' -f (
        $KeyRequest, $DpapiContext, $Data, $DataLength, $Flags
    ))
    $res = $this.Invoke($KeyRequest, $DpapiContext, $Data, $DataLength, $Flags)

    $cekLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($DataLength)
    $cek = [byte[]]::new($cekLength)
    $returnDataPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Data)
    [System.Runtime.InteropServices.Marshal]::Copy($returnDataPtr, $cek, 0, $cek.Length)

    $this.State.Writer.WriteLine('SIDKeyUnprotect -> Res: 0x{0:X8}, CEK: {1}' -f (
        $res, [System.Convert]::ToHexString($cek)
    ))
    $res
}

New-PSDetourHook -Address $CNG_AesKeyUnwrap {
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

    $this.State.Writer.WriteLine(
        'CNG_AesKeyUnwrap(EncryptedData: 0x{0:X8}, EncryptedDataLength: {1}, Key: 0x{2:X8}, 0x{3:X8}, OutData: 0x{4:X8}, OutDataLengh: 0x{5:X8}) - EncryptedCek: {6} Secret: {7}' -f (
        $EncryptedData, $EncryptedDataLength, $Key, $Unknown, $OutData, $OutDataLength,
        [System.Convert]::ToHexString($encryptedCekBytes),
        [System.Convert]::ToHexString($secretBytes)
    ))
    $res = $this.Invoke($EncryptedData, $EncryptedDataLength, $Key, $Unknown, $OutData, $OutDataLength)

    $cekLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($OutDataLength)
    $cek = [byte[]]::new($cekLength)
    $cekPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($OutData)
    [System.Runtime.InteropServices.Marshal]::Copy($cekPtr, $cek, 0, $cek.Length)

    $this.State.Writer.WriteLine('CNG_AesKeyUnwrap -> Res: 0x{0:X8}, CEK: {1} 0x{2:X8}' -f (
        $res, [System.Convert]::ToHexString($cek), $Unknown
    ))

    $res
}

New-PSDetourHook -Address $GetSIDKeyFileName {
    [OutputType([Int64])]
    param (
        [IntPtr]$Unknown1,
        [int]$Unknown2,
        [int]$Unknown3,
        [IntPtr]$Unknown4,
        [IntPtr]$Unknown5
    )

    $this.State.Writer.WriteLine(
        'GetSIDKeyFileName(0x{0:X8}, {1}, {2}, 0x{3:X8}, 0x{4:X8})' -f (
        $Unknown1, $Unknown2, $Unknown3, $Unknown4, $Unknown5
    ))
    $res = $this.Invoke($Unknown1, $Unknown2, $Unknown3, $Unknown4, $Unknown5)

    $pathPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Unknown5)
    $path = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($pathPtr)

    $this.State.Writer.WriteLine('GetSIDKeyFileName -> Res: 0x{0:X8} Path: {1}' -f (
        $res, $path
    ))
    # $null = $this.State.Waiter.ReadByte()

    $res
}

New-PSDetourHook -Address $GenerateSIDKey {
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

    $this.State.Writer.WriteLine(
        'GenerateSIDKey(GroupKeyEnvelope: 0x{0:X8}, GKELength: {1}, PasswordId: 0x{2:X8}, {3}, 0x{4:X8}, 0x{5:X8}, 0x{6:X8})' -f (
        $GroupKeyEnvelope, $GKELength, $PasswordId, $Unknown4, $Unknown5, $Unknown6, $OutData
    ))
    $res = $this.Invoke($GroupKeyEnvelope, $GKELength, $PasswordId, $Unknown4, $Unknown5, $Unknown6, $OutData)

    $kek = [byte[]]::new(32)
    [System.Runtime.InteropServices.Marshal]::Copy($OutData, $kek, 0, $kek.Length)

    $this.State.Writer.WriteLine('GenerateSIDKey -> Res: 0x{0:X8}, KEK: {1}' -f (
        $res,
        [System.Convert]::ToHexString($kek)
    ))
    $null = $this.State.Waiter.ReadByte()

    $res
}