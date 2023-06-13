New-PSDetourHook -DllName ncrypt.dll -MethodName NCryptUnprotectKey {
    [OutputType([int])]
    param (
        [IntPtr]$Descriptor,
        [IntPtr]$Unknown2,
        [IntPtr]$MemPara,
        [IntPtr]$Window,
        [IntPtr]$Data,
        [IntPtr]$DataLength,
        [int]$Flags
    )

    <#
    This is just a guess as these are not documented.
    int NCryptUnprotectKey(
        NCRYPT_DESCRIPTOR_HANDLE phDescriptor,
        void *pbUnknown2,
        NCRYPT_ALLOC_PARA *pMemPara,
        HWND hWnd,
        BYTE **ppbData,
        ULONG *pcbData,
        DWORD dwFlags
    )

    typedef struct NCRYPT_DESCRIPTOR
    {
        int size; // Seems to be 48
        int flags;
        void *field1; // a pointer that then points to -> mskeyprotect.dll
        int field2; // 1
        int field3; // 0
        void *field4; // 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 ...
        void *field5; // 40 53 48 83 EC 20 33 DB 4C 8B C1 48 85 C9 74 26 ...
        void *field6; // 4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 ...
        void *field7; // Seems to be a function in mskeyprotect that NCryptUnprotectKey is calling
        void *field8;
    } NCRYPT_DESCRIPTOR, *NCRYPT_DESCRIPTOR_HANDLE

    typedef struct UNKNOWN2
    {
        int field1; // 3
        int field2; // 0
        int field3; // 4
        int field4; // 0
        int kekIdProtectorLength; // 132
        int field6; // 0
        void *kekIdProtector; // Seems to be the EncPasswordId (key identififer) - 010000004B44534B02000000690100000F0000001D000000A84FC6BA90E87C91109083E7B0F8599620000000180000001800000016B3FA1BFC1066B30B63B29A2D29F31D82FB5AE3CC05F86ECB67EFAC69F2CE5564006F006D00610069006E002E007400650073007400000064006F006D00610069006E002E0074006500730074000000
        void *field7; // 0
        void *field8; // ...
        int kekAlgorithmLength; // 11
        int field9; // 0
        void *kekAlgorithm; // The AES256-wrap OID

        // See if there is anything around 01CA7D019E07 which is the pointer to
    }

    0x7FF980415AD0 - mskeyprotect.dll

    #>

    $this.State.WriteObject(
        'NCryptUnprotectKey(Descriptor: 0x{0:X8}, 0x{1:X8}, MemAllocFunc: 0x{2:X8}, Window: 0x{3:X8}, Data: 0x{4:X8}, DataLength: 0x{5:X8}, Flags: 0x{6:X8})' -f @(
        $Descriptor, $Unknown2, $MemPara, $Window, $Data, $DataLength, $Flags
    ))
    $res = $this.Invoke($Descriptor, $Unknown2, $MemPara, $Window, $Data, $DataLength, $Flags)

    $returnLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($DataLength)
    $returnData = [byte[]]::new($returnLength)
    $returnDataPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Data)
    [System.Runtime.InteropServices.Marshal]::Copy($returnDataPtr, $returnData, 0, $returnData.Length)

    $this.State.WriteObject('NCryptUnprotectKey -> Result: 0x{0:X8} CEK: {1}' -f $res, [Convert]::ToHexString($returnData))

    $res
}