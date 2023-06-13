New-PSDetourHook -DllName mskeyprotect.dll -MethodName SIDKeyProtKeyUnprotect {
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

    $this.State.WriteObject(
        'SIDKeyProtKeyUnprotect(Descriptor: 0x{0:X8}, 0x{1:X8}, MemAllocFunc: 0x{2:X8}, Window: 0x{3:X8}, Data: 0x{4:X8}, DataLength: 0x{5:X8}, Flags: 0x{6:X8})' -f @(
        $Descriptor, $Unknown2, $MemPara, $Window, $Data, $DataLength, $Flags
    ))
    $res = $this.Invoke($Descriptor, $Unknown2, $MemPara, $Window, $Data, $DataLength, $Flags)

    $returnLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($DataLength)
    $returnData = [byte[]]::new($returnLength)
    $returnDataPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Data)
    [System.Runtime.InteropServices.Marshal]::Copy($returnDataPtr, $returnData, 0, $returnData.Length)

    $this.State.WriteObject('SIDKeyProtKeyUnprotect -> Result: 0x{0:X8} CEK: {1}' -f $res, [Convert]::ToHexString($returnData))

    $res
}