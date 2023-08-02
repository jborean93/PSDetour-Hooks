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

    Write-FunctionCall -Arguments ([Ordered]@{
        Descriptor = Format-Pointer $Descriptor
        Unknown2 = Format-Pointer $Unknown2
        MemPara = Format-Pointer $MemPara
        Window = Format-Pointer $Window 'HWND'
        Data = Format-Pointer $Data
        DataLength = Format-Pointer $DataLength
        Flags = Format-Enum $Flags
    })

    $res = $this.Invoke($Descriptor, $Unknown2, $MemPara, $Window, $Data, $DataLength, $Flags)

    $returnLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($DataLength)
    $returnData = [byte[]]::new($returnLength)
    $returnDataPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Data)
    [System.Runtime.InteropServices.Marshal]::Copy($returnDataPtr, $returnData, 0, $returnData.Length)
    Write-FunctionResult -Result $res ([Ordered]@{
        CEK = [System.Convert]::ToHexString($returnData)
    })

    $res
}