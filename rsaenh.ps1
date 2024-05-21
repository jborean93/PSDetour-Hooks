New-PSDetourHook -DllName Rsaenh.dll -MethodName GetSecurityOnContainer -Address 0x14a74 -AddressIsOffset {
    [OutputType([Int64])]
    param (
        [IntPtr]$KeyUniqueName,
        [int]$KeyType,
        [int]$Arg3,
        [int]$SecurityInfo,
        [IntPtr]$Arg5,
        [IntPtr]$Arg6,
        [int]$Arg7
    )

    Write-FunctionCall -Arguments ([Ordered]@{
        KeyUniqueName = Format-WideString $KeyUniqueName
        KeyType = $KeyType
        Arg3 = $Arg3
        SecurityInfo = Format-Enum $SecurityInfo
        Arg5 = Format-Pointer $Arg5
        Arg6 = Format-Pointer $Arg6
        Arg7 = $Arg7
    })
    $res = $this.Invoke($KeyUniqueName, $KeyType, $Arg3, $SecurityInfo, $Arg5, $Arg6, $Arg7)

    Write-FunctionResult -Result $res

    $res
}