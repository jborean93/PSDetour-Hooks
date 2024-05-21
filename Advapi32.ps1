New-PSDetourHook -DllName Advapi32.dll -MethodName CryptGetProvParam {
    [OutputType([bool])]
    param (
        [IntPtr]$Prov,
        [int]$Param,
        [IntPtr]$Data,
        [IntPtr]$DataLen,
        [int]$Flags
    )

    <#
    BOOL CryptGetProvParam(
        [in]      HCRYPTPROV hProv,
        [in]      DWORD      dwParam,
        [out]     BYTE       *pbData,
        [in, out] DWORD      *pdwDataLen,
        [in]      DWORD      dwFlags
    );
    #>

    $dataLenRes = 0
    if ($DataLen -ne [IntPtr]::Zero) {
        $dataLenRes = [System.Runtime.InteropServices.Marshal]::ReadInt32($DataLen)
    }

    $a = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Prov, 160)

    Write-FunctionCall -Arguments ([Ordered]@{
        Prov = Format-Pointer $Prov HCRYPTPROV
        Param = Format-Enum $Param ([Advapi32.CryptGetProvParam])
        Data = Format-Pointer $Data BYTE
        DataLen = [Ordered]@{
            Raw = Format-Pointer $DataLen DWORD
            Value = $dataLenRes
        }
        Flags = Format-Enum $Flags
        Test = Format-Pointer $a
    })
    $res = $this.Invoke($Prov, $Param, $Data, $DataLen, $Flags)

    $dataLenRes = [System.Runtime.InteropServices.Marshal]::ReadInt32($DataLen)
    Write-FunctionResult -Result $res ([ordered]@{
        DataLen = $dataLenRes
    })

    $res
}

# New-PSDetourHook -DllName api-ms-win-security-provider-l1-1-0.dll -MethodName GetNamedSecurityInfoW {
New-PSDetourHook -DllName Advapi32.dll -MethodName GetNamedSecurityInfoW {
    [OutputType([int])]
    param (
        [System.Runtime.InteropServices.MarshalAsAttribute([System.Runtime.InteropServices.UnmanagedType]::LPWStr)]
        [string]$ObjectName,
        [int]$ObjectType,
        [int]$SecurityInfo,
        [IntPtr]$Owner,
        [IntPtr]$Group,
        [IntPtr]$Dacl,
        [IntPtr]$Sacl,
        [IntPtr]$SecurityDescriptor
    )

    <#
    DWORD GetNamedSecurityInfoW(
        [in]            LPCWSTR              pObjectName,
        [in]            SE_OBJECT_TYPE       ObjectType,
        [in]            SECURITY_INFORMATION SecurityInfo,
        [out, optional] PSID                 *ppsidOwner,
        [out, optional] PSID                 *ppsidGroup,
        [out, optional] PACL                 *ppDacl,
        [out, optional] PACL                 *ppSacl,
        [out, optional] PSECURITY_DESCRIPTOR *ppSecurityDescriptor
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        ObjectName = $ObjectName
        ObjectType = Format-Enum $ObjectType ([Advapi32.SeObjectType])
        SecurityInfo = Format-Enum $SecurityInfo ([Advapi32.SecurityInformation])
        Owner = Format-Pointer $Owner *PSID
        Group = Format-Pointer $Group *PSID
        Dacl = Format-Pointer $Dacl *PACL
        Sacl = Format-Pointer $Sacl *PACL
        SecurityDescriptor = Format-Pointer $SecurityDescriptor PSECURITY_DESCRIPTOR
    })
    $res = $this.Invoke($ObjectName, $ObjectType, $SecurityInfo, $Owner, $Group, $Dacl, $Sacl, $SecurityDescriptor)

    $ownerRes = $null
    $groupRes = $null
    $daclRes = $null
    $saclRes = $null
    $sdRes = $null
    if ($res -eq 0) {
        if ($Owner -ne [IntPtr]::Zero) {
            $ownerRes = [System.Security.Principal.SecurityIdentifier]::new(
                [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Owner)).Value
        }
        if ($Group -ne [IntPtr]::Zero) {
            $groupRes = [System.Security.Principal.SecurityIdentifier]::new(
                [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Group)).Value
        }
        if ($Dacl -ne [IntPtr]::Zero) {
            $daclRes = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Dacl)
        }
        if ($Sacl -ne [IntPtr]::Zero) {
            $saclRes = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Sacl)
        }
        if ($SecurityDescriptor -ne [IntPtr]::Zero) {
            $sdRes = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($SecurityDescriptor)
        }
    }

    Write-FunctionResult -Result $res ([ordered]@{
        Owner = $ownerRes
        Group = $groupRes
        Dacl = Format-Pointer $daclRes PACL
        Sacl = Format-Pointer $saclRes PACL
        SecurityDescriptor = Format-Pointer $sdRes PSECURITY_DESCRIPTOR
    })

    $res
}
