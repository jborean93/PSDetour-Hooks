New-PSDetourHook -DllName api-ms-win-security-base-l1-1-0.dll -MethodName AccessCheckAndAuditAlarmW {
    [OutputType([bool])]
    param (
        [IntPtr]$SubsystemName,
        [IntPtr]$HandleId,
        [IntPtr]$ObjectTypeName,
        [IntPtr]$ObjectName,
        [IntPtr]$SecurityDescriptor,
        [int]$DesiredAccess,
        [IntPtr]$GenericMapping,
        [bool]$ObjectCreation,
        [IntPtr]$GrantedAccess,
        [IntPtr]$AccessStatus,
        [IntPtr]$GenerateOnClose
    )

    <#
    BOOL AccessCheckAndAuditAlarmW(
        [in]           LPCWSTR              SubsystemName,
        [in, optional] LPVOID               HandleId,
        [in]           LPWSTR               ObjectTypeName,
        [in, optional] LPWSTR               ObjectName,
        [in]           PSECURITY_DESCRIPTOR SecurityDescriptor,
        [in]           DWORD                DesiredAccess,
        [in]           PGENERIC_MAPPING     GenericMapping,
        [in]           BOOL                 ObjectCreation,
        [out]          LPDWORD              GrantedAccess,
        [out]          LPBOOL               AccessStatus,
        [out]          LPBOOL               pfGenerateOnClose
    );
    #>

    $genericMappingRes = [Ordered]@{
        Raw = Format-Pointer $GenericMapping PGENERIC_MAPPING
    }
    if ($GenericMapping -ne [IntPtr]::Zero) {
        $rawMapping = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
            $GenericMapping,
            [type][Advapi32.GENERIC_MAPPING])

        $genericMappingRes.GenericRead = Format-Enum $rawMapping.GenericRead
        $genericMappingRes.GenericWrite = Format-Enum $rawMapping.GenericWrite
        $genericMappingRes.GenericExecute = Format-Enum $rawMapping.GenericExecute
        $genericMappingRes.GenericAll = Format-Enum $rawMapping.GenericAll
    }

    $sdRes = [Ordered]@{
        Raw = Format-Pointer $SecurityDescriptor PSECURITY_DESCRIPTOR
    }
    if ($SecurityDescriptor -ne [IntPtr]::Zero) {
        $methInfo = Get-PInvokeMethod $this Advapi32 ConvertSecurityDescriptorToStringSecurityDescriptorW

        $sddlPointer = [IntPtr]::Zero
        $sddlLen = 0
        $res = $methInfo.Invoke(
            $SecurityDescriptor,
            1,  # SDDL_REVISION_1
            0xF00101FF,
            [ref]$sddlPointer,
            [ref]$sddlLen); $errMsg = [System.Runtime.InteropServices.Marshal]::GetLastPInvokeErrorMessage()

        try {
            if ($res) {
                $sdRes.SDDL = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(
                    $sddlPointer)
            }
            else {
                $sdRes.Error = $errMsg
            }
        }
        finally {
            if ($sddlPointer -ne [IntPtr]::Zero) {
                [PSDetourHooks.Methods]::LocalFree($sddlPointer)
            }
        }
    }

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent($false)
    $currentUser.Groups | ForEach-Object {
        try {
            $groupName = $_.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            $groupName = "Failed to translate SID to name: $_"
        }

        [PSCustomObject]@{
            Name = $groupName
            SID = $_.Value
        }
    }
    Write-FunctionCall -Arguments ([Ordered]@{
        SubsystemName = Format-WideString $SubsystemName
        HandleId = Format-Pointer $HandleId
        ObjectTypeName = Format-WideString $ObjectTypeName
        ObjectName = Format-WideString $ObjectName
        SecurityDescriptor = $sdRes
        DesiredAccess = Format-Enum $DesiredAccess
        GenericMapping = $genericMappingRes
        ObjectCreation = $ObjectCreation
        GrantedAccess = Format-Pointer $GrantedAccess LPDWORD
        AccessStatus = Format-Pointer $AccessStatus LPBOOL
        GenerateOnClose = Format-Pointer $GenerateOnClose LPBOOl
        ThreadIdentity = [Ordered]@{
            UserName = $currentUser.Name
            SID = $currentUser.User.Value
            AuthenticationType = $currentUser.AuthenticationType
            IsAuthenticated = $currentUser.IsAuthenticated
            Groups = @($currentGroups)
        }
    })

    $res = $this.Invoke(
        $SubsystemName,
        $HandleId,
        $ObjectTypeName,
        $ObjectName,
        $SecurityDescriptor,
        $DesiredAccess,
        $GenericMapping,
        $ObjectCreation,
        $GrantedAccess,
        $AccessStatus,
        $GenerateOnClose
    )

    $grantedAccessRes = $null
    if ($GrantedAccess -ne [IntPtr]::Zero) {
        $grantedAccessRes = Format-Enum ([System.Runtime.InteropServices.Marshal]::ReadInt32($GrantedAccess))
    }
    $accessStatusRes = $null
    if ($AccessStatus -ne [IntPtr]::Zero) {
        $accessStatusRes = [System.Runtime.InteropServices.Marshal]::ReadInt32($AccessStatus) -ne 0
    }
    $generateOnCloseRes = $null
    if ($GenerateOnClose -ne [IntPtr]::Zero) {
        $generateOnCloseRes = [System.Runtime.InteropServices.Marshal]::ReadInt32($GenerateOnClose) -ne 0
    }

    Write-FunctionResult -Result $res ([ordered]@{
        GrantedAccess = $grantedAccessRes
        AccessStatus = $accessStatusRes
        GenerateOnClose = $generateOnCloseRes
    })

    $res
}

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

    Write-FunctionCall -Arguments ([Ordered]@{
        Prov = Format-Pointer $Prov HCRYPTPROV
        Param = Format-Enum $Param ([Advapi32.CryptGetProvParam])
        Data = Format-Pointer $Data BYTE
        DataLen = [Ordered]@{
            Raw = Format-Pointer $DataLen DWORD
            Value = $dataLenRes
        }
        Flags = Format-Enum $Flags
    })
    $res = $this.Invoke($Prov, $Param, $Data, $DataLen, $Flags)

    $dataLenRes = [System.Runtime.InteropServices.Marshal]::ReadInt32($DataLen)
    Write-FunctionResult -Result $res ([ordered]@{
        DataLen = $dataLenRes
    })

    $res
}

New-PSDetourHook -DllName api-ms-win-security-provider-l1-1-0.dll -MethodName GetNamedSecurityInfoW {
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
