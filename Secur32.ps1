Function Get-SecBufferDesc {
    [CmdletBinding()]
    param(
        [IntPtr]$BufferDesc,
        [Switch]$IgnoreValue
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $BufferDesc PSecBufferDesc
    }

    $bufferStructSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][Secur32.SecBuffer])

    if ($BufferDesc -ne [IntPtr]::Zero) {
        $desc = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
            $BufferDesc,
            [Type][Secur32.SecBufferDesc])
        $res.Version = $desc.ulVersion
        $res.Count = $desc.cBuffer
        $res.BufferPtr = Format-Pointer $desc.pBuffers PSecBuffer

        $bufferPtr = $desc.pBuffers
        $res.Buffers = @(
            for ($i = 0; $i -lt $desc.cBuffer; $i++) {
                $buffer = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                    $bufferPtr,
                    [Type][Secur32.SecBuffer])
                $bufferType = $buffer.BufferType -band -bnot ([Secur32.SecBufferFlags]::SECBUFFER_ATTRMASK)
                $bufferFlags = $buffer.BufferType -band ([Secur32.SecBufferFlags]::SECBUFFER_ATTRMASK)
                $bufferPtr = [IntPtr]::Add($bufferPtr, $bufferStructSize)

                if ($buffer.cbBuffer -and $buffer.pvBuffer -ne [IntPtr]::Zero -and -not $IgnoreValue) {
                    $bufferBytes = [byte[]]::new($buffer.cbBuffer)
                    [System.Runtime.InteropServices.Marshal]::Copy($buffer.pvBuffer, $bufferBytes, 0, $bufferBytes.Length)
                }
                else {
                    $bufferBytes = [byte[]]::new(0)
                }

                [Ordered]@{
                    Type = Format-Enum $bufferType ([Secur32.SecBufferType])
                    Flags = Format-Enum $bufferFlags ([Secur32.SecBufferFlags])
                    Size = $buffer.cbBuffer
                    Raw = Format-Pointer $buffer.pvBuffer
                    Data = [System.Convert]::ToHexString($bufferBytes)
                }
            }
        )
    }

    $res
}

Function Get-Luid {
    [CmdletBinding()]
    param(
        [IntPtr]$Luid
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Luid PLUID
    }
    if ($Luid -ne [IntPtr]::Zero) {
        $rawLuid = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Secur32.LUID]($Luid)
        $res.LowPart = $rawLuid.LowPart
        $res.HighPart = $rawLuid.HighPart
    }

    $res
}

New-PSDetourHook -DllName Secur32.dll -MethodName AcquireCredentialsHandleW {
    [OutputType([int])]
    param(
        [IntPtr]$Principal,
        [IntPtr]$Package,
        [int]$CredentialUse,
        [IntPtr]$LogonId,
        [IntPtr]$AuthData,
        [IntPtr]$GetKeyFn,
        [IntPtr]$GetKeyArgument,
        [IntPtr]$Credential,
        [IntPtr]$Expiry
    )

    <#
    SECURITY_STATUS SEC_Entry AcquireCredentialsHandle(
        _In_  SEC_CHAR       *pszPrincipal,
        _In_  SEC_CHAR       *pszPackage,
        _In_  ULONG          fCredentialUse,
        _In_  PLUID          pvLogonID,
        _In_  PVOID          pAuthData,
        _In_  SEC_GET_KEY_FN pGetKeyFn,
        _In_  PVOID          pvGetKeyArgument,
        _Out_ PCredHandle    phCredential,
        _Out_ PTimeStamp     ptsExpiry
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Principal = Format-WideString $Principal
        Package = Format-WideString $Package
        CredentialUse = Format-Enum $CredentialUse ([Secur32.CredentialUse])
        LogonID = Get-Luid $LogonId
        AuthData = Format-Pointer $AuthData PVOID
        GetKeyFn = Format-Pointer $GetKeyFn SEC_GET_KEY_FN
        GetKeyArgument = Format-Pointer $GetKeyArgument PVOID
        Credential = Format-Pointer $Credential PCredHandle
        Expiry = Format-Pointer $Expiry PTimeStamp
    })

    $res = $this.Invoke($Principal, $Package, $CredentialUse, $LogonId, $AuthData, $GetKeyFn, $GetKeyArgument,
        $Credential, $Expiry)

    Write-FunctionResult -Result $res

    $res
}

New-PSDetourHook -DllName Secur32.dll -MethodName AcceptSecurityContext {
    [OutputType([int])]
    param(
        [IntPtr]$Credential,
        [IntPtr]$Context,
        [IntPtr]$InputBuffer,
        [int]$ContextReq,
        [int]$TargetDataRep,
        [IntPtr]$NewContext,
        [IntPtr]$OutputBuffer,
        [IntPtr]$ContextAttr,
        [IntPtr]$Expiry
    )

    <#
    SECURITY_STATUS SEC_Entry AcceptSecurityContext(
        _In_opt_    PCredHandle    phCredential,
        _Inout_opt_ PCtxtHandle    phContext,
        _In_opt_    PSecBufferDesc pInput,
        _In_        ULONG          fContextReq,
        _In_        ULONG          TargetDataRep,
        _Inout_opt_ PCtxtHandle    phNewContext,
        _Inout_opt_ PSecBufferDesc pOutput,
        _Out_       PULONG         pfContextAttr,
        _Out_opt_   PTimeStamp     ptsExpiry
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Credential = Format-Pointer $Credential PCredHandle
        Context = Format-Pointer $Context PCtxtHandle
        Input = Get-SecBufferDesc $InputBuffer
        ContextReq = Format-Enum $ContextReq ([Secur32.AscReq])
        TargetDataRep = Format-Enum $TargetDataRep ([Secur32.TargetDataRep])
        NewContext = Format-Pointer $NewContext PCtxtHandle
        Output = Get-SecBufferDesc $OutputBuffer -IgnoreValue
        ContextAttr = Format-Pointer $ContextAttr
        Expiry = Format-Pointer $Expiry PTimeStamp
    })

    $res = $this.Invoke($Credential, $Context, $InputBuffer, $ContextReq, $TargetDataRep, $NewContext, $OutputBuffer,
        $ContextAttr, $Expiry)

    $contextAttrValue = [System.Runtime.InteropServices.Marshal]::ReadInt32($ContextAttr)
    $expiryValue = if ($Expiry -ne [IntPtr]::Zero) {
        $rawExpiry = [System.Runtime.InteropServices.Marshal]::ReadInt64($Expiry)
        Format-FileTime $rawExpiry
    }
    Write-FunctionResult -Result $res ([Ordered]@{
        Output = Get-SecBufferDesc $OutputBuffer
        ContextAttr = Format-Enum  $contextAttrValue ([Secur32.AscRet])
        Expiry = $expiryValue
    })

    $res
}

New-PSDetourHook -DllName Secur32.dll -MethodName InitializeSecurityContextW {
    [OutputType([int])]
    param(
        [IntPtr]$Credential,
        [IntPtr]$Context,
        [IntPtr]$TargetName,
        [int]$ContextReq,
        [int]$Reserved1,
        [int]$TargetDataRep,
        [IntPtr]$InputBuffer,
        [int]$Reserved2,
        [IntPtr]$NewContext,
        [IntPtr]$OutputBuffer,
        [IntPtr]$ContextAttr,
        [IntPtr]$Expiry
    )

    <#
    KSECDDDECLSPEC SECURITY_STATUS SEC_ENTRY InitializeSecurityContextW(
        [in, optional]      PCredHandle      phCredential,
        [in, optional]      PCtxtHandle      phContext,
        [in, optional]      PSECURITY_STRING pTargetName,
        [in]                unsigned long    fContextReq,
        [in]                unsigned long    Reserved1,
        [in]                unsigned long    TargetDataRep,
        [in, optional]      PSecBufferDesc   pInput,
        [in]                unsigned long    Reserved2,
        [in, out, optional] PCtxtHandle      phNewContext,
        [in, out, optional] PSecBufferDesc   pOutput,
        [out]               unsigned long    *pfContextAttr,
        [out, optional]     PTimeStamp       ptsExpiry
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Credential = Format-Pointer $Credential PCredHandle
        Context = Format-Pointer $Context PCtxtHandle
        TargetName = Format-WideString $TargetName
        ContextReq = Format-Enum $ContextReq ([Secur32.IscReq])
        Reserved1 = $Reserved1
        TargetDataRep = Format-Enum $TargetDataRep ([Secur32.TargetDataRep])
        Input = Get-SecBufferDesc $InputBuffer
        Reserved2 = $Reserved2
        NewContext = Format-Pointer $NewContext PCtxtHandle
        Output = Get-SecBufferDesc $OutputBuffer -IgnoreValue
        ContextAttr = Format-Pointer $ContextAttr
        Expiry = Format-Pointer $Expiry PTimeStamp
    })

    $res = $this.Invoke($Credential, $Context, $TargetName, $ContextReq, $Reserved1, $TargetDataRep, $InputBuffer, $Reserved2,
        $NewContext, $OutputBuffer, $ContextAttr, $Expiry)

    $contextAttrValue = [System.Runtime.InteropServices.Marshal]::ReadInt32($ContextAttr)
    $expiryValue = if ($Expiry -ne [IntPtr]::Zero) {
        $rawExpiry = [System.Runtime.InteropServices.Marshal]::ReadInt64($Expiry)
        Format-FileTime $rawExpiry
    }
    Write-FunctionResult -Result $res ([Ordered]@{
        Output = Get-SecBufferDesc $OutputBuffer
        ContextAttr = Format-Enum $contextAttrValue ([Secur32.IscRet])
        Expiry = $expiryValue
    })

    $res
}

New-PSDetourHook -DllName Secur32.dll -MethodName EncryptMessage {
    [OutputType([int])]
    param(
        [IntPtr]$Context,
        [int]$Qop,
        [IntPtr]$Message,
        [int]$SeqNo
    )

    <#
    SECURITY_STATUS SEC_ENTRY EncryptMessage(
        [in]      PCtxtHandle    phContext,
        [in]      unsigned long  fQOP,
        [in, out] PSecBufferDesc pMessage,
        [in]      unsigned long  MessageSeqNo
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Context = Format-Pointer $Context PCtxtHandle
        Qop = $Qop
        Message = Get-SecBufferDesc $Message
        MessageSeqNo = $SeqNo
    })

    $res = $this.Invoke($Context, $Qop, $Message, $SeqNo)

    Write-FunctionResult -Result $res ([Ordered]@{
        Message = Get-SecBufferDesc $Message
    })

    $res
}

New-PSDetourHook -DllName Secur32.dll -MethodName DecryptMessage {
    [OutputType([int])]
    param(
        [IntPtr]$Context,
        [IntPtr]$Message,
        [int]$SeqNo,
        [IntPtr]$Qop
    )

    <#
    SECURITY_STATUS SEC_ENTRY DecryptMessage(
        [in]      PCtxtHandle    phContext,
        [in, out] PSecBufferDesc pMessage,
        [in]      unsigned long  MessageSeqNo,
        [out]     unsigned long  *pfQOP
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Context = Format-Pointer $Context PCtxtHandle
        Message = Get-SecBufferDesc $Message
        MessageSeqNo = $SeqNo
        Qop = Format-Pointer $Qop
    })

    $res = $this.Invoke($Context, $Message, $SeqNo, $Qop)

    $qopValue = if ($Qop -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::ReadInt32($Qop)
    }
    Write-FunctionResult -Result $res ([Ordered]@{
        Message = Get-SecBufferDesc $Message
        Qop = $qopValue
    })

    $res
}

New-PSDetourHook -DllName Secur32.dll -MethodName LsaLogonUser {
    [OutputType([int])]
    param(
        [IntPtr]$LsaHandle,
        [IntPtr]$OriginName,
        [int]$LogonType,
        [int]$AuthenticationPackage,
        [IntPtr]$AuthenticationInformation,
        [int]$AuthenticationInformationLength,
        [IntPtr]$LocalGroups,
        [IntPtr]$SourceContext,
        [IntPtr]$ProfileBuffer,
        [IntPtr]$ProfileBufferLength,
        [IntPtr]$LogonId,
        [IntPtr]$Token,
        [IntPtr]$Quotas,
        [IntPtr]$SubStatus
    )

    <#
    NTSTATUS LsaLogonUser(
        [in]           HANDLE              LsaHandle,
        [in]           PLSA_STRING         OriginName,
        [in]           SECURITY_LOGON_TYPE LogonType,
        [in]           ULONG               AuthenticationPackage,
        [in]           PVOID               AuthenticationInformation,
        [in]           ULONG               AuthenticationInformationLength,
        [in, optional] PTOKEN_GROUPS       LocalGroups,
        [in]           PTOKEN_SOURCE       SourceContext,
        [out]          PVOID               *ProfileBuffer,
        [out]          PULONG              ProfileBufferLength,
        [out]          PLUID               LogonId,
        [out]          PHANDLE             Token,
        [out]          PQUOTA_LIMITS       Quotas,
        [out]          PNTSTATUS           SubStatus
    );
    #>

    $originNameRes = [Ordered]@{
        Raw = Format-Pointer $OriginName PLSA_STRING
    }
    if ($OriginName -ne [IntPtr]::Zero) {
        $originNameRaw = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Secur32.LSA_STRING]($OriginName)
        $originNameRes.Length = $originNameRaw.Length
        $originNameRes.MaximumLength = $originNameRaw.MaximumLength
        $originNameRes.Buffer = [Ordered]@{
            Raw = Format-Pointer $originNameRaw.Buffer PCHAR
        }
        if ($originNameRaw.Buffer -ne [IntPtr]::Zero) {
            $originNameRes.Buffer.Value = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(
                $originNameRaw.Buffer,
                $originNameRaw.Length)
        }
    }

    $authInfoRes = [Ordered]@{
        Raw = Format-Pointer $AuthenticationInformation
    }
    if ($AuthenticationInformation -ne [IntPtr]::Zero -and $AuthenticationInformationLength) {
        $authInfoBuffer = [byte[]]::new($AuthenticationInformationLength)
        [System.Runtime.InteropServices.Marshal]::Copy(
            $AuthenticationInformation,
            $authInfoBuffer,
            0,
            $authInfoBuffer.Length)
        $authInfoRes.Value = [System.Convert]::ToHexString($authInfoBuffer)
    }

    $localGroupsRes = [Ordered]@{
        Raw = Format-Pointer $LocalGroups PTOKEN_GROUPS
    }
    if ($LocalGroups -ne [IntPtr]::Zero) {
        $tGroupsRaw = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Secur32.TOKEN_GROUPS]($LocalGroups)
        $localGroupsRes.GroupCount = $tGroupsRaw.GroupCount

        $groups = [System.Collections.Generic.List[object]]::new([int]$tGroupsRaw.GroupCount)
        $saaPtr = [IntPtr]::Add(
            $LocalGroups,
            [System.Runtime.InteropServices.Marshal]::OffsetOf(
                [Secur32.TOKEN_GROUPS],
                "Groups"
            )
        )
        for ($i = 0; $i -lt $tGroupsRaw.GroupCount; $i++) {
            $saa = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Secur32.SID_AND_ATTRIBUTES]($saaPtr)

            $sid = [System.Security.Principal.SecurityIdentifier]::new($saa.Sid)
            try {
                $groupName = $sid.Translate([System.Security.Principal.NTAccount]).Value
            }
            catch [System.Security.Principal.IdentityNotMappedException] {
                $groupName = $_.Exception.Message
            }

            $groupInfo = [Ordered]@{
                Sid = $sid.Value
                Name = $groupName
                Attributes = Format-Enum $saa.Attributes ([Secur32.TokenGroupAttributes])
            }
            $groups.Add($groupInfo)

            $saaPtr = [IntPtr]::Add(
                $saaPtr,
                [System.Runtime.InteropServices.Marshal]::SizeOf[Secur32.SID_AND_ATTRIBUTES]())
        }

        $localGroupsRes.Groups = $groups
    }

    $sourceContextRes = [Ordered]@{
        Raw = Format-Pointer $SourceContext PTOKEN_SOURCE
    }
    if ($SourceContext -ne [IntPtr]::Zero) {
        $sourceContextRaw = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Secur32.TOKEN_SOURCE]($SourceContext)
        $sourceContextRes.SourceName = [string]::new($sourceContextRaw.SourceName).TrimEnd([char]0)
        $sourceContextRes.SourceIdentifier = [Ordered]@{
            LowPart = $sourceContextRaw.SourceIdentifier.LowPart
            HighPart = $sourceContextRaw.SourceIdentifier.HighPart
        }
    }

    Write-FunctionCall -Arguments ([Ordered]@{
        LsaHandle = Format-Pointer $LsaHandle HANDLE
        OriginName = $originNameRes
        LogonType = Format-Enum $LogonType ([Secur32.SecurityLogonType])
        AuthenticationPackage = $AuthenticationPackage
        AuthenticationInformation = $authInfoRes
        AuthenticationInformationLength = $AuthenticationInformationLength
        LocalGroups = $localGroupsRes
        SourceContext = $sourceContextRes
        ProfileBuffer = Format-Pointer $ProfileBuffer
        ProfileBufferLength = Format-Pointer $ProfileBufferLength
        LogonId = Format-Pointer $LogonId
        Token = Format-Pointer $Token PHANDLE
        Quotas = Format-Pointer $Quotas PQUOTA_LIMITS
        SubStatus = Format-Pointer $SubStatus PNTSTATUS
    })

    $res = $this.Invoke(
        $LsaHandle,
        $OriginName,
        $LogonType,
        $AuthenticationPackage,
        $AuthenticationInformation,
        $AuthenticationInformationLength,
        $LocalGroups,
        $SourceContext,
        $ProfileBuffer,
        $ProfileBufferLength,
        $LogonId,
        $Token,
        $Quotas,
        $SubStatus)

    $profileBufferRes = $null
    if ($ProfileBuffer -ne [IntPtr]::Zero) {
        $value = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ProfileBuffer)
        $profileBufferRes = Format-Pointer $value
    }

    $profileBufferLengthRes = $null
    if ($ProfileBufferLength -ne [IntPtr]::Zero) {
        $profileBufferLengthRes = [System.Runtime.InteropServices.Marshal]::ReadInt32($ProfileBufferLength)
    }

    $tokenRes = $null
    if ($Token -ne [IntPtr]::Zero) {
        $value = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($Token)
        $tokenRes = Format-Pointer $value HANDLE
    }

    $quotasRes = $null
    if ($Quotas -ne [IntPtr]::Zero) {
        $quotasRaw = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Secur32.QUOTA_LIMITS]($Quotas)
        $quotasRes = [Ordered]@{
            PagedPoolLimit = [Int64]$quotasRaw.PagedPoolLimit
            NonPagedPoolLimit = [Int64]$quotasRaw.NonPagedPoolLimit
            MinimumWorkingSetSize = [Int64]$quotasRaw.MinimumWorkingSetSize
            MaximumWorkingSetSize = [Int64]$quotasRaw.MaximumWorkingSetSize
            PagefileLimit = [Int64]$quotasRaw.PagefileLimit
            TimeLimit = $quotasRaw.TimeLimit
        }
    }

    $subStatusRes = $null
    if ($SubStatus -ne [IntPtr]::Zero) {
        $value = [System.Runtime.InteropServices.Marshal]::ReadInt32($SubStatus)
        $subStatusRes = Format-Enum $value
    }

    Write-FunctionResult -Result $res ([Ordered]@{
        ProfileBuffer = $profileBufferRes
        ProfileBufferLength = $profileBufferLengthRes
        LogonId = Get-Luid $LogonId
        Token = $tokenRes
        Quotas = $quotasRes
        SubStatus = $substatusRes
    }) -LastError $res -ErrorType Lsa

    $res
}