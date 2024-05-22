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

    $luid = [Ordered]@{
        Raw = Format-Pointer $LogonID PLUID
    }
    if ($LogonID -ne [IntPtr]::Zero) {
        $rawLuid = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Secur32.LUID]($LogonID)
        $luid.LowPart = $rawLuid.LowPart
        $luid.HighPart = $rawLuid.HighPart
    }

    Write-FunctionCall -Arguments ([Ordered]@{
        Principal = Format-WideString $Principal
        Package = Format-WideString $Package
        CredentialUse = Format-Enum $CredentialUse ([Secur32.CredentialUse])
        LogonID = $luid
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
