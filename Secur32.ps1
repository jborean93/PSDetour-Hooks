Function Format-SecBufferDesc {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [IntPtr]$BufferDesc
    )

    $typeMap = @{
        0 = 'SECBUFFER_EMPTY'
        1 = 'SECBUFFER_DATA'
        2 = 'SECBUFFER_TOKEN'
        3 = 'SECBUFFER_PKG_PARAMS'
    }

    if ($BufferDesc -ne [IntPtr]::Zero) {
        $version = [System.Runtime.InteropServices.Marshal]::ReadInt32($BufferDesc)
        $cBuffers = [System.Runtime.InteropServices.Marshal]::ReadInt32($BufferDesc, 4)
        $bufferPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($BufferDesc, 8)

        "`tSecBufferDesc(Version: $version, Buffers: $cBuffers)"

        for ($i = 0; $i -lt $cBuffers; $i++) {
            $bufferLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr)
            $bufferType = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr, 4)

            $readOnly = ''
            if ($bufferType -band 0x80000000) {
                $readOnly = ' | SECBUFFER_READONLY'
                $bufferType = $bufferType -band -bnot 0x80000000
            }
            $readOnlyWithChecksum = ''
            if ($bufferType -band 0x10000000) {
                $readOnlyWithChecksum = ' | SECBUFFER_READONLY_WITH_CHECKSUM'
                $bufferType = $bufferType -band -bnot 0x10000000
            }

            $bufferTypeStr = if ($typeMap.Contains([int]$bufferType)) {
                '{0}{1}{2} ({3})' -f ($typeMap[[int]$bufferType], $readOnly, $readOnlyWithChecksum, $bufferType)
            }
            else {
                'SECBUFFER_UNKNOWN{0}{1} ({2})' -f $readOnly, $readOnlyWithChecksum, $bufferType
            }
            $dataPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($bufferPtr, 8)
            $bufferPtr = [IntPtr]::Add($bufferPtr, 16)

            $data = if ($bufferType -in @(1, 2, 3)) {
                $bufferBytes = [byte[]]::new($bufferLength)
                [System.Runtime.InteropServices.Marshal]::Copy($dataPtr, $bufferBytes, 0, $bufferBytes.Length)
                [System.Convert]::ToHexString($bufferBytes)
            }
            else {
                '0x{0:X8}' -f $dataPtr
            }

            "`t`t[$i] Type: $bufferTypeStr, Length: $bufferLength, Data: $data"
        }
    }
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

    Set-Item -Path Function:Format-SecBufferDesc -Value $this.State.GetFunction("Format-SecBufferDesc")

    $targetNameStr = ""
    if ($TargetName -ne [IntPtr]::Zero) {
        $targetNameStr = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($TargetName)
    }

    $this.State.WriteObject(
        'InitializeSecurityContext(Credential: 0x{0:X8}, Context: 0x{1:X8}, TargetName: 0x{2:X8}, ContextReq: 0x{3:X8}, Reserved1: 0x{4:X8}, TargetDataRep: 0x{5:X8}, Input: 0x{6:X8}, Reserved2: 0x{7:X8}, NewContext: 0x{8:X8}, Output: 0x{9:X8}, ContextAttr: 0x{10:X8}, Expiry: 0x{11:X8})' -f @(
        $Credential, $Context, $TargetName, $ContextReq, $Reserved1, $TargetDataRep, $InputBuffer, $Reserved2,
        $NewContext, $OutputBuffer, $ContextAttr, $Expiry
    ))
    $this.State.WriteObject("`tTargetName: $targetNameStr")
    Format-SecBufferDesc -BufferDesc $InputBuffer | ForEach-Object { $this.State.WriteObject($_) }

    $res = $this.Invoke($Credential, $Context, $TargetName, $ContextReq, $Reserved1, $TargetDataRep, $InputBuffer, $Reserved2,
        $NewContext, $OutputBuffer, $ContextAttr, $Expiry)

    $this.State.WriteObject('InitializeSecurityContextW -> Res: 0x{0:X8}' -f $res)
    $contextAttrValue = [System.Runtime.InteropServices.Marshal]::ReadInt32($ContextAttr)
    $this.State.WriteObject("`tContextAttr: 0x{0:X8}" -f $contextAttrValue)
    Format-SecBufferDesc -BufferDesc $OutputBuffer | ForEach-Object { $this.State.WriteObject($_) }

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

    Set-Item -Path Function:Format-SecBufferDesc -Value $this.State.GetFunction("Format-SecBufferDesc")

    $this.State.WriteObject('EncryptMessage(Context: 0x{0:X8}, Qop: {1}, Message: 0x{2:X8}, SeqNo: {3})' -f @(
        $Context, $Qop, $Message, $SeqNo
    ))
    Format-SecBufferDesc -BufferDesc $Message | ForEach-Object { $this.State.WriteObject($_) }

    $res = $this.Invoke($Context, $Qop, $Message, $SeqNo)

    $this.State.WriteObject('EncryptMessage -> Res: 0x{0:X8}' -f $res)
    Format-SecBufferDesc -BufferDesc $Message | ForEach-Object { $this.State.WriteObject($_) }

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

    Set-Item -Path Function:Format-SecBufferDesc -Value $this.State.GetFunction("Format-SecBufferDesc")

    $this.State.WriteObject('DecryptMessage(Context: 0x{0:X8}, Message: 0x{1:X8}, SeqNo: {2}, Qop: 0x{3:X8})' -f @(
        $Context, $Message, $SeqNo, $Qop
    ))
    Format-SecBufferDesc -BufferDesc $Message | ForEach-Object { $this.State.WriteObject($_) }

    $res = $this.Invoke($Context, $Message, $SeqNo, $Qop)

    $qopValue = [System.Runtime.InteropServices.Marshal]::ReadInt32($Qop)

    $this.State.WriteObject('DecryptMessage -> Res: 0x{0:X8}, Qop: {1}' -f @(
        $res, $qopValue
    ))
    Format-SecBufferDesc -BufferDesc $Message | ForEach-Object { $this.State.WriteObject($_) }

    $res
}
