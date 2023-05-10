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

    $writeBuffers = {
        $typeMap = @{
            0 = 'SECBUFFER_EMPTY'
            1 = 'SECBUFFER_DATA'
            2 = 'SECBUFFER_TOKEN'
            3 = 'SECBUFFER_PKG_PARAMS'
        }

        $bufferPtr = $Message
        if ($bufferPtr) {
            $version = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr)
            $cBuffers = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr, 4)
            $bufferPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($bufferPtr, 8)

            $this.State.Writer.WriteLine("`tEncryptMessage Message(Version: $version, Buffers: $cBuffers)")

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

                $this.State.Writer.WriteLine("`t`t[$i] Type: $bufferTypeStr, Length: $bufferLength, Data: $data")
            }
        }
    }

    $this.State.Writer.WriteLine('EncryptMessage(Context: 0x{0:X8}, Qop: {1}, Message: 0x{2:X8}, SeqNo: {3})' -f (
        $Context, $Qop, $Message, $SeqNo
    ))

    &$writeBUffers

    $res = $this.Invoke($Context, $Qop, $Message, $SeqNo)

    $this.State.Writer.WriteLine('EncryptMessage -> Res: 0x{0:X8}' -f (
        $res
    ))

    &$writeBuffers

    $this.State.Writer.WriteLine('')

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

    $writeBuffers = {
        $typeMap = @{
            0 = 'SECBUFFER_EMPTY'
            1 = 'SECBUFFER_DATA'
            2 = 'SECBUFFER_TOKEN'
            3 = 'SECBUFFER_PKG_PARAMS'
        }

        $bufferPtr = $Message
        if ($bufferPtr) {
            $version = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr)
            $cBuffers = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr, 4)
            $bufferPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($bufferPtr, 8)

            $this.State.Writer.WriteLine("`tDecryptMessage Message(Version: $version, Buffers: $cBuffers)")

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

                $this.State.Writer.WriteLine("`t`t[$i] Type: $bufferTypeStr, Length: $bufferLength, Data: $data")
            }
        }
    }

    $this.State.Writer.WriteLine('DecryptMessage(Context: 0x{0:X8}, Message: 0x{1:X8}, SeqNo: {2}, Qop: 0x{3:X8})' -f (
        $Context, $Message, $SeqNo, $Qop
    ))

    &$writeBUffers

    $res = $this.Invoke($Context, $Message, $SeqNo, $Qop)

    $qopValue = [System.Runtime.InteropServices.Marshal]::ReadInt32($Qop)

    $this.State.Writer.WriteLine('DecryptMessage -> Res: 0x{0:X8}, Qop: {1}' -f (
        $res, $qopValue
    ))

    &$writeBuffers

    $this.State.Writer.WriteLine('')

    $res
}
