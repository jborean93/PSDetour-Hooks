Function Get-BCryptBufferDesc {
    [CmdletBinding()]
    param(
        [IntPtr]$BufferDesc,
        [Switch]$IgnoreValue
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $BufferDesc PCryptBufferDesc
    }

    $bufferStructSize = [System.Runtime.InteropServices.Marshal]::SizeOf(
        [Type][BCrypt.BCryptBuffer])

    if ($BufferDesc -ne [IntPtr]::Zero) {
        $desc = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
            $BufferDesc,
            [Type][BCrypt.BCryptBufferDesc])
        $res.Version = $desc.ulVersion
        $res.Count = $desc.cBuffer
        $res.BufferPtr = Format-Pointer $desc.pBuffers PSecBuffer

        $bufferPtr = $desc.pBuffers
        $res.Buffers = @(
            for ($i = 0; $i -lt $desc.cBuffer; $i++) {
                $buffer = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                    $bufferPtr,
                    [Type][BCrypt.BCryptBuffer])
                $bufferPtr = [IntPtr]::Add($bufferPtr, $bufferStructSize)

                if ($buffer.cbBuffer -and $buffer.pvBuffer -ne [IntPtr]::Zero -and -not $IgnoreValue) {
                    $bufferBytes = [byte[]]::new($buffer.cbBuffer)
                    [System.Runtime.InteropServices.Marshal]::Copy($buffer.pvBuffer, $bufferBytes, 0, $bufferBytes.Length)
                }
                else {
                    $bufferBytes = [byte[]]::new(0)
                }

                [Ordered]@{
                    Type = Format-Enum $buffer.BufferType ([BCrypt.BCryptBufferType])
                    Size = $buffer.cbBuffer
                    Raw = Format-Pointer $buffer.pvBuffer
                    Data = [System.Convert]::ToHexString($bufferBytes)
                }
            }
        )
    }

    $res
}

New-PSDetourHook -DllName Bcrypt.dll -MethodName BCryptGenerateKeyPair {
    [OutputType([int])]
    param (
        [IntPtr]$Algorithm,
        [IntPtr]$Key,
        [int]$Length,
        [int]$Flags
    )

    <#
    NTSTATUS BCryptGenerateKeyPair(
        [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
        [out]     BCRYPT_KEY_HANDLE *phKey,
        [in]      ULONG             dwLength,
        [in]      ULONG             dwFlags
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Algorithm = Format-Pointer $Algorithm 'BCRYPT_ALG_HANDLE'
        Key = Format-Pointer $Key 'BCRYPT_KEY_HANDLE'
        Length = $Length
        Flags = Format-Enum $Flags
    })
    $res = $this.Invoke($Algorithm, $Key, $Length, $Flags)
    Write-FunctionResult -Result $res

    $res
}

New-PSDetourHook -DllName Bcrypt.dll -MethodName BCryptGenRandom {
    [OutputType([int])]
    param (
        [IntPtr]$Algorithm,
        [IntPtr]$Buffer,
        [int]$BufferLength,
        [int]$Flags
    )

    <#
    NTSTATUS BCryptGenRandom(
        [in, out] BCRYPT_ALG_HANDLE hAlgorithm,
        [in, out] PUCHAR            pbBuffer,
        [in]      ULONG             cbBuffer,
        [in]      ULONG             dwFlags
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Algorithm = Format-Pointer $Algorithm 'BCRYPT_ALG_HANDLE'
        Buffer = Format-Pointer $Buffer 'PUCHAR'
        BufferLength = $BufferLength
        Flags = Format-Enum $Flags ([BCrypt.GenRandomFlags])
    })

    $res = $this.Invoke($Algorithm, $Buffer, $BufferLength, $Flags)

    $bufferBytes = [byte[]]::new($BufferLength)
    [System.Runtime.InteropServices.Marshal]::Copy($Buffer, $bufferBytes, 0, $bufferBytes.Length)
    Write-FunctionResult -Result $res ([Ordered]@{
        Buffer = [System.Convert]::ToHexString($bufferBytes)
    })

    $res
}

New-PSDetourHook -DllName BCrypt.dll -MethodName BCryptGenerateSymmetricKey {
    [OutputType([int])]
    param (
        [IntPtr]$Algorithm,
        [IntPtr]$Key,
        [IntPtr]$KeyObject,
        [int]$KeyObjectLength,
        [IntPtr]$Secret,
        [int]$SecretLength,
        [int]$Flags
    )

    <#
    NTSTATUS BCryptGenerateSymmetricKey(
        [in, out]       BCRYPT_ALG_HANDLE hAlgorithm,
        [out]           BCRYPT_KEY_HANDLE *phKey,
        [out, optional] PUCHAR            pbKeyObject,
        [in]            ULONG             cbKeyObject,
        [in]            PUCHAR            pbSecret,
        [in]            ULONG             cbSecret,
        [in]            ULONG             dwFlags
    );
    #>

    $secretBytes = [byte[]]::new($SecretLength)
    if ($SecretLength -and $Secret -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::Copy($Secret, $secretBytes, 0, $secretBytes.Length)
    }

    Write-FunctionCall -Arguments ([Ordered]@{
        Algorithm = Format-Pointer $Algorithm 'BCRYPT_ALG_HANDLE'
        Key = Format-Pointer $Key 'BCRYPT_KEY_HANDLE'
        KeyObject = Format-Pointer $KeyObject 'PUCHAR'
        KeyObjectLength = $KeyObjectLength
        Secret = [Ordered]@{
            Raw = Format-Pointer $Secret 'PUCHAR'
            Value = [System.Convert]::ToHexString($secretBytes)
        }
        SecretLength = $SecretLength
        Flags = Format-Enum $Flags
    })

    $res = $this.Invoke($Algorithm, $Key, $KeyObject, $KeyObjectLength, $Secret, $SecretLength, $Flags)

    Write-FunctionResult -Result $res

    $res
}

New-PSDetourHook -DllName BCrypt.dll -MethodName BCryptKeyDerivation {
    [OutputType([int])]
    param (
        [IntPtr]$Key,
        [IntPtr]$ParameterList,
        [IntPtr]$DerivedKey,
        [int]$DerivedKeyLength,
        [IntPtr]$OutKeyLength,
        [int]$Flags
    )

    <#
    NTSTATUS BCryptKeyDerivation(
        [in]           BCRYPT_KEY_HANDLE hKey,
        [in, optional] BCryptBufferDesc  *pParameterList,
        [out]          PUCHAR            pbDerivedKey,
        [in]           ULONG             cbDerivedKey,
        [out]          ULONG             *pcbResult,
        [in]           ULONG             dwFlags
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Key = Format-Pointer $Key 'BCRYPT_KEY_HANDLE'
        ParameterList = Get-BCryptBufferDesc $ParameterList
        DerivedKey = Format-Pointer $DerivedKey 'PUCHAR'
        DerivedKeyLength = $DerivedKeyLength
        OutKeyLength = Format-Pointer $OutKeyLength 'PULONG'
        Flags = Format-Enum $Flags
    })

    $res = $this.Invoke($Key, $ParameterList, $DerivedKey, $DerivedKeyLength, $OutKeyLength, $Flags)

    $keyLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($OutKeyLength)
    $keyData = [byte[]]::new($keyLength)
    if ($keyLength) {
        [System.Runtime.InteropServices.Marshal]::Copy($DerivedKey, $keyData, 0, $keyData.Length)
    }
    Write-FunctionResult -Result $res ([Ordered]@{
        DerivedKey = [System.Convert]::ToHexString($keyData)
    })

    $res
}

New-PSDetourHook -DllName BCrypt.dll -MethodName BCryptSecretAgreement {
    [OutputType([int])]
    param (
        [IntPtr]$PrivKey,
        [IntPtr]$PubKey,
        [IntPtr]$AgreedSecret,
        [int]$Flags
    )

    <#
    NTSTATUS BCryptSecretAgreement(
        [in]  BCRYPT_KEY_HANDLE    hPrivKey,
        [in]  BCRYPT_KEY_HANDLE    hPubKey,
        [out] BCRYPT_SECRET_HANDLE *phAgreedSecret,
        [in]  ULONG                dwFlags
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        PrivKey = Format-Pointer $PrivKey 'BCRYPT_KEY_HANDLE'
        PubKey = Format-Pointer $PubKey 'BCRYPT_KEY_HANDLE'
        AgreedSecret = Format-Pointer $AgreedSecret 'BCRYPT_SECRET_HANDLE'
        Flags = Format-Enum $Flags
    })

    $res = $this.Invoke($PrivKey, $PubKey, $AgreedSecret, $Flags)

    $secretPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($AgreedSecret)
    $outLengthPtr = $secretValue = [IntPtr]::Zero
    try {
        $outLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
        $methInfo = if ($this.DetouredModules.BCrypt.ContainsKey('BCryptDeriveKey')) {
            $this.DetouredModules.BCrypt.BCryptDeriveKey
        }
        else {
            [BCrypt.Methods]::BCryptDeriveKey
        }

        $null = $methInfo.Invoke(
            $secretPtr,
            "TRUNCATE",
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            0,
            $outLengthPtr,
            0)
        $outLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($outLengthPtr)
        $secretValue = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($outLength)
        $null = $methInfo.Invoke(
            $secretPtr,
            "TRUNCATE",
            [IntPtr]::Zero,
            $secretValue,
            $outLength,
            $outLengthPtr,
            0)

        $secret = [byte[]]::new($outLength)
        [System.Runtime.InteropServices.Marshal]::Copy($secretValue, $secret, 0, $secret.Length)
    }
    finally {
        if ($outLengthPtr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($outLengthPtr)
        }
        if ($secretValue -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($secretValue)
        }
    }

    Write-FunctionResult -Result $res ([Ordered]@{
        AgreedSecret = Format-Pointer $secretPtr 'BCRYPT_SECRET_HANDLE'
        Secret = [System.Convert]::ToHexString($Secret)
    })

    $res
}

New-PSDetourHook -DllName BCrypt.dll -MethodName BCryptDeriveKey  {
    [OutputType([int])]
    param (
        [IntPtr]$SharedSecret,
        [System.Runtime.InteropServices.MarshalAsAttribute([System.Runtime.InteropServices.UnmanagedType]::LPWStr)]
        [string]$KdfAlgorithm,
        [IntPtr]$ParameterList,
        [IntPtr]$DerivedKey,
        [int]$DerivedKeyLength,
        [IntPtr]$OutKeyLength,
        [int]$Flags
    )

    <#
    NTSTATUS BCryptDeriveKey(
        [in]            BCRYPT_SECRET_HANDLE hSharedSecret,
        [in]            LPCWSTR              pwszKDF,
        [in, optional]  BCryptBufferDesc     *pParameterList,
        [out, optional] PUCHAR               pbDerivedKey,
        [in]            ULONG                cbDerivedKey,
        [out]           ULONG                *pcbResult,
        [in]            ULONG                dwFlags
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        SharedSecret = Format-Pointer $SharedSecret 'BCRYPT_SECRET_HANDLE'
        KdfAlgorithm = $KdfAlgorithm
        ParameterList = Get-BCryptBufferDesc $ParameterList
        DerivedKey = Format-Pointer $DerivedKey 'PUCHAR'
        DerivedKeyLength = $DerivedKeyLength
        OutKeyLength = Format-Pointer $OutKeyLength 'PULONG'
        Flags = Format-Enum $Flags ([BCrypt.DeriveKeyFlags])
    })

    $res = $this.Invoke($SharedSecret, $KdfAlgorithm, $ParameterList, $DerivedKey, $DerivedKeyLength, $OutKeyLength, $Flags)

    $keyLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($OutKeyLength)
    $keyData = [byte[]]::new($keyLength)
    if ($DerivedKey -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::Copy($DerivedKey, $keyData, 0, $keyData.Length)
    }
    Write-FunctionResult -Result $res ([Ordered]@{
        DerivedKey = [System.Convert]::ToHexString($keyData)
    })

    $res
}

New-PSDetourHook -DllName Bcrypt.dll -MethodName BCryptSetProperty {
    [OutputType([int])]
    param (
        [IntPtr]$Object,
        [System.Runtime.InteropServices.MarshalAsAttribute([System.Runtime.InteropServices.UnmanagedType]::LPWStr)]
        [string]$Property,
        [IntPtr]$InputData,
        [int]$InputLength,
        [int]$Flags
    )

    <#
    NTSTATUS BCryptSetProperty(
        [in, out] BCRYPT_HANDLE hObject,
        [in]      LPCWSTR       pszProperty,
        [in]      PUCHAR        pbInput,
        [in]      ULONG         cbInput,
        [in]      ULONG         dwFlags
    );
    #>

    $inputBytes = [byte[]]::new($InputLength)
    [System.Runtime.InteropServices.Marshal]::Copy($InputData, $inputBytes, 0, $inputBytes.Length)

    Write-FunctionCall -Arguments ([Ordered]@{
        Object = Format-Pointer $Object
        Property = $Property
        InputData = [Ordered]@{
            Raw = Format-Pointer $InputData 'PUCHAR'
            Value = [System.Convert]::ToHexString($inputBytes)
        }
        InputLength = $InputLength
        Flags = Format-Enum $Flags
    })
    $res = $this.Invoke($Object, $Property, $InputData, $InputLength, $Flags)
    Write-FunctionResult -Result $res

    $res
}

New-PSDetourHook -DllName Bcrypt.dll -MethodName BCryptImportKeyPair {
    [OutputType([int])]
    param (
        [IntPtr]$Algorithm,
        [IntPtr]$ImportKey,
        [System.Runtime.InteropServices.MarshalAsAttribute([System.Runtime.InteropServices.UnmanagedType]::LPWStr)]
        [string]$BlobType,
        [IntPtr]$OutKey,
        [IntPtr]$InputData,
        [int]$InputLength,
        [int]$Flags
    )

    <#
    NTSTATUS BCryptImportKeyPair(
        [in]      BCRYPT_ALG_HANDLE hAlgorithm,
        [in, out] BCRYPT_KEY_HANDLE hImportKey,
        [in]      LPCWSTR           pszBlobType,
        [out]     BCRYPT_KEY_HANDLE *phKey,
        [in]      PUCHAR            pbInput,
        [in]      ULONG             cbInput,
        [in]      ULONG             dwFlags
    );
    #>

    $inputBytes = [byte[]]::new($InputLength)
    [System.Runtime.InteropServices.Marshal]::Copy($InputData, $inputBytes, 0, $inputBytes.Length)

    Write-FunctionCall -Arguments ([Ordered]@{
        Algorithm = Format-Pointer $Algorithm 'BCRYPT_ALG_HANDLE'
        ImportKey = Format-Pointer $ImportKey 'BCRYPT_KEY_HANDLE'
        BlobType = $BlobType
        OutKey = Format-Pointer $OutKey 'BCRYPT_KEY_HANDLE'
        InputData = [Ordered]@{
            Raw = Format-Pointer $InputData 'PUCHAR'
            Value = [System.Convert]::ToHexString($inputBytes)
        }
        InputLength = $InputLength
        Flags = Format-Enum $Flags ([BCrypt.ImportKeyFlags])
    })

    $res = $this.Invoke($Algorithm, $ImportKey, $BlobType, $OutKey, $InputData, $InputLength, $Flags)

    $outKeyPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($OutKey)
    Write-FunctionResult -Result $res ([Ordered]@{
        OutKey = Format-Pointer $outKeyPtr 'BCRYPT_KEY_HANDLE'
    })

    $res
}
