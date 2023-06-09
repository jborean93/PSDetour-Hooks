Function Format-BCryptBufferDesc {
    [OutputType([string])]
    param(
        [IntPtr]$BufferDesc
    )

    $typeMap = @{
        0 = 'KDF_HASH_ALGORITHM'
        1 = 'KDF_SECRET_PREPEND'
        2 = 'KDF_SECRET_APPEND'
        3 = 'KDF_HMAC_KEY'
        4 = 'KDF_TLS_PRF_LABEL'
        5 = 'KDF_TLS_PRF_SEED'
        6 = 'KDF_SECRET_HANDLE'
        7 = 'KDF_TLS_PRF_PROTOCOL'
        8 = 'KDF_ALGORITHMID'
        9 = 'KDF_PARTYUINFO'
        10 = 'KDF_PARTYVINFO'
        11 = 'KDF_SUPPUBINFO'
        12 = 'KDF_SUPPPRIVINFO'
        13 = 'KDF_LABEL'
        14 = 'KDF_CONTEXT'
        15 = 'KDF_SALT'
        16 = 'KDF_ITERATION_COUNT'
        17 = 'KDF_GENERIC_PARAMETER'
        18 = 'KDF_KEYBITLENGTH'
    }

    if ($BufferDesc -ne [IntPtr]::Zero) {
        $version = [System.Runtime.InteropServices.Marshal]::ReadInt32($BufferDesc)
        $cBuffers = [System.Runtime.InteropServices.Marshal]::ReadInt32($BufferDesc, 4)
        $bufferPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($BufferDesc, 8)

        "`tBCryptKeyDerivation ParameterList(Version: $version, Buffers: $cBuffers)"

        for ($i = 0; $i -lt $cBuffers; $i++) {
            $bufferLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr)
            $bufferType = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr, 4)
            $bufferTypeStr = if ($typeMap.Contains([int]$bufferType)) {
                '{0} ({1})' -f ($typeMap[[int]$bufferType], $bufferType)
            }
            else {
                'KDF_UNKNOWN ({0})' -f $bufferType
            }
            $dataPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($bufferPtr, 8)
            $bufferPtr = [IntPtr]::Add($bufferPtr, 16)

            $data = if ($bufferType -eq 0) {  # KDF_HASH_ALGORITHM
                [System.Runtime.InteropServices.Marshal]::PtrToStringUni($dataPtr, $bufferLength / 2)
            }
            elseif ($bufferType -in @(8, 9, 10, 17)) {
                $bufferBytes = [byte[]]::new($bufferLength)
                [System.Runtime.InteropServices.Marshal]::Copy($dataPtr, $bufferBytes, 0, $bufferBytes.Length)
                [System.Convert]::ToHexString($bufferBytes)
            }
            else {
                '0x{0:X8}' -f $dataPtr
            }

            "`t`t[$i] Type: $bufferTypeStr, Data: $data"
        }
    }
}

New-PSDetourHook -DllName Bcrypt.dll -MethodName BCryptGenerateKeyPair {
    [OutputType([int])]
    param (
        [IntPtr]$Algorithm,
        [IntPtr]$Key,
        [int]$Length,
        [int]$Flags
    )

    $this.State.WriteLine(
        'BCryptGenerateKeyPair(Algorithm: 0x{0:X8}, Key: 0x{1:X8}, Length: {2}, Flags: {3:X8}',
        $Algorithm, $Key, $Length, $Flags
    )

    $res = $this.Invoke($Algorithm, $Key, $Length, $Flags)
    $this.State.WriteLine('BCryptGenerateKeyPair -> Res: 0x{0:X8}' -f $res)
    $this.State.WriteLine()

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

    $this.State.WriteLine(
        'BCryptGenRandom(Algorithm: 0x{0:X8}, Buffer: 0x{1:X8}, BufferLength: {2}, Flags: {3:X8}',
        $Algorithm, $Buffer, $BufferLength, $Flags
    )

    $res = $this.Invoke($Algorithm, $Buffer, $BufferLength, $Flags)

    $bufferBytes = [byte[]]::new($BufferLength)
    [System.Runtime.InteropServices.Marshal]::Copy($Buffer, $bufferBytes, 0, $bufferBytes.Length)
    $this.State.WriteLine('BCryptGenRandom -> Res: 0x{0:X8}, Buffer: {1}',
        $res,
        [System.Convert]::ToHexString($bufferBytes)
    )
    $this.State.WriteLine()

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

    if ($SecretLength -ne 64) {
        return $this.Invoke($Algorithm, $Key, $KeyObject, $KeyObjectLength, $Secret, $SecretLength, $Flags)
    }

    $secretBytes = [byte[]]::new($SecretLength)
    [System.Runtime.InteropServices.Marshal]::Copy($Secret, $secretBytes, 0, $secretBytes.Length)

    $this.State.WriteLine(
        "BCryptGenerateSymmetricKey(Algorithm: 0x{0:X8}, Key: 0x{1:X8}, KeyObject: 0x{2:X8}, KeyObjectLength: 0x{3:X8}, Secret: 0x{4:X8}, SecretLength: {5}, Flags: 0x{6:X8})`n`tSecret: {7}",
        $Algorithm, $Key, $KeyObject, $KeyObjectLength, $Secret, $SecretLength, $Flags,
        [System.Convert]::ToHexString($secretBytes)
    )

    $res = $this.Invoke($Algorithm, $Key, $KeyObject, $KeyObjectLength, $Secret, $SecretLength, $Flags)
    $this.State.WriteLine('BCryptGenerateSymmetricKey -> Res: 0x{0:X8}',
        $res
    )
    $this.State.WriteLine()

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

    Set-Item -Path Function:Format-BCryptBufferDesc -Value $this.State.GetFunction("Format-BCryptBufferDesc")

    $this.State.WriteLine(
        'BCryptKeyDerivation(Key: 0x{0:X8}, ParameterList: 0x{1:X8}, DerivedKey: 0x{2:X8}, DerivedKeyLength: {3}, OutKeyLength: 0x{4:X8}, Flags: 0x{5:X8})',
        $Key, $ParameterList, $DerivedKey, $DerivedKeyLength, $OutKeyLength, $Flags
    )

    Format-BCryptBufferDesc $ParameterList | ForEach-Object { $this.State.WriteLine($_) }

    $res = $this.Invoke($Key, $ParameterList, $DerivedKey, $DerivedKeyLength, $OutKeyLength, $Flags)

    $keyLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($OutKeyLength)
    $keyData = [byte[]]::new($keyLength)
    [System.Runtime.InteropServices.Marshal]::Copy($DerivedKey, $keyData, 0, $keyData.Length)

    $this.State.WriteLine('BCryptKeyDerivation -> Res: 0x{0:X8}, Derived: {1}',
        $res,
        [System.Convert]::ToHexString($keyData)
    )
    $this.State.WriteLine()

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

    $this.State.WriteLine(
        'BCryptSecretAgreement(PrivKey: 0x{0:X8}, PubKey: 0x{1:X8}, AgreedSecret: 0x{2:X8}, Flags: 0x{3:X8})',
        $PrivKey, $PubKey, $AgreedSecret, $Flags
    )
    $res = $this.Invoke($PrivKey, $PubKey, $AgreedSecret, $Flags)

    $secretPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($AgreedSecret)

    $outLengthPtr = $secretValue = $truncatePtr = [IntPtr]::Zero
    try {
        $truncatePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("TRUNCATE")

        $outLength = 0
        if ($this.DetouredModules.BCrypt.ContainsKey('BCryptDeriveKey')) {
            $outLengthPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)

            $null = $this.DetouredModules.BCrypt.BCryptDeriveKey.Invoke(
                $secretPtr,
                $truncatePtr,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                0,
                $outLengthPtr,
                0)
            $outLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($outLengthPtr)
            $secretValue = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($outLength)
            $null = $this.DetouredModules.BCrypt.BCryptDeriveKey.Invoke(
                $secretPtr,
                $truncatePtr,
                [IntPtr]::Zero,
                $secretValue,
                $outLength,
                $outLengthPtr,
                0)
        }
        else {
            $bcrypt = New-CtypesLib Bcrypt.dll

            $bcrypt.CharSet('Unicode').BCryptDeriveKey[void](
                $secretPtr,
                $truncatePtr,
                $null,
                $null,
                0,
                [ref]$outLength,
                0)
            $secretValue = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($outLength)
            $bcrypt.BCryptDeriveKey[void](
                $secretPtr,
                $truncatePtr,
                $null,
                $secretValue,
                $outLength,
                [ref]$outLength,
                0)
        }

        $secret = [byte[]]::new($outLength)
        [System.Runtime.InteropServices.Marshal]::Copy($secretValue, $secret, 0, $secret.Length)
    }
    finally {
        if ($outLengthPtr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($outLengthPtr)
        }
        if ($truncatePtr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($truncatePtr)
        }
        if ($secretValue -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($secretValue)
        }
    }

    $this.State.WriteLine('BCryptSecretAgreement -> Res: 0x{0:X8}, AgreedSecret: 0x{1:X8}, Secret: {2}',
        $res, $secretPtr,
        ([System.Convert]::ToHexString($secret))
    )
    $this.State.WriteLine()

    $res
}

New-PSDetourHook -DllName BCrypt.dll -MethodName BCryptDeriveKey  {
    [OutputType([int])]
    param (
        [IntPtr]$SharedSecret,
        [IntPtr]$KdfAlgorithm,
        [IntPtr]$ParameterList,
        [IntPtr]$DerivedKey,
        [int]$DerivedKeyLength,
        [IntPtr]$OutKeyLength,
        [int]$Flags
    )

    Set-Item -Path Function:Format-BCryptBufferDesc -Value $this.State.GetFunction("Format-BCryptBufferDesc")

    $kdfAlgoStr = ''
    if ($KdfAlgorithm -ne [IntPtr]::Zero) {
        $kdfAlgoStr = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($KdfAlgorithm)
    }

    $this.State.WriteLine(
        'BCryptDeriveKey(SharedSecret: 0x{0:X8}, KdfAlgorithm: ''{1}'', ParameterList: 0x{2:X8}, DerivedKey: 0x{3:X8}, DerivedKeyLength: {4}, OutKeyLength: 0x{5:X8}, Flags: 0x{6:X8})',
        $SharedSecret, $kdfAlgoStr, $ParameterList, $DerivedKey, $DerivedKeyLength, $OutKeyLength, $Flags
    )

    Format-BCryptBufferDesc $ParameterList | ForEach-Object { $this.State.WriteLine($_) }

    $res = $this.Invoke($SharedSecret, $KdfAlgorithm, $ParameterList, $DerivedKey, $DerivedKeyLength, $OutKeyLength, $Flags)

    $keyLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($OutKeyLength)
    $keyData = [byte[]]::new($keyLength)
    if ($DerivedKey -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::Copy($DerivedKey, $keyData, 0, $keyData.Length)
    }

    $this.State.WriteLine('BCryptDeriveKey -> Res: 0x{0:X8}, Derived: {1}'.
        $res,
        [System.Convert]::ToHexString($keyData)
    )
    $this.State.WriteLine()

    $res
}

New-PSDetourHook -DllName Bcrypt.dll -MethodName BCryptSetProperty {
    [OutputType([int])]
    param (
        [IntPtr]$Object,
        [IntPtr]$Property,
        [IntPtr]$InputData,
        [int]$InputLength,
        [int]$Flags
    )

    $inputBytes = [byte[]]::new($InputLength)
    [System.Runtime.InteropServices.Marshal]::Copy($InputData, $inputBytes, 0, $inputBytes.Length)
    $propertyStr = ''
    if ($Property -ne [IntPtr]::Zero) {
        $propertyStr = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Property)
    }
    $this.State.WriteLine(
        'BCryptSetProperty(Object: 0x{0:X8}, Property: 0x{1:X8}, InputData: 0x{2:X8}, InputLength: {3}, Flags: 0x{4:X8}',
        $Object, $Property, $InputData, $InputLength, $Flags
    )
    $this.State.WriteLine("`tProperty: '$propertyStr', InputData: $([System.Convert]::ToHexString($inputBytes))")

    $res = $this.Invoke($Object, $Property, $InputData, $InputLength, $Flags)
    $this.State.WriteLine('BCryptSetProperty -> Res: 0x{0:X8}', $res)
    $this.State.WriteLine()

    $res
}

New-PSDetourHook -DllName Bcrypt.dll -MethodName BCryptImportKeyPair {
    [OutputType([int])]
    param (
        [IntPtr]$Algorithm,
        [IntPtr]$ImportKey,
        [IntPtr]$BlobType,
        [IntPtr]$OutKey,
        [IntPtr]$InputData,
        [int]$InputLength,
        [int]$Flags
    )

    $inputBytes = [byte[]]::new($InputLength)
    [System.Runtime.InteropServices.Marshal]::Copy($InputData, $inputBytes, 0, $inputBytes.Length)
    $blobTypeStr = ''
    if ($BlobType -ne [IntPtr]::Zero) {
        $blobTypeStr = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($BlobType)
    }
    $this.State.WriteLine(
        'BCryptImportKeyPair(Algorithm: 0x{0:X8}, ImportKey: 0x{1:X8}, BlobType: 0x{2:X8}, OutKey: 0x{3:X8}, InputData: 0x{4:X8}, InputLength: {5}, Flags: 0x{6:X8}',
        $Algorithm, $ImportKey, $BlobType, $OutKey, $InputData, $InputLength, $Flags
    )
    $this.State.WriteLine("`tBlobType: '$blobTypeStr', InputData: $([System.Convert]::ToHexString($inputBytes))")

    $res = $this.Invoke($Algorithm, $ImportKey, $BlobType, $OutKey, $InputData, $InputLength, $Flags)
    $this.State.WriteLine('BCryptImportKeyPair -> Res: 0x{0:X8}, OutKey: 0x{1:X8}' -f @(
        $res,
        [Int64][System.Runtime.InteropServices.Marshal]::ReadIntPtr($OutKey)
    ))
    $this.State.WriteLine()

    $res
}
