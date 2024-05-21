Function Format-WTDFileData {
    [CmdletBinding()]
    param([IntPtr]$Raw)

    $data = [Ordered]@{
        Raw = Format-Pointer $Raw PWINTRUST_FILE_INFO
    }

    if ($Raw -ne [IntPtr]::Zero) {
        $data.CBStruct = [System.Runtime.InteropServices.Marshal]::ReadInt32($Raw)

        $requiredSize = [System.Runtime.InteropServices.Marshal]::SizeOf[Wintrust.WINTRUST_FILE_INFO]()
        if ($data.CBStruct -ge $requiredSize) {
            $rawData = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Wintrust.WINTRUST_FILE_INFO]($Raw)
            $data.FilePath = Format-WideString $rawData.pcwszFilePath
            $data.File = Format-Pointer $rawData.hFile HANDLE
            $data.KnownSubject = Format-Guid $rawData.pgKnownSubject
        }
        else {
            $data.Error = 'Unknown struct size encountered'
        }
    }

    $data
}

Function Format-WTDCatalogData {
    [CmdletBinding()]
    param([IntPtr]$Raw)

    $data = [Ordered]@{
        Raw = Format-Pointer $Raw PWINTRUST_CATALOG_INFO
    }

    if ($Raw -ne [IntPtr]::Zero) {
        $data.CBStruct = [System.Runtime.InteropServices.Marshal]::ReadInt32($Raw)

        $requiredSize = [System.Runtime.InteropServices.Marshal]::SizeOf[Wintrust.WINTRUST_CATALOG_INFO]()
        if ($data.CBStruct -ge $requiredSize) {
            $rawData = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Wintrust.WINTRUST_CATALOG_INFO]($Raw)
            $data.CatalogVersion = $rawData.dwCatalogVersion
            $data.CatalogFilePath = Format-WideString $rawData.pcwszCatalogFilePath
            $data.MemberTag = Format-WideString $rawData.pcwszMemberTag
            $data.MemberFilePath = Format-WideString $rawData.pcwszMemberFilePath
            $data.MemberFile = Format-Pointer $rawData.hMemberFile HANDLE

            $data.CalculatedFileHash = [Ordered]@{
                Size = $rawData.cbCalculatedFileHash
                Raw = Format-Pointer $rawData.pbCalculatedFileHash
            }
            if ($rawData.pbCalculatedFileHash -ne [IntPtr]::Zero) {
                $dataBytes = [byte[]]::new($rawData.cbCalculatedFileHash)
                [System.Runtime.InteropServices.Marshal]::Copy($rawData.pbCalculatedFileHash, $dataBytes, 0, $dataBytes.Length)
                $data.CalculatedFileHash.Value = [Convert]::ToHexString($dataBytes)
            }

            $data.CatalogContext = Format-Pointer $rawData.pcCatalogContext PCCTL_CONTEXT
            $data.CatAdmin = Format-Pointer $rawData.hCatAdmin HCATADMIN
        }
        else {
            $data.Error = 'Unknown struct size encountered'
        }
    }

    $data
}

Function Format-WTDBlobData {
    [CmdletBinding()]
    param([IntPtr]$Raw)

    $data = [Ordered]@{
        Raw = Format-Pointer $Raw PWINTRUST_BLOB_INFO
    }

    if ($Raw -ne [IntPtr]::Zero) {
        $data.CBStruct = [System.Runtime.InteropServices.Marshal]::ReadInt32($Raw)

        $requiredSize = [System.Runtime.InteropServices.Marshal]::SizeOf[Wintrust.WINTRUST_BLOB_INFO]()
        if ($data.CBStruct -ge $requiredSize) {
            $rawData = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Wintrust.WINTRUST_BLOB_INFO]($Raw)
            $data.Subject = $rawData.gSubject.Guid
            $data.DisplayName = Format-WideString $rawData.pcwszDisplayName

            $data.MemObject = [Ordered]@{
                Size = $rawData.cbMemObject
                Raw = Format-Pointer $rawData.pbMemObject
            }
            if ($rawData.pbMemObject -ne [IntPtr]::Zero) {
                $dataBytes = [byte[]]::new($rawData.cbMemObject)
                [System.Runtime.InteropServices.Marshal]::Copy($rawData.pbMemObject, $dataBytes, 0, $dataBytes.Length)
                $data.MemObject.Value = [Convert]::ToHexString($dataBytes)
            }

            $data.MemSignedMsg = [Ordered]@{
                Size = $rawData.cbMemSignedMsg
                Raw = Format-Pointer $rawData.pbMemSignedMsg
            }
            if ($rawData.pbMemSignedMsg -ne [IntPtr]::Zero) {
                $dataBytes = [byte[]]::new($rawData.cbMemSignedMsg)
                [System.Runtime.InteropServices.Marshal]::Copy($rawData.pbMemSignedMsg, $dataBytes, 0, $dataBytes.Length)
                $data.MemSignedMsg.Value = [Convert]::ToHexString($dataBytes)
            }
        }
        else {
            $data.Error = 'Unknown struct size encountered'
        }
    }

    $data
}


New-PSDetourHook -DllName Wintrust.dll -MethodName WinVerifyTrust {
    [OutputType([int])]
    param(
        [IntPtr]$Hwnd,
        [IntPtr]$ActionID,
        [IntPtr]$Data
    )

    <#
    LONG WinVerifyTrust(
        [in] HWND   hwnd,
        [in] GUID   *pgActionID,
        [in] LPVOID pWVTData
    );
    #>

    $actionInfo = Format-Guid $ActionID
    $actionInfo.ID = switch ($actionInfo.Value) {
        00AAC56B-CD44-11d0-8CC2-00C04FC295EE { 'WINTRUST_ACTION_GENERIC_VERIFY_V2' }
        573E31F8-DDBA-11d0-8CCB-00C04FC295EE { 'WINTRUST_ACTION_TRUSTPROVIDER_TEST' }
        189A3842-3041-11d1-85E1-00C04FC295EE { 'WINTRUST_ACTION_GENERIC_CERT_VERIFY' }
        fc451c16-ac75-11d1-b4b8-00c04fb66ea0 { 'WINTRUST_ACTION_GENERIC_CHAIN_VERIFY' }
        573E31F8-AABA-11d0-8CCB-00C04FC295EE { 'HTTPSPROV_ACTION' }
        5555C2CD-17FB-11d1-85C4-00C04FC295EE { 'OFFICESIGN_ACTION_VERIFY' }
        F750E6C3-38EE-11d1-85E5-00C04FC295EE { 'DRIVER_ACTION_VERIFY' }
        6078065b-8f22-4b13-bd9b-5b762776f386 { 'CONFIG_CI_ACTION_VERIFY' }
        default { 'UNKNOWN' }
    }

    $trustData = [Ordered]@{
        Raw = Format-Pointer $DATA PWINTRUST_DATA
    }
    if ($Data -ne [IntPtr]::Zero) {
        $rawData = [System.Runtime.InteropServices.Marshal]::PtrToStructure[Wintrust.WINTRUST_DATA]($DATA)
        $trustData.CBStruct = $rawData.cbStruct
        $trustData.PolicyCallbackData = Format-Pointer $rawData.pPolicyCallbackData
        $trustData.SIPClientData = Format-Pointer $rawData.pSIDClientData
        $trustData.UIChoice = Format-Enum $rawData.dwUIChoice ([Wintrust.TrustDataUIChoice])
        $trustData.RevocationChecks = Format-Enum $rawData.fdwRevocationChecks ([Wintrust.TrustDataRevocationChecks])
        $trustData.UnionChoice = Format-Enum $rawData.dwUnionChoice ([Wintrust.TrustDataUnionChoice])

        $trustData.UnionData = if ($rawData.dwStateAction -eq ([int][Wintrust.TrustDataStateAction]::WTD_STATEACTION_CLOSE)) {
            Format-Pointer $trustData.unionData
        }
        else {
            switch ($rawData.dwUnionChoice) {
                ([int][Wintrust.TrustDataUnionChoice]::WTD_CHOICE_FILE) { Format-WTDFileData $rawData.unionData }
                ([int][Wintrust.TrustDataUnionChoice]::WTD_CHOICE_CATALOG) { Format-WTDCatalogData $rawData.unionData }
                ([int][Wintrust.TrustDataUnionChoice]::WTD_CHOICE_BLOB) { Format-WTDBlobData $rawData.unionData }
                default { Format-Pointer $rawData.unionData }
            }
        }

        $trustData.StateAction = Format-Enum $rawData.dwStateAction ([Wintrust.TrustDataStateAction])
        $trustData.WVTStateData = Format-Pointer $rawData.hWVTStateData HANDLE
        $trustData.URLReference = Format-WideString $rawData.pwszURLReference
        $trustData.ProvFlags = Format-Enum $rawData.dwProvFlags ([Wintrust.TrustDataProvFlags])
        $trustData.UIContext = Format-Enum $rawData.dwUIContext ([Wintrust.TrustDataUIContext])
        $trustData.SignatureSettings = Format-Pointer $rawData.pSignatureSettings PWINTRUST_SIGNATURE_SETTINGS
    }

    Write-FunctionCall -Arguments ([Ordered]@{
        Hwdn = Format-Pointer $Hwnd HWND
        ActionId = $actionInfo
        Data = $trustData
    })

    $res = $this.Invoke($Hwnd, $ActionID, $Data)

    Write-FunctionResult -Result $res ([Ordered]@{
        ErrorCode = switch ($res) {
            0 { 'SUCCESS' }
            0x800B0001 { 'TRUST_E_PROVIDER_UNKNOWN' }
            0x800B0002 { 'TRUST_E_ACTION_UNKNOWN' }
            0x800B0003 { 'TRUST_E_SUBJECT_FORM_UNKNOWN' }
            0x800B0004 { 'TRUST_E_SUBJECT_NOT_TRUSTED' }
            0x800B0005 { 'DIGSIG_E_ENCODE' }
            0x800B0006 { 'DIGSIG_E_DECODE' }
            0x800B0007 { 'DIGSIG_E_EXTENSIBILITY' }
            0x800B0008 { 'DIGSIG_E_CRYPTO' }
            0x800B0009 { 'PERSIST_E_SIZEDEFINITE' }
            0x800B000A { 'PERSIST_E_SIZEINDEFINITE' }
            0x800B000B { 'PERSIST_E_NOTSELFSIZING' }
            0x800B0100 { 'TRUST_E_NOSIGNATURE' }
            0x800B0101 { 'CERT_E_EXPIRED' }
            0x800B0102 { 'CERT_E_VALIDITYPERIODNESTING' }
            0x800B0103 { 'CERT_E_ROLE' }
            0x800B0104 { 'CERT_E_PATHLENCONST' }
            0x800B0105 { 'CERT_E_CRITICAL' }
            0x800B0106 { 'CERT_E_PURPOSE' }
            0x800B0107 { 'CERT_E_ISSUERCHAINING' }
            0x800B0108 { 'CERT_E_MALFORMED' }
            0x800B0109 { 'CERT_E_UNTRUSTEDROOT' }
            0x800B010A { 'CERT_E_CHAINING' }
            0x800B010B { 'TRUST_E_FAIL' }
            0x800B010C { 'CERT_E_REVOKED' }
            0x800B010D { 'CERT_E_UNTRUSTEDTESTROOT' }
            0x800B010E { 'CERT_E_REVOCATION_FAILURE' }
            0x800B010F { 'CERT_E_CN_NO_MATCH' }
            0x800B0110 { 'CERT_E_WRONG_USAGE' }
            0x800B0111 { 'TRUST_E_EXPLICIT_DISTRUST'}
            0x800B0112 { 'CERT_E_UNTRUSTEDCA'}
            0x800B0113 { 'CERT_E_INVALID_POLICY'}
            0x800B0114 { 'CERT_E_INVALID_NAME'}
            0x80096001 { 'TRUST_E_SYSTEM_ERROR' }
            0x80096002 { 'TRUST_E_NO_SIGNER_CERT' }
            0x80096003 { 'TRUST_E_COUNTER_SIGNER' }
            0x80096004 { 'TRUST_E_CERT_SIGNATURE' }
            0x80096005 { 'TRUST_E_TIME_STAMP' }
            0x80096010 { 'TRUST_E_BAD_DIGEST' }
            0x80096011 { 'TRUST_E_MALFORMED_SIGNATURE' }
            0x80096019 { 'TRUST_E_BASIC_CONSTRAINTS' }
            0x8009601E { 'TRUST_E_FINANCIAL_CRITERIA' }
            default { 'UNKNOWN' }
        }
    })

    $res
}