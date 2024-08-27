Function Get-CryptUIDigitalSignBlobInfo {
    [CmdletBinding()]
    param(
        [IntPtr]$Raw
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw PCRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO
    }

    if ($Raw -eq [IntPtr]::Zero) {
        $res
        return
    }

    $blobInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
        $Raw,
        [Type][CryptUI.CRYPTUI_WIZ_DIGITAL_SIGN_BLOB_INFO]
    )

    if ($blobInfo.cbBlob -and $blobInfo.pbBlob -ne [IntPtr]::Zero) {
        $blob = [byte[]]::new($blobInfo.cbBlob)
        [System.Runtime.InteropServices.Marshal]::Copy($blobInfo.pbBlob, $blob, 0, $blob.Length)
    }
    else {
        $blob = [byte[]]::new(0)
    }

    $res.Size = $blobInfo.dwSize
    $res.Subject = Format-Guid $blobInfo.pGuidSubject
    $res.Blob = [Ordered]@{
        Count = $blobInfo.cbBlob
        Raw = Format-Pointer $blobInfo.pbBlob BYTE
        Data = [System.Convert]::ToHexString($blob)
    }
    $res.DisplayName = Format-WideString $blobInfo.pwszDisplayName

    $res
}

Function Get-CryptUIDigitalSignExtendedInfo {
    [CmdletBinding()]
    param(
        [IntPtr]$Raw
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw PCRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO
    }

    if ($Raw -eq [IntPtr]::Zero) {
        $res
        return
    }

    $extInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
        $Raw,
        [Type][CryptUI.CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO]
    )

    $res.Size = $extInfo.dwSize
    $res.Flags = Format-Enum $extInfo.dwAttrFlags
    $res.Description = Format-WideString $extInfo.pwszDescription
    $res.MoreInfoLocation = Format-WideString $extInfo.pwszMoreInfoLocation
    $res.HashAlg = Format-AnsiString $extInfo.pszHashAlg
    $res.SigningCertDisplayString = Format-WideString $extInfo.pwszSigningCertDisplayString
    $res.AdditionalCertStore = Format-Pointer $extInfo.hAdditionalCertStore HCERTSTORE
    $res.Authenticated = Format-Pointer $extInfo.psAuthenticated PCRYPT_ATTRIBUTES
    $res.Unauthenticated = Format-Pointer $extInfo.psUnauthenticated PCRYPT_ATTRIBUTES

    $res
}


Function Get-CryptUIDigitalSignInfo {
    [CmdletBinding()]
    param(
        [IntPtr]$Raw
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw PCCRYPTUI_WIZ_DIGITAL_SIGN_INFO
    }

    if ($Raw -eq [IntPtr]::Zero) {
        $res
        return
    }

    $signInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
        $Raw,
        [Type][CryptUI.CRYPTUI_WIZ_DIGITAL_SIGN_INFO]
    )

    $res.Size = $signInfo.dwSize
    $res.SubjectChoice = Format-Enum $signInfo.dwSubjectChoice
    $res.Subject = switch ($signInfo.dwSubjectChoice) {
        CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_FILE {
            Format-WideString $signInfo.SubjectUnion
        }
        CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT_BLOB {
            Get-CryptUIDigitalSignBlobInfo $signInfo.SubjectUnion
        }
        default {
            Format-Pointer $signInfo.SubjectUnion 'Unknown'
        }
    }
    $res.SigningCertChoice = Format-Enum $signInfo.dwSigningCertChoice
    $res.SigningCert = Format-Pointer $signInfo.SigningCertUnion
    $res.TimestampURL = Format-WideString $signInfo.pwszTimestampURL
    $res.AdditionalCertChoice = Format-Enum $signInfo.dwAdditionalCertChoice
    $res.SignExtInfo = Get-CryptUIDigitalSignExtendedInfo $signInfo.pSignExtInfo

    $res
}

Function Get-CryptUIDigitalSignContext {
    [CmdletBinding()]
    param(
        [IntPtr]$Raw
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw PCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT
    }

    if ($Raw -eq [IntPtr]::Zero) {
        $res
        return
    }

    $context = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
        $Raw,
        [Type][CryptUI.CRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT]
    )

    if ($context.cbBlob -and $context.pbBlob -ne [IntPtr]::Zero) {
        $blob = [byte[]]::new($context.cbBlob)
        [System.Runtime.InteropServices.Marshal]::Copy($context.pbBlob, $blob, 0, $blob.Length)
    }
    else {
        $blob = [byte[]]::new(0)
    }

    $res.Size = $context.dwSize
    $res.Count = $context.cbBlob
    $res.Raw = Format-Pointer $context.pbBlob BYTE
    $res.Blob = [System.Convert]::ToHexString($blob)


    $res
}

New-PSDetourHook -DllName Cryptui.dll -MethodName CryptUIWizDigitalSign {
    [OutputType([bool])]
    param (
        [int]$Flags,
        [IntPtr]$WndParent,
        [IntPtr]$WizardTitle,
        [IntPtr]$DigitalSignInfo,
        [IntPtr]$SignContext
    )

    <#
    BOOL CryptUIWizDigitalSign(
        [in]            DWORD                              dwFlags,
        [in, optional]  HWND                               hwndParent,
        [in, optional]  LPCWSTR                            pwszWizardTitle,
        [in]            PCCRYPTUI_WIZ_DIGITAL_SIGN_INFO    pDigitalSignInfo,
        [out, optional] PCCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT *ppSignContext
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Flags = Format-Enum $Flags ([CryptUI.CryptUIWizFlags])
        WndParent = Format-Pointer $WndParent HWND
        WizardTitle = Format-WideString $WizardTitle
        DigitalSignInfo = Get-CryptUIDigitalSignInfo $DigitalSignInfo
        SignContext = Format-Pointer $SignContext PCCRYPTUI_WIZ_DIGITAL_SIGN_CONTEXT
    })
    $res = $this.Invoke(
        $Flags,
        $WndParent,
        $WizardTitle,
        $DigitalSignInfo,
        $SignContext); $lastError = [System.Runtime.InteropServices.Marshal]::GetLastPInvokeError()

    Write-FunctionResult -Result $res ([ordered]@{
        SignContext = Get-CryptUIDigitalSignContext $SignContext
    }) $lastError

    $res
}
