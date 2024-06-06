Function Format-Guid {
    [CmdletBinding()]
    param ($Value)

    $guidValue = if ($Value -ne [IntPtr]::Zero) {
        $guidBytes = [byte[]]::new(16)
        [System.Runtime.InteropServices.Marshal]::Copy($Value, $guidBytes, 0, 16)
        [Guid]::new($guidBytes).Guid
    }

    [Ordered]@{
        Raw = Format-Pointer $Value PGUID
        Value = $guidValue
    }
}

Function Format-Pointer {
    [CmdletBinding()]
    param($Value, $Type = 'Pointer')

    '0x{0:X8} - {1}' -f ([Int64]$Value, $Type)
}

Function Format-Enum {
    [CmdletBinding()]
    param(
        $Value,
        [Type]$EnumType
    )

    $valueStr = if ($Value -is [Enum]) {
        " - $Value"
    }
    elseif ($EnumType -and $null -ne ($Value -as $EnumType)) {
        " - $($Value -as $EnumType)"
    }

    '0x{0:X8}{1}' -f ([int]$Value, $valueStr)
}

Function Format-WideString {
    [CmdletBinding()]
    param([IntPtr]$Value)

    $strValue = $null
    if ($Value -ne [IntPtr]::Zero) {
        $strValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Value)
    }

    [Ordered]@{
        Raw = Format-Pointer $Value
        Value = $strValue
    }
}

Function Format-FileTime {
    [CmdletBinding()]
    param([long]$Value)

    try {
        $dt = [DateTime]::FromFileTimeUtc($Value)
    }
    catch [System.ArgumentOutOfRangeException] {
        $dt = $null
    }
    [Ordered]@{
        Raw = $Value
        DateTime = $dt
    }
}

Function Get-PInvokeMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $State,

        [Parameter(Mandatory)]
        [string]
        $DllName,

        [Parameter(Mandatory)]
        [string]
        $Name
    )

    if ($State.DetouredModules.ContainsKey($DllName) -and $State.DetouredModules[$DllName].ContainsKey($Name)) {
        $State.DetouredModules[$DllName][$Name]
        return
    }

    $methodClass = "$DllName.Methods" -as [type]
    if (-not $methodClass) {
        $methodClass = [PSDetourHooks.Methods]
    }

    if ($methodClass -and $methodClass.GetMember($Name)) {
        $methodClass::$Name
        return
    }

    throw "Failed to find PInvoke method $DllName.$Name"
}

Function Write-FunctionCall {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Collections.IDictionary]
        $Arguments = @{}
    )

    $res = [Ordered]@{
        Function = (Get-PSCallStack)[1].FunctionName
        Time = Get-Date
        ThreadId = [PSDetourHooks.Methods]::GetCurrentThreadId()
        Arguments = $Arguments
    }
    $this.State.WriteObject($res)
}

Function Write-FunctionResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowNull()]
        [Object]
        $Result,

        [System.Collections.IDictionary]
        $Info = @{},

        [int]
        $LastError,

        [ValidateSet("Win32", "Lsa")]
        [string]
        $ErrorType = 'Win32'
    )

    $res = [Ordered]@{
        Function = (Get-PSCallStack)[1].FunctionName
        Time = Get-Date
        ThreadId = [PSDetourHooks.Methods]::GetCurrentThreadId()
        Result = $Result
        Info = $Info
    }

    if ($LastError) {
        $res.Error = Format-Enum $LastError

        if ($ErrorType -eq 'Lsa') {
            $res.LsaNtStatus = Format-Enum $LastError
            $methInfo = Get-PInvokeMethod $this Advapi32 LsaNtStatusToWinError
            $LastError = $methInfo.Invoke($LastError)
        }

        $res.ErrorMessage = [System.ComponentModel.Win32Exception]::new($LastError).Message
    }

    $this.State.WriteObject($res)
}
