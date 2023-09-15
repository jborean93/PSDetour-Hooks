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

    $dt = [DateTime]::FromFileTimeUtc($Value)
    [Ordered]@{
        Raw = $Value
        DateTime = $dt
    }
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
        $Info = @{}
    )

    $res = [Ordered]@{
        Function = (Get-PSCallStack)[1].FunctionName
        Time = Get-Date
        ThreadId = [PSDetourHooks.Methods]::GetCurrentThreadId()
        Result = $Result
        Info = $Info
    }
    $this.State.WriteObject($res)
}
