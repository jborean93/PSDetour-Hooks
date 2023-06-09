#Requires -Module PSDetour

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Metadata,

    [Parameter()]
    [Alias("Id")]
    [int]$ProcessId = 0
)

$traceParams = @{
    FunctionsToDefine = [System.Collections.Generic.Dictionary[[string], [string]]]::new()
}

if ($ProcessId) {
    $traceParams.ProcessId = $ProcessId
}

$hooks = foreach ($kvp in $Metadata.GetEnumerator()) {
    $filePath = Join-Path $PSScriptRoot "$($kvp.Key).ps1"
    if (-not (Test-Path -LiteralPath $filePath)) {
        Write-Error -Message "Unknown Dll specified '$($kvp.Key)' in metadata"
        continue
    }

    . $filePath | Where-Object {
        if ($_ -isnot [PSDetour.DetourHook]) {
            return $false
        }

        foreach ($methodMatch in $kvp.Value) {
            if ($_.MethodName -like $methodMatch) {
                return $true
            }
        }

        return $false
    }

    $script = Get-Content -LiteralPath $filePath -Raw
    $ast = [System.Management.Automation.Language.Parser]::ParseInput(
        $script,
        [ref]$null,
        [ref]$null
    ).EndBlock.Statements
    $ast.FindAll(
        [Func[Management.Automation.Language.Ast,bool]]{
            $args[0] -is [Management.Automation.Language.FunctionDefinitionAst]
        }, $false
    ) | ForEach-Object {
        $traceParams.FunctionsToDefine[$_.Name] = (Get-Item "Function:$($_.Name)").ScriptBlock.ToString()
    }
}

if (-not $hooks) {
    Write-Error -Message "Failed to find any hooks matching input metadata"
    return
}

$hooks | Trace-PSDetourProcess @traceParams
