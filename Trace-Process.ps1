#Requires -Module PSDetour

[CmdletBinding(DefaultParameterSetName = "ProcessId")]
param (
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$Metadata,

    [Parameter(Mandatory, ParameterSetName = "ProcessId")]
    [Alias("Id")]
    [int]$ProcessId,

    [Parameter(Mandatory, ParameterSetName = "Service")]
    [string]
    $Service,

    [Parameter(ParameterSetName = "Service")]
    [switch]
    $RestartService,

    [Parameter()]
    [ValidateSet('Raw', 'Yaml')]
    [string]$OutputFormat = 'Raw'
)

if ($OutputFormat -eq 'Yaml') {
    Import-Module -Name Yayaml -ErrorAction Stop
}

$traceParams = @{
    FunctionsToDefine = [System.Collections.Generic.Dictionary[[string], [ScriptBlock]]]::new()
    CSharpToLoad = [System.Collections.Generic.List[string]]::new()
}

if ($PSCmdlet.ParameterSetName -eq 'ProcessId') {
    $traceParams.ProcessId = $ProcessId
}
else {
    if ($RestartService) {
        Restart-Service -Name $Service -Force -ErrorAction Stop
    }

    $serviceInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Service'" -Property ProcessId -ErrorAction Stop
    if (-not $serviceInfo) {
        throw "Failed to find process for service '$Service', is it running?"
    }

    # WMI returns a UInt32, we want the signed equivalent of it. We cannot
    # cast as any UInt32 > Int32.MaxValue will fail.
    $traceParams.ProcessId = [Convert]::ToInt32(
        [Convert]::ToString($serviceInfo.ProcessId, 16),
        16)
}

$commonScriptPath = Join-Path $PSScriptRoot common.ps1
. $commonScriptPath
$commonScript = Get-Content -LiteralPath $commonScriptPath -Raw
$ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $commonScript,
    [ref]$null,
    [ref]$null
).EndBlock.Statements
$ast.FindAll(
    [Func[Management.Automation.Language.Ast, bool]] {
        $args[0] -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $false
) | ForEach-Object {
    $traceParams.FunctionsToDefine[$_.Name] = (Get-Item "Function:$($_.Name)").ScriptBlock
}

$traceParams.CSharpToLoad.Add((Get-Content -LiteralPath (Join-Path $PSScriptRoot common.cs) -Raw))

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
        [Func[Management.Automation.Language.Ast, bool]] {
            $args[0] -is [Management.Automation.Language.FunctionDefinitionAst]
        }, $false
    ) | ForEach-Object {
        $traceParams.FunctionsToDefine[$_.Name] = (Get-Item "Function:$($_.Name)").ScriptBlock
    }

    $csharpPath = Join-Path $PSScriptRoot "$($kvp.Key).cs"
    if (Test-Path -LiteralPath $csharpPath) {
        $traceParams.CSharpToLoad.Add((Get-Content -LiteralPath $csharpPath -Raw))
    }
}

if (-not $hooks) {
    Write-Error -Message "Failed to find any hooks matching input metadata"
    return
}

$hooks | Trace-PSDetourProcess @traceParams | ForEach-Object {
    if ($OutputFormat -eq 'Yaml') {
        ConvertTo-Yaml -InputObject $_ -Depth 10 -AsArray
    }
    else {
        $_
    }
}
