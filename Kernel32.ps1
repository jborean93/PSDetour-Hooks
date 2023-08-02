New-PSDetourHook -DllName Kernel32.dll -MethodName GetEnvironmentVariableW {
    [OutputType([int])]
    param(
        [System.Runtime.InteropServices.MarshalAsAttribute([System.Runtime.InteropServices.UnmanagedType]::LPWStr)]
        [string]$Name,
        [IntPtr]$Buffer,
        [int]$Size
    )

    <#
    DWORD GetEnvironmentVariableW(
        [in, optional]  LPCWSTR lpName,
        [out, optional] LPWSTR  lpBuffer,
        [in]            DWORD   nSize
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Name = $Name
        Buffer = Format-Pointer $Buffer 'LPWSTR'
        Size = $Size
    })

    $res = $this.Invoke($Name, $Buffer, $Size)

    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $envValue = if ($res -gt 0) {
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Buffer, $res)
    }
    Write-FunctionResult -Result $res ([Ordered]@{
        Size = $res
        Error = $err
        Value = $envValue
    })

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName SetEnvironmentVariableW {
    [OutputType([bool])]
    param(
        [System.Runtime.InteropServices.MarshalAsAttribute([System.Runtime.InteropServices.UnmanagedType]::LPWStr)]
        [string]$Name,
        [IntPtr]$Value
    )

    <#
    BOOL SetEnvironmentVariableW(
        [in]           LPCWSTR lpName,
        [in, optional] LPCWSTR lpValue
    );
    #>

    $envValue = if ($Value -ne [IntPtr]::Zero)   {
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Value)
    }
    Write-FunctionCall -Arguments ([Ordered]@{
        Name = $Name
        Value = [Ordered]@{
            Raw = Format-Pointer $Value 'LPCWSTR'
            Value = $envValue
        }
    })
    $res = $this.Invoke($Name, $Value)
    Write-FunctionResult -Result $res

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName GetProcessId {
    [OutputType([int])]
    param(
        [IntPtr]$Process
    )

    <#
    DWORD GetProcessId(
        [in] HANDLE Process
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        Process = Format-Pointer $Process 'HANDLE'
    })
    $res = $this.Invoke($Process)
    Write-FunctionResult -Result $res

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName OpenProcess {
    [OutputType([IntPtr])]
    param(
        [int]$DesiredAccess,
        [bool]$InheritHandle,
        [int]$ProcessId
    )

    <#
    HANDLE OpenProcess(
        [in] DWORD dwDesiredAccess,
        [in] BOOL  bInheritHandle,
        [in] DWORD dwProcessId
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
        DesiredAccess = Format-Enum $DesiredAccess ([Kernel32.ProcessAccessMask])
        InheritHandle = $InheritHandle
        ProcessId = $ProcessId
    })
    $res = $this.Invoke($DesiredAccess, $InheritHandle, $ProcessId)
    Write-FunctionResult -Result (Format-Pointer $res 'HANDLE')

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName Sleep -Action {
    param([int]$Milliseconds)

    Write-FunctionCall -Arguments ([Ordered]@{
        Milliseconds = $Milliseconds
    })
    $this.Invoke($Milliseconds)
    Write-FunctionResult -Result $null
}
