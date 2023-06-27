New-PSDetourHook -DllName Kernel32.dll -MethodName GetEnvironmentVariableW {
    [OutputType([int])]
    param(
        [System.Runtime.InteropServices.MarshalAsAttribute([System.Runtime.InteropServices.UnmanagedType]::LPWStr)]
        [string]$Name,

        [IntPtr]$Buffer,

        [int]$Size
    )

    $this.State.WriteObject('GetEnvironmentVariable(Name: ''{0}'', Buffer: 0x{1:X8}, Size: {2})' -f @(
        $Name, $Buffer, $Size))
    $res = $this.Invoke($Name, $Buffer, $Size)
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $this.State.WriteObject('GetEnvironmentVariable - Return: 0x{0:X8}, Size: {1}' -f ($err, $res))
    if ($res -gt 0) {
        $envValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Buffer, $res)
        $this.State.WriteObject("`t$envValue")
    }

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName SetEnvironmentVariableW {
    [OutputType([bool])]
    param(
        [System.Runtime.InteropServices.MarshalAsAttribute([System.Runtime.InteropServices.UnmanagedType]::LPWStr)]
        [string]$Name,

        [IntPtr]$Value
    )

    $this.State.WriteObject('SetEnvironmentVariable(Name: ''{0}'', Value: 0x{1:X8})' -f @(
        $Name, $Value))
    if ($Value -ne [IntPtr]::Zero)   {
        $envValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Value)
        $this.State.WriteObject("`tValue: $envValue")
    }

    $res = $this.Invoke($Name, $Value)
    $this.State.WriteObject('SetEnvironmentVariable - Return: {0}' -f $res)

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName GetProcessId {
    [OutputType([int])]
    param(
        [IntPtr]$Process
    )

    $this.State.WriteObject('GetProcessId(Process: 0x{0:X8})' -f $Process)
    $res = $this.Invoke($Process)
    $this.State.WriteObject('GetProcessId - Return: 0x{0:X8}' -f $res)

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName OpenProcess {
    [OutputType([IntPtr])]
    param(
        [int]$DesiredAccess,
        [bool]$InheritHandle,
        [int]$ProcessId
    )

    $this.State.WriteObject('OpenProcess(DesiredAccess: 0x{0:X8}, InheritHandle: {1}, ProcessId: {2})' -f @(
        $DesiredAccess, $InheritHandle, $ProcessId))
    $res = $this.Invoke($DesiredAccess, $InheritHandle, $ProcessId)
    $this.State.WriteObject('OpenProcess - Return: 0x{0:X8}' -f $res)

    $res
}
