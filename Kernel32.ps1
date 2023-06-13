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
