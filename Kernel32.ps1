New-PSDetourHook -DllName Kernel32.dll -MethodName GetProcessId {
    [OutputType([int])]
    param(
        [IntPtr]$Process
    )

    $this.State.WriteLine('GetProcessId(Process: 0x{0:X8})', $Process)
    $res = $this.Invoke($Process)
    $this.State.WriteLine('GetProcessId - Return: 0x{0:X8}', $res)
    $this.State.WriteLine()

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName OpenProcess {
    [OutputType([IntPtr])]
    param(
        [int]$DesiredAccess,
        [bool]$InheritHandle,
        [int]$ProcessId
    )

    $this.State.WriteLine('OpenProcess(DesiredAccess: 0x{0:X8}, InheritHandle: {1}, ProcessId: {2})',
        $DesiredAccess, $InheritHandle, $ProcessId)
    $res = $this.Invoke($DesiredAccess, $InheritHandle, $ProcessId)
    $this.State.WriteLine('OpenProcess - Return: 0x{0:X8}', $res)
    $this.State.WriteLine()

    $res
}
