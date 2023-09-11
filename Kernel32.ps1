Function Get-SecurityAttributes {
    [CmdletBinding()]
    param(
        [IntPtr]$Raw
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw LPSECURITY_ATTRIBUTES
    }

    if ($Raw -ne [IntPtr]::Zero) {
        $sa = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Raw, [type][Kernel32.SECURITY_ATTRIBUTES])

        $sd = $null
        if ($sa.lpSecurityDescriptor -ne [IntPtr]::Zero) {
            $sdBytes = [byte[]]::new($sa.nLength)
            [System.Runtime.InteropServices.Marshal]::Copy($sd.lpSecurityDescriptor, $sdBytes, 0, $sdBytes.Length)
            $sd = [System.Convert]::ToHexString($sdBytes)
        }
        $res.SecurityDescriptor = $sd
        $res.InheritHandle = $sa.bInheritHandle
    }

    $res
}

Function Get-StartupInfo {
    [CmdletBinding()]
    param(
        [IntPtr]$Raw,
        [switch]$IsExtended
    )

    $pointerType = if ($IsExtended) {
        'LPSTARTUPINFOEXW'
    }
    else {
        'LPSTARTUPINFOW'
    }

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw $pointerType
    }

    if ($Raw -ne [IntPtr]::Zero) {
        if ($IsExtended) {
            $value = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Raw, [type][Kernel32.STARTUPINFOEXW])
            $si = $value.StartupInfo
            $attrList = $value.lpAttributeList
        }
        else {
            $si = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Raw, [type][Kernel32.STARTUPINFOW])
            $attrList = [IntPtr]::Zero
        }

        $reserved2 = $null
        if ($si.cbReserved2 -and $si.lpReserved2 -ne [IntPtr]::Zero) {
            $reserved2Bytes = [byte[]]::new($si.cbReserved2)
            [System.Runtime.InteropServices.Marshal]::Copy($si.lpReserved2, $reserved2Bytes, 0, $reserved2Bytes.Length)
            $reserved2 = [System.Convert]::ToHexString($reserved2Bytes)
        }

        $res.Size = $si.cb
        $res.Reserved = Format-WideString $si.lpReserved
        $res.Desktop = Format-WideString $si.lpDesktop
        $res.Title = Format-WideString $si.lpTitle
        $res.X = $si.dwX
        $res.Y = $si.dwY
        $res.XSize = $si.dwXSize
        $res.YSize = $si.dwYSize
        $res.XCountChars = $si.dwXCountChars
        $res.YCountChars = $si.dwYCountChars
        $res.FillAttribute = Format-Enum $si.dwFillAttribute ([Kernel32.ConsoleFill])
        $res.Flags = Format-Enum $si.dwFlags ([Kernel32.StartupInfoFlags])
        $res.ShowWindow = Format-Enum $si.wShowWindow ([Kernel32.WindowStyle])
        $res.Reserved2 = $reserved2
        $res.StdInput = Format-Pointer $si.hStdInput HANDLE
        $res.StdOutput = Format-Pointer $si.hStdOutput HANDLE
        $res.StdError = Format-Pointer $si.hStdError HANDLE

        $res.AttributeList = Format-Pointer $attrList LPPROC_THREAD_ATTRIBUTE_LIST
    }

    $res
}

Function Get-ProcessInformation {
    [CmdletBinding()]
    param(
        [IntPtr]$Raw
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw LPPROCESS_INFORMATION
    }

    if ($Raw -ne [IntPtr]::Zero) {
        $pi = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Raw, [type][Kernel32.PROCESS_INFORMATION])

        $res.Process = Format-Pointer $pi.hProcess HANDLE
        $res.Thread = Format-Pointer $pi.hThread HANDLE
        $res.ProcessId = $pi.dwProcessId
        $res.ThreadId = $pi.dwThreadId
    }

    $res
}

Function Get-ProcessEnvironment {
    [CmdletBinding()]
    param (
        [IntPtr]$Raw,
        [switch]$UnicodeEnvironment
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw LPVOID
    }

    if ($Raw -ne [IntPtr]::Zero) {
        if ($UnicodeEnvironment) {
            $ptrUnpackFunc = [System.Runtime.InteropServices.Marshal]::PtrToStringUni
            $charSize = 2
        }
        else {
            $ptrUnpackFunc = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi
            $charSize = 1
        }
        $ptr = $Raw
        $res.Values = [string[]]@(
            while ($true) {
                $entry = $ptrUnpackFunc.Invoke($ptr)
                if ([string]::IsNullOrEmpty($entry)) {
                    break
                }

                $entry
                $ptr = [IntPtr]::Add($ptr, ($entry.Length * $charSize) + $charSize)
            }
        )
    }

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName CreateProcessAsUserW {
    [OutputType([bool])]
    param(
        [IntPtr]$Token,
        [IntPtr]$ApplicationName,
        [IntPtr]$CommandLine,
        [IntPtr]$ProcessAttributes,
        [IntPtr]$ThreadAttributes,
        [bool]$InheritHandles,
        [int]$CreationFlags,
        [IntPtr]$Environment,
        [IntPtr]$CurrentDirectory,
        [IntPtr]$StartupInfo,
        [IntPtr]$ProcessInformation
    )

    <#
    BOOL CreateProcessAsUserW(
        [in, optional]      HANDLE                hToken,
        [in, optional]      LPCWSTR               lpApplicationName,
        [in, out, optional] LPWSTR                lpCommandLine,
        [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
        [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
        [in]                BOOL                  bInheritHandles,
        [in]                DWORD                 dwCreationFlags,
        [in, optional]      LPVOID                lpEnvironment,
        [in, optional]      LPCWSTR               lpCurrentDirectory,
        [in]                LPSTARTUPINFOW        lpStartupInfo,
        [out]               LPPROCESS_INFORMATION lpProcessInformation
    );
    #>

    $unicodeEnv = [bool]($CreationFlags -band [Kernel32.ProcessCreationFlags]::CREATE_UNICODE_ENVIRONMENT)
    $isExtended = [bool]($CreationFlags -band [Kernel32.ProcessCreationFlags]::EXTENDED_STARTUPINFO_PRESENT)
    Write-FunctionCall -Arguments ([Ordered]@{
            Token = Format-Pointer $Token HANDLE
            ApplicationName = Format-WideString $ApplicationName
            CommandLine = Format-WideString $CommandLine
            ProcessAttributes = Get-SecurityAttributes $ProcessAttributes
            Threadattributes = Get-SecurityAttributes $ThreadAttributes
            InheritHandles = $InheritHandles
            CreationFlags = Format-Enum $CreationFlags ([Kernel32.ProcessCreationFlags])
            Environment = Get-ProcessEnvironment $Environment -UnicodeEnvironment:$unicodeEnv
            CurrentDirectory = Format-WideString $CurrentDirectory
            StartupInfo = Get-StartupInfo $StartupInfo -IsExtended:$isExtended
            ProcessInformation = Format-Pointer $ProcessInformation LPPROCESS_INFORMATION
        })

    $res = $this.Invoke(
        $Token,
        $ApplicationName,
        $CommandLine,
        $ProcessAttributes,
        $ThreadAttributes,
        $InheritHandles,
        $CreationFlags,
        $Environment,
        $CurrentDirectory,
        $StartupInfo,
        $ProcessInformation
    )

    $commandLineStr = if ($CommandLine -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($CommandLine)
    }

    Write-FunctionResult -Result $res ([Ordered]@{
            CommandLine = $commandLineStr
            ProcessInformation = Get-ProcessInformation $ProcessInformation
        })

    $res
}

New-PSDetourHook -DllName Kernel32.dll -MethodName CreateProcessW {
    [OutputType([bool])]
    param(
        [IntPtr]$ApplicationName,
        [IntPtr]$CommandLine,
        [IntPtr]$ProcessAttributes,
        [IntPtr]$ThreadAttributes,
        [bool]$InheritHandles,
        [int]$CreationFlags,
        [IntPtr]$Environment,
        [IntPtr]$CurrentDirectory,
        [IntPtr]$StartupInfo,
        [IntPtr]$ProcessInformation
    )

    <#
    BOOL CreateProcessW(
        [in, optional]      LPCWSTR               lpApplicationName,
        [in, out, optional] LPWSTR                lpCommandLine,
        [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
        [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
        [in]                BOOL                  bInheritHandles,
        [in]                DWORD                 dwCreationFlags,
        [in, optional]      LPVOID                lpEnvironment,
        [in, optional]      LPCWSTR               lpCurrentDirectory,
        [in]                LPSTARTUPINFOW        lpStartupInfo,
        [out]               LPPROCESS_INFORMATION lpProcessInformation
    );
    #>

    $unicodeEnv = [bool]($CreationFlags -band [Kernel32.ProcessCreationFlags]::CREATE_UNICODE_ENVIRONMENT)
    $isExtended = [bool]($CreationFlags -band [Kernel32.ProcessCreationFlags]::EXTENDED_STARTUPINFO_PRESENT)
    Write-FunctionCall -Arguments ([Ordered]@{
            ApplicationName = Format-WideString $ApplicationName
            CommandLine = Format-WideString $CommandLine
            ProcessAttributes = Get-SecurityAttributes $ProcessAttributes
            Threadattributes = Get-SecurityAttributes $ThreadAttributes
            InheritHandles = $InheritHandles
            CreationFlags = Format-Enum $CreationFlags ([Kernel32.ProcessCreationFlags])
            Environment = Get-ProcessEnvironment $Environment -UnicodeEnvironment:$unicodeEnv
            CurrentDirectory = Format-WideString $CurrentDirectory
            StartupInfo = Get-StartupInfo $StartupInfo -IsExtended:$isExtended
            ProcessInformation = Format-Pointer $ProcessInformation LPPROCESS_INFORMATION
        })

    $res = $this.Invoke(
        $ApplicationName,
        $CommandLine,
        $ProcessAttributes,
        $ThreadAttributes,
        $InheritHandles,
        $CreationFlags,
        $Environment,
        $CurrentDirectory,
        $StartupInfo,
        $ProcessInformation
    )

    $commandLineStr = if ($CommandLine -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($CommandLine)
    }

    Write-FunctionResult -Result $res ([Ordered]@{
            CommandLine = $commandLineStr
            ProcessInformation = Get-ProcessInformation $ProcessInformation
        })

    $res
}

# This is in Advapi32.dll but it shares a lot of common structs with the others so is defined here
New-PSDetourHook -DllName Advapi32.dll -MethodName CreateProcessWithLogonW {
    [OutputType([bool])]
    param(
        [IntPtr]$Username,
        [IntPtr]$Domain,
        [IntPtr]$Password,
        [int]$LogonFlags,
        [IntPtr]$ApplicationName,
        [IntPtr]$CommandLine,
        [int]$CreationFlags,
        [IntPtr]$Environment,
        [IntPtr]$CurrentDirectory,
        [IntPtr]$StartupInfo,
        [IntPtr]$ProcessInformation
    )

    <#
    BOOL CreateProcessWithLogonW(
        [in]                LPCWSTR               lpUsername,
        [in, optional]      LPCWSTR               lpDomain,
        [in]                LPCWSTR               lpPassword,
        [in]                DWORD                 dwLogonFlags,
        [in, optional]      LPCWSTR               lpApplicationName,
        [in, out, optional] LPWSTR                lpCommandLine,
        [in]                DWORD                 dwCreationFlags,
        [in, optional]      LPVOID                lpEnvironment,
        [in, optional]      LPCWSTR               lpCurrentDirectory,
        [in]                LPSTARTUPINFOW        lpStartupInfo,
        [out]               LPPROCESS_INFORMATION lpProcessInformation
    );
    #>

    $unicodeEnv = [bool]($CreationFlags -band [Kernel32.ProcessCreationFlags]::CREATE_UNICODE_ENVIRONMENT)
    $isExtended = [bool]($CreationFlags -band [Kernel32.ProcessCreationFlags]::EXTENDED_STARTUPINFO_PRESENT)
    Write-FunctionCall -Arguments ([Ordered]@{
            Username = Format-WideString $Username
            Domain = Format-WideString $Domain
            Password = Format-WideString $Password
            LogonFlags = Format-Enum $LogonFlags ([Kernel32.LogonFlags])
            ApplicationName = Format-WideString $ApplicationName
            CommandLine = Format-WideString $CommandLine
            CreationFlags = Format-Enum $CreationFlags ([Kernel32.ProcessCreationFlags])
            Environment = Get-ProcessEnvironment $Environment -UnicodeEnvironment:$unicodeEnv
            CurrentDirectory = Format-WideString $CurrentDirectory
            StartupInfo = Get-StartupInfo $StartupInfo -IsExtended:$isExtended
            ProcessInformation = Format-Pointer $ProcessInformation LPPROCESS_INFORMATION
        })

    $res = $this.Invoke(
        $Username,
        $Domain,
        $Password,
        $LogonFlags,
        $ApplicationName,
        $CommandLine,
        $CreationFlags,
        $Environment,
        $CurrentDirectory,
        $StartupInfo,
        $ProcessInformation
    )

    $commandLineStr = if ($CommandLine -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($CommandLine)
    }

    Write-FunctionResult -Result $res ([Ordered]@{
            CommandLine = $commandLineStr
            ProcessInformation = Get-ProcessInformation $ProcessInformation
        })

    $res
}

New-PSDetourHook -DllName Advapi32.dll -MethodName CreateProcessWithTokenW {
    [OutputType([bool])]
    param(
        [IntPtr]$Token,
        [int]$LogonFlags,
        [IntPtr]$ApplicationName,
        [IntPtr]$CommandLine,
        [int]$CreationFlags,
        [IntPtr]$Environment,
        [IntPtr]$CurrentDirectory,
        [IntPtr]$StartupInfo,
        [IntPtr]$ProcessInformation
    )

    <#
    BOOL CreateProcessWithTokenW(
        [in]                HANDLE                hToken,
        [in]                DWORD                 dwLogonFlags,
        [in, optional]      LPCWSTR               lpApplicationName,
        [in, out, optional] LPWSTR                lpCommandLine,
        [in]                DWORD                 dwCreationFlags,
        [in, optional]      LPVOID                lpEnvironment,
        [in, optional]      LPCWSTR               lpCurrentDirectory,
        [in]                LPSTARTUPINFOW        lpStartupInfo,
        [out]               LPPROCESS_INFORMATION lpProcessInformation
    );
    #>

    $unicodeEnv = [bool]($CreationFlags -band [Kernel32.ProcessCreationFlags]::CREATE_UNICODE_ENVIRONMENT)
    $isExtended = [bool]($CreationFlags -band [Kernel32.ProcessCreationFlags]::EXTENDED_STARTUPINFO_PRESENT)
    Write-FunctionCall -Arguments ([Ordered]@{
            Token = Format-Pointer $Token HANDLE
            LogonFlags = Format-Enum $LogonFlags ([Kernel32.LogonFlags])
            ApplicationName = Format-WideString $ApplicationName
            CommandLine = Format-WideString $CommandLine
            CreationFlags = Format-Enum $CreationFlags ([Kernel32.ProcessCreationFlags])
            Environment = Get-ProcessEnvironment $Environment -UnicodeEnvironment:$unicodeEnv
            CurrentDirectory = Format-WideString $CurrentDirectory
            StartupInfo = Get-StartupInfo $StartupInfo -IsExtended:$isExtended
            ProcessInformation = Format-Pointer $ProcessInformation LPPROCESS_INFORMATION
        })

    $res = $this.Invoke(
        $Token,
        $LogonFlags,
        $ApplicationName,
        $CommandLine,
        $CreationFlags,
        $Environment,
        $CurrentDirectory,
        $StartupInfo,
        $ProcessInformation
    )

    $commandLineStr = if ($CommandLine -ne [IntPtr]::Zero) {
        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($CommandLine)
    }

    Write-FunctionResult -Result $res ([Ordered]@{
            CommandLine = $commandLineStr
            ProcessInformation = Get-ProcessInformation $ProcessInformation
        })

    $res
}

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

    $envValue = if ($Value -ne [IntPtr]::Zero) {
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
