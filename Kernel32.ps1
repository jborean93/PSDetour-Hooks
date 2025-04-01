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
            $getLengthMeth = Get-PInvokeMethod Advapi32 GetSecurityDescriptorLength

            $sdLength = $getLengthMeth.Invoke($sa.lpSecurityDescriptor)

            if ($sdLength) {
                $sdBytes = [byte[]]::new($sdLength)
                [System.Runtime.InteropServices.Marshal]::Copy($sa.lpSecurityDescriptor, $sdBytes, 0, $sdBytes.Length)
                $sdHex = [System.Convert]::ToHexString($sdBytes)
                $sdObj = [System.Security.AccessControl.RawSecurityDescriptor]::new($sdBytes, 0)
                $sd = [Ordered]@{
                    Bytes = $sdHex
                    SDDL = $sdObj.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
                }
            }
            else {
                $sd = 'Failed to unpack SECURITY_DESCRIPTOR'
            }
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

    $siSize = 0
    $siExSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Kernel32.STARTUPINFOEXW])
    if ($Raw -ne [IntPtr]::Zero) {
        $siSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($Raw)
    }

    $pointerType = if ($IsExtended -and $siSize -ge $siExSize) {
        'LPSTARTUPINFOEXW'
    }
    else {
        'LPSTARTUPINFOW'
    }

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw $pointerType
    }

    if ($Raw -ne [IntPtr]::Zero) {
        if ($pointerType -eq 'LPSTARTUPINFOEXW') {
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

        $res.AttributeList = Get-ProcThreadAttributeList $attrList
    }

    $res
}

Function Get-ProcThreadAttributeList {
    [CmdletBinding()]
    param(
        [IntPtr]$Raw,
        [int]$StartupInfoSize
    )

    $res = [Ordered]@{
        Raw = Format-Pointer $Raw LPPROC_THREAD_ATTRIBUTE_LIST
    }

    if ($Raw -ne [IntPtr]::Zero) {
        $attrList = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Raw, [type][Kernel32.PROC_THREAD_ATTRIBUTE_LIST])

        $res.Flags = "0x{0:X8}" -f $attrList.dwFlags
        $res.MaximumCount = $attrList.dwMaximumCount
        $res.Count = $attrList.dwActualCount
        $res.Unknown = "0x{0:X8}" -f $attrList.dwUnknown1
        # $attrList.ExtendedFlagsAttribute is just the pointer to the
        # ProcThreadAttributeExtendedFlags entry if present.

        $attrPtr = [IntPtr]::Add(
            $Raw,
            [System.Runtime.InteropServices.Marshal]::OffsetOf(
                [Kernel32.PROC_THREAD_ATTRIBUTE_LIST],
                "Entries"
            )
        )
        $attrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Kernel32.PROC_THREAD_ATTRIBUTE_ENTRY])
        $res.Attributes = @(
            for ($i = 0; $i -lt $attrList.dwActualCount; $i++) {
                $attr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($attrPtr, [type][Kernel32.PROC_THREAD_ATTRIBUTE_ENTRY])

                $attrType = ([int]$attr.Attribute -band [Kernel32.ProcessThreadAttributeFlags]::PROC_THREAD_ATTRIBUTE_NUMBER)
                $attrFlags = ([int]$attr.Attribute -band -bnot [Kernel32.ProcessThreadAttributeFlags]::PROC_THREAD_ATTRIBUTE_NUMBER)
                $attrValue = [Ordered]@{
                    Attribute = Format-Pointer $attr.Attribute PROC_ATTRIBUTE
                    Type = Format-Enum $attrType ([Kernel32.ProcessThreadAttribute])
                    Flags = Format-Enum $attrFlags([Kernel32.ProcessThreadAttributeFlags])
                    Size = [int64]$attr.Size
                    Raw = Format-Pointer $attr.Value
                }

                if (
                    $attrType -eq [Kernel32.ProcessThreadAttribute]::ProcThreadAttributeParentProcess -and
                    $attr.Value -ne [IntPtr]::Zero
                ) {
                    $handle = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($attr.Value)

                    $methInfo = Get-PInvokeMethod Kernel32 GetProcessId

                    # This will be 0 if the handle doesn't have the required rights, nothing
                    # we can do about that.
                    $procId = $methInfo.Invoke($handle)
                    if ($procId -eq 0) {
                        $procId = 'Failed to get proc id, probably due to limited access rights'
                    }

                    $attrValue.Value = [Ordered]@{
                        Handle = Format-Pointer $handle HANDLE
                        ProcessId = $procId
                    }
                }
                elseif ($attrType -eq [Kernel32.ProcessThreadAttribute]::ProcThreadAttributeExtendedFlags) {
                    $attrValue.Value = Format-Enum ([int]$attr.Value) ([Kernel32.ExtendedProcessCreationFlags])
                }
                elseif (
                    $attrType -eq [Kernel32.ProcessThreadAttribute]::ProcThreadAttributeHandleList -and
                    $attr.Value -ne [IntPtr]::Zero
                ) {
                    $attrValue.Value = @(
                        for ($i = 0; $i -lt [int]$attr.Size; $i += [IntPtr]::Size) {
                            $handle = [System.Runtime.InteropServices.Marshal]::ReadIntPtr(
                                [IntPtr]::Add($attr.Value, $i)
                            )

                            Format-Pointer $handle 'HANDLE'
                        }
                    )
                }
                elseif (
                    $attrType -eq [Kernel32.ProcessThreadattribute]::ProcThreadAttributePseudoConsole -and
                    $attr.Value -ne [IntPtr]::Zero
                ) {
                    $handle = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($attr.Value)

                    $attrValue.Value = Format-Pointer $handle HPCON
                }
                elseif (
                    $attrType -eq [Kernel32.ProcessThreadAttribute]::ProcThreadAttributeChildProcessPolicy -and
                    $attr.Value -ne [IntPtr]::Zero
                ) {
                    $flags = [System.Runtime.InteropServices.Marshal]::ReadInt32($attr.Value)

                    $attrValue.Value = Format-Enum $flags ([Kernel32.ProcessCreationChildProcessFlags])
                }

                $attrValue

                $attrPtr = [IntPtr]::Add($attrPtr, $attrSize)
            }
        )
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

New-PSDetourHook -DllName api-ms-win-core-processthreads-l1-1-0 -MethodName CreateProcessW {
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
New-PSDetourHook -DllName api-ms-win-security-cpwl-l1-1-0.dll -MethodName CreateProcessWithLogonW {
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

New-PSDetourHook -DllName api-ms-win-core-processenvironment-l1-1-0.dll -MethodName GetEnvironmentVariableW {
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

New-PSDetourHook -DllName api-ms-win-core-processenvironment-l1-1-0.dll -MethodName SetEnvironmentVariableW {
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

New-PSDetourHook -DllName api-ms-win-core-processthreads-l1-1-0.dll -MethodName GetProcessId {
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

New-PSDetourHook -DllName api-ms-win-core-processthreads-l1-1-0.dll -MethodName OpenProcess {
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

New-PSDetourHook -DllName api-ms-win-core-console-l2-1-0.dll -MethodName ReadConsoleOutputW {
    [OutputType([bool])]
    param(
        [IntPtr]$ConsoleOutput,
        [IntPtr]$Buffer,
        [Kernel32.COORD]$BufferSize,
        [Kernel32.COORD]$BufferCoord,
        [IntPtr]$ReadRegion
    )

    <#
    BOOL WINAPI ReadConsoleOutput(
        _In_    HANDLE      hConsoleOutput,
        _Out_   PCHAR_INFO  lpBuffer,
        _In_    COORD       dwBufferSize,
        _In_    COORD       dwBufferCoord,
        _Inout_ PSMALL_RECT lpReadRegion
    );
    #>

    Write-FunctionCall -Arguments ([Ordered]@{
            ConsoleOutput = Format-Pointer $ConsoleOutput HANDLE
            Buffer = Format-Pointer $Buffer PCHAR_INFO
            BufferSize = [Ordered]@{
                X = $BufferSize.X
                Y = $BufferSize.Y
            }
            BufferCoord = [Ordered]@{
                X = $BufferCoord.X
                Y = $BufferCoord.Y
            }
            ReadRegion = Format-Pointer $ReadRegion PSMALL_RECT
        })

    $res = $this.Invoke(
        $ConsoleOutput,
        $Buffer,
        $BufferSize,
        $bufferCoord,
        $ReadRegion)

    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-FunctionResult -Result $res -LastError $err

    $res
}

New-PSDetourHook -DllName api-ms-win-core-synch-l1-2-0.dll -MethodName Sleep -Action {
    param([int]$Milliseconds)

    Write-FunctionCall -Arguments ([Ordered]@{
            Milliseconds = $Milliseconds
        })
    $this.Invoke($Milliseconds)
    Write-FunctionResult -Result $null
}
