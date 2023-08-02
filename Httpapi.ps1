Function Get-HttpDataChunk {
    [CmdletBinding()]
    param([IntPtr]$Buffer, [int]$Count)

    # Largest known union combination of HTTP_DATA_CHUNK
    $chunkSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Httpapi.HTTP_DATA_CHUNK_FRAGMENT_CACHE_EX])

    if ($Buffer -eq [IntPtr]::Zero -or -not $Count) {
        return ,@()
    }

    , @(
        for($i = 0; $i -lt $Count; $i++) {
            $chunkType = [System.Runtime.InteropServices.Marshal]::ReadInt32($Buffer)
            $data = if ($chunkType -eq [Httpapi.HTTP_DATA_CHUNK_TYPE]::HttpDataChunkFromMemory) {
                $chunk = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Buffer, [type][Httpapi.HTTP_DATA_CHUNK_MEMORY])

                if ($chunk.pBuffer -ne [IntPtr]::Zero -and $chunk.BufferLength) {
                    $dataBytes = [byte[]]::new($chunk.BufferLength)
                    [System.Runtime.InteropServices.Marshal]::Copy($chunk.pBuffer, $dataBytes, 0, $dataBytes.Length)
                    [System.Convert]::ToHexString($dataBytes)
                }
            }
            else {
                'Chunk type unpacking has not been implemented'
            }

            [PSCustomObject]@{
                ChunkType = Format-Enum $chunkType ([Httpapi.HTTP_DATA_CHUNK_TYPE])
                Data = $data
            }
            $Buffer = [IntPtr]::Add($Buffer, $chunkSize)
        }
    )
}

Function Get-HttpResponse {
    [CmdletBinding()]
    param([IntPtr]$Raw)

    if ($Raw -eq [IntPtr]::Zero) {
        [Ordered]@{
            Raw = Format-Pointer $Raw PHTTP_RESPONSE
        }
        return
    }

    $response = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Raw, [type][Httpapi.HTTP_RESPONSE_V1])
    $reason = ''
    if ($response.pReason -ne [IntPtr]::Zero) {
        $reason = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($response.pReason, $response.ReasonLength)
    }

    # FUTURE: Support pUnknownHeaders
    $headers = [Ordered]@{}
    foreach ($prop in $response.Headers.PSObject.Properties) {
        if (-not $prop.Name.StartsWith('Header')) {
            continue
        }

        $headerName = $prop.Name.Substring(6)
        $rawValue = $prop.Value
        if ($rawValue.pRawValue -ne [IntPtr]::Zero) {
            $value = if ($rawValue.RawValueLength) {
                [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($rawValue.pRawValue, $rawValue.RawValueLength)
            }
            $headers[$headerName] = $value
        }
    }

    $chunks = Get-HttpDataChunk -Buffer $response.pEntityChunks -Count $response.EntityChunkCount

    [Ordered]@{
        Raw = Format-Pointer $Raw PHTTP_RESPONSE
        Flags = Format-Enum $response.Flags
        MajorVersion = $response.Version.MajorVersion
        MinorVersion = $response.Version.MinorVersion
        StatusCode = $response.StatusCode
        Reason = $reason
        Headers = $headers
        UnknownHeaderCount = $response.Headers.UnknownHeaderCount
        EntityChunks = $chunks
    }
}

New-PSDetourHook -DllName Httpapi.dll -MethodName HttpSendHttpResponse {
    [OutputType([int])]
    param(
        [IntPtr]$RequestQueueHandle,
        [long]$RequestId,
        [int]$Flags,
        [IntPtr]$HttpResponse,
        [IntPtr]$CachePolicy,
        [IntPtr]$BytesSent,
        [IntPtr]$Reserved1,
        [int]$Reserved2,
        [IntPtr]$Overlapped,
        [IntPtr]$LogData
    )

    <#
    HTTPAPI_LINKAGE ULONG HttpSendHttpResponse(
        [in]           HANDLE             RequestQueueHandle,
        [in]           HTTP_REQUEST_ID    RequestId,
        [in]           ULONG              Flags,
        [in]           PHTTP_RESPONSE     HttpResponse,
        [in, optional] PHTTP_CACHE_POLICY CachePolicy,
        [out]          PULONG             BytesSent,
        [in]           PVOID              Reserved1,
        [in]           ULONG              Reserved2,
        [in]           LPOVERLAPPED       Overlapped,
        [in, optional] PHTTP_LOG_DATA     LogData
    );
    #>

    $response = Get-HttpResponse -Raw $HttpResponse

    Write-FunctionCall -Arguments ([Ordered]@{
        RequestQueueHandle = Format-Pointer $RequestQueueHandle HANDLE
        RequestId = $RequestId
        Flags = Format-Enum $Flags ([Httpapi.HTTP_SEND_RESPONSE_FLAG])
        HttpResponse = $response
        CachePolicy = Format-Pointer $CachePolicy PHTTP_CACHE_POLICY
        BytesSent = Format-Pointer $BytesSent PULONG
        Reserved1 = Format-Pointer $Reserved1 PVOID
        Reserved2 = $Reserved2
        Overlapped = Format-Pointer $Overlapped LPOVERLAPPED
        LogData = Format-Pointer $LogData PHTTP_LOG_DATA
    })

    $res = $this.Invoke($RequestQueueHandle, $RequestId, $Flags, $HttpResponse, $CachePolicy, $BytesSent, $Reserved1,
        $Reserved2, $Overlapped, $LogData)

    Write-FunctionResult -Result $res

    $res
}

New-PSDetourHook -DllName Httpapi.dll -MethodName HttpSendResponseEntityBody {
    [OutputType([int])]
    param(
        [IntPtr]$RequestQueueHandle,
        [long]$RequestId,
        [int]$Flags,
        [int16]$EntityChunkCount,
        [IntPtr]$EntityChunks,
        [IntPtr]$BytesSent,
        [IntPtr]$Reserved1,
        [int]$Reserved2,
        [IntPtr]$Overlapped,
        [IntPtr]$LogData
    )

    <#
    HTTPAPI_LINKAGE ULONG HttpSendResponseEntityBody(
        [in]           HANDLE           RequestQueueHandle,
        [in]           HTTP_REQUEST_ID  RequestId,
        [in]           ULONG            Flags,
        [in]           USHORT           EntityChunkCount,
        [in]           PHTTP_DATA_CHUNK EntityChunks,
        [out]          PULONG           BytesSent,
        [in]           PVOID            Reserved1,
        [in]           ULONG            Reserved2,
        [in]           LPOVERLAPPED     Overlapped,
        [in, optional] PHTTP_LOG_DATA   LogData
    );
    #>

    $chunks = Get-HttpDataChunk -Buffer $EntityChunks -Count $EntityChunkCount

    Write-FunctionCall -Arguments ([Ordered]@{
        RequestQueueHandle = Format-Pointer $RequestQueueHandle HANDLE
        RequestId = $RequestId
        Flags = Format-Enum $Flags ([Httpapi.HTTP_SEND_RESPONSE_FLAG])
        EntityChunkCount = $EntityChunkCount
        EntityChunks = [Ordered]@{
            Raw = Format-Pointer $EntityChunks PHTTP_DATA_CHUNK
            Value = $chunks
        }
        BytesSent = Format-Pointer $BytesSent PULONG
        Reserved1 = Format-Pointer $Reserved1 PVOID
        Reserved2 = $Reserved2
        Overlapped = Format-Pointer $Overlapped LPOVERLAPPED
        LogData = Format-Pointer $LogData PHTTP_LOG_DATA
    })

    $res = $this.Invoke($RequestQueueHandle, $RequestId, $Flags, $EntityChunkCount, $EntityChunks, $BytesSent, $Reserved1,
        $Reserved2, $Overlapped, $LogData)

    Write-FunctionResult -Result $res

    $res
}
