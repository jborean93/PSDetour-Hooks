$dataLog = [System.IO.File]::Open('C:\temp\laps.log', "Append", "Write", "Read")
$waitPipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'LsassWait', 'In')
$dataWriter = [System.IO.StreamWriter]::new($dataLog)

Write-Host "Connecting to named pipe"
$waitPipe.Connect()
Write-Host "Named pipe connected"

$dataWriter.AutoFlush = $true
$state = @{
    Waiter = $waitPipe
    Writer = $dataWriter
}
