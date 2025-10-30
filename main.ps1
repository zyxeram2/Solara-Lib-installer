function Split-File {
    param (
        [string]$FilePath,
        [int64]$MaxBytes = $MaxPartSize
    )
    $buffsize = 8MB
    $filename = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $ext = [System.IO.Path]::GetExtension($FilePath)
    $files = @()
    $fs = [System.IO.File]::OpenRead($FilePath)
    $part = 1

    try {
        while ($fs.Position -lt $fs.Length) {
            $target = "$($FilePath)_part$part$ext"
            $partStream = [System.IO.File]::Create($target)
            $written = 0
            while (($written -lt $MaxBytes) -and ($fs.Position -lt $fs.Length)) {
                $toRead = [Math]::Min([Math]::Min($buffsize, ($MaxBytes - $written)), ($fs.Length - $fs.Position))
                $buffer = New-Object byte[] $toRead
                $read = $fs.Read($buffer, 0, $toRead)
                if ($read -gt 0) { $partStream.Write($buffer, 0, $read); $written += $read }
                else { break }
            }
            $partStream.Close()
            $files += $target
            $part++
        }
    } finally { $fs.Close() }
    return $files
}
