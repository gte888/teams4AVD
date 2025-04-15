# Updated Installation Script for New Microsoft Teams on Azure Virtual Desktop
# Enhancements:
#   - Optional uninstallation of old Teams and the Teams Meeting Add-in
#   - Uninstallation of the add-in is performed by reading the GUID from registry keys (without affecting other MSI installations)
#   - Downloads and installation of Visual C++ Redistributable (x86 and x64)
#   - Installation of WebRTC, Teams, and configuration of the Outlook add-in
#   - Verification of the add-in installation using Get-AppLockerFileInformation and forcing the installation path to:
#       C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\<version>
#
# Note: The TARGETDIR parameter is passed to msiexec to specify the desired installation directory.

function Handle-Error {
    param($ErrorMessage)
    Write-Host "ERROR: $ErrorMessage" -ForegroundColor Red
    exit 1
}

function Check-FSLogixVersion {
    $minVersion = [version]"2.9.8884.27471"
    $fslogixExecutables = @(
        "${env:ProgramFiles}\FSLogix\Apps\frx.exe",
        "${env:ProgramFiles(x86)}\FSLogix\Apps\frx.exe"
    )
    
    $installedVersion = $null

    foreach ($exe in $fslogixExecutables) {
        if (Test-Path $exe) {
            $fileVersion = (Get-Item $exe).VersionInfo.FileVersion
            if ($fileVersion) {
                $installedVersion = [version]$fileVersion
                break
            }
        }
    }

    if ($null -eq $installedVersion) {
        Write-Host "WARNING: FSLogix does not appear to be installed." -ForegroundColor Yellow
        Write-Host "It is recommended to install FSLogix before proceeding with the Teams installation." -ForegroundColor Yellow
        $continue = Read-Host "Do you want to continue with the Teams installation anyway? (Y/N)"
        if ($continue -ne "Y" -and $continue -ne "y") {
            exit 0
        }
    }
    elseif ($installedVersion -lt $minVersion) {
        Write-Host "Installed FSLogix version: $installedVersion" -ForegroundColor Cyan
        Write-Host "WARNING: The installed FSLogix version is lower than the recommended minimum ($minVersion)." -ForegroundColor Yellow
        Write-Host "It is recommended to update FSLogix to the latest version available." -ForegroundColor Yellow
        $continue = Read-Host "Do you want to continue with the Teams installation anyway? (Y/N)"
        if ($continue -ne "Y" -and $continue -ne "y") {
            exit 0
        }
    }
    else {
        Write-Host "Installed FSLogix version: $installedVersion" -ForegroundColor Cyan
        Write-Host "FSLogix is up-to-date." -ForegroundColor Green
    }
}

$ProgressPreference = 'SilentlyContinue'

try {
    # Checking FSLogix version
    Check-FSLogixVersion

    # Checking for administrator privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Handle-Error "This script requires administrator privileges. Please run PowerShell as an administrator and try again."
    }

    # --- ADDITIONAL FEATURES ---

    # URLs used for Teams (for both uninstallation and installation)
    $urlTeamsBootstrapper = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409"
    $urlTeamsMSIX = "https://go.microsoft.com/fwlink/?linkid=2196106"

    # 1. Uninstallation of old Teams
    $uninstallOld = Read-Host "Do you want to uninstall the old Teams before proceeding? (Y/N)"
    if ($uninstallOld -eq "Y" -or $uninstallOld -eq "y") {
    
        Write-Host "Downloading Microsoft Teams Bootstrapper for uninstallation..." -ForegroundColor Cyan
        Invoke-WebRequest -UseBasicParsing -Uri $urlTeamsBootstrapper -OutFile "C:\Windows\Temp\teamsbootstrapper.exe"
        Write-Host "Download complete." -ForegroundColor Green

        Write-Host "Downloading Microsoft Teams MSIX file for uninstallation..." -ForegroundColor Cyan
        Invoke-WebRequest -UseBasicParsing -Uri $urlTeamsMSIX -OutFile "C:\Windows\Temp\MSTeams-x64.msix"
        Write-Host "Download complete." -ForegroundColor Green

        Write-Host "Uninstalling old Teams..." -ForegroundColor Cyan
        $uninstallProcess = Start-Process "C:\Windows\Temp\teamsbootstrapper.exe" -ArgumentList "-x -o C:\Windows\Temp\MSTeams-x64.msix" -Wait -NoNewWindow -PassThru
        if ($uninstallProcess.ExitCode -ne 0) {
            Handle-Error "Teams uninstallation failed with exit code: $($uninstallProcess.ExitCode)"
        }
        else {
            Write-Host "Old Teams uninstalled successfully." -ForegroundColor Green
        }

        # 1.a Optional uninstallation of the Teams Meeting Add-in
        $removeMeetingAddin = Read-Host "Do you want to also uninstall the Teams Meeting Add-in? (Y/N)"
        if ($removeMeetingAddin -eq "Y" -or $removeMeetingAddin -eq "y") {
            # Reading registry keys to get the add-in GUID
            $registryPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )
            $addinGUID = $null
            foreach ($regPath in $registryPaths) {
                $subKeys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                foreach ($subKey in $subKeys) {
                    try {
                        $props = Get-ItemProperty -Path $subKey.PSPath -ErrorAction Stop
                    }
                    catch {
                        continue
                    }
                    if ($props.DisplayName -like "*Teams Meeting Add-in for Microsoft Office*") {
                        # The registry key name is the GUID (ProductCode)
                        $addinGUID = $subKey.PSChildName
                        break
                    }
                }
                if ($addinGUID) { break }
            }
            if ($addinGUID) {
                Write-Host "Found add-in GUID: $addinGUID" -ForegroundColor Cyan
                $uninstallCmd = "msiexec.exe /x `"$addinGUID`" /qn /norestart"
                Write-Host "Executing: $uninstallCmd" -ForegroundColor Yellow
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/x `"$addinGUID`" /qn /norestart" -Verb RunAs -Wait
                Write-Host "Teams Meeting Add-in uninstalled successfully." -ForegroundColor Green
            }
            else {
                Write-Host "Teams Meeting Add-in not found in the registry." -ForegroundColor Yellow
            }
        }
    }

    # 2. Installation of Visual C++ Redistributable
    Write-Host "Downloading and installing Visual C++ Redistributable (x86)..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri "https://aka.ms/vs/17/release/vc_redist.x86.exe" -OutFile "C:\Windows\Temp\vc_redist.x86.exe"
    $vcX86Process = Start-Process "C:\Windows\Temp\vc_redist.x86.exe" -ArgumentList "/install", "/quiet", "/norestart" -Wait -NoNewWindow -PassThru
    if ($vcX86Process.ExitCode -ne 0) {
        Write-Host "Installation of Visual C++ Redistributable (x86) failed or may already be installed. Please verify manually if necessary." -ForegroundColor Yellow
    }
    else {
        Write-Host "Visual C++ Redistributable (x86) installed successfully." -ForegroundColor Green
    }

    Write-Host "Downloading and installing Visual C++ Redistributable (x64)..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "C:\Windows\Temp\vc_redist.x64.exe"
    $vcX64Process = Start-Process "C:\Windows\Temp\vc_redist.x64.exe" -ArgumentList "/install", "/quiet", "/norestart" -Wait -NoNewWindow -PassThru
    if ($vcX64Process.ExitCode -ne 0) {
        Write-Host "Installation of Visual C++ Redistributable (x64) failed or may already be installed. Please verify manually if necessary." -ForegroundColor Yellow
    }
    else {
        Write-Host "Visual C++ Redistributable (x64) installed successfully." -ForegroundColor Green
    }

    # --- Installation of WebRTC ---
    Write-Host "Downloading the latest AVD Remote Desktop WebRTC Redirector Service Installer..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri "https://aka.ms/msrdcwebrtcsvc/msi" -OutFile "C:\Windows\Temp\MsRdcWebRTCSvc_x64.msi"
    Write-Host "Download complete." -ForegroundColor Green

    Write-Host "Installing WebRTC..." -ForegroundColor Cyan
    $webRtcInstallProcess = Start-Process msiexec.exe -ArgumentList "/i `"C:\Windows\Temp\MsRdcWebRTCSvc_x64.msi`" Reboot=ReallySuppress /qn" -Wait -NoNewWindow -PassThru
    if ($webRtcInstallProcess.ExitCode -ne 0) {
        Handle-Error "WebRTC installation failed with exit code: $($webRtcInstallProcess.ExitCode)"
    }

    # Verify WebRTC service
    $rtcService = Get-Service -Name RDWebRTCSvc -ErrorAction SilentlyContinue
    if ($rtcService -and $rtcService.Status -eq 'Running') {
        Write-Host "RDWebRTCSvc service installed and running." -ForegroundColor Green
    }
    else {
        Handle-Error "RDWebRTCSvc service not found or not running after installation."
    }

    # Configuring registry for the AVD environment
    Write-Host "Configuring registry for the AVD environment..." -ForegroundColor Cyan
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name IsWVDEnvironment -PropertyType DWORD -Value 1 -Force | Out-Null

    # --- Installation of Microsoft Teams (new release) ---
    Write-Host "Downloading Microsoft Teams Bootstrapper..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri $urlTeamsBootstrapper -OutFile "C:\Windows\Temp\teamsbootstrapper.exe"
    Write-Host "Downloading Microsoft Teams MSIX file..." -ForegroundColor Cyan
    Invoke-WebRequest -UseBasicParsing -Uri $urlTeamsMSIX -OutFile "C:\Windows\Temp\MSTeams-x64.msix"

    Write-Host "Installing Microsoft Teams..." -ForegroundColor Cyan
    $teamsInstallProcess = Start-Process "C:\Windows\Temp\teamsbootstrapper.exe" -ArgumentList "-p -o C:\Windows\Temp\MSTeams-x64.msix" -Wait -NoNewWindow -PassThru
    if ($teamsInstallProcess.ExitCode -ne 0) {
        Handle-Error "Teams installation failed with exit code: $($teamsInstallProcess.ExitCode)"
    }

    # Disabling Microsoft Teams auto-update
    Write-Host "Disabling Microsoft Teams auto-update..." -ForegroundColor Cyan
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name disableAutoUpdate -PropertyType DWORD -Value 1 -Force | Out-Null

    # --- Installation of the Teams add-in for Outlook ---
    Write-Host "Searching for the Teams add-in path..." -ForegroundColor Cyan
    # Search for the MSTeams_* folder in WindowsApps (latest Teams installation)
    $teamsFolder = Get-ChildItem -Path "C:\Program Files\WindowsApps" -Directory |
                   Where-Object { $_.Name -like "MSTeams_*" } |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $teamsFolder) {
        Handle-Error "Teams installation folder not found"
    }
    $teamsMsiPath = Join-Path $teamsFolder.FullName "MicrosoftTeamsMeetingAddinInstaller.msi"
    if (-not (Test-Path $teamsMsiPath)) {
        Handle-Error "MSI file for the Teams add-in not found: $teamsMsiPath"
    }

    # Retrieve add-in version using Get-AppLockerFileInformation
    $appLockerInfo = Get-AppLockerFileInformation -Path $teamsMsiPath -ErrorAction SilentlyContinue
    if ($appLockerInfo -and $appLockerInfo.Publisher -and $appLockerInfo.Publisher.BinaryVersion) {
        $addinVersion = $appLockerInfo.Publisher.BinaryVersion
        Write-Host "Detected add-in version: $addinVersion" -ForegroundColor Cyan
        
        # Set target directory for forced installation: must be in Program Files (x86)
        $targetDir = "C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\$addinVersion"
        Write-Host "Target installation directory set to: $targetDir" -ForegroundColor Cyan

        # Execute the add-in installation with the correct TARGETDIR parameter
        $installCommand = "msiexec.exe /i `"$teamsMsiPath`" ALLUSERS=1 TARGETDIR=`"$targetDir`" /qn /norestart"
        Write-Host "Executing: $installCommand" -ForegroundColor Yellow
        $addinInstallProcess = Start-Process cmd.exe -ArgumentList "/c $installCommand" -Verb RunAs -Wait -PassThru
        if ($addinInstallProcess.ExitCode -eq 0) {
            Write-Host "Teams add-in installation completed successfully." -ForegroundColor Green

            # Verify DLL presence (check first in the 'x64' subfolder, then in the folder itself)
            $dllPath1 = Join-Path $targetDir "x64\Microsoft.Teams.MeetingAddin.dll"
            $dllPath2 = Join-Path $targetDir "Microsoft.Teams.MeetingAddin.dll"
            if (Test-Path $dllPath1) {
                $dllPath = $dllPath1
            }
            elseif (Test-Path $dllPath2) {
                $dllPath = $dllPath2
            }
            else {
                Handle-Error "DLL file not found at expected path: $targetDir"
            }
            $dllVersion = (Get-Item $dllPath).VersionInfo.FileVersion
            Write-Host "Teams add-in installed successfully. Installed version: $dllVersion" -ForegroundColor Green
        }
        else {
            Handle-Error "Error during add-in installation. Exit code: $($addinInstallProcess.ExitCode)"
        }
    }
    else {
        Handle-Error "Unable to retrieve the add-in version from the MSI: $teamsMsiPath"
    }

    # Configuring registry keys for the Outlook add-in
    Write-Host "Configuring registry keys for the Outlook add-in..." -ForegroundColor Cyan
    $regPath = "HKLM:\Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect"
    New-Item -Path $regPath -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "LoadBehavior" -PropertyType DWORD -Value 3 -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "Description" -PropertyType String -Value "Microsoft Teams Meeting Add-in for Microsoft Office" -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "FriendlyName" -PropertyType String -Value "Microsoft Teams Meeting Add-in for Microsoft Office" -Force | Out-Null

    Write-Host "Installation and configuration completed successfully. You can now launch Teams. Remember to verify the 'AVD SlimCore Media Optimized' or 'AVD Media Optimized' designation in the system information." -ForegroundColor Green
}
catch {
    Handle-Error $_.Exception.Message
}
finally {
    $ProgressPreference = 'Continue'
}
