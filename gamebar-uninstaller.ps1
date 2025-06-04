#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Attempts to disable and remove the Xbox Game Bar and associated components,
    including the Game Bar Presence Writer, and silence ms-gamebar protocol pop-ups.
    Includes a step to back up relevant registry keys before modification.
    Defaults backup location to script's directory if not specified.

.DESCRIPTION
    This script performs several actions to remove the Xbox Game Bar:
    0. Backs up relevant registry keys to a user-specified location (defaults to script's directory).
    1. Modifies registry settings to disable Game Bar and GameDVR features.
    2. Uninstalls the XboxGamingOverlay AppX package for the current user, all users,
       and removes the provisioned package.
    3. Attempts to disable the Game Bar Presence Writer by modifying its COM activation registry key.
       If this fails due to permissions, it provides instructions to manually take ownership.
    4. Attempts to silence the 'ms-gamebar://' protocol handler to prevent pop-ups.
    5. Recommends a system reboot after execution.

.NOTES
    Author: Gemini
    Version: 1.5
    RUN THIS SCRIPT AS ADMINISTRATOR.
    IT IS STRONGLY RECOMMENDED TO CREATE A SYSTEM RESTORE POINT BEFORE RUNNING THIS SCRIPT,
    IN ADDITION TO THE REGISTRY BACKUP PERFORMED BY THIS SCRIPT.
    This script makes significant changes to your system. Use at your own risk.
    Some operations, especially deep registry changes, might be reverted by Windows Updates
    or might not be fully effective on all Windows versions/configurations.

.LINK
    Based on common troubleshooting steps for removing Xbox Game Bar.
#>

#------------------------------------------------------------------------------
# SECTION 0: PRE-CHECKS AND WARNINGS
#------------------------------------------------------------------------------

Write-Host "--------------------------------------------------------------------"
Write-Host "Xbox Game Bar Removal Script with Registry Backup"
Write-Host "--------------------------------------------------------------------"
Write-Host ""
Write-Host "IMPORTANT: This script will attempt to remove Xbox Game Bar components." -ForegroundColor Yellow
Write-Host "IT IS STRONGLY RECOMMENDED to create a System Restore Point before proceeding," -ForegroundColor Yellow
Write-Host "in addition to the registry backup this script will perform." -ForegroundColor Yellow
Write-Host ""

# Check for Administrator Privileges
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentUser = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

if (-Not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Administrator privileges are required to run this script. Please re-run as Administrator."
    Start-Sleep -Seconds 10
    Exit 1
}

# Ask user to confirm they want to proceed
$confirmation = Read-Host "Do you want to proceed with backing up registry and then disabling/removing Xbox Game Bar? (Yes/No)"
if ($confirmation -ne 'Yes') {
    Write-Host "Script execution aborted by the user." -ForegroundColor Green
    Exit 0
}

Write-Host "Proceeding with script execution..." -ForegroundColor Cyan
Write-Host ""

#------------------------------------------------------------------------------
# SECTION 1: REGISTRY BACKUP
#------------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------"
Write-Host "SECTION 1: REGISTRY BACKUP" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------"

$registryKeysToBackup = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR",
    "HKCU:\System\GameConfigStore",
    "HKCU:\Software\Microsoft\GameBar",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR",
    "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter",
    "HKEY_CLASSES_ROOT\ms-gamebar" # Using full path for reg export compatibility
)

# Get the directory where the script is located
$scriptDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDirectory)) { # Fallback if $PSScriptRoot is not available (e.g., running selection in ISE)
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Definition
    if ([string]::IsNullOrWhiteSpace($scriptDirectory)) {
        $scriptDirectory = Get-Location # Last resort, current working directory
    }
}


$userInputBackupPath = Read-Host "Enter FULL path for registry backups (e.g., C:\RegBackups) [Press Enter to use script's directory: '$scriptDirectory']"

if ([string]::IsNullOrWhiteSpace($userInputBackupPath)) {
    $backupPath = $scriptDirectory
    Write-Host "No path entered. Defaulting backup location to script directory: $backupPath" -ForegroundColor Yellow
} else {
    $backupPath = $userInputBackupPath
}

if (-Not (Test-Path -Path $backupPath -PathType Container)) {
    try {
        New-Item -ItemType Directory -Path $backupPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Created backup directory: $backupPath" -ForegroundColor Green
    } catch {
        Write-Error "Invalid backup path or failed to create directory: $backupPath. Error: $($_.Exception.Message)"
        Write-Error "Please ensure the parent directory exists and you have write permissions."
        Exit 1
    }
}

Write-Host "Backing up registry keys to '$backupPath'..."
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupSuccessCount = 0
$backupFailCount = 0

foreach ($keyPath in $registryKeysToBackup) {
    $keyName = $keyPath.Split('\')[-1].Replace(":", "_") # Sanitize name for file
    $backupFile = Join-Path -Path $backupPath -ChildPath "RegBackup_$keyName_$timestamp.reg"

    # Convert PowerShell path to reg.exe compatible path
    $regExePath = $keyPath.Replace("HKCU:\", "HKEY_CURRENT_USER\").Replace("HKLM:\", "HKEY_LOCAL_MACHINE\").Replace("HKCR:\", "HKEY_CLASSES_ROOT\")

    Write-Host "  Attempting to back up '$regExePath' to '$backupFile'..."
    try {
        # Check if key exists before attempting export
        if (Test-Path $keyPath) {
            & reg.exe export "$regExePath" "$backupFile" /y # /y overwrites if file exists (though timestamp should make it unique)
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    Successfully backed up '$regExePath'." -ForegroundColor Green
                $backupSuccessCount++
            } else {
                Write-Warning "    Failed to back up '$regExePath'. reg.exe exited with code $LASTEXITCODE."
                $backupFailCount++
            }
        } else {
            Write-Host "    Registry key '$regExePath' does not exist. Skipping backup for this key." -ForegroundColor DarkGray
        }
    } catch {
        Write-Warning "    An error occurred while trying to back up '$regExePath'. Error: $($_.Exception.Message)"
        $backupFailCount++
    }
}

Write-Host "Registry backup process complete. Success: $backupSuccessCount, Failed: $backupFailCount."
if ($backupFailCount -gt 0) {
    Write-Warning "Some registry keys failed to back up. Please review the messages above."
}
Write-Host "To restore a key, right-click the .reg file in '$backupPath' and select 'Merge'."
Write-Host ""

#------------------------------------------------------------------------------
# SECTION 2: DISABLE GAME BAR AND GAMEDVR VIA REGISTRY
#------------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------"
Write-Host "SECTION 2: DISABLE GAME BAR AND GAMEDVR VIA REGISTRY" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------"

$regPathCurrentUserGameDVR = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
$regPathCurrentUserGameConfigStore = "HKCU:\System\GameConfigStore"
$regPathCurrentUserGameBar = "HKCU:\Software\Microsoft\GameBar"
$regPathLocalMachineGameDVRPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"

function Ensure-RegistryKeyPath {
    param ([string]$Path)
    if (-Not (Test-Path $Path)) {
        try {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            Write-Host "  Created registry path: $Path" -ForegroundColor DarkGray
        } catch {
            Write-Warning "  Failed to create registry path: $Path. Error: $($_.Exception.Message)"
        }
    }
}

function Set-RegistryDwordValue {
    param ([string]$Path, [string]$Name, [int]$Value)
    try {
        Ensure-RegistryKeyPath -Path $Path
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) -ne $null) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force -ErrorAction Stop
            Write-Host "  Set registry value: $Path\$Name = $Value"
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop
            Write-Host "  Created and set registry value: $Path\$Name = $Value"
        }
    } catch {
        Write-Warning "  Failed to set registry value $Path\$Name. Error: $($_.Exception.Message)"
    }
}

function Set-RegistryStringValue {
    param ([string]$Path, [string]$Name, [string]$Value)
    try {
        Ensure-RegistryKeyPath -Path $Path
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) -ne $null) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type String -Force -ErrorAction Stop
            Write-Host "  Set registry value: $Path\$Name = '$Value'"
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force -ErrorAction Stop
            Write-Host "  Created and set registry value: $Path\$Name = '$Value'"
        }
    } catch {
        Write-Warning "  Failed to set registry value $Path\$Name. Error: $($_.Exception.Message)"
    }
}

Set-RegistryDwordValue -Path $regPathCurrentUserGameDVR -Name "AppCaptureEnabled" -Value 0
Set-RegistryDwordValue -Path $regPathCurrentUserGameConfigStore -Name "GameDVR_Enabled" -Value 0
Set-RegistryDwordValue -Path $regPathCurrentUserGameBar -Name "Enabled" -Value 0
Set-RegistryDwordValue -Path $regPathCurrentUserGameBar -Name "AllowAutoGameMode" -Value 0
Set-RegistryDwordValue -Path $regPathCurrentUserGameBar -Name "AutoGameModeEnabled" -Value 0
Set-RegistryDwordValue -Path $regPathLocalMachineGameDVRPolicy -Name "AllowGameDVR" -Value 0

Write-Host "Registry modifications for disabling Game Bar and GameDVR attempted." -ForegroundColor Green
Write-Host ""

#------------------------------------------------------------------------------
# SECTION 3: UNINSTALL XBOX GAME BAR APPX PACKAGE
#------------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------"
Write-Host "SECTION 3: UNINSTALL XBOX GAME BAR APPX PACKAGE" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------"
$packageName = "Microsoft.XboxGamingOverlay"

try {
    Write-Host "  Removing for current user..."
    Get-AppxPackage $packageName | Remove-AppxPackage -ErrorAction Stop
    Write-Host "  Xbox Game Bar package removal for current user attempted." -ForegroundColor Green
} catch {
    Write-Warning "  Failed to remove Xbox Game Bar for current user (it might already be removed or an error occurred): $($_.Exception.Message)"
}

try {
    Write-Host "  Removing for all users..."
    Get-AppxPackage -AllUsers $packageName | Remove-AppxPackage -AllUsers -ErrorAction Stop
    Write-Host "  Xbox Game Bar package removal for all users attempted." -ForegroundColor Green
} catch {
    Write-Warning "  Failed to remove Xbox Game Bar for all users (it might already be removed or an error occurred): $($_.Exception.Message)"
}

try {
    Write-Host "  Removing provisioned package..."
    Get-ProvisionedAppxPackage -Online | Where-Object {$_.PackageName -like "*$packageName*"} | Remove-ProvisionedAppxPackage -Online -ErrorAction Stop
    Write-Host "  Xbox Game Bar provisioned package removal attempted." -ForegroundColor Green
} catch {
    Write-Warning "  Failed to remove Xbox Game Bar provisioned package (it might already be removed or an error occurred): $($_.Exception.Message)"
}
Write-Host ""

#------------------------------------------------------------------------------
# SECTION 4: ATTEMPT TO DISABLE GAME BAR PRESENCE WRITER COM ACTIVATION
#------------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------"
Write-Host "SECTION 4: ATTEMPT TO DISABLE GAME BAR PRESENCE WRITER COM ACTIVATION" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------"
$presenceWriterRegPath = "HKLM:\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter"

try {
    if (Test-Path $presenceWriterRegPath) {
        Set-ItemProperty -Path $presenceWriterRegPath -Name "ActivationType" -Value 0 -Type DWord -Force -ErrorAction Stop
        Write-Host "  Set ActivationType to 0 for GameBar Presence Writer." -ForegroundColor Green
    } else {
        Write-Host "  GameBar Presence Writer registry key not found (possibly already removed or not applicable)."
    }
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Warning "  Failed to set ActivationType for GameBar Presence Writer. Error: $errorMessage"
    if ($errorMessage -like "*Requested registry access is not allowed*") {
        Write-Host ""
        Write-Host "--------------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host "INSTRUCTIONS TO MANUALLY TAKE OWNERSHIP OF REGISTRY KEY:" -ForegroundColor Yellow
        Write-Host "The script could not modify the following key due to permissions:" -ForegroundColor Yellow
        Write-Host "  $presenceWriterRegPath" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "To fix this, you need to manually take ownership in Registry Editor:" -ForegroundColor Yellow
        Write-Host "1. Open Registry Editor (regedit) AS ADMINISTRATOR." -ForegroundColor Yellow
        Write-Host "2. Navigate to the key shown above." -ForegroundColor Yellow
        Write-Host "3. Right-click the key -> Permissions... -> Advanced." -ForegroundColor Yellow
        Write-Host "4. At the top, next to 'Owner:', click 'Change'." -ForegroundColor Yellow
        Write-Host "5. Type 'Administrators', click 'Check Names', then 'OK'." -ForegroundColor Yellow
        Write-Host "6. Check 'Replace owner on subcontainers and objects'." -ForegroundColor Yellow
        Write-Host "7. Click 'Apply', then 'OK'." -ForegroundColor Yellow
        Write-Host "8. Back in 'Permissions', select 'Administrators' and check 'Full Control' -> Allow." -ForegroundColor Yellow
        Write-Host "9. Click 'Apply', then 'OK'." -ForegroundColor Yellow
        Write-Host "10. After taking ownership, you can try re-running this script," -ForegroundColor Yellow
        Write-Host "    or manually set the 'ActivationType' (DWORD) value to 0 for this key." -ForegroundColor Yellow
        Write-Host "--------------------------------------------------------------------" -ForegroundColor Yellow
    }
}
Write-Host ""

#------------------------------------------------------------------------------
# SECTION 4.5: ATTEMPT TO SILENCE MS-GAMEBAR PROTOCOL POP-UP
#------------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------"
Write-Host "SECTION 4.5: ATTEMPT TO SILENCE MS-GAMEBAR PROTOCOL POP-UP" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------"
$msGameBarProtocolPath = "HKCR:\ms-gamebar" # HKCR is an alias for HKEY_CLASSES_ROOT

if (Test-Path $msGameBarProtocolPath) {
    Write-Host "  Found protocol key: $msGameBarProtocolPath"
    Set-RegistryStringValue -Path $msGameBarProtocolPath -Name "URL Protocol" -Value ""
} else {
    Write-Host "  'ms-gamebar' protocol key not found at $msGameBarProtocolPath (possibly already removed or never existed)."
}
Write-Host "Attempt to silence 'ms-gamebar://' protocol pop-ups complete." -ForegroundColor Green
Write-Host ""


#------------------------------------------------------------------------------
# SECTION 5: TERMINATE RELATED PROCESSES (Optional)
#------------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------"
Write-Host "SECTION 5: TERMINATE RELATED PROCESSES (Optional)" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------------"
$processesToStop = @(
    "GameBarPresenceWriter",
    "XboxGamingOverlay",
    "GamingServices"
)

foreach ($procName in $processesToStop) {
    try {
        Get-Process $procName -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Host "  Attempted to stop process: $procName"
    }
    catch {
        Write-Warning "  Could not stop process $procName (might not be running or access denied)."
    }
}
Write-Host "Process termination attempts complete." -ForegroundColor Green
Write-Host ""

#------------------------------------------------------------------------------
# SECTION 6: COMPLETION AND REBOOT RECOMMENDATION
#------------------------------------------------------------------------------
Write-Host "--------------------------------------------------------------------"
Write-Host "SCRIPT EXECUTION COMPLETE." -ForegroundColor Green
Write-Host "--------------------------------------------------------------------"
Write-Host ""
Write-Host "Summary of actions attempted:" -ForegroundColor Yellow
Write-Host "- Backed up relevant registry keys."
Write-Host "- Disabled Game Bar and GameDVR features via registry."
Write-Host "- Uninstalled Xbox Game Bar AppX package."
Write-Host "- Attempted to disable Game Bar Presence Writer COM activation."
Write-Host "- Attempted to silence 'ms-gamebar://' protocol handler."
Write-Host "- Attempted to terminate related processes."
Write-Host ""
Write-Host "RECOMMENDATION: A system REBOOT is highly recommended for all changes to take full effect." -ForegroundColor Yellow
Write-Host ""
Write-Host "Please check your system to ensure the Game Bar is no longer active and pop-ups are gone."
Write-Host "If issues persist or if the Game Bar returns, further manual steps or investigation might be needed,"
Write-Host "as Windows updates can sometimes re-enable these features."
Write-Host "Registry backups are in the directory you specified. To restore, right-click a .reg file and select 'Merge'."
Write-Host ""

# End of Script
