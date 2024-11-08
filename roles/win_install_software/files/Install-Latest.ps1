param (
    [Parameter(Mandatory = $true)]
    [string]$Repository,

    [Parameter(Mandatory = $true)]
    [string[]]$Apps
)

# Function to grab current software versions
function Get-InstalledSoftware {
    # Empty hash table to contain all installed software
    $installed_software = @{}

    # Empty hash table to contain the unique versions
    $installed_software_unique = @{}

    # Array to ignore certain terms
    $ignore = @("Update", "Maintenance")

    # Installed software registry paths
    $registry_paths = @(
        # 32-bit Software on a 32-bit system or 64-bit Software on a 64-bit system
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",

        # 32-bit Software on a 64-bit system
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",

        # User-specific Software (installed for the current user)
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    # Grab all installed software
    foreach ($path in $registry_paths) {
        Get-ChildItem -Path $path | ForEach-Object {
            $name = (Get-ItemProperty -Path $_.PsPath).DisplayName
            $version = (Get-ItemProperty -Path $_.PsPath).DisplayVersion
            
            if ($null -ne $name -and $null -ne $version) {
                # Returns 1 if current value matches any terms in the ignore array
                # Returns 0 if it doesn't match
                $ignore_match = ($ignore | Where-Object { $name -match $_ }).Count

                switch ($ignore_match) { 0 { $installed_software.Add($name, $version); break } }
            }
        }
    }

    # Loop through each key-value pair
    foreach ($key in $installed_software.Keys) {
        $value = $installed_software[$key]
        
        # If the value is not already in the new hashtable, add it
        if (-not $installed_software_unique.ContainsValue($value)) {
            $installed_software_unique[$key] = $value
        }
    }

    return $installed_software_unique
}

# Function to install using EXE
function Install-Exe ($Name, $Installer, $ArgList, $Latest) {
    # Compare latest and installed version
    try {
        # Get current version installed, if $null sets the version to 0.0 to ensure installation
        try { $current_version = [System.Version]$installed.( $( $installed.Keys -like "*$Name*" ) ) }
        catch { $current_version = [System.Version]"0.0" }

        # Stop running processes
        Get-Process -Name "*$Name*" | Stop-Process -Force

        if ($Latest -gt $current_version) {
            # Command to install the EXE file (you can modify this command as needed)
            Start-Process -FilePath $Installer -ArgumentList $ArgList -Wait
            Write-Output "$Name EXE: Successfully installed/updated.`n"
        } elseif ($Latest -eq $current_version) {
            Write-Output "$Name EXE: System is up to date.`n"
        } else {
            Write-Output "$Name EXE: Software is already up-to-date.`n"
        }

    } catch {
        # Output a custom message
        Write-Output "$Name EXE: An error occurred."

        # Output the detailed error message
        Write-Output "`tError details: $($_.Exception.Message)`n"
    }
}

# Function to install using MSI
function Install-Msi ($Name, $Installer, $ArgList, $Latest) {
    # Compare latest and installed version
    try {
        # Get current version installed, if $null sets the version to 0.0 to ensure installation
        try { $current_version = [System.Version]$installed.( $( $installed.Keys -like "*$Name*" ) ) }
        catch { $current_version = [System.Version]"0.0" }

        # Stop running processes
        Get-Process -Name "*$Name*" | Stop-Process -Force
        Get-Process -Name "msiexec" | Stop-Process -Force

        if ($Latest -gt $current_version) {
            # Command to install the MSI file (you can modify this command as needed)
            Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$Installer`" $ArgList" -Wait
            Write-Output "$Name MSI: Successfully installed/updated.`n"
        } elseif ($Latest -eq $current_version) {
            Write-Output "$Name MSI: System is up to date.`n"
        } else {
            Write-Output "$Name MSI: Software is already up-to-date.`n"
        }

    } catch {
        # Output a custom message
        Write-Output "$Name MSI: An error occurred."

        # Output the detailed error message
        Write-Output "`tError details: $($_.Exception.Message)`n"
    }
}

$installed = Get-InstalledSoftware

# Loop through each app in the array
foreach ($app in $Apps) {
    # Import args from JSON file
    $app_args = Get-Content "$Repository\$app\args.json" | ConvertFrom-Json

    # Gets the latest version
    $latest = [System.Version]((Get-ChildItem -Path "$Repository\$app\*latest" -Directory).Name -split "_")[0]

    # Grab both installers
    $exe_file = Get-ChildItem -Path "$Repository\$app\*latest\*.exe" | Select-Object -ExpandProperty FullName
    $msi_file = Get-ChildItem -Path "$Repository\$app\*latest\*.msi" | Select-Object -ExpandProperty FullName

    # Try preferred installer EXE
    if ($app_args.preferred_installer -ieq "exe") {
        try {
            Install-Exe -Name $app -Installer $exe_file -ArgList $app_args.exe_args -Latest $latest
        } catch {
            Install-Msi -Name $app -Installer $msi_file -ArgList $app_args.msi_args -Latest $latest
        }
    }
    # Try preferred installer MSI
    elseif ($app_args.preferred_installer -ieq "msi") {
        try {
            Install-Msi -Name $app -Installer $msi_file -ArgList $app_args.msi_args -Latest $latest
        } catch {
            Install-Exe -Name $app -Installer $exe_file -ArgList $app_args.exe_args -Latest $latest
        }
    }
    # Fails if variable is not specified
    else {
        Write-Output "Preferred installer not specified." 
    }
}
