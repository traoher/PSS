$cg = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard" -ErrorAction SilentlyContinue
if ($cg -and $cg.EnableVirtualizationBasedSecurity -eq 1) {
    Write-Output "Credential Guard is likely ENABLED (check msinfo32 to confirm)."
} else {
    Write-Output "Credential Guard is NOT enabled."
}


# Enable Virtualization-Based Security (VBS) and Credential Guard
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord

# Enable Windows features (if not already enabled)
Enable-WindowsOptionalFeature -Online -FeatureName IsolatedUserMode -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All -NoRestart

Write-Output "Credential Guard configuration applied. Please reboot your computer to complete the process."
