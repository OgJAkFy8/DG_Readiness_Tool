<#
.SYNOPSIS
    Enable virtualization in Lenovo Bios and enable Credential Guard in Windows 10
.DESCRIPTION
    This script will only run on Lenovo computers. If run on Lenovo computer, the script will check if virtualization is enabled in BIOS. 
    If not, virtualization will be enabled in the process of enabling CredentialGuard.
    Also appends actions to logfile: EnableCredentialGuard.log
 
.NOTES
    FileName:    Enable-VirtualizationCredentialGuard.ps1
    Author:      Martin Bengtsson
    Created:     19-07-2017
#>

$Logfile = "C:\Windows\EnableCredentialGuard.log"

#Create LogWrite function
Function LogWrite
{
   Param ([string]$Logstring)

   Add-Content $Logfile -Value $Logstring
}

#Get computermanufacturer
$Lenovo = Get-WmiObject Win32_ComputerSystemProduct | Select-Object Vendor

#If not a Lenovo laptop, write to log and exit script
If ($Lenovo.Vendor -ne "Lenovo"){
    
    LogWrite "Not a Lenovo laptop - exiting script"
    Write-Warning -Message "Not a Lenovo laptop - exiting script" ; exit 1
}

Else {
    
    Write-Host -ForegroundColor Yellow "Collecting Lenovo_BiosSetting information" ; LogWrite "Collecting Lenovo_BiosSetting information"
    $VirtEnabled = Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\WMI | Where-Object {$_.CurrentSetting -match "Virtualization*"} | Select-Object CurrentSetting

If ($VirtEnabled.CurrentSetting -eq "VirtualizationTechnology,Disable"){
    
    Write-Host -ForegroundColor Cyan "Virtualization disabled - trying to enable virtualization" ; LogWrite "Virtualization disabled - trying to enable virtualization"
    Try {
        (Get-WmiObject -Class Lenovo_SetBiosSetting -Namespace root\wmi).SetBiosSetting("VirtualizationTechnology,Enable")
        (Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace root\wmi).SaveBiosSettings()

    }
    Catch {
        Write-Host -ForegroundColor Cyan "An error occured when enabling virtualization in the BIOS" ; LogWrite "An error occured when enabling virtualization in the BIOS" ; exit 1
    }
    cls
    Write-Host -ForegroundColor Cyan "Virtualization Successfully enabled" ; LogWrite "Virtualization Successfully enabled"
    
}

#Add required registry key for Credential Guard
$RegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    If (-not(Test-Path -Path $RegistryKeyPath)) {
        Write-Host -ForegroundColor Yellow "Creating HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard registry key" ; LogWrite "Creating HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard registry key"
        New-Item -Path $RegistryKeyPath -ItemType Directory -Force
    }
    #Add registry key: RequirePlatformSecurityFeatures - 1 for Secure Boot only, 3 for Secure Boot and DMA Protection
    New-ItemProperty -Path $RegistryKeyPath -Name RequirePlatformSecurityFeatures -PropertyType DWORD -Value 1
    Write-Host -ForegroundColor Yellow "Successfully added RequirePlatformSecurityFeatures regkey" ; LogWrite "Successfully added RequirePlatformSecurityFeatures regkey"
    
    #Add registry key: EnableVirtualizationBasedSecurity - 1 for Enabled, 0 for Disabled
    New-ItemProperty -Path $RegistryKeyPath -Name EnableVirtualizationBasedSecurity -PropertyType DWORD -Value 1
    Write-Host -ForegroundColor Yellow "Successfully added EnableVirtualizationBasedSecurity regkey" ; LogWrite "Successfully added EnableVirtualizationBasedSecurity regkey"
    
    #Add registry key: LsaCfgFlags - 1 enables Credential Guard with UEFI lock, 2 enables Credential Guard without lock, 0 for Disabled
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LsaCfgFlags -PropertyType DWORD -Value 2
    Write-Host -ForegroundColor Yellow "Successfully added LsaCfgFlags regkey" ; LogWrite "Successfully added LsaCfgFlags regkey"
    
    Write-Host -ForegroundColor Yellow "Successfully enabled Credential Guard - please reboot the computer" ; LogWrite "Successfully enabled Credential Guard - please reboot the computer"
    
}   