#requires -Version 3.0 -Modules CimCmdlets, SecureBoot, TrustedPlatformModule
# xequires -RunAsAdministrator

# requires driver verifier on system.

# Test for Domain Controller first.
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if($osInfo.ProductType -eq 2){
  Write-Error -Message 'Not compatible with domain controllers'
  Return
  }

 
Function Set-DgReadiness 
{
  <#
      .SYNOPSIS
      Script to make changes to the Device Guard compliant machine


      .DESCRIPTION
      Script to make changes to the Device Guard compliant machine.  
    
      Hardware requirements for enabling Device Guard and Credential Guard
      1. Hardware: Recent hardware that supports virtualization extension with SLAT


      .PARAMETER Enable
      Used with the other parameters to enable the specific features.  Alone it will enable both Device Guard and Credential Guard.

      .PARAMETER Disable
      To Disable Device Guard / Credential Guard.

      .PARAMETER SIPolicyPath
      If you have a custom SIPolicy.p7b then use the -Path parameter else the hardcoded default policy is used

      .PARAMETER AutoReboot
      Describe parameter -AutoReboot.

      .PARAMETER HLK
      Describe parameter -HLK.

      .PARAMETER Clear
      Describe parameter -Clear.

      .PARAMETER ResetVerifier
      Describe parameter -ResetVerifier.

      .EXAMPLE
      Set-DgReadiness -Disable 
      Disables Device Guard / Credential Guard.

      .EXAMPLE
      Set-DgReadiness -Enable 
      To Enable both Device Guard and Credential Guard.

      .EXAMPLE
      Set-DgReadiness -Enable -CG 
      Enable only Credential Guard

      .EXAMPLE
      Set-DgReadiness -Enable -Path <full path to the SIPolicy.p7b> 
      If you have a custom SIPolicy.p7b then use the -Path parameter

      .EXAMPLE
      Set-DgReadiness -Enable -HVCI
      Enables only HVCI

      .NOTES
      None at this time

      .LINK
      https://aka.ms/dgwhcr
      The first link is opened by Get-Help -Online Get-DgReadiness
    

      .INPUTS
      List of input types that are accepted by this function.

      .OUTPUTS
      1. Red Errors: Basic things are missing that will prevent enabling and using Device Guard / Credential Guard
      2. Yellow Warnings: This device can be used to enable and use Device Guard / Credential Guard, but additional security benefits will be absent.
      3. Green Messages: This device is fully compliant with Device Guard / Credential Guard requirements

      Log file with details is found here: $env:HOMEDRIVE\DGLogs 
  #>

  if($Disable)
  {
    Log-AndConsole -message 'Disabling Device Guard and Credential Guard'
    Log-AndConsole -message 'Deleting RegKeys to disable DG/CG'

    Execute-CommandAndLog -_cmd 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /f'
    Execute-CommandAndLog -_cmd 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /f'

    $_isRedstone = Test-IsRedstone
    if(!$_isRedstone)
    {
      Execute-CommandAndLog -_cmd 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "NoLock" /f'
    }
    else
    {
      Execute-CommandAndLog -_cmd 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /f'
    }

    if(!$CG)
    {
      Execute-CommandAndLog -_cmd 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /f'
      if($_isRedstone)
      {
        Execute-CommandAndLog -_cmd 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /f'
      }
    }

    if(!$HVCI -and !$DG)
    {
      Execute-CommandAndLog -_cmd 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /f'
    }

    if(!$HVCI -and !$CG)
    {
      Execute-CommandAndLog -_cmd 'del "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"'
    }

    if(!$HVCI -and !$DG -and !$CG)
    {
      Log-AndConsole -message 'Disabling Hyper-V and IOMMU'
      $_isRedstone = Test-IsRedstone
      if(!$_isRedstone)
      {
        Log-AndConsole -message 'OS Not Redstone, disabling IsolatedUserMode separately'
        #Enable/Disable IOMMU seperately
        Execute-CommandAndLog -_cmd 'DISM.EXE /Online /disable-Feature /FeatureName:IsolatedUserMode /NoRestart'
      }
      $CmdOutput = & "$env:windir\system32\dism.exe" /Online /disable-Feature /FeatureName:Microsoft-Hyper-V-Hypervisor /NoRestart | Out-String
      if(!$CmdOutput.Contains('The operation completed successfully.'))
      {
        $CmdOutput = & "$env:windir\system32\dism.exe" /Online /disable-Feature /FeatureName:Microsoft-Hyper-V-Online /NoRestart | Out-String
      }
      Write-Log -message $CmdOutput
      if($CmdOutput.Contains('The operation completed successfully.'))
      {
        Log-AndConsoleSuccess -message 'Disabling Hyper-V and IOMMU successful'
      }
      else
      {
        Log-AndConsoleWarning -message 'Disabling Hyper-V failed please check the log file'
      }

      #set of commands to run SecConfig.efi to delete UEFI variables if were set in pre OS
      #these steps can be performed even if the UEFI variables were not set - if not set it will lead to No-Op but this can be run in general always 
      #this requires a reboot and accepting the prompt in the Pre-OS which is self explanatory in the message that is displayed in pre-OS
      $FreeDrive = Get-ChildItem -Path function:[s-z]: -Name |
      Where-Object -FilterScript {
        !(Test-Path -Path $_)
      } |
      random
      Write-Log -message ('FreeDrive={0}' -f $FreeDrive)
      Execute-CommandAndLog -_cmd 'mountvol $FreeDrive /s'
      $CmdOutput = Copy-Item -Path "$env:windir\System32\SecConfig.efi" -Destination $FreeDrive\EFI\Microsoft\Boot\SecConfig.efi -Force | Out-String
      Log-AndConsole -message $CmdOutput
      Execute-CommandAndLog -_cmd 'bcdedit /create "{0cb3b571-2f2e-4343-a879-d86a476d7215}" /d DGOptOut /application osloader'
      Execute-CommandAndLog -_cmd 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" path \EFI\Microsoft\Boot\SecConfig.efi'
      Execute-CommandAndLog -_cmd 'bcdedit /set "{bootmgr}" bootsequence "{0cb3b571-2f2e-4343-a879-d86a476d7215}"'
      Execute-CommandAndLog -_cmd 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" loadoptions DISABLE-LSA-ISO,DISABLE-VBS'
      Execute-CommandAndLog -_cmd 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" device partition=$FreeDrive'
      Execute-CommandAndLog -_cmd 'mountvol $FreeDrive /d'
      #steps complete
    }
    Auto-RebootHelper
  }

  function Reset-Verifier  
  {
    $verifier_state = & "$env:windir\system32\verifier.exe" /query | Out-String
    if(!$verifier_state.ToString().Contains('No drivers are currently verified.'))
    {
      Execute-CommandAndLog -_cmd 'verifier.exe /reset'
    }
    Auto-RebootHelper
  }
}