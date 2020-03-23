#requires -Version 3.0 -Modules CimCmdlets
#requires -RunAsAdministrator

function Test-DefenderDeviceGuardSecurityFeatures
{
  <#
      .SYNOPSIS
      Validate enabled Windows Defender Device Guard hardware-based security features

      .DESCRIPTION
      Validate enabled Windows Defender Device Guard hardware-based security features
      Windows 10 and Windows Server 2016 have a WMI class for related properties and features: Win32_DeviceGuard. 
      This class can be queried from an elevated Windows PowerShell session
  #>

  [cmdletbinding(DefaultParameterSetName = 'Log')]
  param(
    [Parameter(ParameterSetName = 'Log', Position = 0)]
    [switch]$WriteToLog
  )

  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage)
  function Get-DeviceGuardFeature
  {
    param
    (
      [Parameter(Mandatory, Position = 0)]
      [Object]$InputObject
    )
    $FunctionMessage = $MyInvocation.MyCommand
    Write-Verbose -Message ('Entering function: {0} with {1} parameter.' -f $FunctionMessage, $InputObject)
    
    $Results = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).$InputObject
    Return $Results
  }
  
  $RequiredSecurityProperties = Get-DeviceGuardFeature -InputObject RequiredSecurityProperties
  $SecurityServicesConfigured = Get-DeviceGuardFeature -InputObject SecurityServicesConfigured
  $SecurityServicesRunning = Get-DeviceGuardFeature -InputObject SecurityServicesRunning
  $VirtualizationBasedSecurityStatus = Get-DeviceGuardFeature -InputObject VirtualizationBasedSecurityStatus


  Switch ($RequiredSecurityProperties){
    #This field describes the required security properties to enable virtualization-based security.

    0 
    {
      Write-Output -NoEnumerate -InputObject 'Required Security Properties - Nothing is required.'
    }
    1 
    {
      Write-Output -NoEnumerate -InputObject 'Required Security Properties - If present, hypervisor support is needed.'
    }
    2 
    {
      Write-Output -NoEnumerate -InputObject 'Required Security Properties - If present, Secure Boot is needed.'
    }
    3 
    {
      Write-Output -NoEnumerate -InputObject 'Required Security Properties - If present, DMA protection is needed.'
    }
    4 
    {
      Write-Output -NoEnumerate -InputObject 'Required Security Properties - If present, Secure Memory Overwrite is needed.'
    }
    5 
    {
      Write-Output -NoEnumerate -InputObject 'Required Security Properties - If present, NX protections are needed.'
    }
    6 
    {
      Write-Output -NoEnumerate -InputObject 'Required Security Properties - If present, SMM mitigations are needed.'
    }
    7 
    {
      Write-Output -NoEnumerate -InputObject 'Required Security Properties - If present, Mode Based Execution Control is needed.'
    }
  }
  
  Switch ($SecurityServicesConfigured){
    #This field indicates whether the Windows Defender Credential Guard or HVCI service has been configured.

    0 
    {
      Write-Output -NoEnumerate -InputObject 'Security Services Configured - No services configured.'
    }
    1 
    {
      Write-Output -NoEnumerate -InputObject 'Security Services Configured - If present, Windows Defender Credential Guard is configured.'
    }
    2 
    {
      Write-Output -NoEnumerate -InputObject 'Security Services Configured - If present, HVCI is configured.'
    }
    3 
    {
      Write-Output -NoEnumerate -InputObject 'Security Services Configured - If present, System Guard Secure Launch is configured.'
    }
  }
  
  Switch ($SecurityServicesRunning){
    #This field indicates whether the Windows Defender Credential Guard or HVCI service is running.

    0 
    {
      Write-Output -NoEnumerate -InputObject 'Security Services Running - No services running.'
    }
    1 
    {
      Write-Output -NoEnumerate -InputObject 'Security Services Running - If present, Windows Defender Credential Guard is running.'
    }
    2 
    {
      Write-Output -NoEnumerate -InputObject 'Security Services Running - If present, HVCI is running.'
    }
    3 
    {
      Write-Output -NoEnumerate -InputObject 'Security Services Running - If present, System Guard Secure Launch is running.'
    }
  }

  Switch ($VirtualizationBasedSecurityStatus){
    #This field indicates whether VBS is enabled and running.

    0 
    {
      Write-Output -NoEnumerate -InputObject 'Virtualization Based Security Status - (VBS) is not enabled.'
    }
    1 
    {
      Write-Output -NoEnumerate -InputObject 'Virtualization Based Security Status - (VBS) is enabled but not running.'
    }
    2 
    {
      Write-Output -NoEnumerate -InputObject 'Virtualization Based Security Status - (VBS) is enabled and running.'
    }
  }
}

Test-DefenderDeviceGuardSecurityFeatures -Verbose
