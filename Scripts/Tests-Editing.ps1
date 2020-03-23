#requires -Version 3.0 -Modules CimCmdlets, SecureBoot, TrustedPlatformModule
#Requires -PSEdition Desktop
#Requires -RunAsAdministrator

###  Tests-Editing - Pulling out all of the the tests from the original script

# Data to be used 
$OSSKU = @{
  0 = 'The SKU is undefined'
  1 = 'SKU is Ultimate Edition'
  2 = 'SKU is Home Basic Edition'
  3 = 'SKU is Home Premium Edition'
  4 = 'SKU is Enterprise Edition'
  5 = 'SKU is Home Basic N Edition'
  6 = 'SKU is Business Edition'
  7 = 'SKU is Standard Server Edition'
  8 = 'SKU is Datacenter Server Edition'
  9 = 'SKU is Small Business Server Edition'
  10 = 'SKU is Enterprise Server Edition'
  11 = 'SKU is Starter Edition'
  12 = 'SKU is Datacenter Server Core Edition'
  13 = 'SKU is Standard Server Core Edition'
  14 = 'SKU is Enterprise Server Core Edition'
  15 = 'SKU is Enterprise Server IA64 Edition'
  16 = 'SKU is Business N Edition'
  17 = 'SKU is Web Server Edition'
  18 = 'SKU is Cluster Server Edition'
  19 = 'SKU is Home Server Edition'
  20 = 'SKU is Storage Express Server Edition'
  21 = 'SKU is Storage Standard Server Edition'
  22 = 'SKU is Storage Workgroup Server Edition'
  23 = 'SKU is Storage Enterprise Server Edition'
  24 = 'SKU is Server For Small Business Edition'
  25 = 'SKU is Small Business Server Premium Edition'
  26 = 'SKU is to be determined'
  27 = 'SKU is Windows Enterprise'
  28 = 'SKU is Windows Ultimate'
  29 = 'SKU is Web Server (core installation)'
  33 = 'SKU is Server Foundation'
  34 = 'SKU is Windows Home Server'
  36 = 'SKU is Windows Server Standard without Hyper-V'
  37 = 'SKU is Windows Server Datacenter without Hyper-V (full installation)'
  38 = 'SKU is Windows Server Enterprise without Hyper-V (full installation)'
  39 = 'SKU is Windows Server Datacenter without Hyper-V (core installation)'
  40 = 'SKU is Windows Server Standard without Hyper-V (core installation)'
  41 = 'SKU is Windows Server Enterprise without Hyper-V (core installation)'
  42 = 'SKU is Microsoft Hyper-V Server'
  43 = 'SKU is Storage Server Express (core installation)'
  44 = 'SKU is Storage Server Standard (core installation)'
  45 = 'SKU is Storage Server Workgroup (core installation)'
  46 = 'SKU is Storage Server Enterprise (core installation)'
  50 = 'SKU is Windows Small Business Server 2011 Essentials'
  63 = 'SKU is Small Business Server Premium (core installation)'
  64 = 'SKU is Windows Server Hyper Core V'
  87 = 'SKU is Windows Thin PC'
  89 = 'SKU is Windows Embedded Industry'
  97 = 'SKU is Windows RT'
  101 = 'SKU is Windows Home'
  103 = 'SKU is Windows Professional with Media Center'
  104 = 'SKU is Windows Mobile'
  118 = 'SKU is Windows Embedded Handheld'
  123 = 'SKU is Windows IoT (Internet of Things) Core'
}

function Get-SystemData
{
  # Operating System Properties to test for
  $OSPropertiesAry = @(
    'PSComputerName', 
    'BuildNumber', 
    'BuildType', 
    'Caption', 
    'Description', 
    'OperatingSystemSKU', 
    'Organization', 
    'OSArchitecture', 
    'Version', 
    'WindowsDirectory', 
    'ProductType'
  )

  # Property Output Hash Table
  # Access using: $MachineSysProperty['OperatingSystemSKU']] or $MachineSysProperty[<variable>]]
  $Script:MachineSysProperty = @{}

  foreach($property in $OSPropertiesAry)
  {
    $MachineSysProperty.Add($property,((Get-WmiObject -Class win32_operatingsystem).$property))
  }
  ####
  $SystemProcessorAry = @(
    'VirtualizationFirmwareEnabled', 
    'VMMonitorModeExtensions'
  )

  $SystemProcessor = @{}

  foreach($property in $SystemProcessorAry)
  {
    $SystemProcessor.Add($property,((Get-WmiObject -Class Win32_processor).$property))
    $MachineSysProperty.Add($property,((Get-WmiObject -Class Win32_processor).$property))
  }

  ####
  $ComputerSystemAry = @(
    'HypervisorPresent'
  )

  $ComputerSystem = @{}

  foreach($property in $ComputerSystemAry)
  {
    $ComputerSystem.Add($property,((Get-CimInstance -ClassName Win32_ComputerSystem).$property))
    $MachineSysProperty.Add($property,((Get-CimInstance -ClassName Win32_ComputerSystem).$property))
  }
  #Return $MachineSysProperty
}

 $Script:MachineSysProperty = Get-SystemData # Sets up the Machine Properties Hash Table

##############  Variables ##################
$OutputFilePath = "$env:HOMEDRIVE\temp\DGLogs"
$Script:LogFile = ('{0}\FunctionTest-{1}.txt' -f $OutputFilePath, (Get-Date -Format MMddhhmmss))
$registryPath = 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuard2' # TEsting without admin
#$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities'

function Write-Log
{
  <#
      .SYNOPSIS
      Used to write data to a date stamped log.  
      This is independent of the transcript which is over written each time.
  #>
  param
  (
    [Parameter(ParameterSetName = 'Log',Mandatory = $false)]
    [String]$LogMessage,
    [Parameter(ParameterSetName = 'Message',Mandatory = $false)]
    [String]$Message
  )
  if($Message)
  {
    $LogMessage = $Message
  }

  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) 

  $timeStamp = Get-Date -UFormat '%D %T'

  Tee-Object -InputObject ('{0} : {1}' -f $timeStamp, $LogMessage) -FilePath $LogFile -Append
  Write-Verbose -Message ('Write-Log >>> {0}' -f $LogMessage)
}
######################################
function Test-IsDomainController
{
  <#
      .SYNOPSIS
      # Test for Domain Controller
  #>
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage)
  
  if($($MachineSysProperty['ProductType']) -eq 2)
  {
    Write-Verbose -Message 'Not compatible with domain controllers'
    Return $true
  }
  Return $false
}

function Test-OSSKUcompatablity  # Does  not seem to be used anywhere
<#bookmark Deprecated #>
{
  <#
      .SYNOPSIS
      Default Comment based Help.  This still needs to be completed.
      
      .NOTE
      This still needs to be completed.
  #>
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose

  
  Write-Log -LogMessage ('OS SKU compatablity: {0}' -f $OSSKU[[int]$MachineSysProperty['OperatingSystemSKU']])
  if($([int]$MachineSysProperty['OperatingSystemSKU']) -eq 101)
  {
    <#
        $SKUarray = @('Enterprise', 'Education', 'IoT', 'Windows Server', 'Pro', 'Home')
        $HLKAllowed = @('microsoft windows 10 pro')
    #>
  }
}
    
function Test-OSArchitecture  # For Checks only.  Does no work. 
{
  <#
      .SYNOPSIS
      Default Comment based Help.  This still needs to be completed.
      
      .NOTE
      This still needs to be completed.
  #>
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose

  Write-Log -LogMessage ('OS Architecture: {0}' -f $($MachineSysProperty['OSArchitecture']))
}

function Test-SecureBootState
{
  <#
      .SYNOPSIS
      Default Comment based Help.  This still needs to be completed.
      
      .NOTE
      This still needs to be completed.
  #>
  param
  (
    [Parameter(Mandatory = $false)]
    [String]$InputData
  )
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage)
  $user = [Security.Principal.WindowsIdentity]::GetCurrent()
  $IsAdmin = (New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  

  if($IsAdmin)
  {
    if(Confirm-SecureBootUEFI)
    {
      Write-Log -LogMessage 'Secure Boot is present.'
    }
    else
    {
      Write-Log -LogMessage 'Secure Boot is absent / not enabled.'
      Write-Log -LogMessage 'If Secure Boot is supported on the system, enable Secure Boot in the BIOS and run the script again.'
    }
  }
  else
  {
    Write-Log -LogMessage ('Unable to run {0}. Administrator privilege is required' -f $FunctionMessage)
  }
}
#TESt Function
# Test-SecureBootState

function Test-Virtualization
{
  <#
      .SYNOPSIS
      Default Comment based Help.  This still needs to be completed.
      
      .NOTE
      This still needs to be completed.
  #>
  $vmmExtension = $MachineSysProperty['VMMonitorModeExtensions']
  $vmFirmwareExtension = $MachineSysProperty['VirtualizationFirmwareEnabled']
  $vmHyperVPresent = $MachineSysProperty['HypervisorPresent']
  Write-Log -LogMessage ('VMMonitorModeExtensions: {0}' -f $vmmExtension)
  Write-Log -LogMessage ('VirtualizationFirmwareEnabled: {0}' -f $vmFirmwareExtension)
  Write-Log -LogMessage ('HyperVisorPresent: {0}' -f $vmHyperVPresent)

  #success if either processor supports and enabled or if hyper-v is present
  if(($vmmExtension -and $vmFirmwareExtension) -or $vmHyperVPresent )
  {
    Write-Log -LogMessage 'Virtualization firmware check passed'
    #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "Virtualization" /t REG_DWORD /d 2 /f '
    #Write-Registry -registryPath $registryPath -Name 'Virtualization' -value 2 -PropertyType DWord
  }
  else
  {
    Write-Log -LogMessage 'Virtualization firmware check failed.'
    # Write-Log -LogMessage 'If Virtualization extensions are supported on the system, enable hardware virtualization (Intel Virtualization Technology, Intel VT-x, Virtualization Extensions, or similar) in the BIOS and run the script again.'
    #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "Virtualization" /t REG_DWORD /d 0 /f '
    #Write-Registry -registryPath $registryPath -Name 'Virtualization' -value 0 -PropertyType DWord
    #$null = $DGVerifyCrit.AppendLine('Virtualization firmware check failed.')
  }
}

function Test-TPM
{
  <#
      .SYNOPSIS
      Default Comment based Help.  This still needs to be completed.
      
      .NOTE
      This still needs to be completed.
  #>
  
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage)
  $user = [Security.Principal.WindowsIdentity]::GetCurrent()
  $IsAdmin = (New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  

  if($IsAdmin)
  {
    $TPMStatus = $(Get-Tpm) # Administrator privilege is required to execute this command.
    $TPMStatus.LockoutCount
    if($TPMStatus.LockoutCount)
    {
      Write-Verbose -Message $TPMStatus.LockoutCount
    }
    else
    {
      Write-Warning -Message 'TPM is absent or not ready for use'
    }
  }

  else
  {
    Write-Warning -Message ('Unable to run {0}. Administrator privilege is required' -f $FunctionMessage)
  }
}

Function Test-DeviceGuard 
<#bookmark NewFunction #>
<#bookmark Deprecated CheckDGRunning #>
<#bookmark Deprecated CheckDGFeatures #>
{
  <#
      .SYNOPSIS
      Default Comment based Help.  This still needs to be completed.
      
      .NOTE
      This still needs to be completed.
  #>
  [cmdletbinding(DefaultParameterSetName = 'Item')]
  param
  (
    [Parameter(ParameterSetName = 'Running', Position = 0)]
    [Switch]$CheckDGRunning,
    [Parameter(ParameterSetName = 'Features', Position = 0)]
    [Switch]$CheckDGFeatures,
    [Parameter(Mandatory,HelpMessage = 'Value to test against', Position = 1)]
    [Parameter(ParameterSetName = 'Running', Position = 1)]
    [Parameter(ParameterSetName = 'Features', Position = 1)]
    [int]$ItemValue
  )
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose
  #Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))

  switch ($PSBoundParameters.Keys) 
  {  
    'CheckDGRunning'
    {
      $DgItem = 'SecurityServicesRunning'
    }
    'CheckDGFeatures'
    {
      $DgItem = 'AvailableSecurityProperties'
    }
  }

  $DGObj = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'

  for($i = 0; $i -lt $DGObj.$DgItem.length; $i++)
  {
    if($DGObj.$DgItem[$i] -eq $ItemValue)
    {
      return $true
    }
  }
  return $false
}
#Test-DeviceGuard -CheckDGRunning -ItemValue 2
function Test-SecureMOR
{
  [cmdletbinding()]
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose
  # Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))

  $isSecureMOR = Test-DeviceGuard -CheckDGFeatures -ItemValue 4
  Write-Log -LogMessage ('isSecureMOR: {0} ' -f $isSecureMOR) 
  if($isSecureMOR -eq 1)
  {
    Write-Log -LogMessage ('Secure MOR is available') 
  }
}



Function Start-MachineTests
{
  #requires -runasadministrator
  [cmdletbinding()]
  param(
    [Parameter(Mandatory = $false)][Switch]$OpenLog
    )

  Get-SystemData
  Test-IsDomainController
  Test-OSSKUcompatablity
  Test-OSArchitecture
  Test-SecureBootState
  Test-Virtualization
  Test-TPM
  Test-SecureMOR
  If($OpenLog)
  {
    Start-Process -FilePath notepad.exe -ArgumentList $LogFile
  }
}
Start-MachineTests -OpenLog 


