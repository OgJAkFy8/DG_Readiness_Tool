###  Tests-Editing

function Test-IsDomainController # Replaced by test at to of script
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
  Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
  <#
      $_isDC = 0
      $CompConfig = Get-WmiObject -Class Win32_ComputerSystem
      foreach ($ObjItem in $CompConfig) 
      {
      $Role = $ObjItem.DomainRole
      Write-Log -LogMessage ('Role={0}' -f $Role)
      Switch ($Role) 
      {
      0 
      {
      Write-Log -LogMessage 'Standalone Workstation'
      }
      1 
      {
      Write-Log -LogMessage 'Member Workstation'
      }
      2 
      {
      Write-Log -LogMessage 'Standalone Server'
      }
      3 
      {
      Write-Log -LogMessage 'Member Server'
      }
      4 
      {
      Write-Log -LogMessage 'Backup Domain Controller'
      $_isDC = 1
      break
      }
      5 
      {
      Write-Log -LogMessage 'Primary Domain Controller'
      $_isDC = 1
      break
      }
      default 
      {
      Write-Log -LogMessage 'Unknown Domain Role'
      }
      }
      }
      return $_isDC
  #>
}

function Confirm-OSSKU  # Does  not seem to be used anywhere
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
  Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
  <#
      $osname = $((Get-WmiObject -Class win32_operatingsystem).Name).ToLower()
      $_SKUSupported = 0
      Write-Log -LogMessage ('OSNAME:{0}' -f $osname)
      $SKUarray = @('Enterprise', 'Education', 'IoT', 'Windows Server', 'Pro', 'Home')
      $HLKAllowed = @('microsoft windows 10 pro')
      foreach ($SKUent in $SKUarray) 
      {
      if($osname.ToString().Contains($SKUent.ToLower()))
      {
      $_SKUSupported = 1
      break
      }
      }

      # For running HLK tests only, professional SKU's are marked as supported.
      if($HLK)
      {
      if($osname.ToString().Contains($HLKAllowed.ToLower()))
      {
      $_SKUSupported = 1
      }
      }
      $_isDomainController = Test-IsDomainController
      if($_SKUSupported)
      {
      Write-OSSKUErrorWrite-OSSKUError -message 'This PC edition is Supported for DeviceGuard'
      if(($_isDomainController -eq 1) -and !$HVCI -and !$DG)
      {
      Write-Log -LogMessage 'This PC is configured as a Domain Controller, Credential Guard is not supported on DC.'
      }
      Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "OSSKU" /t REG_DWORD /d 2 /f '
      }
      else 
      {
      Write-Log -LogMessage 'This PC edition is Unsupported for Device Guard'
      $null = $DGVerifyCrit.AppendLine('OS SKU unsupported')
      Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "OSSKU" /t REG_DWORD /d 0 /f '
      }
  #>
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
  Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))

  $OSArch = $(Get-WmiObject -Class win32_operatingsystem).OSArchitecture
  Write-Log -LogMessage $OSArch 
  if($OSArch.Contains('32-bit'))
  {
    Write-Log -LogMessage ('32 Bit OS - {0}' -f $MyInvocation.ScriptLineNumber)
  }
  elseif($OSArch.Contains('64-bit'))
  {
    Write-Log -LogMessage ('64 Bit OS. - {0}' -f $MyInvocation.ScriptLineNumber) 
    $null = $DGVerifyCrit.AppendLine('32 Bit OS, OS Architecture failure..')
  }
  else
  {
    Write-Log -LogMessage ('Unknown architecture - {0}' -f $MyInvocation.ScriptLineNumber)
    $null = $DGVerifyCrit.AppendLine('Unknown OS, OS Architecture failure..')
  }
}

function Test-SecureBootState
{
  <#
      .SYNOPSIS
      Default Comment based Help.  This still needs to be completed.
      
      .NOTE
      This still needs to be completed.
  #>
  $_secureBoot = Confirm-SecureBootUEFI
  Write-Log -LogMessage $_secureBoot
  if($_secureBoot)
  {
    Write-Log -LogMessage ('Secure Boot is present - {0}' -f $MyInvocation.ScriptLineNumber)
    #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "SecureBoot" /t REG_DWORD /d 2 /f '
    Write-Registry -registryPath $registryPath -Name 'SecureBoot' -value 2 -PropertyType DWord
  }
  else
  {
    Write-Log -LogMessage ('Secure Boot is absent / not enabled. - {0}' -f $MyInvocation.ScriptLineNumber)
    Write-Log -LogMessage ('If Secure Boot is supported on the system, enable Secure Boot in the BIOS and run the script again. - {0}' -f $MyInvocation.ScriptLineNumber)
    #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "SecureBoot" /t REG_DWORD /d 0 /f '
    Write-Registry -registryPath $registryPath -Name  'SecureBoot' -value 0 -PropertyType DWord
    $null = $DGVerifyCrit.AppendLine('Secure boot validation failed.')
  }
}

function Test-Virtualization
{
  <#
      .SYNOPSIS
      Default Comment based Help.  This still needs to be completed.
      
      .NOTE
      This still needs to be completed.
  #>
  $_vmmExtension = $(Get-WmiObject -Class Win32_processor).VMMonitorModeExtensions
  $_vmFirmwareExtension = $(Get-WmiObject -Class Win32_processor).VirtualizationFirmwareEnabled
  $_vmHyperVPresent = (Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent
  Write-Log -LogMessage ('VMMonitorModeExtensions {0}' -f $_vmmExtension)
  Write-Log -LogMessage ('VirtualizationFirmwareEnabled {0}' -f $_vmFirmwareExtension)
  Write-Log -LogMessage ('HyperVisorPresent {0}' -f $_vmHyperVPresent)

  #success if either processor supports and enabled or if hyper-v is present
  if(($_vmmExtension -and $_vmFirmwareExtension) -or $_vmHyperVPresent )
  {
    Write-Log -LogMessage 'Virtualization firmware check passed'
    #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "Virtualization" /t REG_DWORD /d 2 /f '
    Write-Registry -registryPath $registryPath -Name 'Virtualization' -value 2 -PropertyType DWord
  }
  else
  {
    Write-Log -LogMessage 'Virtualization firmware check failed.'
    # Write-Log -LogMessage 'If Virtualization extensions are supported on the system, enable hardware virtualization (Intel Virtualization Technology, Intel VT-x, Virtualization Extensions, or similar) in the BIOS and run the script again.'
    #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "Virtualization" /t REG_DWORD /d 0 /f '
    Write-Registry -registryPath $registryPath -Name 'Virtualization' -value 0 -PropertyType DWord
    $null = $DGVerifyCrit.AppendLine('Virtualization firmware check failed.')
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
  $user = [Security.Principal.WindowsIdentity]::GetCurrent()
  $IsAdmin = (New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  

  if($IsAdmin)
  {
    $TPMStatus = $(Get-Tpm) # Administrator privilege is required to execute this command.
  }
  else
  {

  }
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose
  # Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
  $WarningMsg = $FunctionMessage
      
  if($TPMLockout)
  {
    if($TPMLockout.ToString().Contains('Not Supported for TPM 1.2'))
    {
      if($HLK)
      {
        Write-Log -LogMessage ('TPM 1.2 is present.')
      }
      else
      {
        $WarningMsg = ('TPM 1.2 is Present. TPM 2.0 is Preferred.')
        Write-Log -LogMessage $WarningMsg
        $null = $DGVerifyWarn.AppendLine($WarningMsg)
      }
    }
    else
    {
      Write-Log -LogMessage ('TPM 2.0 is present.')
    }
    #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "TPM" /t REG_DWORD /d 2 /f '
    Write-Verbose -Message 'TPM -value 2' 
    Write-Registry -registryPath $registryPath -Name 'TPM' -value 2 -PropertyType DWord
  }
  else
  {
    $WarningMsg = $UserMessage.Error_100 
    if($HLK)
    {
      Write-Log -LogMessage $WarningMsg
      $null = $DGVerifyCrit.AppendLine($WarningMsg)
    }
    else
    {
      Write-Log -LogMessage $WarningMsg
      $null = $DGVerifyWarn.AppendLine($WarningMsg)
    }
    #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "TPM" /t REG_DWORD /d 0 /f '
    Write-Registry -registryPath $registryPath -Name 'TPM' -value 0 -PropertyType DWord
  }
}

function Test-SecureMOR
{
  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose
  # Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))

  $isSecureMOR = Test-DeviceGuard -CheckDGFeatures -ItemValue 4
  Write-Log -LogMessage ('isSecureMOR= {0} ' -f $isSecureMOR) 
  if($isSecureMOR -eq 1)
  {
    Write-Log -LogMessage $MessageInfo.SuccessMOR
  }
}



 

  