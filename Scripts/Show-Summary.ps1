function Show-Summary
{
  <#
      .SYNOPSIS
      Make changes to the Registry
      
      .NOTE
      It is labled as a "Show", but does make a lot of changes to the registry.  This needs to be relabled and moved to the Set-DGReadiness
  #>
  param(
    [Parameter(Mandatory = $false)]
    [string]$DGVerifyCrit = 'Test',
    [switch]$HVCI,
    [switch]$DG,
    [switch]$CG,
    $DGVerifyWarn = 'Test-2'
  )

  $registryPath = 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuardTest'
  function Write-Log
  {
    <#
        .SYNOPSIS
        Used to write data to a date stamped log.  
        This is independent of the transcript which is over written each time.
    #>
    param
    (
      [Parameter(Mandatory)]
      [String]$LogMessage
    )
      
    $FunctionMessage = $MyInvocation.MyCommand
    Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose

    $timeStamp = Get-Date -UFormat '%D %T'

    #Tee-Object -InputObject ('{0} : {1}' -f $timeStamp, $LogMessage) -FilePath $LogFile -Append
    Write-Verbose -Message ('Write-Log >> {0} : {1}' -f $timeStamp, $LogMessage)
  }
  function Write-Registry
  {
    <#
        .SYNOPSIS
        Used to write to the registry
        .NOTES
        String: Specifies a null-terminated string. Equivalent to REG_SZ.
        ExpandString: Specifies a null-terminated string that contains unexpanded references to environment variables that are expanded when the value is retrieved. Equivalent to REG_EXPAND_SZ.
        Binary: Specifies binary data in any form. Equivalent to REG_BINARY.
        DWord: Specifies a 32-bit binary number. Equivalent to REG_DWORD.
        MultiString: Specifies an array of null-terminated strings terminated by two null characters. Equivalent to REG_MULTI_SZ.
        Qword: Specifies a 64-bit binary number. Equivalent to REG_QWORD.
        Unknown: Indicates an unsupported registry data type, such as REG_RESOURCE_LIST.
    #>

    param(
      [Parameter(Mandatory)][String]$registryPath,
      [Parameter(Mandatory = $true)][String]$Name,
      [Parameter(Mandatory = $true)][String]$value,
      [Parameter(Mandatory = $true,HelpMessage = 'String=REG_SZ: ExpandString=REG_EXPAND_SZ: Binary=REG_BINARY: DWord=REG_DWORD: MultiString=REG_MULTI_SZ: Qword=REG_QWORD: Unknown=REG_RESOURCE_LIST')]
      [ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')] 
      [String]$PropertyType
    )
    $FunctionMessage = $MyInvocation.MyCommand
    Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose
    #Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
      
    IF(!(Test-Path -Path $registryPath))

    {
      Write-Verbose -Message 'Writing to Registry'
      $null = New-Item -Path $registryPath -Force
      #$null = 
      New-ItemProperty -Path $registryPath -Name $Name -Value $value -PropertyType $PropertyType -Force
    }

    ELSE 
    {
      #$null = 
      New-ItemProperty -Path $registryPath -Name $Name -Value $value -PropertyType $PropertyType -Force
    }
  }

  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose
      

  if($DGVerifyCrit.Length -ne 0 )
  {
    Write-Log -LogMessage 'Machine is not Device Guard / Credential Guard compatible because of the following:'
    Write-Log -LogMessage $DGVerifyCrit.ToString()
    Write-Log -LogMessage $DGVerifyWarn.ToString()
        
    if(!$HVCI -and !$DG)
    {
      Write-Registry -registryPath $registryPath -Name 'CG_Capable' -value 0 -PropertyType DWord
    } 
    if(!$CG)
    {
      Write-Registry -registryPath $registryPath -Name 'DG_Capable' -value 0 -PropertyType DWord
      Write-Registry -registryPath $registryPath -Name 'HVCI_Capable' -value 0 -PropertyType DWord
    }
  }
  elseif ($DGVerifyWarn.Length -ne 0 )
  {
    Write-Log -LogMessage "Device Guard / Credential Guard can be enabled on this machine.`n"
    Write-Log -LogMessage 'The following additional qualifications, if present, can enhance the security of Device Guard / Credential Guard on this system:'
    Write-Log -LogMessage $DGVerifyWarn.ToString()
        
    if(!$HVCI -and !$DG)
    {
      Write-Registry -registryPath $registryPath -Name 'CG_Capable' -value 1 -PropertyType DWord
    }
    if(!$CG)
    {
      Write-Registry -registryPath $registryPath -Name 'DG_Capable' -value 1 -PropertyType DWord
      Write-Registry -registryPath $registryPath -Name 'HVCI_Capable' -value 1 -PropertyType DWord
    }
  }
  else
  {
    Write-Log -LogMessage $MessageInfo.Info_130 # Info_130 = 'Machine is Device Guard / Credential Guard Ready.' 

    if(!$HVCI -and !$DG)
    {
      Write-Registry -registryPath $registryPath -Name 'CG_Capable' -value 2 -PropertyType DWord
    }
    if(!$CG)
    {
      Write-Registry -registryPath $registryPath -Name 'DG_Capable' -value 2 -PropertyType DWord
      Write-Registry -registryPath $registryPath -Name 'HVCI_Capable' -value 2 -PropertyType DWord
    }
  }
}

Show-Summary -HVCI -CG -DGVerifyWarn 'Test-2' -Verbose
#Show-Summary -HVCI -Verbose
#Show-Summary -DG -Verbose
#Show-Summary -CG -DG -Verbose
#Show-Summary -DGVerifyWarn Test -Verbose