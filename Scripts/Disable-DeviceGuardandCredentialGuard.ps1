function Disable-DeviceGuardandCredentialGuard
{
  [cmdletbinding(DefaultParameterSetName = 'Default')]
  param
  (
    [Parameter(ParameterSetName = 'Capable', Position = 0)]
    [switch]$Capable, 
    [Parameter(ParameterSetName = 'Ready', Position = 0)]
    [switch]$Ready, 
    [Parameter(ParameterSetName = 'Enable', Position = 0)]
    [switch]$Enable, 
    [Parameter(ParameterSetName = 'Disable', Position = 0)]
    [switch]$Disable,

    [Parameter(ParameterSetName = 'Enable')]
    [switch]$AutoReboot, 
    [switch]$DG, 
    [switch]$CG, 
    [switch]$HVCI, 
    [switch]$HLK, 
    [Parameter(ParameterSetName = 'Enable')]
    [switch]$Clear, 
    [Parameter(ParameterSetName = 'Enable')]
    [switch]$ResetVerifier,

    [Parameter(ParameterSetName = 'Enable')]
    [String]$SIPolicyPath, 
        
    [Parameter(Mandatory = $false)]
    [string]$OutputFilePath = "$env:HOMEDRIVE\temp\DGLogs"
        

  )
  Begin{

    # Set Variables 
    $Script:LogFile = ('{0}\DeviceGuardCheckWrite-{1}.txt' -f $OutputFilePath, (Get-Date -Format MMddhhmmss))
    Write-Verbose -Message ('Writing logs to: {0}' -f $LogFile) -Verbose
    $Script:CompatibleModules = New-Object -TypeName System.Text.StringBuilder
    $Script:FailingModules = New-Object -TypeName System.Text.StringBuilder
    $Script:FailingExecuteWriteCheck = New-Object -TypeName System.Text.StringBuilder

    $Script:DGVerifyCrit = New-Object -TypeName System.Text.StringBuilder
    $Script:DGVerifyWarn = New-Object -TypeName System.Text.StringBuilder
    $Script:DGVerifySuccess = New-Object -TypeName System.Text.StringBuilder # Potentially Unsed Assignment
    
    $registryPath = 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities' # TEsting without admin
    #$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities'

    $Script:Sys32Path = "$env:windir\system32"
    $Script:DriverPath = "$env:windir\system32\drivers"

    if(!(Test-Path -Path $OutputFilePath))
    {
      New-Item -ItemType Directory -Path $OutputFilePath
    }
    
    # Functions

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
      #Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
      
      $timeStamp = Get-Date -UFormat '%D %T'

      Tee-Object -InputObject ('{0} : {1}' -f $timeStamp, $LogMessage) -FilePath $LogFile -Append
      Write-Verbose -Message ('Write Log >>> {0}' -f $LogMessage)
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
        $null = New-ItemProperty -Path $registryPath -Name $Name -Value $value -PropertyType $PropertyType -Force
      }

      ELSE 
      {
        $null = New-ItemProperty -Path $registryPath -Name $Name -Value $value -PropertyType $PropertyType -Force
      }
    }
    #Write-Registry -registryPath 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -value 1 -PropertyType DWORD
  }
  Process
  {

    if($Disable)
    {
      Write-LogAndConsole 'Disabling Device Guard and Credential Guard'
      Write-LogAndConsole 'Deleting RegKeys to disable DG/CG'

      ExecuteCommandAndLog 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /f'
      ExecuteCommandAndLog 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /f'

      $_isRedstone = IsRedstone
      if(!$_isRedstone)
      {
        ExecuteCommandAndLog 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "NoLock" /f'
      }
      else
      {
        ExecuteCommandAndLog 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /f'
      }

      if(!$CG)
      {
        ExecuteCommandAndLog 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /f'
        if($_isRedstone)
        {
          ExecuteCommandAndLog 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /f'
        }
      }

      if(!$HVCI -and !$DG)
      {
        ExecuteCommandAndLog 'REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /f'
      }

      if(!$HVCI -and !$CG)
      {
        ExecuteCommandAndLog 'del  "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"'
      }

      if(!$HVCI -and !$DG -and !$CG)
      {
        Write-LogAndConsole 'Disabling Hyper-V and IOMMU'
        $_isRedstone = IsRedstone
        if(!$_isRedstone)
        {
          Write-LogAndConsole 'OS Not Redstone, disabling IsolatedUserMode separately'
          #Enable/Disable IOMMU seperately
          ExecuteCommandAndLog 'DISM.EXE /Online /disable-Feature /FeatureName:IsolatedUserMode /NoRestart'
        }
        $CmdOutput = Dism.exe /Online /disable-Feature /FeatureName:Microsoft-Hyper-V-Hypervisor /NoRestart | Out-String
        if(!$CmdOutput.Contains('The operation completed successfully.'))
        {
          $CmdOutput = Dism.exe /Online /disable-Feature /FeatureName:Microsoft-Hyper-V-Online /NoRestart | Out-String
        }
        Write-Log $CmdOutput
        if($CmdOutput.Contains('The operation completed successfully.'))
        {
          Write-LogAndConsoleSuccess 'Disabling Hyper-V and IOMMU successful'
        }
        else
        {
          Write-LogAndConsoleWarning 'Disabling Hyper-V failed please check the log file'
        }

        #set of commands to run SecConfig.efi to delete UEFI variables if were set in pre OS
        #these steps can be performed even if the UEFI variables were not set - if not set it will lead to No-Op but this can be run in general always 
        #this requires a reboot and accepting the prompt in the Pre-OS which is self explanatory in the message that is displayed in pre-OS
        $FreeDrive = Get-ChildItem -Path function:[s-z]: -Name |
        Where-Object -FilterScript {
          !(Test-Path $_) 
        } |
        random
        Write-Log "FreeDrive=$FreeDrive"
        ExecuteCommandAndLog 'mountvol $FreeDrive /s'
        $CmdOutput = Copy-Item -Path "$env:windir\System32\SecConfig.efi" -Destination $FreeDrive\EFI\Microsoft\Boot\SecConfig.efi -Force | Out-String
        Write-LogAndConsole $CmdOutput
        ExecuteCommandAndLog 'bcdedit /create "{0cb3b571-2f2e-4343-a879-d86a476d7215}" /d DGOptOut /application osloader'
        ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" path \EFI\Microsoft\Boot\SecConfig.efi'
        ExecuteCommandAndLog 'bcdedit /set "{bootmgr}" bootsequence "{0cb3b571-2f2e-4343-a879-d86a476d7215}"'
        ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" loadoptions DISABLE-LSA-ISO,DISABLE-VBS'
        ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" device partition=$FreeDrive'
        ExecuteCommandAndLog 'mountvol $FreeDrive /d'
        #steps complete
      }
      # AutoRebootHelper
    }
  }
  End{}
}
