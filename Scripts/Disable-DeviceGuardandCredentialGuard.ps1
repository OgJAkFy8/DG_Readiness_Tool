function Disable-DeviceGuardandCredentialGuard
{
  [cmdletbinding(DefaultParameterSetName = 'Default')]
  param
  (
    [Parameter(Position = 0)]
    [string]$OutputFilePath = "$env:HOMEDRIVE\temp\DGLogs"
  )

  Begin {

    # Set Variables 
    $DismOpSuccessful = 'The operation completed successfully.'
    $DismOpFailed = 'Disabling Hyper-V failed please check the log file'

    $registryPath = 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuardTest' # TEsting without admin
    #$registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities'

    $stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
    
    $Script:LogFile = ('{0}\DeviceGuardCheckWrite-{1}.txt' -f $OutputFilePath, (Get-Date -Format MMddhhmmss))
    Write-Verbose -Message ('Writing logs to: {0}' -f $LogFile) -Verbose

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

    function Remove-Registry
    {
      <#
          .SYNOPSIS
          Used to deletes a property and its value from an item. You can use it to delete registry values and the data that they store.
          .EXAMPLE
          Remove-Registry -registryPath 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuardTest' -registryName CG_Capable
          .EXAMPLE
          $registryPath = 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuardTest' # TEsting without admin
          $registryName = 'Test'
          Remove-Registry -registryPath $registryPath -registryName $registryName
          .NOTES
      #>

      param(
        [Parameter(Mandatory)][String]$registryPath,
        [Parameter(Mandatory)][String]$registryName
      )
      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose

      function Test-RegistryValue 
      {
        param (
          [parameter(Mandatory)]
          [ValidateNotNullOrEmpty()][String]$Path,

          [parameter(Mandatory)]
          [ValidateNotNullOrEmpty()][String]$Name
        )
        try 
        {
          $null = Get-ItemProperty -Path $registryPath |
          Select-Object -ExpandProperty $Name -ErrorAction Stop
          return $true
        }
        catch 
        {
          return $false
        }
      }

      if(Test-RegistryValue -Path $registryPath -Name $registryName)
      {
        Write-Verbose -Message ('Deleting "{0}" from {1}' -f $registryName, $registryPath) -Verbose
        $null = Remove-ItemProperty -Path $registryPath -Name $registryName -Force
      }
      
      ELSE
      {
        Write-Verbose -Message ('"{0}" is not present in {1}' -f $registryName, $registryPath) -Verbose
      }
    }
  }

  Process {
    Write-Verbose -Message 'Disabling Device Guard and Credential Guard'
    Write-Verbose -Message 'Deleting RegKeys to disable DG/CG'

    Remove-Registry -registryPath $registryPath -registryName 'EnableVirtualizationBasedSecurity' 
    Remove-Registry -registryPath $registryPath -registryName 'RequirePlatformSecurityFeatures' 
    Remove-Registry -registryPath $registryPath -registryName 'NoLock'
    Remove-Registry -registryPath $registryPath -registryName 'Locked'

    Remove-Registry -registryPath $registryPath -registryName 'HypervisorEnforcedCodeIntegrity' 
    Remove-Registry -registryPath "$registryPath\Scenarios" -registryName 'HypervisorEnforcedCodeIntegrity' 

    Remove-Registry -registryPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'  -registryName  'LsaCfgFlags'

    try{
      Remove-Item -Path "$env:windir\System32\CodeIntegrity\SIPolicy.p7b" -Force -ErrorAction Stop
    }
    catch{
      Write-Warning "SIPolicy.p7b not present" 
    }

    Write-Log -LogMessage 'Disabling Hyper-V and IOMMU'
    <#        $_isRedstone = IsRedstone
        if(!$_isRedstone)
        {
        Write-Log 'OS Not Redstone, disabling IsolatedUserMode separately'
        #Enable/Disable IOMMU seperately
        ExecuteCommandAndLog 'DISM.EXE /Online /disable-Feature /FeatureregistryName:IsolatedUserMode /NoRestart'
    }#>
    $WaitTime = 10
    $stopWatch.Start()
    Do
    {
      $i = '.'*$stopWatch.Elapsed.Seconds
      Write-Verbose -Message ('Working {0}' -f $i ) -Verbose
      
      $CmdOutput = & "$env:windir\system32\dism.exe" /Online /disable-Feature /FeatureName:Microsoft-Hyper-V-Hypervisor /NoRestart | Out-String
      Start-Sleep -Seconds 1
    }
    while((! $CmdOutput.Contains($DismOpSuccessful)) -and ($stopWatch.Elapsed.Seconds -lt $WaitTime))
    $stopWatch.Reset()

    Write-Log -LogMessage $CmdOutput
    if(! $CmdOutput.Contains($DismOpSuccessful))
    {
      Write-Warning -Message $DismOpFailed
    }

    #set of commands to run SecConfig.efi to delete UEFI variables if were set in pre OS
    #these steps can be performed even if the UEFI variables were not set - if not set it will lead to No-Op but this can be run in general always 
    #this requires a reboot and accepting the prompt in the Pre-OS which is self explanatory in the message that is displayed in pre-OS
    $FreeDrive = Get-ChildItem -Path function:[s-z]: -Name |
    Where-Object -FilterScript {
      !(Test-Path -Path $_)
    } |
    random
    Write-Log -LogMessage ('FreeDrive = {0}' -f $FreeDrive)
    <#    ExecuteCommandAndLog 'mountvol $FreeDrive /s'
        $CmdOutput = Copy-Item -Path "$env:windir\System32\SecConfig.efi" -Destination $FreeDrive\EFI\Microsoft\Boot\SecConfig.efi -Force | Out-String
        Write-Log -LogMessage $CmdOutput
        ExecuteCommandAndLog 'bcdedit /create "{0cb3b571-2f2e-4343-a879-d86a476d7215}" /d DGOptOut /application osloader'
        ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" path \EFI\Microsoft\Boot\SecConfig.efi'
        ExecuteCommandAndLog 'bcdedit /set "{bootmgr}" bootsequence "{0cb3b571-2f2e-4343-a879-d86a476d7215}"'
        ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" loadoptions DISABLE-LSA-ISO,DISABLE-VBS'
        ExecuteCommandAndLog 'bcdedit /set "{0cb3b571-2f2e-4343-a879-d86a476d7215}" device partition=$FreeDrive'
    ExecuteCommandAndLog 'mountvol $FreeDrive /d'#>
    # steps complete
 
    # AutoRebootHelper
  }

  End {}
}
