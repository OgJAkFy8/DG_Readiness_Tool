#requires -Version 3.0 
# xequires -RunAsAdministrator

function Set-DeviceGuard 
{

  [cmdletbinding(DefaultParameterSetName = 'Enable')]
  param(
  [Parameter(ParameterSetName = 'Enable', Position = 0)]
  [switch]$Enabled, 
  [Parameter(ParameterSetName = 'Disable', Position = 0)]
  [switch]$Disabled
  )

  Begin {

    #SECTION - VERIABLES 
    $registryPath = 'HKcu:\SYSTEM\CurrentControlSet\Control\DeviceGuardTest2'

    #SECTION - FUNCTION
    function Test-RegistryValue 
    {
      <#
          .SYNOPSIS
          Tests the presents of a Registry value

          .DESCRIPTION
          Tests the presents of a Registry value and returns a True of false
      #>

      param (
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$registryPath,
        [parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String]$valueName
      )
      try 
      {
        $null = Get-ItemProperty -Path $registryPath |
        Select-Object -ExpandProperty $valueName -ErrorAction Stop
        return $true
      }
      catch 
      {
        return $false
      }
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
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage)

      if(Test-RegistryValue -registryPath $registryPath -valueName $registryName)
      {
        Write-Verbose -Message ('Deleting "{0}" from {1}' -f $registryName, $registryPath)
        $null = Remove-ItemProperty -Path $registryPath -Name $registryName -Force
      }
      
      ELSE
      {
        Write-Verbose -Message ('"{0}" is not present in {1}' -f $registryName, $registryPath)
      }
    }

    function Write-Registry
    {
      <#
          .SYNOPSIS
          Used to write to the registry
          .DESCRIPTION
          Tests to see if the registry path exists.  Adds it if it is not, then writes the key and registryValue
          .EXAMPLE
          Write-Registry -registryPath 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -registryName 'EnableVirtualizationBasedSecurity' -registryValue 1 -registryType DWORD
          .EXAMPLE
          $registryName = 'HVCI_Capable'
          $registryPath = 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
          Write-Registry -registryPath $registryPath -registryName $registryName -registryValue 2 -registryType DWord
          .NOTES
          String: Specifies a null-terminated string. Equivalent to REG_SZ.
          ExpandString: Specifies a null-terminated string that contains unexpanded references to environment variables that are expanded when the registryValue is retrieved. Equivalent to REG_EXPAND_SZ.
          Binary: Specifies binary data in any form. Equivalent to REG_BINARY.
          DWord: Specifies a 32-bit binary number. Equivalent to REG_DWORD.
          MultiString: Specifies an array of null-terminated strings terminated by two null characters. Equivalent to REG_MULTI_SZ.
          Qword: Specifies a 64-bit binary number. Equivalent to REG_QWORD.
          Unknown: Indicates an unsupported registry data type, such as REG_RESOURCE_LIST.
      #>

      param(
        [Parameter(Mandatory,ValueFromPipeline,HelpMessage = 'Written like - HKCU:\SYSTEM\CurrentControlSet\Control')]
        [String]$registryPath,
        [Parameter(Mandatory,HelpMessage = 'Registry Key Name')]
        [String]$registryName,
        [Parameter(Mandatory,HelpMessage = 'Value to set the Key to')]
        [String]$registryValue,
        [Parameter(Mandatory,HelpMessage = 'String=REG_SZ: ExpandString=REG_EXPAND_SZ: Binary=REG_BINARY: DWord=REG_DWORD: MultiString=REG_MULTI_SZ: Qword=REG_QWORD: Unknown=REG_RESOURCE_LIST')]
        #[ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')] 
        [String]$registryType
      )

      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose

      If (-not(Test-Path -Path $registryPath)) 
      {
        New-Item -Path $registryPath -ItemType Directory -Force
      }

      if(Test-RegistryValue -registryPath $registryPath -valueName $registryName)
      {
        Write-Verbose -Message ('Setting "{0}" to {1}' -f $registryName, $registryValue)
        $null = Set-ItemProperty -Path $registryPath -Name $registryName -Type $registryType -Value $registryValue -Force
      }
      
      ELSE
      {
        Write-Verbose -Message ('Creating "{0}" in {1}' -f $registryName, $registryPath)
        $null = New-ItemProperty -Path $registryPath -Name $registryName -Type $registryType -Value $registryValue -Force
      }
    }

    #SECTION - Initial Environmental Tests

    $ReleaseId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' -Name ReleaseId).ReleaseId 
    If($ReleaseId -lt 1607)
    {
      Write-Warning -Message 'Upgrade your OS.  Exiting...'
      Return
    }
  } ##SECTION - BEGIN end
  Process {
    Try
    {
      switch ($PSBoundParameters.Keys) {

        'Enabled'
        {
          #For Windows 10 version 1607 and later
          #Recommended settings (to enable virtualization-based protection of Code Integrity policies, without UEFI Lock):
          Write-Registry -registryPath $registryPath -registryName 'EnableVirtualizationBasedSecurity' -registryType DWord -registryValue 1
          Write-Registry -registryPath $registryPath -registryName 'RequirePlatformSecurityFeatures'  -registryType DWord -registryValue 1
          Write-Registry -registryPath $registryPath -registryName 'Locked' -registryType DWord -registryValue 0

          Write-Registry -registryPath "$registryPath\Scenarios\HypervisorEnforcedCodeIntegrity" -registryName  'Enabled' -registryType DWord -registryValue 1
          Write-Registry -registryPath "$registryPath\Scenarios\HypervisorEnforcedCodeIntegrity" -registryName  'Locked' -registryType DWord -registryValue 0

          #Write-Registry -registryPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'  -registryName  'LsaCfgFlags' -registryType DWord -registryValue 2
        }

        'Disabled'
        {
          Write-Verbose -Message 'Disabling Device Guard and Credential Guard'
          Write-Verbose -Message 'Deleting RegKeys to disable DG/CG'

          Remove-Registry -registryPath $registryPath -registryName 'EnableVirtualizationBasedSecurity' 
          Remove-Registry -registryPath $registryPath -registryName 'RequirePlatformSecurityFeatures' 
          Remove-Registry -registryPath $registryPath -registryName 'NoLock'
          Remove-Registry -registryPath $registryPath -registryName 'Locked'
          Remove-Registry -registryPath $registryPath -registryName 'Unlocked'
          Remove-Registry -registryPath $registryPath -registryName 'HypervisorEnforcedCodeIntegrity' 
          Remove-Registry -registryPath "$registryPath\Scenarios" -registryName 'HypervisorEnforcedCodeIntegrity' 

          Remove-Registry -registryPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'  -registryName  'LsaCfgFlags'

          try
          {
            Remove-Item -Path "$env:windir\System32\CodeIntegrity\SIPolicy.p7b" -Force -ErrorAction Stop
          }
          catch
          {
            Write-Warning -Message 'SIPolicy.p7b not present'
          }
        }

        Default
        {
          Write-Warning -Message ('Unhandled parameter -> [{0}]' -f ($_))
        }
      }
    }
    Catch
    {
      # get error record
      [Management.Automation.ErrorRecord]$e = $_

      # retrieve information about runtime error
      $info = [PSCustomObject]@{
        Exception = $e.Exception.Message
        Reason    = $e.CategoryInfo.Reason
        Target    = $e.CategoryInfo.TargetName
        Script    = $e.InvocationInfo.ScriptName
        Line      = $e.InvocationInfo.ScriptLineNumber
        Column    = $e.InvocationInfo.OffsetInLine
      }
   
      # output information. Post-process collected info, and log info (optional)
      $info
    }
  } ##SECTION - PROCESS end
  End{ } ##SECTION - END end
}

#Set-DeviceGuard -Enabled -Verbose
