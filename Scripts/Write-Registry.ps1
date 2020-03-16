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
   

Write-Registry -registryPath $registryPath -Name 'HVCI_Capable' -value 2 -PropertyType DWord
