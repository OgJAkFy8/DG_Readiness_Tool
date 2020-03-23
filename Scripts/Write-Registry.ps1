#requires -Version 3.0

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
    [Parameter(Mandatory,ValueFromPipeline = $true,HelpMessage = 'Written like - HKCU:\SYSTEM\CurrentControlSet\Control')]
    [String]$registryPath,
    [Parameter(Mandatory,HelpMessage = 'Registry Key Name')]
    [String]$registryName,
    [Parameter(Mandatory,HelpMessage = 'Value to set the Key to')]
    [String]$registryValue,
    [Parameter(Mandatory,HelpMessage = 'String=REG_SZ: ExpandString=REG_EXPAND_SZ: Binary=REG_BINARY: DWord=REG_DWORD: MultiString=REG_MULTI_SZ: Qword=REG_QWORD: Unknown=REG_RESOURCE_LIST')]
    [ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')] 
    [String]$registryType
  )

  $FunctionMessage = $MyInvocation.MyCommand
  Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) #-Verbose

  if(Test-RegistryValue -registryPath $registryPath -valueName $registryName)
  {
    Write-Verbose -Message ('Setting "{0}" to {1}' -f $registryName, $registryValue) -Verbose
    $null = Set-ItemProperty -Path $registryPath -Name $registryName -Type $registryType -Value $registryValue -Force
  }
      
  ELSE
  {
    Write-Verbose -Message ('Creating "{0}" in {1}' -f $registryName, $registryPath) -Verbose
    $null = New-ItemProperty -Path $registryPath -Name $registryName -Type $registryType -Value $registryValue -Force
  }
}
# TEST FUNCTION
#Write-Registry -registryPath 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -registryName 'EnableVirtualizationBasedSecurity' -registryValue 1 -registryType DWORD
#Write-Registry -registryPath $registryPath -registryName 'HVCI_Capable' -registryValue 2 -registryType DWord
