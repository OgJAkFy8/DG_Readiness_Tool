#requires -Version 3.0 -Modules CimCmdlets, SecureBoot, TrustedPlatformModule
# xequires -RunAsAdministrator

# requires driver verifier on system.

# Test for Domain Controller first.
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if($osInfo.ProductType -eq 2)
{
  Write-Error -Message 'Not compatible with domain controllers'
  Return
}

Function Get-DgReadiness
{
  <# Get-DgReadiness
      .SYNOPSIS
      Script to find out if machine is Device Guard compliant


      .DESCRIPTION
      Script to find out if machine is Device Guard compliant
      Log file with details is found here: C:\DGLogs 

      .PARAMETER Capable
      Describe parameter -Capable.

      .PARAMETER Ready
      To Verify the status of DG/CG and whether it is enabled or disabled

      .PARAMETER AutoReboot
      Reboots the computer

      .PARAMETER DG
      To Verify if this device is DG/CG Capable

      .PARAMETER CG
      To Verify if this device is DG/CG Capable

      .PARAMETER HVCI
      To Verify if this device is HVCI Capable

      .PARAMETER HLK
      Describe parameter -HLK.

      .PARAMETER Clear
      Describe parameter -Clear.

      .PARAMETER ResetVerifier
      Describe parameter -ResetVerifier.

      .EXAMPLE
      Get-DgReadiness  -Ready 
      To Verify the status of DG/CG and whether it is enabled or disabled
      ** Suggest turning this to the default

      .EXAMPLE
      Get-DgReadiness -Capable -DG 
      To Verify if this device is DG/CG Capable

      .EXAMPLE
      Get-DgReadiness -Capable  -CG 
      To Verify if this device is DG/CG Capable


      .EXAMPLE
      Get-DgReadiness -Capable  -HVCI 
      To Verify if this device is HVCI Capable

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

  [CmdletBinding()]
  param(
    [switch]$Capable, 
    [switch]$Ready, 
    [switch]$Enable, 
    [switch]$Disable, 
    [Parameter(Mandatory)][String]$SIPolicyPath, 
    [switch]$AutoReboot, 
    [switch]$DG, 
    [switch]$CG, 
    [switch]$HVCI, 
    [switch]$HLK, 
    [switch]$Clear, 
    [switch]$ResetVerifier,
    [string]$OutputFilePath = "$env:HOMEDRIVE\temp\DGLogs"
  )
  
  BEGIN
  {
    
    $Script:LogFile = ('{0}\DeviceGuardCheckLog-{1}.txt' -f $OutputFilePath, (Get-Date -Format MMddhhmmss))

    $Script:CompatibleModules = New-Object -TypeName System.Text.StringBuilder
    $Script:FailingModules = New-Object -TypeName System.Text.StringBuilder
    $Script:FailingExecuteWriteCheck = New-Object -TypeName System.Text.StringBuilder

    $Script:DGVerifyCrit = New-Object -TypeName System.Text.StringBuilder
    $Script:DGVerifyWarn = New-Object -TypeName System.Text.StringBuilder
    $Script:DGVerifySuccess = New-Object -TypeName System.Text.StringBuilder # Potentially Unsed Assignment

    # $registryPath = 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities'

    $Script:Sys32Path = "$env:windir\system32"
    $Script:DriverPath = "$env:windir\system32\drivers"

    
    ########
    # All messages and Error messages
    $MessageInfo = @{
      RebootRequired       = 'Please reboot the machine, for settings to be applied.'
      EnableVerifier       = 'Enabling Driver verifier'
      EnableVerifierReboot = 'Enabling Driver Verifier and Rebooting system'
      RebootTimer          = 'PC will restart in 30 seconds'
      Deprecated           = 'Feature has been deprecated'
      SuccessHVDIDriver    = 'No Incompatible Drivers found'
      SuccessMOR           = 'Secure MOR is available'
    }

    $MessageWarning = @{
      IncompatibleHVDIDriver = 'Incompatible HVCI Kernel Driver Modules found'
      Warning_102            = 'Secure MOR is absent'
      AbsentMOR              = 'Secure MOR is absent'
      Warning_100            = 'HVCI is already enabled on this machine, driver compat list might not be complete.'
      Warning_101            = 'Please disable HVCI and run the script again...'
    }

    $UserMessage = @{
      Error_100           = 'TPM is absent or not ready for use'
      Error_101           = 'Copying and loading HSTITest.dll failed'
      Error_303           = 'Disabling Hyper-V and IOMMU'
      DisableIsoUserMode  = 'OS Not Redstone, disabling IsolatedUserMode separately'
      FailWritingSIPolicy = 'Writing SIPolicy.p7b file failed'
      FailKernel32        = 'Instantiate-Kernel32 failed'
      FailKernel64        = 'Instantiate-Kernel64 failed'
      Error_3001          = 'Error: Capable is currently fully supported in Redstone only.'
      Error_3002          = '32Bit architecture '
      Error_3003          = 'If Secure Boot is supported on the system, enable Secure Boot in the BIOS and run the script again.'
      Error_3004          = 'If Virtualization extensions are supported on the system, enable hardware virtualization(Intel VirtualizationTechnology, Intel VT-x,Virtualization Extensions,or similar)in the BIOS and run the script again.'
      Error_3005          = 'Instantiate-HSTI failed'
      Error_3006          = 'Machine is not Device Guard  /Credential Guard  compatible because of the following:'
      Error_3007          = 'Secure Boot is absent/not enabled.'
      Error_3008          = 'This PC edition is Unsupported for Device Guard'
      Error_3009          = 'This PC is configured as a Domain Controller, Credential Guard  is not supported on DC.'
      Error_3010          = 'Unknown architecture'
      Error_3011          = 'Failed: Virtualization firmware check'
      Separator_1         = '###########################################################################'
      Information_1009    = 'Checking if the device is DG / CG Capable'
      Information_1010    = 'Copying and loading HSTITest.dll failed'
      Information_1011    = 'Copying HSTITest.dll'
      Information_1012    = 'Copying user provided SIpolicy.p7b'
      Information_1013    = 'Edit Registry: Deleting Reg Keys to disable Device Guard and Credential Guard'
      Information_1014    = 'Disabled: Device Guard and Credential Guard '
      Information_1015    = 'Disabled: Hyper-V and IOMMU '
      Information_1016    = 'Enabled: Driver verifier'
      Information_1017    = 'Enabled: Device Guard and Credential Guard '
      Information_1018    = 'Enabled: Driver verifier'
      Information_1019    = 'Enabled: Driver verifier and Rebooting system'
      Information_1020    = 'Enabled: Hyper-V and IOMMU '
      Information_1021    = 'OS Not Redstone, disabling Isolated User Mode separately'
      Information_1022    = 'OS Not Redstone, enabling Isolated User Mode separately'
      Information_1023    = 'Please reboot manually and run the script again....'
      Information_1024    = 'Please re-execute this script after reboot....'
      Information_1025    = 'Setting Reg Keys to enable Device Guard and Credential Guard'
      Information_1026    = 'To learn more about required hardware and software please visit: https://aka.ms/dgwhcr'
      Information_1027    = 'Verifying each module please wait....'
      Information_1028    = 'Writing SI Policy.p7b file failed'
      Information_2001    = 'Success: Device Guard and Credential Guard can be enabled on this machine.'
      Information_2002    = 'Success: Machine is Device Guard and Credential Guard  Ready.'
      Information_2008    = '64Bit architecture '
      Information_2009    = 'Disabled: Hyper-V and  IOMMU '
      Information_2010    = 'Enabled: Hyper-V and  IOMMU '
      Information_2011    = 'Success: HSTI validation'
      Information_2012    = 'Enabled: HVCI, and Config-Ciare running.'
      Information_2013    = 'Enabled: HVCI, Credential Guard and Config-Ciare running.'
      Information_2014    = 'Available: NX Protector'
      Information_2015    = 'Present: Secure Boot'
      Information_2016    = 'Available: SMM Mitigation'
      Information_2017    = 'Present: TPM1.2'
      Information_2018    = 'Present: TPM2.0'
      Information_2019    = 'Passed: Virtualization firmware check'
      Information_2020    = "Readiness Tool Version 3.4 Release.`n Tool to check if your device is capable to run Device Guard and Credential Guard ."
      Warning_2001        = 'Disabled: Hyper-V failed please check the log file'
      Warning_2002        = 'Enabled: Hyper-V failed please check the log file'
      Warning_2003        = 'HSTI is absent'
      Warning_2004        = 'Not all services are running.'
      Warning_2005        = 'Not all services are running.'
      Warning_2006        = 'NX Protector is absent'
      Warning_2007        = 'Running on a Virtual Machine. DG/CG is supported only if both guest VM and host machine are running with Windows10, version 1703 or later with English localization.'
      Warning_2008        = 'SMM Mitigation is absent'
      Warning_2009        = 'The following additional qualifications, if present, can enhance the security of Device Guard and Credential Guard on this system:'
    }
  

    #########
    ## Log Functions
    function Use-TranscriptLog 
    {
      param(
        [Switch]$Start,
        [Switch]$Stop,
        [Parameter(Mandatory)][String]$LogFile
      )

      if ($Start)
      {
        Start-Transcript -Path $LogFile
      }
      if ($Stop)
      {
        Stop-Transcript
      }
      Write-Verbose -Message ('Find the log file here: {0}' -f $LogFile)
    }

    function Write-Registry
    {
      param(
        [Parameter(Mandatory)][String]$registryPath,
        [Parameter(Mandatory = $false)][String]$Name,
        [Parameter(Mandatory = $false)][String]$value,
        [Parameter(Mandatory = $false)][String]$PropertyType
      )
      Write-Verbose -Message ('Enter Function : ' -f $MyInvocation.MyCommand) -Verbose
      IF(!(Test-Path -Path $registryPath))

      {
        Write-Verbose -Message 'Writing to Registry'
        $null = New-Item -Path $registryPath -Force
        $null = New-ItemProperty -Path $registryPath -Name $Name -Value $value -PropertyType $PropertyType -Force
      }

      ELSE 
      {
        $null = New-ItemProperty -Path $registryPath -Name $Name -Value $value -PropertyType DWORD -Force
      }
    }

    #Write-Registry -registryPath 'HKCU:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -value 1 -PropertyType DWORD
    function Write-OnScreen
    <#Bookmark NewFunction#>
    {
      param(
        [Parameter(Mandatory = $false)][String]$LogFile,
        [Parameter(Mandatory = $false)][String]$message

      )
      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) -Verbose
      Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
    }

    function Write-Log
    {
      param
      (
        [Parameter(Mandatory)]
        [String]$message
      )
      $timeStamp = Get-Date -UFormat '%D %T'

      Tee-Object -InputObject ('{0} : {1}' -f $timeStamp, $message) -FilePath $LogFile -Append
      Write-Verbose -Message $message
    }

    function Log-ToLogAndConsole([Parameter(Mandatory)][String]$message)
    {
      Write-Verbose -Message $message -Verbose
      Write-Log -message $message
    }

    function Log-AndConsoleWarning([Parameter(Mandatory)]$message)
    {
      Write-Verbose -Message $message -Verbose
      Write-Log -message $message
    }

    function Log-AndConsoleSuccess([Parameter(Mandatory)]$message)
    {
      Write-Verbose -Message $message -Verbose
      Write-Log -message $message
    }

    function Log-AndConsoleError([Parameter(Mandatory)]$message)
    {
      Write-Verbose -Message $message -Verbose
      Write-Log -message $message
    }

    # Ridiculous amount of Fuctions
    ##########
    function Test-IsExempt 
    {
      param
      (
        [Parameter(Mandatory)][IO.FileInfo]
        $item
      )
      $cert = (Get-AuthenticodeSignature -FilePath $item.FullName).SignerCertificate
      if($cert.ToString().Contains('CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'))
      {
        Write-Log -message ('{0} {1}' -f $item.FullName, 'MS Exempted')
        return 1
      }
      else
      {
        Write-Log -message ('{0}.FullName Not-exempted' -f $item)
        Write-Log -message $cert.ToString()
        return 0
      }
    } 

    function Check-Exemption
    {
      param
      (
        [Parameter(Mandatory)]$_ModName
      )
      $mod1 = Get-ChildItem -Path $Sys32Path -Filter $_ModName
      $mod2 = Get-ChildItem -Path $DriverPath -Filter $_ModName
      if($mod1)
      { 
        Write-Log -message ('NonDriver module {0}.FullName' -f $mod1)
        return Test-IsExempt -item ($mod1) 
      }
      elseif($mod2)
      {
        Write-Log -message ('Driver Module {0}.FullName' -f $mod2)
        return Test-IsExempt -item ($mod2)
      }
    }

    function Check-FailedDriver
    {
      param
      (
        [Parameter(Mandatory)][String]$_ModName,

        [Parameter(Mandatory)][Object]$CIStats
      )
      Write-Log -message 'Module: ' $_ModName.Trim()
      if(Check-Exemption -_ModName ($_ModName.Trim()) - eq 1)
      {
        $null = $CompatibleModules.AppendLine(('Windows Signed: {0}.Trim()' -f $_ModName))
        return
      }
      $index = $CIStats.IndexOf('execute pool type count:'.ToLower())
      if($index -eq -1)
      {
        return
      }
      $_tempStr = $CIStats.Substring($index)
      $Result = 'PASS'
      $separator = "`r`n", ''
      $option = [StringSplitOptions]::RemoveEmptyEntries
      $stats = $_tempStr.Split($separator,$option)
      Write-Log -message $stats.Count

      $FailingStat = ''
      foreach( $stat in $stats)
      {
        $_t = $stat.Split(':')
        if($_t.Count -eq 2 -and $_t[1].trim() -ne '0')
        {
          $Result = 'FAIL'
          $FailingStat = $stat
          break
        }
      }
      if($Result.Contains('PASS'))
      {
        $null = $CompatibleModules.AppendLine($_ModName.Trim())
      }
      elseif($FailingStat.Trim().Contains('execute-write'))
      {
        $null = $FailingExecuteWriteCheck.AppendLine('Module: '+ $_ModName.Trim() + "`r`n`tReason: " + $FailingStat.Trim() )
      }
      else
      {
        $null = $FailingModules.AppendLine('Module: '+ $_ModName.Trim() + "`r`n`tReason: " + $FailingStat.Trim() )
      }
      Write-Log -message 'Result: ' $Result
    }

    function Show-CIStats
    {
      param
      (
        [Parameter(Mandatory)][String]$_ModName,

        [Parameter(Mandatory)][Object]$str1
      )
      $i1 = $str1.IndexOf('Code Integrity Statistics:'.ToLower())
      if($i1 -eq -1 )
      {
        Write-Log -message 'String := ' $str1
        Write-Log -message 'Warning! CI Stats are missing for ' $_ModName
        return 
      }
      $temp_str1 = $str1.Substring($i1)
      $CIStats = $temp_str1.Substring(0).Trim()

      Check-FailedDriver -_ModName $_ModName -CIStats $CIStats
    }

    function Show-ListOfDrivers
    {
      param
      (
        [Parameter(Mandatory)][Object]$str
      )
      $_tempStr = $str

      $separator = 'module:', ''
      $option = [StringSplitOptions]::RemoveEmptyEntries
      $index1 = $_tempStr.IndexOf('MODULE:'.ToLower())
      if($index1 -lt 0)
      {
        return
      }
      $_tempStr = $_tempStr.Substring($index1)
      $_SplitStr = $_tempStr.Split($separator,$option)


      Write-Log -message $_SplitStr.Count
      Log-AndConsole -message $UserMessage.Information_1027
      foreach($ModuleDetail in $_SplitStr)
      {
        #Write-Confirm-OSSKU $Module
        $Index2 = $ModuleDetail.IndexOf('(')
        if($Index2 -eq -1)
        {
          'Skipping ..'
          continue
        }
        $ModName = $ModuleDetail.Substring(0,$Index2-1)
        Write-Log -message ('Driver: {0}' -f $ModName)
        Write-Log -message ('Processing module: {0}' -f $ModName)
        Show-CIStats -_ModName $ModName -str1 $ModuleDetail
      }

      $DriverScanCompletedMessage = ('Completed scan. List of Compatible Modules can be found at {0}' -f $LogFile)
      Log-AndConsole -message $DriverScanCompletedMessage 

      if($FailingModules.Length -gt 0 -or $FailingExecuteWriteCheck.Length -gt 0 )
      {
        # $WarningMessage = $MessageWarning.IncompatibleHVDIDriver
        if($HLK)
        {
          Write-Verbose -Message $MessageWarning.IncompatibleHVDIDriver
          Write-Log -message $MessageWarning.IncompatibleHVDIDriver
        }
        else 
        {
          Write-Verbose -Message $MessageWarning.IncompatibleHVDIDriver
          Write-Log -message $MessageWarning.IncompatibleHVDIDriver
        }

        Log-AndConsoleError -message $FailingExecuteWriteCheck.ToString()
        if($HLK)
        {
          Log-AndConsoleError -message $FailingModules.ToString()
        }
        else
        {
          Log-AndConsoleWarning -message $FailingModules.ToString()
        }
        if($FailingModules.Length -ne 0 -or $FailingExecuteWriteCheck.Length -ne 0 )
        {
          if($HLK)
          {
            $null = $DGVerifyCrit.AppendLine($MessageWarning.IncompatibleHVDIDriver)
          }
          else
          {
            $null = $DGVerifyWarn.AppendLine($MessageWarning.IncompatibleHVDIDriver)
          }
        }
      }
      else
      {
        Log-AndConsoleSuccess -message $MessageInfo.SuccessHVDIDriver
      }
    }

    function Show-Summary()
    {
      if($DGVerifyCrit.Length -ne 0 )
      {
        Log-AndConsoleError -message 'Machine is not Device Guard / Credential Guard compatible because of the following:'
        Log-AndConsoleError -message $DGVerifyCrit.ToString()
        Log-AndConsoleWarning -message $DGVerifyWarn.ToString()
        if(!$HVCI -and !$DG)
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "CG_Capable" /t REG_DWORD /d 0 /f '
        }
        if(!$CG)
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "DG_Capable" /t REG_DWORD /d 0 /f '
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "HVCI_Capable" /t REG_DWORD /d 0 /f '
        }
      }
      elseif ($DGVerifyWarn.Length -ne 0 )
      {
        Log-AndConsoleSuccess -message "Device Guard / Credential Guard can be enabled on this machine.`n"
        Log-AndConsoleWarning -message 'The following additional qualifications, if present, can enhance the security of Device Guard / Credential Guard on this system:'
        Log-AndConsoleWarning -message $DGVerifyWarn.ToString()
        if(!$HVCI -and !$DG)
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "CG_Capable" /t REG_DWORD /d 1 /f '
        }
        if(!$CG)
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "DG_Capable" /t REG_DWORD /d 1 /f '
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "HVCI_Capable" /t REG_DWORD /d 1 /f '
        }
      }
      else
      {
        Log-AndConsoleSuccess -message $MessageInfo.Info_130 # Info_130 = 'Machine is Device Guard / Credential Guard Ready.' 

        if(!$HVCI -and !$DG)
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "CG_Capable" /t REG_DWORD /d 2 /f '
        }
        if(!$CG)
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "DG_Capable" /t REG_DWORD /d 2 /f '
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "HVCI_Capable" /t REG_DWORD /d 2 /f '
        }
      }
    }


    function Instantiate-Kernel32 
    {
      try 
      {
        Add-Type -TypeDefinition @'
 using System;
 using System.Diagnostics;
 using System.Runtime.InteropServices;
 
 public static class Kernel32
 {
 [DllImport("kernel32", SetLastError=true, CharSet = CharSet.Ansi)]
 public static extern IntPtr LoadLibrary(
 [MarshalAs(UnmanagedType.LPStr)]string lpFileName);
 
 [DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
 public static extern IntPtr GetProcAddress(
 IntPtr hModule,
 string procName);
 }
 
'@
      }
      catch
      {
        Write-Log -message $_.Exception.Message 
        Log-AndConsole -message $($MessageError.FailKernel32)
      }
    }

    function Instantiate-HSTI 
    {
      try 
      {
        Add-Type -TypeDefinition @'
 using System;
 using System.Diagnostics;
 using System.Runtime.InteropServices;
 using System.Net;
 
 public static class HstiTest3
 {
 [DllImport("hstitest.dll", CharSet = CharSet.Unicode)]
 public static extern int QueryHSTIdetails( 
 ref HstiOverallError pHstiOverallError, 
 [In, Out] HstiProviderErrorDuple[] pHstiProviderErrors,
 ref uint pHstiProviderErrorsCount,
 byte[] hstiPlatformSecurityBlob,
 ref uint pHstiPlatformSecurityBlobBytes);

 [DllImport("hstitest.dll", CharSet = CharSet.Unicode)]
 public static extern int QueryHSTI(ref bool Pass); 
 
 [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
 public struct HstiProviderErrorDuple
 {
 internal uint protocolError;
 internal uint role;
 internal HstiProviderErrors providerError;
 [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
 internal string ID;
 [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 4096)]
 internal string ErrorString;
 }
 
 [FlagsAttribute]
 public enum HstiProviderErrors : int
 {
 None = 0x00000000,
 VersionMismatch = 0x00000001,
 RoleUnknown = 0x00000002,
 RoleDuplicated = 0x00000004,
 SecurityFeatureSizeMismatch = 0x00000008,
 SizeTooSmall = 0x00000010,
 VerifiedMoreThanImplemented = 0x00000020,
 VerifiedNotMatchImplemented = 0x00000040
 }

 [FlagsAttribute]
 public enum HstiOverallError : int
 {
 None = 0x00000000,
 RoleTooManyPlatformReference = 0x00000001,
 RoleTooManyIbv = 0x00000002,
 RoleTooManyOem = 0x00000004,
 RoleTooManyOdm = 0x00000008,
 RoleMissingPlatformReference = 0x00000010,
 VerifiedIncomplete = 0x00000020,
 ProtocolErrors = 0x00000040,
 BlobVersionMismatch = 0x00000080,
 PlatformSecurityVersionMismatch = 0x00000100,
 ProviderError = 0x00000200
 } 
 
 }
'@

        #$LibHandle = [Kernel32]::LoadLibrary("$env:windir\System32\hstitest.dll")
        # $FuncHandle = [Kernel32]::GetProcAddress($LibHandle, 'QueryHSTIdetails')
        # $FuncHandle2 = [Kernel32]::GetProcAddress($LibHandle, 'QueryHSTI')

        if ([IntPtr]::Size -eq 8) 
        {
          #assuming 64 bit 
          Write-Log -message ("`nKernel32::LoadLibrary 64bit --> 0x{0}" -f ('{0:X16}' -f $LibHandle.ToInt64()))
          Write-Log -message ('HstiTest2::QueryHSTIdetails 64bit --> 0x{0}' -f ('{0:X16}' -f $FuncHandle.ToInt64()))
        }
        else
        {
          return
        }
        # $overallError = New-Object -TypeName HstiTest3+HstiOverallError
        $providerErrorDupleCount = New-Object -TypeName int
        $blobByteSize = New-Object -TypeName int
        #$hr = [HstiTest3]::QueryHSTIdetails([ref] $overallError, $null, [ref] $providerErrorDupleCount, $null, [ref] $blobByteSize)

        [byte[]]$blob = New-Object -TypeName byte[] -ArgumentList $blobByteSize
        #[HstiTest3+HstiProviderErrorDuple[]]$providerErrors = New-Object -TypeName HstiTest3+HstiProviderErrorDuple[] -ArgumentList $providerErrorDupleCount 
        #$hr = [HstiTest3]::QueryHSTIdetails([ref] $overallError, $providerErrors, [ref] $providerErrorDupleCount, $blob, [ref] $blobByteSize)
        $string = $null
        $blob | ForEach-Object -Process {
          $string = ("{0} {1}.ToString('X2')," -f $string, $_)
        }

        $hstiStatus = New-Object -TypeName bool
        #$hr = [HstiTest3]::QueryHSTI([ref] $hstiStatus)

        Log-AndConsole -message ('HSTI Duple Count: {0}' -f $providerErrorDupleCount)
        Log-AndConsole -message ('HSTI Blob size: {0}' -f $blobByteSize)
        Log-AndConsole -message ('String: {0}' -f $string)
        Log-AndConsole -message ('HSTIStatus: {0}' -f $hstiStatus)
        if(($blobByteSize -gt 512) -and ($providerErrorDupleCount -gt 0) -and $hstiStatus)
        {
          Log-AndConsoleSuccess -message 'HSTI validation successful'
        }
        elseif(($providerErrorDupleCount -eq 0) -or ($blobByteSize -le 512))
        {
          Log-AndConsoleWarning -message 'HSTI is absent'
          $null = $DGVerifyWarn.AppendLine('HSTI is absent')
        }
        else
        {
          $ErrorMessage = 'HSTI validation failed'
          if($HLK)
          {
            Log-AndConsoleError -message $ErrorMessage
            $null = $DGVerifyCrit.AppendLine($ErrorMessage)
          }
          else 
          {
            Log-AndConsoleWarning -message $ErrorMessage
            $null = $DGVerifyWarn.AppendLine('HSTI is absent')
          }
        }
      }
      catch 
      {
        Log-AndConsoleError -message $_.Exception.Message 
        Log-AndConsoleError -message 'Instantiate-HSTI failed'
      }
    }

    Function Check-DeviceGuard 
    <#bookmark NewFunction #>
    {
      [cmdletbinding(DefaultParameterSetName = 'Item')]
      param
      (
        [Parameter(ParameterSetName = 'Running')]
        [Switch]$CheckDGRunning,
        [Parameter(ParameterSetName = 'Features')]
        [Switch]$CheckDGFeatures,
        [Parameter(Mandatory,HelpMessage = 'Value to test against', Position = 0)]
        [int]$ItemValue
      )
    
      if($CheckDGRunning)
      {
        $DgItem = 'SecurityServicesRunning'
      }
      if($CheckDGFeatures)
      {
        $DgItem = 'AvailableSecurityProperties'
      }

      $DGObj = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

      for($i = 0; $i -lt $DGObj.$DgItem.length; $i++)
      {
        if($DGObj.$DgItem[$i] -eq $ItemValue)
        {
          return 1
        }
      }
      return 0
    }
  
    function Write-ConfigCIDetails
    {
      param
      (
        [Parameter(Mandatory)][Object]$_ConfigCIState
      )
      $_ConfigCIRunning = 'Config-CI is enabled and running.'
      $_ConfigCIDisabled = 'Config-CI is not running.'
      $_ConfigCIMode = 'Not Enabled'
      switch ($_ConfigCIState)
      {
        0 
        {
          $_ConfigCIMode = 'Not Enabled'
        }
        1 
        {
          $_ConfigCIMode = 'Audit mode'
        }
        2 
        {
          $_ConfigCIMode = 'Enforced mode'
        }
        default 
        {
          $_ConfigCIMode = 'Not Enabled'
        }
      }

      if($_ConfigCIState -ge 1)
      {
        Log-AndConsoleSuccess -message ('{0} ({1})' -f $_ConfigCIRunning, $_ConfigCIMode)
      }
      else
      {
        Log-AndConsoleWarning -message ('{0} ({1})' -f $_ConfigCIDisabled, $_ConfigCIMode)
      }
    }

    function Show-HVCIDetails
    {
      param
      (
        [Parameter(Mandatory)][Object]$_HVCIState
      )
      $_HvciRunning = 'HVCI is enabled and running.'
      $_HvciDisabled = 'HVCI is not running.'

      if($_HVCIState)
      {
        Log-AndConsoleSuccess -message $_HvciRunning
      }
      else
      {
        Log-AndConsoleWarning -message $_HvciDisabled
      }
    }

    function Show-CGDetails
    {
      param
      (
        [Parameter(Mandatory)][Object]$_CGState
      )
      $_CGRunning = 'Credential-Guard is enabled and running.'
      $_CGDisabled = 'Credential-Guard is not running.'

      if($_CGState)
      {
        Log-AndConsoleSuccess -message $_CGRunning
      }
      else
      {
        Log-AndConsoleWarning -message $_CGDisabled
      }
    }

    if(![IO.Directory]::Exists($OutputFilePath))
    {
      New-Item -ItemType directory -Path $OutputFilePath
    }

    function Test-IsRedstone
    {
      $_osVersion = [environment]::OSVersion.Version
      Write-Log -message $_osVersion
      #Check if build Major is Windows 10
      if($_osVersion.Major -lt 10)
      {
        return 0
      }
      #Check if the build is post Threshold2 (1511 release) => Redstone
      if($_osVersion.Build -gt 10586)
      {
        return 1
      }
      #default return False
      return 0
    }

    function Execute-CommandAndLog
    {
      param
      (
        [Parameter(Mandatory)][Object]$_cmd
      )
      try
      {
        Write-Log -message ('Executing: {0}' -f $_cmd)
        $CmdOutput = Invoke-Command -ScriptBlock $_cmd | Out-String
        Write-Log -message ('Output: {0}' -f $CmdOutput)
      }
      catch 
      {
        Write-Log -message ('Exception while exectuing {0}' -f $_cmd)
        Write-Log -message $_.Exception.Message 
      }
    }

    function Print-RebootWarning
    {
      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) -Verbose
      Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
    }

    function Auto-RebootHelper
    {
      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) -Verbose
      Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
      if($AutoReboot)
      {
        $FunctionMessage = $MyInvocation.MyCommand
        Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) -Verbose
        Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
        #Confirm-OSSKU -message 'PC will restart in 30 seconds'
        #Execute-CommandAndLog -_cmd 'shutdown /r /t 30'
      }
      else
      {
        Write-Warning -Message $MessageInfo.RebootRequired
        Write-Log -message  $MessageInfo.RebootRequired
      }
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

    function Write-HardwareReq
    {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory = $false)]$MsgDetails
      )
      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) -Verbose
      Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
      <#
          "##########################################################################
          OS and Hardware requirements for enabling Device Guard and Credential Guard
          1. OS SKUs: Available only on these OS Skus - Enterprise, Server, Education, Enterprise IoT, Pro, and Home
          2. Hardware: Recent hardware that supports virtualization extension with SLAT
          To learn more please visit: https://aka.ms/dgwhcr
          ########################################################################### `n"
      #>
    }

    function Confirm-DriverCompatability
    {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)]$MsgDetails
      )
      $MsgDetails = ('function : ' -f $MyInvocation.MyCommand)
      Write-Debug -Message $MsgDetails
      Write-Verbose -Message $MsgDetails

      $_HVCIState = Check-DeviceGuard -CheckDGRunning -ItemValue 2
      if($_HVCIState)
      {
        Log-AndConsoleWarning -message $MessageWarning.Warning_100
        Log-AndConsoleWarning -message $MessageWarning.Warning_101
      }
      $verifier_state = & "$env:windir\system32\verifier.exe" /query | Out-String
      if($verifier_state.ToString().Contains('No drivers are currently verified.'))
      {
        Log-AndConsole -message 'Enabling Driver verifier'
        & "$env:windir\system32\verifier.exe" /flags 0x02000000 /all /log.code_integrity

        Log-AndConsole -message 'Enabling Driver Verifier and Rebooting system'
        Write-Log -message $verifier_state 
        Log-AndConsole -message 'Please re-execute this script after reboot....'
        
        Write-Warning -Message $MessageInfo.RebootRequired
        <#
            if($AutoReboot)
            {
            #Confirm-OSSKU -message 'PC will restart in 30 seconds'
            #Execute-CommandAndLog -_cmd 'shutdown /r /t 30'
            }
            else
            {
            Log-AndConsole -message 'Please reboot manually and run the script again....'
            }
        #>
        exit
      }
      else
      {
        Log-AndConsole -message 'Driver verifier already enabled'
        Write-Log -message $verifier_state 
        Show-Summary -str ($verifier_state.Trim().ToLowerInvariant())
      }
    }
    function Test-IsDomainController # Replaced by test at to of script
    {
      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) -Verbose
      Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
      <#
          $_isDC = 0
          $CompConfig = Get-WmiObject -Class Win32_ComputerSystem
          foreach ($ObjItem in $CompConfig) 
          {
          $Role = $ObjItem.DomainRole
          Write-Log -message ('Role={0}' -f $Role)
          Switch ($Role) 
          {
          0 
          {
          Write-Log -message 'Standalone Workstation'
          }
          1 
          {
          Write-Log -message 'Member Workstation'
          }
          2 
          {
          Write-Log -message 'Standalone Server'
          }
          3 
          {
          Write-Log -message 'Member Server'
          }
          4 
          {
          Write-Log -message 'Backup Domain Controller'
          $_isDC = 1
          break
          }
          5 
          {
          Write-Log -message 'Primary Domain Controller'
          $_isDC = 1
          break
          }
          default 
          {
          Write-Log -message 'Unknown Domain Role'
          }
          }
          }
          return $_isDC
      #>
    }

    function Confirm-OSSKU  # Does  not seem to be used anywhere
    {
      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) -Verbose
      Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))
      <#
          $osname = $((Get-WmiObject -Class win32_operatingsystem).Name).ToLower()
          $_SKUSupported = 0
          Write-Log -message ('OSNAME:{0}' -f $osname)
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
          Log-AndConsoleError -message 'This PC is configured as a Domain Controller, Credential Guard is not supported on DC.'
          }
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "OSSKU" /t REG_DWORD /d 2 /f '
          }
          else 
          {
          Log-AndConsoleError -message 'This PC edition is Unsupported for Device Guard'
          $null = $DGVerifyCrit.AppendLine('OS SKU unsupported')
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "OSSKU" /t REG_DWORD /d 0 /f '
          }
      #>
    }
    function Check-OSArchitecture  # For Checks only.  serves no purpose
    {
      $FunctionMessage = $MyInvocation.MyCommand
      Write-Verbose -Message ('Entering function: {0}' -f $FunctionMessage) -Verbose
      Write-Warning -Message ('{0}: {1}' -f $FunctionMessage, $($MessageInfo.Deprecated))

      $OSArch = $(Get-WmiObject -Class win32_operatingsystem).OSArchitecture
      Write-Log -message $OSArch 
      if($OSArch.Contains('32-bit'))
      {
        Log-AndConsoleSuccess -message '64 bit arch.....'
      }
      elseif($OSArch.Contains('64-bit'))
      {
        Log-AndConsoleError -message '32 bit arch....' 
        $null = $DGVerifyCrit.AppendLine('32 Bit OS, OS Architecture failure..')
      }
      else
      {
        Log-AndConsoleError -message 'Unknown architecture'
        $null = $DGVerifyCrit.AppendLine('Unknown OS, OS Architecture failure..')
      }
    }


    function Check-SecureBootState
    {
      $_secureBoot = Confirm-SecureBootUEFI
      Write-Log -message $_secureBoot
      if($_secureBoot)
      {
        Log-AndConsoleSuccess -message 'Secure Boot is present'
        #Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "SecureBoot" /t REG_DWORD /d 2 /f '
        Write-Registry -registryPath $registryPath -Name 'SecureBoot' -value 2 -PropertyType REG_DWORD
      }
      else
      {
        Log-AndConsoleError -message 'Secure Boot is absent / not enabled.'
        Log-AndConsoleError -message 'If Secure Boot is supported on the system, enable Secure Boot in the BIOS and run the script again.'
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "SecureBoot" /t REG_DWORD /d 0 /f '
        $null = $DGVerifyCrit.AppendLine('Secure boot validation failed.')
      }
    }

    function Check-Virtualization
    {
      $_vmmExtension = $(Get-WmiObject -Class Win32_processor).VMMonitorModeExtensions
      $_vmFirmwareExtension = $(Get-WmiObject -Class Win32_processor).VirtualizationFirmwareEnabled
      $_vmHyperVPresent = (Get-CimInstance -ClassName Win32_ComputerSystem).HypervisorPresent
      Write-Log -message ('VMMonitorModeExtensions {0}' -f $_vmmExtension)
      Write-Log -message ('VirtualizationFirmwareEnabled {0}' -f $_vmFirmwareExtension)
      Write-Log -message ('HyperVisorPresent {0}' -f $_vmHyperVPresent)

      #success if either processor supports and enabled or if hyper-v is present
      if(($_vmmExtension -and $_vmFirmwareExtension) -or $_vmHyperVPresent )
      {
        Log-AndConsoleSuccess -message 'Virtualization firmware check passed'
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "Virtualization" /t REG_DWORD /d 2 /f '
      }
      else
      {
        Log-AndConsoleError -message 'Virtualization firmware check failed.'
        Log-AndConsoleError -message 'If Virtualization extensions are supported on the system, enable hardware virtualization (Intel Virtualization Technology, Intel VT-x, Virtualization Extensions, or similar) in the BIOS and run the script again.'
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "Virtualization" /t REG_DWORD /d 0 /f '
        $null = $DGVerifyCrit.AppendLine('Virtualization firmware check failed.')
      }
    }

    function Check-TPM
    {
      $TPMLockout = $(Get-Tpm).LockoutCount # Administrator privilege is required to execute this command.

      if($TPMLockout)
      {
        if($TPMLockout.ToString().Contains('Not Supported for TPM 1.2'))
        {
          if($HLK)
          {
            Log-AndConsoleSuccess -message 'TPM 1.2 is present.'
          }
          else
          {
            $WarningMsg = 'TPM 1.2 is Present. TPM 2.0 is Preferred.'
            Log-AndConsoleWarning -message $WarningMsg
            $null = $DGVerifyWarn.AppendLine($WarningMsg)
          }
        }
        else
        {
          Log-AndConsoleSuccess -message 'TPM 2.0 is present.'
        }
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "TPM" /t REG_DWORD /d 2 /f '
      }
      else
      {
        $WarningMsg = $MessageError.Error_100 
        if($HLK)
        {
          Log-AndConsoleError -message $WarningMsg
          $null = $DGVerifyCrit.AppendLine($WarningMsg)
        }
        else
        {
          Log-AndConsoleWarning -message $WarningMsg
          $null = $DGVerifyWarn.AppendLine($WarningMsg)
        }
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "TPM" /t REG_DWORD /d 0 /f '
      }
    }

    function Check-SecureMOR
    {
      $isSecureMOR = Check-DeviceGuard -CheckDGFeatures -ItemValue 4
      Write-Log -message ('isSecureMOR= {0} ' -f $isSecureMOR) 
      if($isSecureMOR -eq 1)
      {
        Log-AndConsoleSuccess -message $MessageInfo.SuccessMOR
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "SecureMOR" /t REG_DWORD /d 2 /f '
      }
      else
      {
        $WarningMsg = $MessageWarning.AbsentMOR
        if($HLK)
        {
          Log-AndConsoleError -message $WarningMsg
          $null = $DGVerifyCrit.AppendLine($WarningMsg)
        }
        else
        {
          Log-AndConsoleWarning -message $WarningMsg
          $null = $DGVerifyWarn.AppendLine($WarningMsg)
        }
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "SecureMOR" /t REG_DWORD /d 0 /f '
      }
    }

    function Check-NXProtection
    {
      $isNXProtected = Check-DGFeatures -_val (5)
      Write-Log -message ('isNXProtected= {0} ' -f $isNXProtected) 
      if($isNXProtected -eq 1)
      {
        Log-AndConsoleSuccess -message 'NX Protector is available'
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "UEFINX" /t REG_DWORD /d 2 /f '
      }
      else
      {
        Log-AndConsoleWarning -message 'NX Protector is absent'
        $null = $DGVerifyWarn.AppendLine('NX Protector is absent')
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "UEFINX" /t REG_DWORD /d 0 /f '
      }
    }

    function Check-SMMProtection
    {
      $isSMMMitigated = Check-DGFeatures -_val (6)
      Write-Log -message ('isSMMMitigated= {0} ' -f $isSMMMitigated) 
      if($isSMMMitigated -eq 1)
      {
        Log-AndConsoleSuccess -message 'SMM Mitigation is available'
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "SMMProtections" /t REG_DWORD /d 2 /f '
      }
      else
      {
        Log-AndConsoleWarning -message 'SMM Mitigation is absent'
        $null = $DGVerifyWarn.AppendLine('SMM Mitigation is absent')
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "SMMProtections" /t REG_DWORD /d 0 /f '
      }
    }

    function Check-HSTI
    {
      Log-AndConsole -message 'Copying HSTITest.dll'
      try 
      {
        $HSTITest_Decoded = [Convert]::FromBase64String($HSTITest_Encoded)
        [IO.File]::WriteAllBytes("$env:windir\System32\hstitest.dll",$HSTITest_Decoded)
      }
      catch 
      {
        Log-AndConsole -message $_.Exception.Message 
        Log-AndConsole -message 'Copying and loading HSTITest.dll failed'
      }

      Instantiate-Kernel32
      Instantiate-HSTI
    }

    function Write-ToolVersion
    {
      Write-Verbose -Message 'Entering function: Write-ToolVersion '

      # Log-AndConsole -message '###########################################################################'
      # Log-AndConsole -message "Readiness Tool Version 3.4 Release. `nTool to check if your device is capable to run Device Guard and Credential Guard."
      # Log-AndConsole -message '###########################################################################'
    }

  } # End BEGIN section


  ######################################################################################################################################
  ######################################################################################################################################
  ######################################################################################################################################
  ######################################################################################################################################


  PROCESS
  {  
    # Write-ToolVersion

    # Test Virtual System
    $isRunningOnVM = (Get-WmiObject -Class win32_computersystem).model
    if($isRunningOnVM.Contains('Virtual'))
    {
      Log-AndConsoleWarning -message 'Running on a Virtual Machine. DG/CG is supported only if both guest VM and host machine are running with Windows 10, version 1703 or later with English localization.'
    }
    # Test Virtual System
    

    <# Check the DG status if enabled or disabled, meaning if the device is ready or not #>
    if($Ready)
    {
      # Write-HardwareReq

      $DGRunning = $(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
      $_ConfigCIState = $(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).CodeIntegrityPolicyEnforcementStatus
      Write-Log -message ('Current DGRunning = {0}, ConfigCI= {1}' -f $DGRunning, $_ConfigCIState)
      $_HVCIState = Check-DeviceGuard -CheckDGRunning -ItemValue 2
      $_CGState = Check-DeviceGuard -CheckDGRunning -ItemValue 1

      if($HVCI)
      {
        Write-Log -message ('_HVCIState: {0}' -f $_HVCIState)
        Show-HVCIDetails -_HVCIState $_HVCIState
      }
      elseif($CG)
      {
        Write-Log -message ('_CGState: {0}' -f $_CGState)
        Show-CGDetails -_CGState $_CGState
 
        if($_CGState)
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "CG_Running" /t REG_DWORD /d 1 /f'
        }
        else
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "CG_Running" /t REG_DWORD /d 0 /f'
        }
      }
      elseif($DG)
      {
        Write-Log -message ('_HVCIState: {0}, _ConfigCIState: {1}' -f $_HVCIState, $_ConfigCIState) 

        Show-HVCIDetails -_HVCIState $_HVCIState
        # Write-ConfigCIDetails -_ConfigCIState $_ConfigCIState 

        if($_ConfigCIState -and $_HVCIState)
        {
          Log-AndConsoleSuccess -message 'HVCI, and Config-CI are enabled and running.'
 
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "DG_Running" /t REG_DWORD /d 1 /f'
        }
        else
        {
          Log-AndConsoleWarning -message 'Not all services are running.'
 
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "DG_Running" /t REG_DWORD /d 0 /f'
        }
      }
      else 
      {
        Write-Log -message ('_CGState: {0}, _HVCIState: {1}, _ConfigCIState: {2}' -f $_CGState, $_HVCIState, $_ConfigCIState) 
 
        Show-CGDetails -_CGState $_CGState
        Show-HVCIDetails -_HVCIState $_HVCIState
        # Write-ConfigCIDetails -_ConfigCIState $_ConfigCIState

        if(($DGRunning.Length -ge 2) -and ($_CGState) -and ($_HVCIState) -and ($_ConfigCIState -ge 1))
        {
          Log-AndConsoleSuccess -message 'HVCI, Credential-Guard, and Config-CI are enabled and running.'
        }
        else
        {
          Log-AndConsoleWarning -message 'Not all services are running.'
        }
      }
    }

    <# Enable and Disable #>
    if($Enable)
    {
      Write-HardwareReq

      Log-AndConsole -message 'Enabling Device Guard and Credential Guard'
      Log-AndConsole -message 'Setting RegKeys to enable DG/CG'

      Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f'
      #Only SecureBoot is required as part of RequirePlatformSecurityFeatures
      Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 1 /f'

      $_isRedstone = Test-IsRedstone
      if(!$_isRedstone)
      {
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Unlocked" /t REG_DWORD /d 1 /f'
      }
      else
      {
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 0 /f'
      }

      if(!$HVCI -and !$DG)
      {
        # value is 2 for both Th2 and RS1
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d 2 /f'
      }
      if(!$CG)
      {
        if(!$_isRedstone)
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d 1 /f'
        }
        else 
        {
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f'
          Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d 0 /f'
        }
      }

      try
      {
        if(!$HVCI -and !$CG)
        {
          if(!$SIPolicyPath) 
          { 
            Write-Log -message 'Writing Decoded SIPolicy.p7b'
            $SIPolicy_Decoded = [Convert]::FromBase64String($SIPolicy_Encoded)
            [IO.File]::WriteAllBytes("$env:windir\System32\CodeIntegrity\SIPolicy.p7b",$SIPolicy_Decoded)
          }
          else
          {
            Log-AndConsole -message 'Copying user provided SIpolicy.p7b'
            $CmdOutput = Copy-Item -Path $SIPolicyPath -Destination "$env:windir\System32\CodeIntegrity\SIPolicy.p7b" | Out-String
            Write-Log -message $CmdOutput
          }
        }
      }
      catch
      {
        Log-AndConsole -message 'Writing SIPolicy.p7b file failed'
      }

      Log-AndConsole -message 'Enabling Hyper-V and IOMMU'
      $_isRedstone = Test-IsRedstone
      if(!$_isRedstone)
      {
        Log-AndConsole -message 'OS Not Redstone, enabling IsolatedUserMode separately'
        #Enable/Disable IOMMU seperately
        Execute-CommandAndLog -_cmd 'DISM.EXE /Online /Enable-Feature:IsolatedUserMode /NoRestart'
      }
      $CmdOutput = & "$env:windir\system32\dism.exe" /Online /Enable-Feature:Microsoft-Hyper-V-Hypervisor /All /NoRestart | Out-String
      if(!$CmdOutput.Contains('The operation completed successfully.'))
      {
        $CmdOutput = & "$env:windir\system32\dism.exe" /Online /Enable-Feature:Microsoft-Hyper-V-Online /All /NoRestart | Out-String
      }

      Write-Log -message $CmdOutput
      if($CmdOutput.Contains('The operation completed successfully.'))
      {
        Log-AndConsoleSuccess -message 'Enabling Hyper-V and IOMMU successful'
        #Reg key for HLK validation of DISM.EXE step
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "HyperVEnabled" /t REG_DWORD /d 1 /f'
      }
      else
      {
        Log-AndConsoleWarning -message 'Enabling Hyper-V failed please check the log file'
        #Reg key for HLK validation of DISM.EXE step
        Execute-CommandAndLog -_cmd 'REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Capabilities\" /v "HyperVEnabled" /t REG_DWORD /d 0 /f'
      }
      Auto-RebootHelper
    }




    <# Is machine Device Guard / Cred Guard Capable and Verify #>
    if($Capable)
    {
      Write-HardwareReq

      Log-AndConsole -message 'Checking if the device is DG/CG Capable'

      $_isRedstone = Test-IsRedstone
      if(!$_isRedstone)
      {
        Log-AndConsoleWarning -message 'Capable is currently fully supported in Redstone only..'
      }
      $null = 1
      function Write-ProgressHelper 
      {
        param(
          [Parameter(Mandatory)][int]$StepNumber,
          [Parameter(Mandatory)][string]$message,
          [Parameter(Mandatory)][int]$Steps
        )
    
        Write-Progress -Activity 'Title' -Status $message -PercentComplete (($StepNumber / $Steps) * 100)
      }
      

      $CheckList = @{
        1 = @{
          Check   = 'Check-DriverCompat'
          Message = 'Driver Compat'
        }
        2 = @{
          Check   = 'Check-SecureBootState '
          Message = 'Secure boot present'
        }
        3 = @{
          Check   = 'Check-HSTI'
          Message = 'MS UEFI HSTI tests'
        }
        4 = @{
          Check   = 'Check-OSArchitecture'
          Message = 'OS Architecture'
        }
        5 = @{
          Check   = 'Check-OSSKU'
          Message = 'Supported OS SKU'
        }
        6 = @{
          Check   = 'Check-Virtualization'
          Message = 'Virtualization Firmware'
        }
        7 = @{
          Check   = 'Check-TPM'
          Message = 'TPM version'
        }
        8 = @{
          Check   = 'Check-SecureMOR'
          Message = 'Secure MOR'
        }
        9 = @{
          Check   = 'Check-NXProtection'
          Message = 'NX Protector'
        }
        10 = @{
          Check   = 'Check-SMMProtection'
          Message = 'SMM Mitigation'
        }
        11 = @{
          Check   = 'List-Summary'
          Message = 'Summary'
        }
      }

      [int]$Steps = ($CheckList.Count)

      for($stepCounter = 01;$stepCounter -le $Steps;$stepCounter++)
      {
        Write-ProgressHelper -Message ($CheckList.$stepCounter.Message) -StepNumber ($stepCounter) -Steps $Steps
        Write-Host $($CheckList.$stepCounter.check)
        . ($CheckList.$stepCounter.check)
      }
 
    
    
      Log-AndConsole -message 'To learn more about required hardware and software please visit: https://aka.ms/dgwhcr'
    }
  } #End PROCESS section

  END
  {}
}

######################################################################################################################################

######################################################################################################################################

######################################################################################################################################

######################################################################################################################################

######################################################################################################################################
 

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

      .PARAMETER SIPolicyOutputFilePath
      If you have a custom SIPolicy.p7b then use the -OutputFilePath parameter else the hardcoded default policy is used

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
      Set-DgReadiness -Enable -OutputFilePath <full OutputFilePath to the SIPolicy.p7b> 
      If you have a custom SIPolicy.p7b then use the -OutputFilePath parameter

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




