#Requires -Version 5.1
<#
.SYNOPSIS
    ADTierGuard - Enterprise AD Tier Isolation via Kerberos Authentication Policies
    
.DESCRIPTION
    ADTierGuard is a 100% Pure ADSI implementation for Active Directory Tier 0/1 isolation.
    NO ActiveDirectory or GroupPolicy PowerShell modules required.
    
    Features:
    - Forest-wide deployment with single command
    - Kerberos Authentication Policies for privileged account isolation
    - Automatic Kerberos Armoring (FAST) configuration
    - GMSA-based scheduled tasks for ongoing sync
    - Protected Users group management
    - Privileged group cleanup
    
    Technical Implementation:
    - P/Invoke SDDL conversion for conditional ACEs (Member_of, Member_of_any)
    - Custom Registry.pol binary writer for GPO settings
    - Pure ADSI (System.DirectoryServices) for all AD operations
    - Parallel processing via RunspacePool
    
.PARAMETER Scope
    Tier0, Tier1, or All (default: All)
    
.EXAMPLE
    .\Install-ADTierGuard.ps1 -Scope All
    Deploys full Tier 0 and Tier 1 isolation to all domains in the forest.
    
.NOTES
    Project:  ADTierGuard
    Author:   ADTierGuard Contributors  
    License:  MIT
    Requires: Enterprise Admin privileges, Windows Server 2012 R2+ Forest Functional Level
    
.LINK
    https://github.com/yourorg/ADTierGuard
#>

[CmdletBinding()]
param(
    [ValidateSet('Tier0','Tier1','All')][string]$Scope = 'All',
    [switch]$SkipGMSA,
    [switch]$SkipGPO,
    [switch]$SkipArmoring
)

$ErrorActionPreference = 'Stop'
$script:Version = '5.0.0'
$script:ScriptPath = $PSScriptRoot
$script:LogFile = Join-Path $env:TEMP "ADTierGuard_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

#region P/Invoke for SDDL Conversion
# ConvertStringSecurityDescriptorToSecurityDescriptor handles conditional ACEs (XA/XD types)
# including Member_of{SID(...)} expressions that .NET's RawSecurityDescriptor cannot parse

$sddlConverterCode = @'
using System;
using System.Runtime.InteropServices;

public class SddlConverter
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string StringSecurityDescriptor,
        uint StringSDRevision,
        out IntPtr SecurityDescriptor,
        out uint SecurityDescriptorSize);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static byte[] ConvertSddlToBinary(string sddl)
    {
        IntPtr pSD = IntPtr.Zero;
        uint size = 0;
        
        try
        {
            // SDDL_REVISION_1 = 1
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out pSD, out size))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Exception("SDDL conversion failed. Win32 error: " + error + ". SDDL: " + sddl);
            }
            
            byte[] sdBytes = new byte[size];
            Marshal.Copy(pSD, sdBytes, 0, (int)size);
            return sdBytes;
        }
        finally
        {
            if (pSD != IntPtr.Zero)
                LocalFree(pSD);
        }
    }
}
'@

try {
    Add-Type -TypeDefinition $sddlConverterCode -ErrorAction Stop
} catch {
    if ($_.Exception.Message -notlike "*already exists*") {
        throw "Failed to load SDDL converter: $_"
    }
}

#endregion

#region Logging

function Write-Log {
    param([string]$Message, [ValidateSet('Info','Success','Warning','Error','Debug')][string]$Level = 'Info', [switch]$NoConsole)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logLine = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $logLine -ErrorAction SilentlyContinue
    if (-not $NoConsole) {
        $colors = @{Info='White';Success='Green';Warning='Yellow';Error='Red';Debug='Gray'}
        Write-Host $logLine -ForegroundColor $colors[$Level]
    }
}

#endregion

#region Registry.pol Writer
# Registry.pol format (MS-GPREG):
# Header: PReg signature (0x67655250) + Version (1)
# Body: [key;value;type;size;data] entries in UTF-16LE

function Write-RegistryPol {
    param([string]$Path, [hashtable[]]$Entries)
    
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    
    # Header: "PReg" + Version 1
    $bw.Write([uint32]0x67655250)
    $bw.Write([uint32]0x00000001)
    
    $encoding = [System.Text.Encoding]::Unicode
    
    foreach ($entry in $Entries) {
        # [
        $bw.Write([byte[]]@(0x5B, 0x00))
        
        # Key (UTF-16LE null-terminated)
        $bw.Write($encoding.GetBytes($entry.Key))
        $bw.Write([byte[]]@(0x00, 0x00))
        
        # ;
        $bw.Write([byte[]]@(0x3B, 0x00))
        
        # Value name (UTF-16LE null-terminated)
        $bw.Write($encoding.GetBytes($entry.ValueName))
        $bw.Write([byte[]]@(0x00, 0x00))
        
        # ;
        $bw.Write([byte[]]@(0x3B, 0x00))
        
        # Type (DWORD = 4)
        $bw.Write([uint32]$entry.Type)
        
        # ;
        $bw.Write([byte[]]@(0x3B, 0x00))
        
        # Size (4 bytes for DWORD)
        $bw.Write([uint32]$entry.Size)
        
        # ;
        $bw.Write([byte[]]@(0x3B, 0x00))
        
        # Data
        $bw.Write([uint32]$entry.Data)
        
        # ]
        $bw.Write([byte[]]@(0x5D, 0x00))
    }
    
    $bw.Flush()
    $bytes = $ms.ToArray()
    $bw.Close()
    $ms.Close()
    
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

#endregion

#region ADSI Functions

function Get-ADSIForestInfo {
    $results = @()
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $configNC = $rootDSE.configurationNamingContext.Value
        $currentDomainDN = $rootDSE.defaultNamingContext.Value
        
        $partitions = [ADSI]"LDAP://CN=Partitions,$configNC"
        $forestRootDN = ($partitions.Children | Where-Object { $_.nTMixedDomain -ne $null -and $_.systemFlags.Value -band 0x2 } | Select-Object -First 1).nCName.Value
        if (-not $forestRootDN) { $forestRootDN = $currentDomainDN }
        $forestRootFQDN = ($forestRootDN -replace 'DC=','' -replace ',','.').ToLower()
        
        $domainPartitions = $partitions.Children | Where-Object { $_.objectClass -contains 'crossRef' -and $_.systemFlags.Value -band 0x3 -and $_.nCName -like "DC=*" }
        
        foreach ($partition in $domainPartitions) {
            $domainDN = $partition.nCName.Value
            $domainFQDN = ($domainDN -replace 'DC=','' -replace ',','.').ToLower()
            
            try {
                $dcContainer = [ADSI]"LDAP://OU=Domain Controllers,$domainDN"
                if ($dcContainer.distinguishedName) {
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher($dcContainer)
                    $searcher.Filter = "(objectClass=computer)"
                    $searcher.PropertiesToLoad.AddRange(@('dNSHostName')) | Out-Null
                    
                    foreach ($dc in $searcher.FindAll()) {
                        $dcFQDN = $dc.Properties['dNSHostName'][0]
                        $online = $false; $isPDC = $false
                        
                        try {
                            $testRootDSE = [ADSI]"LDAP://$dcFQDN/RootDSE"
                            $online = ($null -ne $testRootDSE.dnsHostName)
                            if ($online) {
                                $domainEntry = [ADSI]"LDAP://$dcFQDN/$domainDN"
                                $fsmo = $domainEntry.fSMORoleOwner.Value
                                if ($fsmo) { $isPDC = ($dcFQDN -like "$(($fsmo -split ',')[1] -replace 'CN=','')*") }
                            }
                        } catch {}
                        
                        $results += [PSCustomObject]@{
                            Domain = $domainFQDN; DomainDN = $domainDN; FQDN = $dcFQDN
                            Online = $online; IsPDC = $isPDC
                            ForestRootFQDN = $forestRootFQDN; ForestRootDN = $forestRootDN; ConfigNC = $configNC
                        }
                    }
                }
            } catch {}
        }
    } catch { Write-Log "Forest discovery failed: $_" -Level Error }
    return $results
}

function Test-ADSIPath {
    param([string]$Path, [string]$Server)
    try { $entry = [ADSI]"LDAP://$Server/$Path"; return ($null -ne $entry.distinguishedName) } catch { return $false }
}

function New-ADSIOrganizationalUnit {
    param([string]$RelativePath, [string]$DomainDN, [string]$Server)
    $parts = $RelativePath -split '(?<!\\),' | Where-Object { $_ -match '^OU=' }
    [array]::Reverse($parts)
    $currentPath = $DomainDN
    foreach ($part in $parts) {
        $testPath = "$part,$currentPath"
        if (-not (Test-ADSIPath -Path $testPath -Server $Server)) {
            try {
                $parent = [ADSI]"LDAP://$Server/$currentPath"
                $newOU = $parent.Create('organizationalUnit', $part)
                $newOU.Put('description', 'Created by ADTierGuard') | Out-Null
                $newOU.SetInfo() | Out-Null
                Write-Log "    Created: $testPath" -Level Success
            } catch { Write-Log "    Failed: $testPath - $_" -Level Error; return }
        }
        $currentPath = $testPath
    }
}

function New-ADSIUniversalGroup {
    param([string]$Name, [string]$Description, [string]$Container, [string]$Server)
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Server/$Container")
    $searcher.Filter = "(&(objectClass=group)(sAMAccountName=$Name))"
    $searcher.PropertiesToLoad.Add('objectSid') | Out-Null
    $existing = $searcher.FindOne()
    
    if ($existing) {
        $sid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$existing.Properties['objectSid'][0], 0)).Value.Trim()
        Write-Log "    Group exists: $Name (SID: $sid)" -Level Info
        return $sid
    }
    
    try {
        $parent = [ADSI]"LDAP://$Server/$Container"
        $group = $parent.Create('group', "CN=$Name")
        $group.Put('sAMAccountName', $Name) | Out-Null
        # Universal Security Group: -2147483640 = 0x80000008
        $group.Put('groupType', -2147483640) | Out-Null
        $group.Put('description', $Description) | Out-Null
        $group.SetInfo() | Out-Null
        
        $groupEntry = [ADSI]"LDAP://$Server/$($group.distinguishedName.Value)"
        $groupEntry.Put('adminCount', 1) | Out-Null
        $groupEntry.SetInfo() | Out-Null
        $groupEntry.RefreshCache(@('objectSid')) | Out-Null
        $sid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$groupEntry.objectSid.Value, 0)).Value.Trim()
        Write-Log "    Created: $Name (SID: $sid)" -Level Success
        return $sid
    } catch { Write-Log "    Failed: $Name - $_" -Level Error; return $null }
}

function New-ADSIAuthenticationPolicy {
    param([string]$Name, [string]$SDDL, [string]$Description, [string]$ConfigNC, [string]$Server)
    
    $container = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$ConfigNC"
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Server/$container")
    $searcher.Filter = "(&(objectClass=msDS-AuthNPolicy)(cn=$Name))"
    if ($searcher.FindOne()) { 
        Write-Log "    Policy exists: $Name" -Level Info
        return 
    }
    
    try {
        Write-Log "    Converting SDDL: $SDDL" -Level Debug -NoConsole
        $sdBytes = [SddlConverter]::ConvertSddlToBinary($SDDL)
        Write-Log "    Binary SD size: $($sdBytes.Length) bytes" -Level Debug -NoConsole
        
        $parent = [ADSI]"LDAP://$Server/$container"
        $policy = $parent.Create('msDS-AuthNPolicy', "CN=$Name")
        $policy.Put('msDS-AuthNPolicyEnforced', $true) | Out-Null
        $policy.Put('description', $Description) | Out-Null
        # msDS-UserAllowedToAuthenticateFrom is attributeSyntax 2.5.5.10 (octet string)
        $policy.Put('msDS-UserAllowedToAuthenticateFrom', $sdBytes) | Out-Null
        $policy.SetInfo() | Out-Null
        Write-Log "    Created policy: $Name with SDDL" -Level Success
    } catch {
        Write-Log "    FAILED policy: $Name - $_" -Level Error
        Write-Log "    SDDL was: $SDDL" -Level Error
    }
}

function New-ADSIAuthenticationSilo {
    param([string]$Name, [string]$PolicyName, [string]$Description, [string]$ConfigNC, [string]$Server)
    
    $policyContainer = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$ConfigNC"
    $siloContainer = "CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,$ConfigNC"
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Server/$siloContainer")
    $searcher.Filter = "(&(objectClass=msDS-AuthNPolicySilo)(cn=$Name))"
    if ($searcher.FindOne()) { Write-Log "    Silo exists: $Name" -Level Info; return }
    
    try {
        $parent = [ADSI]"LDAP://$Server/$siloContainer"
        $silo = $parent.Create('msDS-AuthNPolicySilo', "CN=$Name")
        $silo.Put('msDS-AuthNPolicySiloEnforced', $true) | Out-Null
        $silo.Put('msDS-UserAuthNPolicy', "CN=$PolicyName,$policyContainer") | Out-Null
        $silo.Put('msDS-ServiceAuthNPolicy', "CN=$PolicyName,$policyContainer") | Out-Null
        $silo.Put('msDS-ComputerAuthNPolicy', "CN=$PolicyName,$policyContainer") | Out-Null
        $silo.Put('description', $Description) | Out-Null
        $silo.SetInfo() | Out-Null
        Write-Log "    Created silo: $Name" -Level Success
    } catch { Write-Log "    Failed silo: $Name - $_" -Level Error }
}

function New-ADSIGMSA {
    param([string]$Name, [string]$DomainDN, [string]$DomainFQDN, [string]$Server)
    
    $container = "CN=Managed Service Accounts,$DomainDN"
    
    # Check for existing GMSA using multiple detection methods
    # Method 1: Search by CN (most reliable)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Server/$container")
    $searcher.Filter = "(&(objectClass=msDS-GroupManagedServiceAccount)(cn=$Name))"
    $existing = $searcher.FindOne()
    
    # Method 2: Direct LDAP bind test if search didn't find it
    if (-not $existing) {
        try {
            $directPath = [ADSI]"LDAP://$Server/CN=$Name,$container"
            if ($directPath.distinguishedName) {
                $existing = $true
                Write-Log "    GMSA exists (direct bind): $Name" -Level Info
                return
            }
        } catch {
            # Object doesn't exist, continue with creation
        }
    }
    
    if ($existing) {
        Write-Log "    GMSA exists: $Name" -Level Info
        return
    }
    
    try {
        # Get Domain Controllers group SID for password retrieval
        $dcSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Server/$DomainDN")
        $dcSearcher.Filter = "(&(objectClass=group)(sAMAccountName=Domain Controllers))"
        $dcSearcher.PropertiesToLoad.Add('objectSid') | Out-Null
        $dcResult = $dcSearcher.FindOne()
        if (-not $dcResult) {
            Write-Log "    Failed GMSA: $Name - Domain Controllers group not found" -Level Error
            return
        }
        $dcSid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$dcResult.Properties['objectSid'][0], 0)).Value.Trim()
        
        $sddl = "O:SYD:(A;;RPLCLORC;;;$dcSid)"
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorSddlForm($sddl)
        $sdBytes = $sd.GetSecurityDescriptorBinaryForm()
        
        $parent = [ADSI]"LDAP://$Server/$container"
        $gmsa = $parent.Create('msDS-GroupManagedServiceAccount', "CN=$Name")
        $gmsa.Put('sAMAccountName', "$Name`$") | Out-Null
        $gmsa.Put('dNSHostName', "$Name.$DomainFQDN") | Out-Null
        $gmsa.Put('msDS-ManagedPasswordInterval', 30) | Out-Null
        $gmsa.SetInfo() | Out-Null
        
        $gmsaEntry = [ADSI]"LDAP://$Server/$($gmsa.distinguishedName.Value)"
        $gmsaEntry.Put('msDS-SupportedEncryptionTypes', 24) | Out-Null
        $gmsaEntry.Put('msDS-GroupMSAMembership', $sdBytes) | Out-Null
        $gmsaEntry.Put('description', 'ADTierGuard service account') | Out-Null
        $gmsaEntry.SetInfo() | Out-Null
        Write-Log "    Created GMSA: $Name" -Level Success
    } catch {
        # Check if it's an "already exists" error - this can happen with replication lag
        if ($_.Exception.Message -like "*already exists*") {
            Write-Log "    GMSA exists (detected via error): $Name" -Level Info
        } else {
            Write-Log "    Failed GMSA: $Name - $_" -Level Error
        }
    }
}

function Deploy-ScriptsToDomain {
    param([string]$DomainFQDN, [string]$ConfigJson)
    $sysvolPath = "\\$DomainFQDN\SYSVOL\$DomainFQDN\scripts"
    try {
        if (-not (Test-Path $sysvolPath)) { Write-Log "    SYSVOL not accessible: $sysvolPath" -Level Warning; return }
        $scriptsDir = Join-Path $script:ScriptPath 'Scripts'
        if (Test-Path $scriptsDir) { Get-ChildItem $scriptsDir -Filter '*.ps1' | ForEach-Object { Copy-Item $_.FullName $sysvolPath -Force } }
        $coreSrc = Join-Path $script:ScriptPath 'Core'
        $coreDst = Join-Path $sysvolPath 'Core'
        if (Test-Path $coreSrc) {
            if (-not (Test-Path $coreDst)) { New-Item $coreDst -ItemType Directory -Force | Out-Null }
            Copy-Item "$coreSrc\*" $coreDst -Recurse -Force
        }
        $ConfigJson | Out-File (Join-Path $sysvolPath 'ADTierGuard.config.json') -Encoding UTF8
        Write-Log "    Scripts deployed to $DomainFQDN" -Level Success
    } catch { Write-Log "    Scripts failed for $DomainFQDN : $_" -Level Error }
}

function Deploy-GPOToDomain {
    param([string]$DomainFQDN, [string]$DomainDN, [string]$Server, [string]$GPOName, [string]$SysvolScriptPath, [string]$GMSAName)
    
    try {
        $machineExtensions = "[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
        $gpoGuid = [guid]::NewGuid().ToString('B').ToUpper()
        $gpoPoliciesContainer = "CN=Policies,CN=System,$DomainDN"
        
        $gpoSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Server/$gpoPoliciesContainer")
        $gpoSearcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=$GPOName))"
        $existing = $gpoSearcher.FindOne()
        
        if ($existing) {
            $gpoGuid = $existing.Properties['name'][0]
            $gpoEntry = $existing.GetDirectoryEntry()
            $currentVer = [int]$gpoEntry.Properties['versionNumber'].Value
            $gpoEntry.Put('versionNumber', $currentVer + 1) | Out-Null
            $gpoEntry.Put('gPCMachineExtensionNames', $machineExtensions) | Out-Null
            $gpoEntry.SetInfo() | Out-Null
            Write-Log "    GPO updated: $DomainFQDN" -Level Info
        } else {
            $parent = [ADSI]"LDAP://$Server/$gpoPoliciesContainer"
            $gpo = $parent.Create('groupPolicyContainer', "CN=$gpoGuid")
            $gpo.Put('displayName', $GPOName) | Out-Null
            $gpo.Put('gPCFileSysPath', "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\$gpoGuid") | Out-Null
            $gpo.Put('gPCFunctionalityVersion', 2) | Out-Null
            $gpo.Put('flags', 0) | Out-Null
            $gpo.Put('versionNumber', 1) | Out-Null
            $gpo.Put('gPCMachineExtensionNames', $machineExtensions) | Out-Null
            $gpo.SetInfo() | Out-Null
            $gpo.Create('container', 'CN=Machine').SetInfo() | Out-Null
            $gpo.Create('container', 'CN=User').SetInfo() | Out-Null
            Write-Log "    GPO created: $DomainFQDN" -Level Success
        }
        
        # Create SYSVOL structure
        $gpoPath = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\$gpoGuid"
        @("$gpoPath\Machine\Preferences\ScheduledTasks") | ForEach-Object {
            if (-not (Test-Path $_)) { New-Item $_ -ItemType Directory -Force | Out-Null }
        }
        Set-Content "$gpoPath\GPT.INI" -Value "[General]`r`nVersion=1" -Encoding ASCII
        
        # Scheduled tasks XML
        $templatePath = Join-Path $script:ScriptPath "GPO\ScheduledTasks.xml"
        if (Test-Path $templatePath) {
            $taskXml = (Get-Content $templatePath -Raw).Replace('#ScriptPath', $SysvolScriptPath).Replace('#GMSAName', $GMSAName)
            [System.IO.File]::WriteAllText("$gpoPath\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml", $taskXml, [System.Text.UTF8Encoding]::new($true))
        }
        
        # Link to DC OU
        $dcEntry = [ADSI]"LDAP://$Server/OU=Domain Controllers,$DomainDN"
        if (-not $dcEntry.gpLink -or $dcEntry.gpLink -notlike "*$gpoGuid*") {
            $link = "[LDAP://CN=$gpoGuid,$gpoPoliciesContainer;0]"
            $dcEntry.Put('gpLink', $(if ($dcEntry.gpLink) { $link + $dcEntry.gpLink } else { $link })) | Out-Null
            $dcEntry.SetInfo() | Out-Null
            Write-Log "    GPO linked to DC OU" -Level Success
        }
    } catch { Write-Log "    GPO failed: $DomainFQDN - $_" -Level Error }
}

function Enable-KerberosArmoring {
    param([string]$DomainFQDN, [string]$DomainDN, [string]$Server)
    
    # Registry paths per MS documentation:
    # KDC (DC side): SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters
    #   EnableCbacAndArmor = 1 (enable)
    #   CbacAndArmorLevel = 2 (Supported mode)
    # Kerberos (client side): SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters
    #   EnableCbacAndArmor = 1 (enable)
    
    try {
        # Default Domain Controllers Policy - KDC armoring support
        $dcPolicySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Server/CN=Policies,CN=System,$DomainDN")
        $dcPolicySearcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=Default Domain Controllers Policy))"
        $dcPolicy = $dcPolicySearcher.FindOne()
        
        if ($dcPolicy) {
            $dcPolicyGuid = $dcPolicy.Properties['name'][0]
            $regPolDir = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\$dcPolicyGuid\Machine"
            if (-not (Test-Path $regPolDir)) { New-Item $regPolDir -ItemType Directory -Force | Out-Null }
            $regPolPath = "$regPolDir\Registry.pol"
            
            Write-RegistryPol -Path $regPolPath -Entries @(
                @{ Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"; ValueName = "EnableCbacAndArmor"; Type = 4; Size = 4; Data = 1 }
                @{ Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"; ValueName = "CbacAndArmorLevel"; Type = 4; Size = 4; Data = 2 }
            )
            
            # Update GPT.INI version
            $gptPath = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\$dcPolicyGuid\GPT.INI"
            if (Test-Path $gptPath) {
                $content = Get-Content $gptPath -Raw
                if ($content -match 'Version=(\d+)') {
                    $newVer = [int]$Matches[1] + 1
                    $content = $content -replace 'Version=\d+', "Version=$newVer"
                    Set-Content $gptPath -Value $content -Encoding ASCII
                }
            }
            
            # Update AD version
            $dcPolicyEntry = $dcPolicy.GetDirectoryEntry()
            $dcPolicyEntry.Put('versionNumber', [int]$dcPolicy.Properties['versionNumber'][0] + 1) | Out-Null
            $dcPolicyEntry.SetInfo() | Out-Null
            Write-Log "    KDC Armoring enabled: $DomainFQDN (Default DC Policy)" -Level Success
        } else {
            Write-Log "    Default DC Policy not found in $DomainFQDN" -Level Warning
        }
        
        # Default Domain Policy - Client armoring support
        $domainPolicySearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$Server/CN=Policies,CN=System,$DomainDN")
        $domainPolicySearcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=Default Domain Policy))"
        $domainPolicy = $domainPolicySearcher.FindOne()
        
        if ($domainPolicy) {
            $domainPolicyGuid = $domainPolicy.Properties['name'][0]
            $regPolDir = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\$domainPolicyGuid\Machine"
            if (-not (Test-Path $regPolDir)) { New-Item $regPolDir -ItemType Directory -Force | Out-Null }
            $regPolPath = "$regPolDir\Registry.pol"
            
            Write-RegistryPol -Path $regPolPath -Entries @(
                @{ Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"; ValueName = "EnableCbacAndArmor"; Type = 4; Size = 4; Data = 1 }
            )
            
            $gptPath = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\$domainPolicyGuid\GPT.INI"
            if (Test-Path $gptPath) {
                $content = Get-Content $gptPath -Raw
                if ($content -match 'Version=(\d+)') {
                    $newVer = [int]$Matches[1] + 1
                    $content = $content -replace 'Version=\d+', "Version=$newVer"
                    Set-Content $gptPath -Value $content -Encoding ASCII
                }
            }
            
            $domainPolicyEntry = $domainPolicy.GetDirectoryEntry()
            $domainPolicyEntry.Put('versionNumber', [int]$domainPolicy.Properties['versionNumber'][0] + 1) | Out-Null
            $domainPolicyEntry.SetInfo() | Out-Null
            Write-Log "    Client Armoring enabled: $DomainFQDN (Default Domain Policy)" -Level Success
        } else {
            Write-Log "    Default Domain Policy not found in $DomainFQDN" -Level Warning
        }
    } catch { Write-Log "    Armoring failed: $DomainFQDN - $_" -Level Error }
}

#endregion

#region Main

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "       ADTierGuard v$script:Version - Pure ADSI Installation" -ForegroundColor Cyan  
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""

Write-Log "Log: $script:LogFile"

# Discover forest
Write-Log "Discovering forest..." -Level Info
$forestInfo = Get-ADSIForestInfo
if (-not $forestInfo) { Write-Log "Forest discovery failed" -Level Error; exit 1 }

$allDomains = @($forestInfo | Select-Object -ExpandProperty Domain -Unique)
$forestRootFQDN = $forestInfo[0].ForestRootFQDN
$forestRootDN = $forestInfo[0].ForestRootDN
$configNC = $forestInfo[0].ConfigNC
$pdcServer = ($forestInfo | Where-Object { $_.Domain -eq $forestRootFQDN -and ($_.IsPDC -or $_.Online) } | Select-Object -First 1).FQDN

Write-Log "Forest Root: $forestRootFQDN" -Level Info
Write-Log "PDC/Target DC: $pdcServer" -Level Info
Write-Log "Config NC: $configNC" -Level Info
Write-Log "Domains found: $($allDomains -join ', ')" -Level Info

$domainTable = @{}
foreach ($d in $allDomains) {
    $dc = $forestInfo | Where-Object { $_.Domain -eq $d -and $_.Online } | Select-Object -First 1
    if ($dc) { $domainTable[$d] = @{ DN = $dc.DomainDN; Server = $dc.FQDN } }
}

# Permission check
$isEA = [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object { $_.Value -like "*-519" }
if (-not $isEA) { Write-Log "Enterprise Admin required" -Level Error; exit 1 }
Write-Log "Enterprise Admin: Yes" -Level Success

# Configuration
$config = @{
    Tier0 = @{ PolicyName = "Tier0-RestrictedAuth"; SiloName = "Tier0-Silo"; GroupName = "Tier0-Computers" }
    Tier1 = @{ PolicyName = "Tier1-RestrictedAuth"; SiloName = "Tier1-Silo"; GroupName = "Tier1-Computers" }
    GMSA = @{ Name = "ADTierGuard-svc" }
    GPO = @{ Name = "ADTierGuard Tier Isolation" }
}

# Create OUs
Write-Log "Creating OUs..." -Level Info
$ouPaths = @("OU=ADTierGuard","OU=Tier 0,OU=ADTierGuard","OU=Users,OU=Tier 0,OU=ADTierGuard","OU=Service Accounts,OU=Tier 0,OU=ADTierGuard","OU=Computers,OU=Tier 0,OU=ADTierGuard","OU=Groups,OU=Tier 0,OU=ADTierGuard")
if ($Scope -in @('Tier1','All')) { $ouPaths += @("OU=Tier 1,OU=ADTierGuard","OU=Users,OU=Tier 1,OU=ADTierGuard","OU=Service Accounts,OU=Tier 1,OU=ADTierGuard","OU=Computers,OU=Tier 1,OU=ADTierGuard","OU=Groups,OU=Tier 1,OU=ADTierGuard") }

foreach ($domain in $allDomains) {
    $di = $domainTable[$domain]; if (-not $di) { continue }
    Write-Log "  $domain" -Level Info
    foreach ($ou in $ouPaths) { if (-not (Test-ADSIPath "$ou,$($di.DN)" $di.Server)) { New-ADSIOrganizationalUnit $ou $di.DN $di.Server } }
}

# Deploy scripts
Write-Log "Deploying scripts..." -Level Info
$configJson = $config | ConvertTo-Json -Depth 5
foreach ($domain in $allDomains) { Deploy-ScriptsToDomain $domain $configJson }

# Create GMSA
if (-not $SkipGMSA) { 
    Write-Log "Creating GMSA..." -Level Info
    New-ADSIGMSA $config.GMSA.Name $forestRootDN $forestRootFQDN $pdcServer 
}

# Create Groups
Write-Log "Creating universal security groups..." -Level Info
$t0SID = if ($Scope -in @('Tier0','All')) { New-ADSIUniversalGroup $config.Tier0.GroupName "Tier 0 computers - Members can authenticate Tier 0 users" $forestRootDN $pdcServer } else { $null }
$t1SID = if ($Scope -in @('Tier1','All')) { New-ADSIUniversalGroup $config.Tier1.GroupName "Tier 1 computers - Members can authenticate Tier 1 users" $forestRootDN $pdcServer } else { $null }

# Create Authentication Policies
Write-Log "Creating Authentication Policies..." -Level Info

# SDDL format for conditional ACE:
# O:SY = Owner: SYSTEM
# G:SY = Group: SYSTEM  
# D: = DACL
# XA = ACCESS_ALLOWED_CALLBACK_ACE_TYPE (conditional allow)
# OICI = Object Inherit + Container Inherit flags
# CR = Control Right (0x100 - right to authenticate)
# WD = Everyone (placeholder - condition does the real work)
# Condition: Member_of{SID(ED)} = Enterprise Domain Controllers
#            Member_of_any{SID(group-sid)} = Any member of specified group

if ($t0SID) {
    # Tier 0: Allow from Enterprise DCs OR Tier0-Computers group members
    $t0SDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)}) || (Member_of_any {SID($($t0SID.Trim()))})))"
    Write-Log "  Tier0 SDDL: $t0SDDL" -Level Debug -NoConsole
    New-ADSIAuthenticationPolicy $config.Tier0.PolicyName $t0SDDL "Tier 0 Authentication Policy - Restricts authentication to Tier 0 computers only" $configNC $pdcServer
    New-ADSIAuthenticationSilo $config.Tier0.SiloName $config.Tier0.PolicyName "Tier 0 Silo" $configNC $pdcServer
}

if ($t0SID -and $t1SID) {
    # Tier 1: Allow from Enterprise DCs OR Tier0-Computers OR Tier1-Computers
    $t1SDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;(((Member_of {SID(ED)}) || (Member_of_any {SID($($t0SID.Trim()))})) || (Member_of_any {SID($($t1SID.Trim()))})))"
    Write-Log "  Tier1 SDDL: $t1SDDL" -Level Debug -NoConsole
    New-ADSIAuthenticationPolicy $config.Tier1.PolicyName $t1SDDL "Tier 1 Authentication Policy - Restricts authentication to Tier 0 and Tier 1 computers" $configNC $pdcServer
    New-ADSIAuthenticationSilo $config.Tier1.SiloName $config.Tier1.PolicyName "Tier 1 Silo" $configNC $pdcServer
}

# Deploy GPO
if (-not $SkipGPO) {
    Write-Log "Deploying GPO..." -Level Info
    foreach ($domain in $allDomains) {
        $di = $domainTable[$domain]; if (-not $di) { continue }
        Deploy-GPOToDomain $domain $di.DN $di.Server $config.GPO.Name "\\$domain\SYSVOL\$domain\scripts" $config.GMSA.Name
    }
}

# Enable Kerberos Armoring
if (-not $SkipArmoring) {
    Write-Log "Enabling Kerberos Armoring (FAST)..." -Level Info
    foreach ($domain in $allDomains) {
        $di = $domainTable[$domain]; if (-not $di) { continue }
        Enable-KerberosArmoring $domain $di.DN $di.Server
    }
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host "                 Installation Complete" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Green
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Run 'gpupdate /force' on ALL domain controllers" -ForegroundColor White
Write-Host "  2. Verify Kerberos armoring: Check Event ID 309 in KDC Operational log" -ForegroundColor White
Write-Host "  3. Move Tier 0 computers to OU=Computers,OU=Tier 0,OU=ADTierGuard" -ForegroundColor White
Write-Host "  4. Move Tier 0 users to OU=Users,OU=Tier 0,OU=ADTierGuard" -ForegroundColor White
Write-Host "  5. Run the sync scripts to apply policies to users:" -ForegroundColor White
Write-Host "     Invoke-TierUserSync.ps1 -ConfigurationPath <config.json> -TierLevel 0" -ForegroundColor Cyan
Write-Host "     (This sets msDS-AssignedAuthNPolicy on user objects)" -ForegroundColor Gray
Write-Host "  6. Verify policy assignment on a user:" -ForegroundColor White
Write-Host "     Get-ADUser <username> -Properties msDS-AssignedAuthNPolicy" -ForegroundColor Cyan
Write-Host "  7. Enable scheduled tasks GPO for automatic ongoing sync" -ForegroundColor White
Write-Host ""
Write-Host "NOTE: The 'Accounts' section in ADAC Authentication Policies will remain" -ForegroundColor Gray
Write-Host "      empty - ADTierGuard sets policies on user objects, not on the policy." -ForegroundColor Gray
Write-Host ""
Write-Host "Log file: $script:LogFile" -ForegroundColor Gray

#endregion
