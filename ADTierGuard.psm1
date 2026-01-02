#Requires -Version 5.1
<#
.SYNOPSIS
    ADTierGuard - Pure ADSI Active Directory Tier Isolation Module
    
.DESCRIPTION
    Enterprise-grade Active Directory Tier 0/1 isolation implementation using
    Kerberos Authentication Policies. This module provides complete tier management
    without any dependency on the ActiveDirectory PowerShell module.
    
    Key Features:
    - Pure ADSI (System.DirectoryServices) implementation
    - Runspace-based parallel processing for high performance
    - Automatic computer group membership management
    - Kerberos Authentication Policy enforcement
    - Protected Users group management
    - Privileged group cleanup for Tier 0
    
.NOTES
    Module:      ADTierGuard
    Author:      Enterprise Security Team
    Version:     2.0.0
    Requires:    Windows PowerShell 5.1 or PowerShell 7+
                 Domain Admin or Enterprise Admin privileges
                 Windows Server 2012 R2 Forest Functional Level (for AuthN Policies)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Module Variables

# Module root path
$script:ModuleRoot = $PSScriptRoot

# Version information
$script:ModuleVersion = '2.0.0'

# Cached configuration
$script:CurrentConfiguration = $null

# Module state
$script:IsInitialized = $false

#endregion

#region Module Loading

# Define module paths
$script:CoreModulePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Core'
$script:EngineModulePath = Join-Path -Path $script:ModuleRoot -ChildPath 'Engine'
$script:ScriptsPath = Join-Path -Path $script:ModuleRoot -ChildPath 'Scripts'

# Import core modules (order matters - ForestTopology before SyncUtilities, AuthPolicyManager after AdsiOperations)
$moduleFiles = @(
    @{ Path = (Join-Path -Path $script:CoreModulePath -ChildPath 'AdsiOperations.psm1'); Name = 'AdsiOperations' }
    @{ Path = (Join-Path -Path $script:CoreModulePath -ChildPath 'AuthPolicyManager.psm1'); Name = 'AuthPolicyManager' }
    @{ Path = (Join-Path -Path $script:CoreModulePath -ChildPath 'ConfigurationManager.psm1'); Name = 'ConfigurationManager' }
    @{ Path = (Join-Path -Path $script:CoreModulePath -ChildPath 'ForestTopology.psm1'); Name = 'ForestTopology' }
    @{ Path = (Join-Path -Path $script:CoreModulePath -ChildPath 'ForestDeployment.psm1'); Name = 'ForestDeployment' }
    @{ Path = (Join-Path -Path $script:CoreModulePath -ChildPath 'SyncUtilities.psm1'); Name = 'SyncUtilities' }
    @{ Path = (Join-Path -Path $script:EngineModulePath -ChildPath 'RunspaceEngine.psm1'); Name = 'RunspaceEngine' }
)

foreach ($module in $moduleFiles) {
    if (Test-Path -Path $module.Path) {
        try {
            Import-Module -Name $module.Path -Force -Global -DisableNameChecking
            Write-Verbose "Imported module: $($module.Name)"
        }
        catch {
            Write-Warning "Failed to import module $($module.Name): $_"
            throw
        }
    }
    else {
        throw "Required module not found: $($module.Path)"
    }
}

#endregion

#region Public Functions

function Initialize-TierGuard {
    <#
    .SYNOPSIS
        Initializes the ADTierGuard module with a configuration file.
        
    .DESCRIPTION
        Loads and validates the configuration, initializes event logging,
        and prepares the module for tier management operations.
        
    .PARAMETER ConfigurationPath
        Path to the JSON configuration file.
        
    .PARAMETER ValidateOnly
        Only validate the configuration without initializing.
        
    .EXAMPLE
        Initialize-TierGuard -ConfigurationPath 'C:\ADTierGuard\Config\TierGuard.json'
        
    .OUTPUTS
        PSCustomObject with initialization status and any warnings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$ConfigurationPath,
        
        [Parameter()]
        [switch]$ValidateOnly
    )
    
    try {
        Write-Verbose "Initializing ADTierGuard from: $ConfigurationPath"
        
        # Load configuration
        $config = Import-TierGuardConfiguration -Path $ConfigurationPath
        
        # Validate configuration
        $validation = Test-TierGuardConfiguration -Configuration $config
        
        if (-not $validation.IsValid) {
            $errorMessage = "Configuration validation failed:`n" + ($validation.Errors -join "`n")
            throw $errorMessage
        }
        
        if ($ValidateOnly) {
            return [PSCustomObject]@{
                IsValid  = $true
                Warnings = $validation.Warnings
                Config   = $config
            }
        }
        
        # Initialize event logging
        if (-not [string]::IsNullOrWhiteSpace($config.General.EventLogSource)) {
            Initialize-TierGuardEventLog -SourceName $config.General.EventLogSource
        }
        
        # Store configuration
        $script:CurrentConfiguration = $config
        $script:IsInitialized = $true
        
        # Log initialization
        Write-TierGuardEvent -EventId 9000 -Message "ADTierGuard initialized successfully" -EntryType Information
        
        return [PSCustomObject]@{
            Status      = 'Initialized'
            Version     = $script:ModuleVersion
            Warnings    = $validation.Warnings
            Tier0       = $config.Tier0.Enabled
            Tier1       = $config.Tier1.Enabled
            ForestScope = $config.General.ForestScope
        }
    }
    catch {
        Write-Error "Failed to initialize ADTierGuard: $_"
        throw
    }
}

function Get-TierGuardStatus {
    <#
    .SYNOPSIS
        Gets the current status of the ADTierGuard module.
        
    .DESCRIPTION
        Returns initialization state, configuration summary, and version information.
        
    .EXAMPLE
        Get-TierGuardStatus
        
    .OUTPUTS
        PSCustomObject with module status information.
    #>
    [CmdletBinding()]
    param()
    
    return [PSCustomObject]@{
        ModuleName    = 'ADTierGuard'
        Version       = $script:ModuleVersion
        IsInitialized = $script:IsInitialized
        ModuleRoot    = $script:ModuleRoot
        Configuration = if ($script:CurrentConfiguration) {
            [PSCustomObject]@{
                Tier0Enabled = $script:CurrentConfiguration.Tier0.Enabled
                Tier1Enabled = $script:CurrentConfiguration.Tier1.Enabled
                ForestScope  = $script:CurrentConfiguration.General.ForestScope
                LogPath      = $script:CurrentConfiguration.General.LogPath
            }
        } else { $null }
    }
}

function Invoke-TierComputerSync {
    <#
    .SYNOPSIS
        Synchronizes computer group membership for a specified tier.
        
    .DESCRIPTION
        Scans configured OUs for computers and ensures they are members of
        the appropriate tier restriction group. Uses parallel processing
        for high performance in large environments.
        
    .PARAMETER ConfigurationPath
        Path to the JSON configuration file.
        
    .PARAMETER TierLevel
        The tier level to synchronize (0 or 1).
        
    .PARAMETER ForestScope
        Process all domains in the forest. If not specified, uses config setting.
        
    .PARAMETER ThrottleLimit
        Maximum number of parallel operations.
        
    .PARAMETER WhatIf
        Shows what would happen without making changes.
        
    .EXAMPLE
        Invoke-TierComputerSync -ConfigurationPath 'C:\ADTierGuard\Config\TierGuard.json' -TierLevel 0
        
    .EXAMPLE
        Invoke-TierComputerSync -ConfigurationPath 'C:\ADTierGuard\Config\TierGuard.json' -TierLevel 1 -WhatIf
        
    .OUTPUTS
        PSCustomObject with synchronization results.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$ConfigurationPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)]
        [int]$TierLevel,
        
        [Parameter()]
        [switch]$ForestScope,
        
        [Parameter()]
        [ValidateRange(1, 32)]
        [int]$ThrottleLimit = 8,
        
        [Parameter()]
        [switch]$WhatIf
    )
    
    $scriptPath = Join-Path -Path $script:ScriptsPath -ChildPath 'Invoke-TierComputerSync.ps1'
    
    if (-not (Test-Path -Path $scriptPath)) {
        throw "Script not found: $scriptPath"
    }
    
    $params = @{
        ConfigurationPath = $ConfigurationPath
        TierLevel         = $TierLevel
        ThrottleLimit     = $ThrottleLimit
    }
    
    if ($ForestScope) { $params['ForestScope'] = $true }
    if ($WhatIf) { $params['WhatIf'] = $true }
    
    & $scriptPath @params
}

function Invoke-TierUserSync {
    <#
    .SYNOPSIS
        Synchronizes user policies and group membership for a specified tier.
        
    .DESCRIPTION
        Applies Kerberos Authentication Policies, manages Protected Users group
        membership, and optionally cleans up privileged groups.
        
    .PARAMETER ConfigurationPath
        Path to the JSON configuration file.
        
    .PARAMETER TierLevel
        The tier level to synchronize (0 or 1).
        
    .PARAMETER ForestScope
        Process all domains in the forest.
        
    .PARAMETER SkipProtectedUsers
        Skip adding users to the Protected Users group.
        
    .PARAMETER SkipPrivilegedGroupCleanup
        Skip removing unauthorized users from privileged groups.
        
    .PARAMETER ThrottleLimit
        Maximum number of parallel operations.
        
    .PARAMETER WhatIf
        Shows what would happen without making changes.
        
    .EXAMPLE
        Invoke-TierUserSync -ConfigurationPath 'C:\ADTierGuard\Config\TierGuard.json' -TierLevel 0
        
    .EXAMPLE
        Invoke-TierUserSync -ConfigurationPath 'C:\ADTierGuard\Config\TierGuard.json' -TierLevel 0 -SkipPrivilegedGroupCleanup -WhatIf
        
    .OUTPUTS
        PSCustomObject with synchronization results.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$ConfigurationPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)]
        [int]$TierLevel,
        
        [Parameter()]
        [switch]$ForestScope,
        
        [Parameter()]
        [switch]$SkipProtectedUsers,
        
        [Parameter()]
        [switch]$SkipPrivilegedGroupCleanup,
        
        [Parameter()]
        [ValidateRange(1, 32)]
        [int]$ThrottleLimit = 8,
        
        [Parameter()]
        [switch]$WhatIf
    )
    
    $scriptPath = Join-Path -Path $script:ScriptsPath -ChildPath 'Invoke-TierUserSync.ps1'
    
    if (-not (Test-Path -Path $scriptPath)) {
        throw "Script not found: $scriptPath"
    }
    
    $params = @{
        ConfigurationPath = $ConfigurationPath
        TierLevel         = $TierLevel
        ThrottleLimit     = $ThrottleLimit
    }
    
    if ($ForestScope) { $params['ForestScope'] = $true }
    if ($SkipProtectedUsers) { $params['SkipProtectedUsers'] = $true }
    if ($SkipPrivilegedGroupCleanup) { $params['SkipPrivilegedGroupCleanup'] = $true }
    if ($WhatIf) { $params['WhatIf'] = $true }
    
    & $scriptPath @params
}

function Get-TierComputers {
    <#
    .SYNOPSIS
        Gets all computers in a specified tier's OUs.
        
    .DESCRIPTION
        Searches configured OUs and returns all computer objects that should
        be members of the tier restriction group.
        
    .PARAMETER ConfigurationPath
        Path to the JSON configuration file.
        
    .PARAMETER TierLevel
        The tier level to query (0 or 1).
        
    .PARAMETER IncludeDisabled
        Include disabled computer accounts.
        
    .EXAMPLE
        Get-TierComputers -ConfigurationPath 'C:\ADTierGuard\Config\TierGuard.json' -TierLevel 0
        
    .OUTPUTS
        Array of computer objects with DN, Name, and properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$ConfigurationPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)]
        [int]$TierLevel,
        
        [Parameter()]
        [switch]$IncludeDisabled
    )
    
    try {
        $config = Import-TierGuardConfiguration -Path $ConfigurationPath
        $tierConfig = if ($TierLevel -eq 0) { $config.Tier0 } else { $config.Tier1 }
        
        if (-not $tierConfig.Enabled) {
            Write-Warning "Tier $TierLevel is not enabled in configuration"
            return @()
        }
        
        $computers = [System.Collections.ArrayList]::new()
        
        foreach ($ou in $tierConfig.ComputerOUs) {
            $searchParams = @{
                SearchBase        = $ou
                LdapFilter        = '(objectClass=computer)'
                PropertiesToLoad  = @('distinguishedName', 'name', 'dNSHostName', 'operatingSystem', 'userAccountControl')
                SearchScope       = 'Subtree'
                IncludeDisabled   = $IncludeDisabled.IsPresent
            }
            
            $results = Get-AdsiComputer @searchParams
            foreach ($result in $results) {
                [void]$computers.Add($result)
            }
        }
        
        return $computers.ToArray()
    }
    catch {
        Write-Error "Failed to get tier computers: $_"
        throw
    }
}

function Get-TierUsers {
    <#
    .SYNOPSIS
        Gets all users in a specified tier's Admin OUs.
        
    .DESCRIPTION
        Searches configured Admin OUs and returns all user objects that should
        have the tier's Kerberos Authentication Policy applied.
        
    .PARAMETER ConfigurationPath
        Path to the JSON configuration file.
        
    .PARAMETER TierLevel
        The tier level to query (0 or 1).
        
    .PARAMETER IncludeServiceAccounts
        Also include service accounts from ServiceAccountOUs.
        
    .EXAMPLE
        Get-TierUsers -ConfigurationPath 'C:\ADTierGuard\Config\TierGuard.json' -TierLevel 0
        
    .OUTPUTS
        Array of user objects with DN, Name, and policy information.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$ConfigurationPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet(0, 1)]
        [int]$TierLevel,
        
        [Parameter()]
        [switch]$IncludeServiceAccounts
    )
    
    try {
        $config = Import-TierGuardConfiguration -Path $ConfigurationPath
        $tierConfig = if ($TierLevel -eq 0) { $config.Tier0 } else { $config.Tier1 }
        
        if (-not $tierConfig.Enabled) {
            Write-Warning "Tier $TierLevel is not enabled in configuration"
            return @()
        }
        
        $users = [System.Collections.ArrayList]::new()
        
        # Get admin users
        foreach ($ou in $tierConfig.AdminOUs) {
            $searchParams = @{
                SearchBase       = $ou
                LdapFilter       = '(&(objectClass=user)(objectCategory=person))'
                PropertiesToLoad = @('distinguishedName', 'sAMAccountName', 'userPrincipalName', 'msDS-AssignedAuthNPolicy', 'memberOf')
                SearchScope      = 'Subtree'
            }
            
            $results = Get-AdsiUser @searchParams
            foreach ($result in $results) {
                # Skip MSAs
                if (-not (Test-AdsiManagedServiceAccount -DistinguishedName $result.distinguishedName)) {
                    [void]$users.Add([PSCustomObject]@{
                        DistinguishedName = $result.distinguishedName
                        SamAccountName    = $result.sAMAccountName
                        UserPrincipalName = $result.userPrincipalName
                        CurrentPolicy     = $result.'msDS-AssignedAuthNPolicy'
                        Type              = 'Admin'
                    })
                }
            }
        }
        
        # Get service accounts if requested
        if ($IncludeServiceAccounts) {
            foreach ($ou in $tierConfig.ServiceAccountOUs) {
                $searchParams = @{
                    SearchBase       = $ou
                    LdapFilter       = '(&(objectClass=user)(objectCategory=person))'
                    PropertiesToLoad = @('distinguishedName', 'sAMAccountName', 'userPrincipalName', 'msDS-AssignedAuthNPolicy')
                    SearchScope      = 'Subtree'
                }
                
                $results = Get-AdsiUser @searchParams
                foreach ($result in $results) {
                    [void]$users.Add([PSCustomObject]@{
                        DistinguishedName = $result.distinguishedName
                        SamAccountName    = $result.sAMAccountName
                        UserPrincipalName = $result.userPrincipalName
                        CurrentPolicy     = $result.'msDS-AssignedAuthNPolicy'
                        Type              = 'ServiceAccount'
                    })
                }
            }
        }
        
        return $users.ToArray()
    }
    catch {
        Write-Error "Failed to get tier users: $_"
        throw
    }
}

function Test-TierEnvironment {
    <#
    .SYNOPSIS
        Tests the environment readiness for tier isolation.
        
    .DESCRIPTION
        Validates that the environment meets all prerequisites for
        implementing tier isolation with Kerberos Authentication Policies.
        
    .PARAMETER ConfigurationPath
        Optional path to configuration file for additional validation.
        
    .EXAMPLE
        Test-TierEnvironment
        
    .EXAMPLE
        Test-TierEnvironment -ConfigurationPath 'C:\ADTierGuard\Config\TierGuard.json'
        
    .OUTPUTS
        PSCustomObject with test results and recommendations.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigurationPath
    )
    
    $results = [System.Collections.ArrayList]::new()
    $overallSuccess = $true
    
    # Test 1: Administrative privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    [void]$results.Add([PSCustomObject]@{
        Test    = 'Administrative Privileges'
        Result  = if ($isAdmin) { 'Pass' } else { 'Fail' }
        Details = if ($isAdmin) { 'Running with administrator privileges' } else { 'Administrator privileges required' }
    })
    if (-not $isAdmin) { $overallSuccess = $false }
    
    # Test 2: Domain connectivity
    try {
        $rootDse = Get-AdsiRootDse
        [void]$results.Add([PSCustomObject]@{
            Test    = 'Domain Connectivity'
            Result  = 'Pass'
            Details = "Connected to: $($rootDse.defaultNamingContext)"
        })
    }
    catch {
        [void]$results.Add([PSCustomObject]@{
            Test    = 'Domain Connectivity'
            Result  = 'Fail'
            Details = "Cannot connect to domain: $_"
        })
        $overallSuccess = $false
    }
    
    # Test 3: Forest functional level
    try {
        $rootDse = Get-AdsiRootDse
        $forestLevel = [int]$rootDse.forestFunctionality
        $forestLevelName = switch ($forestLevel) {
            0 { 'Windows 2000' }
            1 { 'Windows Server 2003 Interim' }
            2 { 'Windows Server 2003' }
            3 { 'Windows Server 2008' }
            4 { 'Windows Server 2008 R2' }
            5 { 'Windows Server 2012' }
            6 { 'Windows Server 2012 R2' }
            7 { 'Windows Server 2016' }
            default { "Unknown ($forestLevel)" }
        }
        
        $levelPass = $forestLevel -ge 6
        [void]$results.Add([PSCustomObject]@{
            Test    = 'Forest Functional Level'
            Result  = if ($levelPass) { 'Pass' } else { 'Fail' }
            Details = "$forestLevelName (Level $forestLevel) - Minimum: Windows Server 2012 R2 (Level 6) for Kerberos Authentication Policies"
        })
        if (-not $levelPass) { $overallSuccess = $false }
    }
    catch {
        [void]$results.Add([PSCustomObject]@{
            Test    = 'Forest Functional Level'
            Result  = 'Fail'
            Details = "Cannot determine forest functional level: $_"
        })
        $overallSuccess = $false
    }
    
    # Test 4: PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    $versionPass = $psVersion.Major -ge 5
    [void]$results.Add([PSCustomObject]@{
        Test    = 'PowerShell Version'
        Result  = if ($versionPass) { 'Pass' } else { 'Fail' }
        Details = "PowerShell $($psVersion.ToString()) - Minimum: 5.1"
    })
    if (-not $versionPass) { $overallSuccess = $false }
    
    # Test 5: Configuration validation (if provided)
    if ($ConfigurationPath -and (Test-Path -Path $ConfigurationPath)) {
        try {
            $config = Import-TierGuardConfiguration -Path $ConfigurationPath
            $validation = Test-TierGuardConfiguration -Configuration $config
            
            [void]$results.Add([PSCustomObject]@{
                Test    = 'Configuration Validation'
                Result  = if ($validation.IsValid) { 'Pass' } else { 'Fail' }
                Details = if ($validation.IsValid) { 
                    "Configuration valid. Warnings: $($validation.Warnings.Count)"
                } else {
                    "Errors: $($validation.Errors -join '; ')"
                }
            })
            if (-not $validation.IsValid) { $overallSuccess = $false }
        }
        catch {
            [void]$results.Add([PSCustomObject]@{
                Test    = 'Configuration Validation'
                Result  = 'Fail'
                Details = "Cannot validate configuration: $_"
            })
            $overallSuccess = $false
        }
    }
    
    return [PSCustomObject]@{
        OverallResult = if ($overallSuccess) { 'Pass' } else { 'Fail' }
        Tests         = $results.ToArray()
        Timestamp     = Get-Date
    }
}

#endregion

#region Module Cleanup

$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    # Cleanup module resources
    $script:CurrentConfiguration = $null
    $script:IsInitialized = $false
    Write-Verbose "ADTierGuard module unloaded"
}

#endregion

# Export public functions
Export-ModuleMember -Function @(
    'Initialize-TierGuard'
    'Get-TierGuardStatus'
    'Invoke-TierComputerSync'
    'Invoke-TierUserSync'
    'Get-TierComputers'
    'Get-TierUsers'
    'Test-TierEnvironment'
)
