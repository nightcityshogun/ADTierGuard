@{
    # Module identification
    RootModule        = 'ADTierGuard.psm1'
    ModuleVersion     = '2.2.0'
    GUID              = 'a8c7f3e2-9d4b-4a6c-8f1e-2b5d7c9a3e6f'
    
    # Author information
    Author            = 'Enterprise Security Team'
    CompanyName       = 'Your Organization'
    Copyright         = '(c) 2025. All rights reserved.'
    
    # Module description
    Description       = @'
ADTierGuard - Enterprise Active Directory Tier Isolation Module

A pure ADSI (System.DirectoryServices) implementation for Active Directory 
Tier 0/1 isolation using Kerberos Authentication Policies. This module provides 
complete tier management without any dependency on the ActiveDirectory PowerShell module.

Key Features:
- Zero dependency on ActiveDirectory module - pure ADSI implementation
- Runspace-based parallel processing for high performance
- Automatic computer group membership management
- Kerberos Authentication Policy enforcement
- Protected Users group management
- Privileged group cleanup for Tier 0 accounts
- Comprehensive logging (file and Windows Event Log)
- JSON-based configuration with validation
- Forest-wide or single-domain operation
- WhatIf support for safe testing

Based on Microsoft's Tier Model and Kerberos Authentication Policies.
Requires Windows Server 2012 R2 Forest Functional Level or higher.
'@
    
    # Minimum PowerShell version
    PowerShellVersion = '5.1'
    
    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')
    
    # CLR version (for Desktop edition)
    CLRVersion        = '4.0'
    
    # Processor architecture
    ProcessorArchitecture = 'None'
    
    # Required modules (none - this is pure ADSI)
    RequiredModules   = @()
    
    # Required assemblies
    RequiredAssemblies = @()
    
    # Nested modules
    NestedModules     = @(
        'Core\AdsiOperations.psm1'
        'Core\AuthPolicyManager.psm1'
        'Core\ConfigurationManager.psm1'
        'Core\SyncUtilities.psm1'
        'Core\ForestTopology.psm1'
        'Engine\RunspaceEngine.psm1'
    )
    
    # Functions to export
    FunctionsToExport = @(
        # Main module functions
        'Initialize-TierGuard'
        'Get-TierGuardStatus'
        'Invoke-TierComputerSync'
        'Invoke-TierUserSync'
        'Get-TierComputers'
        'Get-TierUsers'
        'Test-TierEnvironment'
        
        # ADSI Operations
        'New-AdsiConnection'
        'Get-AdsiRootDse'
        'Get-AdsiForestDomains'
        'Search-AdsiDirectory'
        'Get-AdsiObject'
        'Get-AdsiComputer'
        'Test-AdsiDomainController'
        'Get-AdsiUser'
        'Test-AdsiGroupManagedServiceAccount'
        'Test-AdsiManagedServiceAccount'
        'Get-AdsiGroupMember'
        'Add-AdsiGroupMember'
        'Remove-AdsiGroupMember'
        'Get-AdsiPrivilegedGroup'
        'Get-AdsiKerberosAuthenticationPolicy'
        'Set-AdsiAuthenticationPolicy'
        'Remove-AdsiAuthenticationPolicy'
        'Get-AdsiProtectedUsersGroup'
        'Add-AdsiProtectedUser'
        'ConvertTo-AdsiDistinguishedName'
        'Get-AdsiDomainFromDN'
        'Test-AdsiObjectInOU'
        
        # Configuration Management
        'Get-ConfigurationSchema'
        'Import-TierGuardConfiguration'
        'Export-TierGuardConfiguration'
        'New-TierGuardConfiguration'
        'Test-TierGuardConfiguration'
        'Resolve-TierOUPaths'
        'Initialize-TierGuardEventLog'
        'Write-TierGuardEvent'
        'Get-TierGuardEventIds'
        
        # Sync Utilities
        'Initialize-SyncUtilities'
        'Test-SyncUtilitiesInitialized'
        'Write-SyncLog'
        'Get-TierSpecificConfiguration'
        'Test-TierEnabled'
        'Get-SyncTargetDomains'
        'Resolve-OUPathForDomain'
        'Get-EffectiveThrottleLimit'
        'New-SyncOperationResult'
        'Format-SyncSummary'
        
        # Forest Topology
        'Initialize-ForestTopology'
        'Get-ForestTopology'
        'Get-ForestRootDomain'
        'Get-ChildDomains'
        'Get-TreeRootDomains'
        'Get-DomainByName'
        'Test-IsForestRoot'
        'Get-ForestPrivilegedGroups'
        'Get-DomainPrivilegedGroups'
        'Get-AllPrivilegedGroupsForDomain'
        'Get-OnlineDomainController'
        'Get-GlobalCatalogServer'
        'Get-ForestInfo'
        
        # Runspace Engine
        'New-RunspacePool'
        'Close-RunspacePool'
        'Invoke-ParallelOperation'
        'Invoke-BatchOperation'
        'New-ThreadSafeDictionary'
        'New-ThreadSafeQueue'
        'New-ThreadSafeBag'
        'New-ProgressTracker'
        'Get-ParallelOperationSummary'
        
        # Authentication Policy Manager
        'Get-AuthPolicyForestContext'
        'Test-AuthPolicyPrerequisites'
        'Get-TierAuthenticationPolicy'
        'New-TierAuthenticationPolicy'
        'Set-TierAuthenticationPolicy'
        'Remove-TierAuthenticationPolicy'
        'Get-TierAuthenticationSilo'
        'New-TierAuthenticationSilo'
        'Set-TierAuthenticationSilo'
        'Remove-TierAuthenticationSilo'
        'Add-TierSiloMember'
        'Remove-TierSiloMember'
        'Initialize-TierAuthenticationPolicy'
        'Get-TierAuthenticationStatus'
        'Set-UserAuthenticationPolicy'
        'Remove-UserAuthenticationPolicy'
    )
    
    # Cmdlets to export
    CmdletsToExport   = @()
    
    # Variables to export
    VariablesToExport = @()
    
    # Aliases to export
    AliasesToExport   = @()
    
    # DSC resources
    DscResourcesToExport = @()
    
    # Module file list
    FileList          = @(
        'ADTierGuard.psd1'
        'ADTierGuard.psm1'
        'Core\AdsiOperations.psm1'
        'Core\AuthPolicyManager.psm1'
        'Core\ConfigurationManager.psm1'
        'Core\SyncUtilities.psm1'
        'Core\ForestTopology.psm1'
        'Core\Get-ForestInfo.ps1'
        'Engine\RunspaceEngine.psm1'
        'Scripts\Invoke-TierComputerSync.ps1'
        'Scripts\Invoke-TierUserSync.ps1'
        'Install-TierGuard.ps1'
        'Config\Sample-TierGuard.json'
        'Docs\AuthPolicy-Configuration.md'
    )
    
    # Private data
    PrivateData       = @{
        PSData = @{
            # Tags for PowerShell Gallery
            Tags         = @(
                'ActiveDirectory'
                'AD'
                'ADSI'
                'Security'
                'TierModel'
                'Tier0'
                'Tier1'
                'Kerberos'
                'AuthenticationPolicy'
                'PrivilegedAccess'
                'PAM'
                'Enterprise'
                'Windows'
            )
            
            # License URI
            LicenseUri   = ''
            
            # Project URI
            ProjectUri   = ''
            
            # Icon URI
            IconUri      = ''
            
            # Release notes
            ReleaseNotes = @'
Version 2.2.0 - Authentication Policy & Silo Management
========================================================
NEW FEATURES:
- Complete Authentication Policy management via AuthPolicyManager.psm1
- Authentication Policy Silo support for full credential isolation
- Forest context validation (checks forest root, functional level)
- Test-AuthPolicyPrerequisites for environment validation
- Initialize-TierAuthenticationPolicy for complete tier setup
- Silo membership management (Add/Remove-TierSiloMember)
- Policy-only or Policy+Silo deployment options
- Get-TierAuthenticationStatus for current state reporting

KEY INSIGHT:
- Authentication Policies and Silos are FOREST-WIDE objects
- Stored in Configuration NC, not per-domain
- Must be created from forest root DC (or with Enterprise Admin)
- Can be assigned to users in any domain

DOCUMENTATION:
- AuthPolicy-Configuration.md explains Policy vs Silo approach
- SDDL examples for restricting authentication sources
- Multi-domain forest considerations documented

Version 2.1.0 - Forest Topology Aware Release
==============================================
NEW FEATURES:
- Integrated Get-ForestInfo for complete forest topology discovery
- Forest Root / Child Domain / Tree Root classification
- Proper handling of forest-scoped groups (Enterprise Admins, Schema Admins)
- Schema Admins cleanup only runs in forest root domain
- Enterprise Admins cleanup only runs in forest root domain
- Domain SID-based group resolution for accurate targeting
- Online DC detection with GC/PDC preference
- Fallback to adminCount-based enumeration if topology fails

IMPROVEMENTS:
- Multi-domain forest support is now production-ready
- Privileged group cleanup is topology-aware
- Better error handling with fallback mechanisms

Version 2.0.0 - Commercial Ready Release
=========================================
BREAKING CHANGES:
- Refactored sync scripts to use shared SyncUtilities module
- Renamed logging function to Write-SyncLog (was Write-Log)

NEW FEATURES:
- New SyncUtilities module for shared functionality
- Thread-safe logging with file locking
- Standardized result objects across sync operations
- Enhanced summary formatting
- Improved error handling with stack traces

IMPROVEMENTS:
- Eliminated all duplicate code between sync scripts
- Commercial-grade code quality
- Better separation of concerns
- More comprehensive help documentation
- UTC timestamps for consistency

Version 1.0.0 - Initial Release
================================
- Pure ADSI implementation (no ActiveDirectory module dependency)
- Runspace-based parallel processing engine
- Computer group membership synchronization
- User Kerberos Authentication Policy enforcement
- Protected Users group management
- Privileged group cleanup for Tier 0
- JSON-based configuration with validation
- Comprehensive event logging
- Interactive installation wizard
- WhatIf support for safe testing
'@
            
            # Prerelease string
            Prerelease   = ''
            
            # External module dependencies
            ExternalModuleDependencies = @()
        }
    }
    
    # Help info URI
    HelpInfoURI       = ''
    
    # Default command prefix
    DefaultCommandPrefix = ''
}
