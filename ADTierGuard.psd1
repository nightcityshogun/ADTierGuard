@{
    # Module identification
    RootModule        = 'ADTierGuard.psm1'
    ModuleVersion     = '2.0.0'
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
        'Core\ConfigurationManager.psm1'
        'Core\SyncUtilities.psm1'
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
        'Core\ConfigurationManager.psm1'
        'Core\SyncUtilities.psm1'
        'Engine\RunspaceEngine.psm1'
        'Scripts\Invoke-TierComputerSync.ps1'
        'Scripts\Invoke-TierUserSync.ps1'
        'Install-TierGuard.ps1'
        'Config\Sample-TierGuard.json'
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
