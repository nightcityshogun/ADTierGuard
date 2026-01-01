<#
.SYNOPSIS
    ADTierGuard - Authentication Policy and Silo Management Module
    
.DESCRIPTION
    Manages Kerberos Authentication Policies and Authentication Policy Silos
    for the AD Tier Model. These objects are FOREST-WIDE and stored in the
    Configuration Naming Context.
    
    IMPORTANT: Authentication Policies and Silos MUST be created from a DC
    that can write to the Configuration NC (typically forest root DC) by
    a user with Enterprise Admin or equivalent permissions.
    
    Objects created:
    - CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,...
    - CN=AuthN Silos,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,...
    
.NOTES
    Author: ADTierGuard Project
    Version: 2.2.0
    
    Requirements:
    - Must run on a DC in the forest root domain (or with forest-level write access)
    - Requires Enterprise Admin or delegated Configuration NC write permissions
    - Domain functional level must be Windows Server 2012 R2 or higher
    
.LINK
    https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest

#region Forest and Domain Validation

<#
.SYNOPSIS
    Gets forest topology information for policy/silo management.
    
.DESCRIPTION
    Determines forest root domain, current domain, and validates
    whether the current context is appropriate for creating
    forest-wide authentication policies.
#>
function Get-AuthPolicyForestContext {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$Server
    )
    
    $rootDse = Get-AdsiRootDse -Server $Server
    $configNC = $rootDse.ConfigurationNamingContext
    $currentDomainDN = $rootDse.DefaultNamingContext
    
    # Get forest root domain from Configuration NC
    # Configuration NC is: CN=Configuration,DC=forestroot,DC=com
    # Extract the domain portion
    $forestRootDN = $configNC -replace '^CN=Configuration,', ''
    
    # Convert DN to DNS name
    $forestRootDns = ($forestRootDN -replace ',DC=', '.' -replace '^DC=', '')
    $currentDomainDns = ($currentDomainDN -replace ',DC=', '.' -replace '^DC=', '')
    
    # Check if current domain is forest root
    $isForestRoot = ($currentDomainDN -eq $forestRootDN)
    
    # Get domain functional level
    $domainFunctionalLevel = $rootDse.'domainFunctionality'
    $forestFunctionalLevel = $rootDse.'forestFunctionality'
    
    # Check if functional level supports auth policies (requires 2012 R2 = level 6)
    $supportsAuthPolicies = ([int]$domainFunctionalLevel -ge 6)
    
    # Get auth policy configuration path
    $authPolicyConfigPath = "CN=AuthN Policy Configuration,CN=Services,$configNC"
    $authPoliciesPath = "CN=AuthN Policies,$authPolicyConfigPath"
    $authSilosPath = "CN=AuthN Silos,$authPolicyConfigPath"
    
    return @{
        ForestRootDN          = $forestRootDN
        ForestRootDns         = $forestRootDns
        CurrentDomainDN       = $currentDomainDN
        CurrentDomainDns      = $currentDomainDns
        IsForestRoot          = $isForestRoot
        ConfigurationNC       = $configNC
        AuthPolicyConfigPath  = $authPolicyConfigPath
        AuthPoliciesPath      = $authPoliciesPath
        AuthSilosPath         = $authSilosPath
        DomainFunctionalLevel = $domainFunctionalLevel
        ForestFunctionalLevel = $forestFunctionalLevel
        SupportsAuthPolicies  = $supportsAuthPolicies
    }
}

<#
.SYNOPSIS
    Validates that the current context can create authentication policies.
#>
function Test-AuthPolicyPrerequisites {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$Server,
        
        [Parameter()]
        [switch]$RequireForestRoot
    )
    
    $context = Get-AuthPolicyForestContext -Server $Server
    $issues = @()
    $canProceed = $true
    
    # Check functional level
    if (-not $context.SupportsAuthPolicies) {
        $issues += "Domain functional level ($($context.DomainFunctionalLevel)) does not support Authentication Policies. Requires Windows Server 2012 R2 (level 6) or higher."
        $canProceed = $false
    }
    
    # Check if on forest root (if required)
    if ($RequireForestRoot -and -not $context.IsForestRoot) {
        $issues += "Current domain ($($context.CurrentDomainDns)) is not the forest root ($($context.ForestRootDns)). Authentication Policies should be created from the forest root domain."
        # This is a warning, not a blocker - policies CAN be created from child domains if you have Enterprise Admin
    }
    
    # Try to verify write access to Configuration NC
    try {
        $testPath = "LDAP://$Server/$($context.AuthPoliciesPath)"
        $testEntry = New-Object DirectoryServices.DirectoryEntry($testPath)
        $null = $testEntry.distinguishedName
        $testEntry.Dispose()
    }
    catch {
        $issues += "Cannot access Authentication Policies container. Ensure you have Enterprise Admin permissions or delegated access to the Configuration NC."
        $canProceed = $false
    }
    
    return @{
        CanProceed            = $canProceed
        Issues                = $issues
        Context               = $context
        IsForestRoot          = $context.IsForestRoot
        SupportsAuthPolicies  = $context.SupportsAuthPolicies
    }
}

#endregion

#region Authentication Policy Management

<#
.SYNOPSIS
    Gets Authentication Policies from the forest Configuration NC.
    
.PARAMETER Name
    Filter by policy name.
    
.PARAMETER Server
    Target DC to query.
#>
function Get-TierAuthenticationPolicy {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter()]
        [string]$Name,
        
        [Parameter()]
        [string]$Server
    )
    
    $context = Get-AuthPolicyForestContext -Server $Server
    
    $filter = if ($Name) {
        "(&(objectClass=msDS-AuthNPolicy)(cn=$Name))"
    }
    else {
        '(objectClass=msDS-AuthNPolicy)'
    }
    
    $properties = @(
        'distinguishedName', 'cn', 'name', 'description',
        'msDS-AuthNPolicyEnforced',
        'msDS-UserAllowedToAuthenticateFrom',
        'msDS-UserAllowedToAuthenticateTo',
        'msDS-UserTGTLifetime',
        'msDS-ComputerAllowedToAuthenticateTo',
        'msDS-ComputerTGTLifetime',
        'msDS-ServiceAllowedToAuthenticateFrom',
        'msDS-ServiceAllowedToAuthenticateTo',
        'msDS-ServiceTGTLifetime',
        'whenCreated', 'whenChanged'
    )
    
    return Search-AdsiDirectory -SearchBase $context.AuthPoliciesPath -LdapFilter $filter `
        -Properties $properties -Server $Server
}

<#
.SYNOPSIS
    Creates a new Authentication Policy for a tier.
    
.DESCRIPTION
    Creates a Kerberos Authentication Policy in the forest Configuration NC.
    The policy restricts where tier accounts can authenticate from/to.
    
.PARAMETER Name
    Policy name (e.g., "TierGuard-Tier0-AuthPolicy").
    
.PARAMETER Description
    Policy description.
    
.PARAMETER TGTLifetimeMinutes
    TGT lifetime in minutes (default: 240 for Tier 0, 480 for Tier 1).
    
.PARAMETER UserAllowedToAuthenticateFrom
    SDDL string restricting which computers users can authenticate from.
    
.PARAMETER UserAllowedToAuthenticateTo
    SDDL string restricting which services users can authenticate to.
    
.PARAMETER Enforced
    Whether policy is enforced (default: $true).
    
.EXAMPLE
    New-TierAuthenticationPolicy -Name "TierGuard-Tier0-AuthPolicy" -TGTLifetimeMinutes 240
#>
function New-TierAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter()]
        [string]$Description = "ADTierGuard Authentication Policy",
        
        [Parameter()]
        [ValidateRange(60, 600)]
        [int]$TGTLifetimeMinutes = 240,
        
        [Parameter()]
        [string]$UserAllowedToAuthenticateFrom,
        
        [Parameter()]
        [string]$UserAllowedToAuthenticateTo,
        
        [Parameter()]
        [bool]$Enforced = $true,
        
        [Parameter()]
        [string]$Server
    )
    
    # Validate prerequisites
    $prereq = Test-AuthPolicyPrerequisites -Server $Server
    if (-not $prereq.CanProceed) {
        $prereq.Issues | ForEach-Object { Write-Error $_ }
        throw "Cannot create Authentication Policy. See errors above."
    }
    
    $context = $prereq.Context
    
    # Check if policy already exists
    $existing = Get-TierAuthenticationPolicy -Name $Name -Server $Server
    if ($existing.Count -gt 0) {
        Write-Warning "Authentication Policy '$Name' already exists: $($existing[0].distinguishedName)"
        return $existing[0].distinguishedName
    }
    
    $policyDN = "CN=$Name,$($context.AuthPoliciesPath)"
    
    if ($PSCmdlet.ShouldProcess($policyDN, "Create Authentication Policy")) {
        $ldapPath = if ($Server) { "LDAP://$Server/$($context.AuthPoliciesPath)" } else { "LDAP://$($context.AuthPoliciesPath)" }
        $container = $null
        
        try {
            $container = New-Object DirectoryServices.DirectoryEntry($ldapPath)
            
            $newPolicy = $container.Children.Add("CN=$Name", 'msDS-AuthNPolicy')
            
            # Set enforced state
            $newPolicy.Properties['msDS-AuthNPolicyEnforced'].Add($Enforced) | Out-Null
            
            # Set description
            if ($Description) {
                $newPolicy.Properties['description'].Add($Description) | Out-Null
            }
            
            # Set TGT lifetime (in 100-nanosecond intervals, negative for relative time)
            $tgtLifetime = [Int64](-($TGTLifetimeMinutes * 60 * 10000000))
            $newPolicy.Properties['msDS-UserTGTLifetime'].Add($tgtLifetime) | Out-Null
            
            # Set allowed to authenticate from (if specified)
            if ($UserAllowedToAuthenticateFrom) {
                $newPolicy.Properties['msDS-UserAllowedToAuthenticateFrom'].Add($UserAllowedToAuthenticateFrom) | Out-Null
            }
            
            # Set allowed to authenticate to (if specified)
            if ($UserAllowedToAuthenticateTo) {
                $newPolicy.Properties['msDS-UserAllowedToAuthenticateTo'].Add($UserAllowedToAuthenticateTo) | Out-Null
            }
            
            $newPolicy.CommitChanges()
            
            Write-Verbose "Created Authentication Policy: $policyDN"
            return $policyDN
        }
        catch {
            Write-Error "Failed to create Authentication Policy '$Name': $($_.Exception.Message)"
            throw
        }
        finally {
            if ($container) { $container.Dispose() }
        }
    }
}

<#
.SYNOPSIS
    Updates an existing Authentication Policy.
#>
function Set-TierAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter()]
        [string]$Description,
        
        [Parameter()]
        [int]$TGTLifetimeMinutes,
        
        [Parameter()]
        [string]$UserAllowedToAuthenticateFrom,
        
        [Parameter()]
        [string]$UserAllowedToAuthenticateTo,
        
        [Parameter()]
        [bool]$Enforced,
        
        [Parameter()]
        [string]$Server
    )
    
    $existing = Get-TierAuthenticationPolicy -Name $Name -Server $Server
    if ($existing.Count -eq 0) {
        throw "Authentication Policy '$Name' not found"
    }
    
    $policyDN = $existing[0].distinguishedName
    
    if ($PSCmdlet.ShouldProcess($policyDN, "Update Authentication Policy")) {
        $ldapPath = if ($Server) { "LDAP://$Server/$policyDN" } else { "LDAP://$policyDN" }
        $entry = $null
        
        try {
            $entry = New-Object DirectoryServices.DirectoryEntry($ldapPath)
            
            if ($PSBoundParameters.ContainsKey('Description')) {
                $entry.Properties['description'].Clear()
                if ($Description) { $entry.Properties['description'].Add($Description) | Out-Null }
            }
            
            if ($PSBoundParameters.ContainsKey('TGTLifetimeMinutes')) {
                $tgtLifetime = [Int64](-($TGTLifetimeMinutes * 60 * 10000000))
                $entry.Properties['msDS-UserTGTLifetime'].Clear()
                $entry.Properties['msDS-UserTGTLifetime'].Add($tgtLifetime) | Out-Null
            }
            
            if ($PSBoundParameters.ContainsKey('UserAllowedToAuthenticateFrom')) {
                $entry.Properties['msDS-UserAllowedToAuthenticateFrom'].Clear()
                if ($UserAllowedToAuthenticateFrom) {
                    $entry.Properties['msDS-UserAllowedToAuthenticateFrom'].Add($UserAllowedToAuthenticateFrom) | Out-Null
                }
            }
            
            if ($PSBoundParameters.ContainsKey('Enforced')) {
                $entry.Properties['msDS-AuthNPolicyEnforced'].Clear()
                $entry.Properties['msDS-AuthNPolicyEnforced'].Add($Enforced) | Out-Null
            }
            
            $entry.CommitChanges()
            Write-Verbose "Updated Authentication Policy: $policyDN"
        }
        finally {
            if ($entry) { $entry.Dispose() }
        }
    }
}

<#
.SYNOPSIS
    Removes an Authentication Policy.
#>
function Remove-TierAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter()]
        [string]$Server
    )
    
    $existing = Get-TierAuthenticationPolicy -Name $Name -Server $Server
    if ($existing.Count -eq 0) {
        Write-Warning "Authentication Policy '$Name' not found"
        return
    }
    
    $policyDN = $existing[0].distinguishedName
    
    if ($PSCmdlet.ShouldProcess($policyDN, "Remove Authentication Policy")) {
        $context = Get-AuthPolicyForestContext -Server $Server
        $ldapPath = if ($Server) { "LDAP://$Server/$($context.AuthPoliciesPath)" } else { "LDAP://$($context.AuthPoliciesPath)" }
        $container = $null
        
        try {
            $container = New-Object DirectoryServices.DirectoryEntry($ldapPath)
            $policyEntry = $container.Children.Find("CN=$Name", 'msDS-AuthNPolicy')
            $container.Children.Remove($policyEntry)
            $container.CommitChanges()
            
            Write-Verbose "Removed Authentication Policy: $policyDN"
        }
        finally {
            if ($container) { $container.Dispose() }
        }
    }
}

#endregion

#region Authentication Policy Silo Management

<#
.SYNOPSIS
    Gets Authentication Policy Silos from the forest Configuration NC.
#>
function Get-TierAuthenticationSilo {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[hashtable]])]
    param(
        [Parameter()]
        [string]$Name,
        
        [Parameter()]
        [string]$Server
    )
    
    $context = Get-AuthPolicyForestContext -Server $Server
    
    $filter = if ($Name) {
        "(&(objectClass=msDS-AuthNPolicySilo)(cn=$Name))"
    }
    else {
        '(objectClass=msDS-AuthNPolicySilo)'
    }
    
    $properties = @(
        'distinguishedName', 'cn', 'name', 'description',
        'msDS-AuthNPolicySiloEnforced',
        'msDS-AuthNPolicySiloMembers',
        'msDS-UserAuthNPolicy',
        'msDS-ComputerAuthNPolicy',
        'msDS-ServiceAuthNPolicy',
        'whenCreated', 'whenChanged'
    )
    
    return Search-AdsiDirectory -SearchBase $context.AuthSilosPath -LdapFilter $filter `
        -Properties $properties -Server $Server
}

<#
.SYNOPSIS
    Creates a new Authentication Policy Silo for a tier.
    
.DESCRIPTION
    Creates an Authentication Policy Silo in the forest Configuration NC.
    Silos group users, computers, and services that should share authentication policies.
    
.PARAMETER Name
    Silo name (e.g., "TierGuard-Tier0-Silo").
    
.PARAMETER Description
    Silo description.
    
.PARAMETER UserAuthNPolicy
    DN of the Authentication Policy for users in this silo.
    
.PARAMETER ComputerAuthNPolicy
    DN of the Authentication Policy for computers in this silo.
    
.PARAMETER ServiceAuthNPolicy
    DN of the Authentication Policy for services in this silo.
    
.PARAMETER Enforced
    Whether silo is enforced (default: $true).
    
.EXAMPLE
    New-TierAuthenticationSilo -Name "TierGuard-Tier0-Silo" -UserAuthNPolicy $policyDN
#>
function New-TierAuthenticationSilo {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter()]
        [string]$Description = "ADTierGuard Authentication Policy Silo",
        
        [Parameter()]
        [string]$UserAuthNPolicy,
        
        [Parameter()]
        [string]$ComputerAuthNPolicy,
        
        [Parameter()]
        [string]$ServiceAuthNPolicy,
        
        [Parameter()]
        [bool]$Enforced = $true,
        
        [Parameter()]
        [string]$Server
    )
    
    # Validate prerequisites
    $prereq = Test-AuthPolicyPrerequisites -Server $Server
    if (-not $prereq.CanProceed) {
        $prereq.Issues | ForEach-Object { Write-Error $_ }
        throw "Cannot create Authentication Policy Silo. See errors above."
    }
    
    $context = $prereq.Context
    
    # Check if silo already exists
    $existing = Get-TierAuthenticationSilo -Name $Name -Server $Server
    if ($existing.Count -gt 0) {
        Write-Warning "Authentication Policy Silo '$Name' already exists: $($existing[0].distinguishedName)"
        return $existing[0].distinguishedName
    }
    
    $siloDN = "CN=$Name,$($context.AuthSilosPath)"
    
    if ($PSCmdlet.ShouldProcess($siloDN, "Create Authentication Policy Silo")) {
        $ldapPath = if ($Server) { "LDAP://$Server/$($context.AuthSilosPath)" } else { "LDAP://$($context.AuthSilosPath)" }
        $container = $null
        
        try {
            $container = New-Object DirectoryServices.DirectoryEntry($ldapPath)
            
            $newSilo = $container.Children.Add("CN=$Name", 'msDS-AuthNPolicySilo')
            
            # Set enforced state
            $newSilo.Properties['msDS-AuthNPolicySiloEnforced'].Add($Enforced) | Out-Null
            
            # Set description
            if ($Description) {
                $newSilo.Properties['description'].Add($Description) | Out-Null
            }
            
            # Link authentication policies
            if ($UserAuthNPolicy) {
                $newSilo.Properties['msDS-UserAuthNPolicy'].Add($UserAuthNPolicy) | Out-Null
            }
            
            if ($ComputerAuthNPolicy) {
                $newSilo.Properties['msDS-ComputerAuthNPolicy'].Add($ComputerAuthNPolicy) | Out-Null
            }
            
            if ($ServiceAuthNPolicy) {
                $newSilo.Properties['msDS-ServiceAuthNPolicy'].Add($ServiceAuthNPolicy) | Out-Null
            }
            
            $newSilo.CommitChanges()
            
            Write-Verbose "Created Authentication Policy Silo: $siloDN"
            return $siloDN
        }
        catch {
            Write-Error "Failed to create Authentication Policy Silo '$Name': $($_.Exception.Message)"
            throw
        }
        finally {
            if ($container) { $container.Dispose() }
        }
    }
}

<#
.SYNOPSIS
    Adds a member (user, computer, or service) to an Authentication Policy Silo.
    
.DESCRIPTION
    Adds a principal to the silo's member list (msDS-AuthNPolicySiloMembers) AND
    sets the principal's assigned silo (msDS-AssignedAuthNPolicySilo).
    
    Both operations are required for silo membership to be effective.
#>
function Add-TierSiloMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SiloName,
        
        [Parameter(Mandatory)]
        [string]$MemberDN,
        
        [Parameter()]
        [string]$Server
    )
    
    $silo = Get-TierAuthenticationSilo -Name $SiloName -Server $Server
    if ($silo.Count -eq 0) {
        throw "Authentication Policy Silo '$SiloName' not found"
    }
    
    $siloDN = $silo[0].distinguishedName
    
    if ($PSCmdlet.ShouldProcess($MemberDN, "Add to Silo '$SiloName'")) {
        # Step 1: Add member to silo's member list
        $siloLdapPath = if ($Server) { "LDAP://$Server/$siloDN" } else { "LDAP://$siloDN" }
        $siloEntry = $null
        
        try {
            $siloEntry = New-Object DirectoryServices.DirectoryEntry($siloLdapPath)
            
            # Check if already a member
            $existingMembers = @($siloEntry.Properties['msDS-AuthNPolicySiloMembers'])
            if ($MemberDN -notin $existingMembers) {
                $siloEntry.Properties['msDS-AuthNPolicySiloMembers'].Add($MemberDN) | Out-Null
                $siloEntry.CommitChanges()
                Write-Verbose "Added $MemberDN to silo member list"
            }
        }
        finally {
            if ($siloEntry) { $siloEntry.Dispose() }
        }
        
        # Step 2: Set the member's assigned silo attribute
        $memberLdapPath = if ($Server) { "LDAP://$Server/$MemberDN" } else { "LDAP://$MemberDN" }
        $memberEntry = $null
        
        try {
            $memberEntry = New-Object DirectoryServices.DirectoryEntry($memberLdapPath)
            $memberEntry.Properties['msDS-AssignedAuthNPolicySilo'].Clear()
            $memberEntry.Properties['msDS-AssignedAuthNPolicySilo'].Add($siloDN) | Out-Null
            $memberEntry.CommitChanges()
            Write-Verbose "Set msDS-AssignedAuthNPolicySilo on $MemberDN"
        }
        finally {
            if ($memberEntry) { $memberEntry.Dispose() }
        }
    }
}

<#
.SYNOPSIS
    Removes a member from an Authentication Policy Silo.
#>
function Remove-TierSiloMember {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SiloName,
        
        [Parameter(Mandatory)]
        [string]$MemberDN,
        
        [Parameter()]
        [string]$Server
    )
    
    $silo = Get-TierAuthenticationSilo -Name $SiloName -Server $Server
    if ($silo.Count -eq 0) {
        throw "Authentication Policy Silo '$SiloName' not found"
    }
    
    $siloDN = $silo[0].distinguishedName
    
    if ($PSCmdlet.ShouldProcess($MemberDN, "Remove from Silo '$SiloName'")) {
        # Step 1: Remove member from silo's member list
        $siloLdapPath = if ($Server) { "LDAP://$Server/$siloDN" } else { "LDAP://$siloDN" }
        $siloEntry = $null
        
        try {
            $siloEntry = New-Object DirectoryServices.DirectoryEntry($siloLdapPath)
            $siloEntry.Properties['msDS-AuthNPolicySiloMembers'].Remove($MemberDN)
            $siloEntry.CommitChanges()
        }
        finally {
            if ($siloEntry) { $siloEntry.Dispose() }
        }
        
        # Step 2: Clear the member's assigned silo attribute
        $memberLdapPath = if ($Server) { "LDAP://$Server/$MemberDN" } else { "LDAP://$MemberDN" }
        $memberEntry = $null
        
        try {
            $memberEntry = New-Object DirectoryServices.DirectoryEntry($memberLdapPath)
            $memberEntry.Properties['msDS-AssignedAuthNPolicySilo'].Clear()
            $memberEntry.CommitChanges()
        }
        finally {
            if ($memberEntry) { $memberEntry.Dispose() }
        }
    }
}

<#
.SYNOPSIS
    Updates an Authentication Policy Silo.
#>
function Set-TierAuthenticationSilo {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter()]
        [string]$Description,
        
        [Parameter()]
        [string]$UserAuthNPolicy,
        
        [Parameter()]
        [string]$ComputerAuthNPolicy,
        
        [Parameter()]
        [string]$ServiceAuthNPolicy,
        
        [Parameter()]
        [bool]$Enforced,
        
        [Parameter()]
        [string]$Server
    )
    
    $existing = Get-TierAuthenticationSilo -Name $Name -Server $Server
    if ($existing.Count -eq 0) {
        throw "Authentication Policy Silo '$Name' not found"
    }
    
    $siloDN = $existing[0].distinguishedName
    
    if ($PSCmdlet.ShouldProcess($siloDN, "Update Authentication Policy Silo")) {
        $ldapPath = if ($Server) { "LDAP://$Server/$siloDN" } else { "LDAP://$siloDN" }
        $entry = $null
        
        try {
            $entry = New-Object DirectoryServices.DirectoryEntry($ldapPath)
            
            if ($PSBoundParameters.ContainsKey('Description')) {
                $entry.Properties['description'].Clear()
                if ($Description) { $entry.Properties['description'].Add($Description) | Out-Null }
            }
            
            if ($PSBoundParameters.ContainsKey('UserAuthNPolicy')) {
                $entry.Properties['msDS-UserAuthNPolicy'].Clear()
                if ($UserAuthNPolicy) { $entry.Properties['msDS-UserAuthNPolicy'].Add($UserAuthNPolicy) | Out-Null }
            }
            
            if ($PSBoundParameters.ContainsKey('ComputerAuthNPolicy')) {
                $entry.Properties['msDS-ComputerAuthNPolicy'].Clear()
                if ($ComputerAuthNPolicy) { $entry.Properties['msDS-ComputerAuthNPolicy'].Add($ComputerAuthNPolicy) | Out-Null }
            }
            
            if ($PSBoundParameters.ContainsKey('ServiceAuthNPolicy')) {
                $entry.Properties['msDS-ServiceAuthNPolicy'].Clear()
                if ($ServiceAuthNPolicy) { $entry.Properties['msDS-ServiceAuthNPolicy'].Add($ServiceAuthNPolicy) | Out-Null }
            }
            
            if ($PSBoundParameters.ContainsKey('Enforced')) {
                $entry.Properties['msDS-AuthNPolicySiloEnforced'].Clear()
                $entry.Properties['msDS-AuthNPolicySiloEnforced'].Add($Enforced) | Out-Null
            }
            
            $entry.CommitChanges()
            Write-Verbose "Updated Authentication Policy Silo: $siloDN"
        }
        finally {
            if ($entry) { $entry.Dispose() }
        }
    }
}

<#
.SYNOPSIS
    Removes an Authentication Policy Silo.
#>
function Remove-TierAuthenticationSilo {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter()]
        [string]$Server
    )
    
    $existing = Get-TierAuthenticationSilo -Name $Name -Server $Server
    if ($existing.Count -eq 0) {
        Write-Warning "Authentication Policy Silo '$Name' not found"
        return
    }
    
    $siloDN = $existing[0].distinguishedName
    
    if ($PSCmdlet.ShouldProcess($siloDN, "Remove Authentication Policy Silo")) {
        $context = Get-AuthPolicyForestContext -Server $Server
        $ldapPath = if ($Server) { "LDAP://$Server/$($context.AuthSilosPath)" } else { "LDAP://$($context.AuthSilosPath)" }
        $container = $null
        
        try {
            $container = New-Object DirectoryServices.DirectoryEntry($ldapPath)
            $siloEntry = $container.Children.Find("CN=$Name", 'msDS-AuthNPolicySilo')
            $container.Children.Remove($siloEntry)
            $container.CommitChanges()
            
            Write-Verbose "Removed Authentication Policy Silo: $siloDN"
        }
        finally {
            if ($container) { $container.Dispose() }
        }
    }
}

#endregion

#region Tier Policy/Silo Initialization

<#
.SYNOPSIS
    Initializes complete Authentication Policy and Silo structure for a tier.
    
.DESCRIPTION
    Creates both the Authentication Policy AND the Authentication Policy Silo
    for a given tier level. This is the recommended way to set up tier-based
    authentication restrictions.
    
    For Policy + Silo approach:
    - Policy defines the authentication rules (TGT lifetime, allowed from/to)
    - Silo groups users/computers/services that share the policy
    - Both work together for credential isolation
    
    For Policy-only approach:
    - Policy is assigned directly to users via msDS-AssignedAuthNPolicy
    - No silo membership required
    - Less isolation but simpler
    
.PARAMETER TierLevel
    The tier level (0 or 1).
    
.PARAMETER Prefix
    Naming prefix (default: TierGuard).
    
.PARAMETER TGTLifetimeMinutes
    TGT lifetime in minutes.
    
.PARAMETER UseSilo
    Create a silo in addition to the policy.
    
.PARAMETER PAWGroupDN
    DN of the group containing PAW/tier workstations for authentication restrictions.
    
.EXAMPLE
    Initialize-TierAuthenticationPolicy -TierLevel 0 -UseSilo -PAWGroupDN "CN=Tier0-PAWs,OU=Groups,..."
#>
function Initialize-TierAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(0, 1)]
        [int]$TierLevel,
        
        [Parameter()]
        [string]$Prefix = 'TierGuard',
        
        [Parameter()]
        [int]$TGTLifetimeMinutes,
        
        [Parameter()]
        [switch]$UseSilo,
        
        [Parameter()]
        [string]$PAWGroupDN,
        
        [Parameter()]
        [string]$Server
    )
    
    # Validate prerequisites
    $prereq = Test-AuthPolicyPrerequisites -Server $Server -RequireForestRoot
    
    if (-not $prereq.CanProceed) {
        $prereq.Issues | ForEach-Object { Write-Error $_ }
        throw "Prerequisites not met. See errors above."
    }
    
    if (-not $prereq.IsForestRoot) {
        Write-Warning "Current domain is not the forest root. Proceeding, but ensure you have Enterprise Admin permissions."
    }
    
    # Default TGT lifetimes
    if (-not $TGTLifetimeMinutes) {
        $TGTLifetimeMinutes = switch ($TierLevel) {
            0 { 240 }   # 4 hours for Tier 0
            1 { 480 }   # 8 hours for Tier 1
        }
    }
    
    $policyName = "$Prefix-Tier$TierLevel-AuthPolicy"
    $siloName = "$Prefix-Tier$TierLevel-Silo"
    
    $result = @{
        TierLevel  = $TierLevel
        PolicyName = $policyName
        PolicyDN   = $null
        SiloName   = $null
        SiloDN     = $null
        UseSilo    = $UseSilo.IsPresent
    }
    
    # Build SDDL for UserAllowedToAuthenticateFrom if PAW group specified
    $allowedFromSddl = $null
    if ($PAWGroupDN) {
        # Get SID of PAW group
        $pawGroup = Search-AdsiDirectory -SearchBase $PAWGroupDN -LdapFilter '(objectClass=group)' -Properties @('objectSid') -Server $Server
        if ($pawGroup.Count -gt 0) {
            $pawSid = New-Object System.Security.Principal.SecurityIdentifier($pawGroup[0].objectSid, 0)
            
            if ($UseSilo) {
                # With silo: Allow from silo members OR PAW group members
                $allowedFromSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"$siloName`") || (Member_of_any {SID($($pawSid.Value))}))"
            }
            else {
                # Without silo: Allow only from PAW group members
                $allowedFromSddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($($pawSid.Value))}))"
            }
        }
    }
    
    # Create Authentication Policy
    Write-Host "Creating Authentication Policy: $policyName" -ForegroundColor Cyan
    
    $policyParams = @{
        Name              = $policyName
        Description       = "ADTierGuard Tier $TierLevel Authentication Policy"
        TGTLifetimeMinutes = $TGTLifetimeMinutes
        Enforced          = $true
        Server            = $Server
    }
    
    if ($allowedFromSddl) {
        $policyParams['UserAllowedToAuthenticateFrom'] = $allowedFromSddl
    }
    
    $result.PolicyDN = New-TierAuthenticationPolicy @policyParams
    
    # Create Authentication Policy Silo (if requested)
    if ($UseSilo) {
        Write-Host "Creating Authentication Policy Silo: $siloName" -ForegroundColor Cyan
        
        $result.SiloName = $siloName
        $result.SiloDN = New-TierAuthenticationSilo `
            -Name $siloName `
            -Description "ADTierGuard Tier $TierLevel Authentication Policy Silo" `
            -UserAuthNPolicy $result.PolicyDN `
            -ComputerAuthNPolicy $result.PolicyDN `
            -Enforced $true `
            -Server $Server
    }
    
    return $result
}

<#
.SYNOPSIS
    Gets the current status of tier authentication policies and silos.
#>
function Get-TierAuthenticationStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Prefix = 'TierGuard',
        
        [Parameter()]
        [string]$Server
    )
    
    $context = Get-AuthPolicyForestContext -Server $Server
    
    $status = @{
        ForestContext = $context
        Tier0         = @{
            Policy = $null
            Silo   = $null
        }
        Tier1         = @{
            Policy = $null
            Silo   = $null
        }
    }
    
    # Check Tier 0
    $t0Policy = Get-TierAuthenticationPolicy -Name "$Prefix-Tier0-AuthPolicy" -Server $Server
    $t0Silo = Get-TierAuthenticationSilo -Name "$Prefix-Tier0-Silo" -Server $Server
    
    $status.Tier0.Policy = if ($t0Policy.Count -gt 0) {
        @{
            Exists   = $true
            DN       = $t0Policy[0].distinguishedName
            Enforced = $t0Policy[0].'msDS-AuthNPolicyEnforced'
        }
    }
    else {
        @{ Exists = $false }
    }
    
    $status.Tier0.Silo = if ($t0Silo.Count -gt 0) {
        @{
            Exists   = $true
            DN       = $t0Silo[0].distinguishedName
            Enforced = $t0Silo[0].'msDS-AuthNPolicySiloEnforced'
            Members  = @($t0Silo[0].'msDS-AuthNPolicySiloMembers').Count
        }
    }
    else {
        @{ Exists = $false }
    }
    
    # Check Tier 1
    $t1Policy = Get-TierAuthenticationPolicy -Name "$Prefix-Tier1-AuthPolicy" -Server $Server
    $t1Silo = Get-TierAuthenticationSilo -Name "$Prefix-Tier1-Silo" -Server $Server
    
    $status.Tier1.Policy = if ($t1Policy.Count -gt 0) {
        @{
            Exists   = $true
            DN       = $t1Policy[0].distinguishedName
            Enforced = $t1Policy[0].'msDS-AuthNPolicyEnforced'
        }
    }
    else {
        @{ Exists = $false }
    }
    
    $status.Tier1.Silo = if ($t1Silo.Count -gt 0) {
        @{
            Exists   = $true
            DN       = $t1Silo[0].distinguishedName
            Enforced = $t1Silo[0].'msDS-AuthNPolicySiloEnforced'
            Members  = @($t1Silo[0].'msDS-AuthNPolicySiloMembers').Count
        }
    }
    else {
        @{ Exists = $false }
    }
    
    return $status
}

#endregion

#region User Policy Assignment

<#
.SYNOPSIS
    Assigns an Authentication Policy to a user (policy-only approach).
    
.DESCRIPTION
    Sets the msDS-AssignedAuthNPolicy attribute on a user to enforce
    authentication restrictions without using a silo.
#>
function Set-UserAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$UserDN,
        
        [Parameter(Mandatory)]
        [string]$PolicyDN,
        
        [Parameter()]
        [string]$Server
    )
    
    if ($PSCmdlet.ShouldProcess($UserDN, "Assign Authentication Policy")) {
        $ldapPath = if ($Server) { "LDAP://$Server/$UserDN" } else { "LDAP://$UserDN" }
        $entry = $null
        
        try {
            $entry = New-Object DirectoryServices.DirectoryEntry($ldapPath)
            $entry.Properties['msDS-AssignedAuthNPolicy'].Clear()
            $entry.Properties['msDS-AssignedAuthNPolicy'].Add($PolicyDN) | Out-Null
            $entry.CommitChanges()
            
            Write-Verbose "Assigned Authentication Policy to: $UserDN"
        }
        finally {
            if ($entry) { $entry.Dispose() }
        }
    }
}

<#
.SYNOPSIS
    Removes the Authentication Policy assignment from a user.
#>
function Remove-UserAuthenticationPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$UserDN,
        
        [Parameter()]
        [string]$Server
    )
    
    if ($PSCmdlet.ShouldProcess($UserDN, "Remove Authentication Policy")) {
        $ldapPath = if ($Server) { "LDAP://$Server/$UserDN" } else { "LDAP://$UserDN" }
        $entry = $null
        
        try {
            $entry = New-Object DirectoryServices.DirectoryEntry($ldapPath)
            $entry.Properties['msDS-AssignedAuthNPolicy'].Clear()
            $entry.CommitChanges()
            
            Write-Verbose "Removed Authentication Policy from: $UserDN"
        }
        finally {
            if ($entry) { $entry.Dispose() }
        }
    }
}

#endregion

#region Module Exports

Export-ModuleMember -Function @(
    # Forest Context
    'Get-AuthPolicyForestContext'
    'Test-AuthPolicyPrerequisites'
    
    # Authentication Policies
    'Get-TierAuthenticationPolicy'
    'New-TierAuthenticationPolicy'
    'Set-TierAuthenticationPolicy'
    'Remove-TierAuthenticationPolicy'
    
    # Authentication Policy Silos
    'Get-TierAuthenticationSilo'
    'New-TierAuthenticationSilo'
    'Set-TierAuthenticationSilo'
    'Remove-TierAuthenticationSilo'
    'Add-TierSiloMember'
    'Remove-TierSiloMember'
    
    # Tier Initialization
    'Initialize-TierAuthenticationPolicy'
    'Get-TierAuthenticationStatus'
    
    # User Assignment
    'Set-UserAuthenticationPolicy'
    'Remove-UserAuthenticationPolicy'
)

#endregion
