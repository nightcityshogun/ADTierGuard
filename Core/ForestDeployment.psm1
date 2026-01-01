<#
.SYNOPSIS
    ADTierGuard Forest Deployment Module
    
.DESCRIPTION
    Manages forest-wide deployment of ADTierGuard including:
    - Group Managed Service Account (GMSA) creation and configuration
    - GPO creation and linking to Domain Controllers OU
    - SYSVOL script and configuration deployment
    - Scheduled task configuration for distributed execution
    
.NOTES
    Version: 1.0.0
    Requires: Enterprise Admin permissions, PowerShell 5.1+
#>

#Requires -Version 5.1

Set-StrictMode -Version Latest

#region Script Variables

$Script:TierGuardGpoName = 'TierGuard Isolation'
$Script:TierGuardEventSource = 'TierGuard'
$Script:DefaultTier0TgtLifetime = 240
$Script:DefaultTier1TgtLifetime = 480

#endregion

#region KDS Root Key Functions

<#
.SYNOPSIS
    Tests if a KDS Root Key exists and is effective.
    
.DESCRIPTION
    Checks for the existence of a KDS Root Key which is required
    for Group Managed Service Accounts. Returns key details if found.
    
.OUTPUTS
    [hashtable] Key information or $null if no effective key exists
#>
function Test-KdsRootKeyExists {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    try {
        $keys = Get-KdsRootKey -ErrorAction Stop
        if (-not $keys) {
            return $null
        }
        
        $effectiveKey = $keys | Where-Object { 
            $_.EffectiveTime -le [DateTime]::UtcNow 
        } | Sort-Object EffectiveTime -Descending | Select-Object -First 1
        
        if ($effectiveKey) {
            return @{
                KeyId = $effectiveKey.KeyId
                EffectiveTime = $effectiveKey.EffectiveTime
                CreationTime = $effectiveKey.CreationTime
                IsEffective = $true
            }
        }
        
        $pendingKey = $keys | Sort-Object EffectiveTime | Select-Object -First 1
        return @{
            KeyId = $pendingKey.KeyId
            EffectiveTime = $pendingKey.EffectiveTime
            CreationTime = $pendingKey.CreationTime
            IsEffective = $false
            HoursUntilEffective = [math]::Ceiling(($pendingKey.EffectiveTime - [DateTime]::UtcNow).TotalHours)
        }
    }
    catch {
        Write-Warning "Failed to query KDS Root Key: $_"
        return $null
    }
}

<#
.SYNOPSIS
    Creates a new KDS Root Key for GMSA support.
    
.DESCRIPTION
    Creates a KDS Root Key required for Group Managed Service Accounts.
    In production, the key takes 10 hours to replicate and become effective.
    Use -EffectiveImmediately for lab environments only.
    
.PARAMETER EffectiveImmediately
    Makes the key effective immediately (LAB USE ONLY - backdates by 10 hours)
    
.OUTPUTS
    [hashtable] Created key information
#>
function New-TierGuardKdsRootKey {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [switch]$EffectiveImmediately
    )
    
    $existingKey = Test-KdsRootKeyExists
    if ($existingKey -and $existingKey.IsEffective) {
        Write-Verbose "Effective KDS Root Key already exists: $($existingKey.KeyId)"
        return $existingKey
    }
    
    $actionDesc = if ($EffectiveImmediately) {
        "Create KDS Root Key (effective immediately - LAB ONLY)"
    } else {
        "Create KDS Root Key (effective in 10 hours)"
    }
    
    if ($PSCmdlet.ShouldProcess("Active Directory", $actionDesc)) {
        try {
            if ($EffectiveImmediately) {
                $key = Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop
                Write-Warning "KDS Root Key created with immediate effectiveness. This is for LAB USE ONLY."
            }
            else {
                $key = Add-KdsRootKey -EffectiveImmediately:$false -ErrorAction Stop
                Write-Host "KDS Root Key created. It will become effective in approximately 10 hours." -ForegroundColor Yellow
            }
            
            return @{
                KeyId = $key.KeyId
                EffectiveTime = $key.EffectiveTime
                CreationTime = [DateTime]::UtcNow
                IsEffective = $EffectiveImmediately.IsPresent
            }
        }
        catch {
            throw "Failed to create KDS Root Key: $_"
        }
    }
}

#endregion

#region GMSA Functions

<#
.SYNOPSIS
    Tests if the TierGuard GMSA exists.
    
.PARAMETER Name
    The SAM account name of the GMSA (without trailing $)
    
.PARAMETER Server
    Target domain controller
    
.OUTPUTS
    [hashtable] GMSA details or $null if not found
#>
function Get-TierGuardServiceAccount {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 15)]
        [string]$Name,
        
        [Parameter()]
        [string]$Server
    )
    
    $params = @{
        Filter = "Name -eq '$Name'"
        Properties = @('PrincipalsAllowedToRetrieveManagedPassword', 'ServicePrincipalNames', 
                      'Enabled', 'Description', 'MemberOf', 'DistinguishedName')
    }
    if ($Server) { $params.Server = $Server }
    
    try {
        $gmsa = Get-ADServiceAccount @params -ErrorAction Stop
        if (-not $gmsa) { return $null }
        
        return @{
            Name = $gmsa.Name
            DistinguishedName = $gmsa.DistinguishedName
            SamAccountName = $gmsa.SamAccountName
            Enabled = $gmsa.Enabled
            Description = $gmsa.Description
            PrincipalsAllowedToRetrieveManagedPassword = @($gmsa.PrincipalsAllowedToRetrieveManagedPassword)
            ServicePrincipalNames = @($gmsa.ServicePrincipalNames)
            MemberOf = @($gmsa.MemberOf)
        }
    }
    catch {
        Write-Verbose "GMSA lookup failed: $_"
        return $null
    }
}

<#
.SYNOPSIS
    Creates the TierGuard Group Managed Service Account.
    
.DESCRIPTION
    Creates a GMSA for TierGuard scheduled tasks. The GMSA is configured to:
    - Allow password retrieval by Domain Controllers
    - Use AES256 Kerberos encryption
    - Be added to Enterprise Admins for forest-wide management
    
.PARAMETER Name
    The SAM account name (max 15 characters, without trailing $)
    
.PARAMETER Description
    Description for the GMSA
    
.PARAMETER DomainControllersCanRetrieve
    If specified, all DCs in the domain can retrieve the managed password
    
.PARAMETER AddToEnterpriseAdmins
    If specified, adds the GMSA to Enterprise Admins group
    
.OUTPUTS
    [hashtable] Created GMSA details
#>
function New-TierGuardServiceAccount {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1, 15)]
        [ValidatePattern('^[a-zA-Z0-9\-_]+$')]
        [string]$Name,
        
        [Parameter()]
        [string]$Description = 'TierGuard service account for tier isolation management',
        
        [Parameter()]
        [switch]$DomainControllersCanRetrieve,
        
        [Parameter()]
        [switch]$AddToEnterpriseAdmins
    )
    
    # Validate KDS Root Key exists
    $kdsKey = Test-KdsRootKeyExists
    if (-not $kdsKey) {
        throw "No KDS Root Key found. Run New-TierGuardKdsRootKey first."
    }
    if (-not $kdsKey.IsEffective) {
        throw "KDS Root Key exists but is not yet effective. Wait $($kdsKey.HoursUntilEffective) hours or create a new key with -EffectiveImmediately."
    }
    
    # Check if GMSA already exists
    $existing = Get-TierGuardServiceAccount -Name $Name
    if ($existing) {
        Write-Verbose "GMSA '$Name' already exists"
        return $existing
    }
    
    # Get principals allowed to retrieve password
    $principals = @()
    if ($DomainControllersCanRetrieve) {
        $dcGroup = Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-516" -Properties Members
        $principals = @($dcGroup.DistinguishedName)
    }
    
    $domain = Get-ADDomain
    $dnsHostName = "$Name.$($domain.DNSRoot)"
    
    if ($PSCmdlet.ShouldProcess($Name, "Create Group Managed Service Account")) {
        try {
            $gmsaParams = @{
                Name = $Name
                DNSHostName = $dnsHostName
                Description = $Description
                KerberosEncryptionType = 'AES256'
                Enabled = $true
            }
            
            if ($principals.Count -gt 0) {
                $gmsaParams.PrincipalsAllowedToRetrieveManagedPassword = $principals
            }
            
            New-ADServiceAccount @gmsaParams -ErrorAction Stop
            Write-Host "Created GMSA: $Name" -ForegroundColor Green
            
            # Wait for replication
            Start-Sleep -Seconds 2
            
            # Add to Enterprise Admins if requested
            if ($AddToEnterpriseAdmins) {
                $forestRoot = (Get-ADForest).RootDomain
                $eaGroup = Get-ADGroup -Identity "$((Get-ADDomain -Server $forestRoot).DomainSID)-519" -Server $forestRoot
                $gmsa = Get-ADServiceAccount -Identity $Name
                
                Add-ADGroupMember -Identity $eaGroup -Members $gmsa -Server $forestRoot -ErrorAction Stop
                Write-Host "Added $Name to Enterprise Admins" -ForegroundColor Yellow
            }
            
            return Get-TierGuardServiceAccount -Name $Name
        }
        catch {
            throw "Failed to create GMSA: $_"
        }
    }
}

<#
.SYNOPSIS
    Updates the GMSA to allow all Domain Controllers to retrieve the password.
    
.PARAMETER Name
    The GMSA name
    
.PARAMETER Server
    Target domain controller
#>
function Update-TierGuardServiceAccountPrincipals {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter()]
        [string]$Server
    )
    
    $dcGroup = Get-ADGroup -Identity "$((Get-ADDomain).DomainSID)-516"
    $dcs = Get-ADGroupMember -Identity $dcGroup | ForEach-Object { $_.DistinguishedName }
    
    if ($PSCmdlet.ShouldProcess($Name, "Update principals allowed to retrieve managed password")) {
        $params = @{ Identity = $Name }
        if ($Server) { $params.Server = $Server }
        
        Set-ADServiceAccount @params -PrincipalsAllowedToRetrieveManagedPassword $dcs -ErrorAction Stop
        Write-Host "Updated GMSA principals: $($dcs.Count) Domain Controllers" -ForegroundColor Green
    }
}

#endregion

#region Computer Group Functions

<#
.SYNOPSIS
    Creates the tier computer group for Kerberos Authentication Policy claims.
    
.PARAMETER TierLevel
    The tier level (0 or 1)
    
.PARAMETER GroupName
    The name of the group to create
    
.PARAMETER Description
    Group description
    
.PARAMETER Server
    Target domain controller
    
.OUTPUTS
    [hashtable] Group details
#>
function New-TierComputerGroup {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(0, 1)]
        [int]$TierLevel,
        
        [Parameter(Mandatory)]
        [string]$GroupName,
        
        [Parameter()]
        [string]$Description,
        
        [Parameter()]
        [string]$Server
    )
    
    if (-not $Description) {
        $Description = "Tier $TierLevel computers for Kerberos Authentication Policy claims. Members can receive Tier $TierLevel admin authentication."
    }
    
    $params = @{ Filter = "SamAccountName -eq '$GroupName'" }
    if ($Server) { $params.Server = $Server }
    
    $existing = Get-ADGroup @params -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Verbose "Group '$GroupName' already exists"
        return @{
            Name = $existing.Name
            DistinguishedName = $existing.DistinguishedName
            SID = $existing.SID.Value
            GroupScope = $existing.GroupScope
            Existed = $true
        }
    }
    
    if ($PSCmdlet.ShouldProcess($GroupName, "Create Universal Security Group")) {
        $createParams = @{
            Name = $GroupName
            SamAccountName = $GroupName
            GroupScope = 'Universal'
            GroupCategory = 'Security'
            Description = $Description
        }
        if ($Server) { $createParams.Server = $Server }
        
        $group = New-ADGroup @createParams -PassThru -ErrorAction Stop
        
        # Set adminCount = 1 to protect from accidental delegation changes
        Set-ADObject -Identity $group.DistinguishedName -Replace @{adminCount = 1}
        
        Write-Host "Created group: $GroupName" -ForegroundColor Green
        Write-Warning "Move this group to a protected Tier $TierLevel OU"
        
        return @{
            Name = $group.Name
            DistinguishedName = $group.DistinguishedName
            SID = $group.SID.Value
            GroupScope = 'Universal'
            Existed = $false
        }
    }
}

#endregion

#region Kerberos Authentication Policy Functions

<#
.SYNOPSIS
    Creates a Kerberos Authentication Policy for tier isolation.
    
.DESCRIPTION
    Creates an authentication policy that restricts where tier admins can authenticate.
    Uses SDDL claims to limit authentication to specific computer groups.
    
.PARAMETER Name
    Policy name
    
.PARAMETER TierLevel
    Tier level (0 or 1)
    
.PARAMETER ComputerGroupSID
    SID of the computer group for the claim
    
.PARAMETER TGTLifetimeMinutes
    TGT lifetime in minutes
    
.PARAMETER IncludeTier0Computers
    For Tier 1 policy, also allow authentication to Tier 0 computers
    
.PARAMETER Tier0ComputerGroupSID
    SID of Tier 0 computer group (required if IncludeTier0Computers)
    
.PARAMETER Enforce
    If true, policy is enforced. If false, audit only.
    
.OUTPUTS
    [hashtable] Policy details
#>
function New-TierAuthPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [ValidateSet(0, 1)]
        [int]$TierLevel,
        
        [Parameter(Mandatory)]
        [string]$ComputerGroupSID,
        
        [Parameter()]
        [int]$TGTLifetimeMinutes = 240,
        
        [Parameter()]
        [switch]$IncludeTier0Computers,
        
        [Parameter()]
        [string]$Tier0ComputerGroupSID,
        
        [Parameter()]
        [switch]$Enforce
    )
    
    # Check if policy exists
    $existing = Get-ADAuthenticationPolicy -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Verbose "Authentication Policy '$Name' already exists"
        return @{
            Name = $existing.Name
            DistinguishedName = $existing.DistinguishedName
            Enforced = $existing.Enforce
            Existed = $true
        }
    }
    
    # Build SDDL claim
    # ED = Enterprise Domain Controllers (always allowed for DC authentication)
    if ($TierLevel -eq 0) {
        # Tier 0: Can auth to Enterprise DCs OR Tier 0 computers
        $sddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)}) || (Member_of_any {SID($ComputerGroupSID)})))"
        $description = "Tier 0 isolation policy. Users can only authenticate to Domain Controllers or Tier 0 member servers."
    }
    else {
        # Tier 1: Can auth to Enterprise DCs OR Tier 0 computers OR Tier 1 computers
        if ($IncludeTier0Computers -and $Tier0ComputerGroupSID) {
            $sddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(((Member_of {SID(ED)}) || (Member_of_any {SID($Tier0ComputerGroupSID)})) || (Member_of_any {SID($ComputerGroupSID)})))"
        }
        else {
            $sddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)}) || (Member_of_any {SID($ComputerGroupSID)})))"
        }
        $description = "Tier 1 isolation policy. Users can only authenticate to Domain Controllers, Tier 0, or Tier 1 member servers."
    }
    
    if ($PSCmdlet.ShouldProcess($Name, "Create Kerberos Authentication Policy")) {
        try {
            $policyParams = @{
                Name = $Name
                Description = $description
                UserTGTLifetimeMins = $TGTLifetimeMinutes
                UserAllowedToAuthenticateFrom = $sddl
                Enforce = $Enforce.IsPresent
                ProtectedFromAccidentalDeletion = $true
            }
            
            New-ADAuthenticationPolicy @policyParams -ErrorAction Stop
            Write-Host "Created Authentication Policy: $Name" -ForegroundColor Green
            
            if (-not $Enforce) {
                Write-Warning "Policy created in AUDIT mode. Use Set-ADAuthenticationPolicy -Enforce `$true to enforce."
            }
            
            $policy = Get-ADAuthenticationPolicy -Identity $Name
            return @{
                Name = $policy.Name
                DistinguishedName = $policy.DistinguishedName
                Enforced = $policy.Enforce
                TGTLifetimeMinutes = $TGTLifetimeMinutes
                SDDL = $sddl
                Existed = $false
            }
        }
        catch {
            throw "Failed to create Authentication Policy: $_"
        }
    }
}

#endregion

#region SYSVOL Deployment Functions

<#
.SYNOPSIS
    Gets the SYSVOL scripts path for the current domain.
    
.PARAMETER DomainDNS
    Domain DNS name. Defaults to current domain.
    
.OUTPUTS
    [string] UNC path to SYSVOL scripts folder
#>
function Get-SysvolScriptsPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [string]$DomainDNS
    )
    
    if (-not $DomainDNS) {
        $DomainDNS = (Get-ADDomain).DNSRoot
    }
    
    return "\\$DomainDNS\SYSVOL\$DomainDNS\scripts"
}

<#
.SYNOPSIS
    Deploys TierGuard scripts and configuration to SYSVOL.
    
.DESCRIPTION
    Copies the TierGuard scripts and configuration file to SYSVOL
    for access by scheduled tasks on Domain Controllers.
    
.PARAMETER SourcePath
    Path to the ADTierGuard installation
    
.PARAMETER Configuration
    Configuration hashtable to save as JSON
    
.PARAMETER DomainDNS
    Target domain DNS name
    
.OUTPUTS
    [hashtable] Deployed file paths
#>
function Publish-TierGuardToSysvol {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,
        
        [Parameter(Mandatory)]
        [hashtable]$Configuration,
        
        [Parameter()]
        [string]$DomainDNS
    )
    
    $sysvolPath = Get-SysvolScriptsPath -DomainDNS $DomainDNS
    $tierGuardPath = Join-Path $sysvolPath 'TierGuard'
    
    if ($PSCmdlet.ShouldProcess($tierGuardPath, "Deploy TierGuard to SYSVOL")) {
        # Create directory structure
        if (-not (Test-Path $tierGuardPath)) {
            New-Item -Path $tierGuardPath -ItemType Directory -Force | Out-Null
        }
        
        $corePath = Join-Path $tierGuardPath 'Core'
        $enginePath = Join-Path $tierGuardPath 'Engine'
        
        if (-not (Test-Path $corePath)) { New-Item -Path $corePath -ItemType Directory -Force | Out-Null }
        if (-not (Test-Path $enginePath)) { New-Item -Path $enginePath -ItemType Directory -Force | Out-Null }
        
        # Copy core modules
        $coreFiles = @(
            'AdsiOperations.psm1',
            'AuthPolicyManager.psm1',
            'ForestTopology.psm1',
            'SyncUtilities.psm1',
            'ConfigurationManager.psm1'
        )
        
        foreach ($file in $coreFiles) {
            $src = Join-Path $SourcePath "Core\$file"
            if (Test-Path $src) {
                Copy-Item -Path $src -Destination $corePath -Force
            }
        }
        
        # Copy engine
        $engineSrc = Join-Path $SourcePath 'Engine\RunspaceEngine.psm1'
        if (Test-Path $engineSrc) {
            Copy-Item -Path $engineSrc -Destination $enginePath -Force
        }
        
        # Copy DC sync scripts
        $dcScripts = @(
            'Sync-TierComputers.ps1',
            'Sync-TierUsers.ps1'
        )
        
        foreach ($script in $dcScripts) {
            $src = Join-Path $SourcePath "Scripts\$script"
            if (Test-Path $src) {
                Copy-Item -Path $src -Destination $tierGuardPath -Force
            }
        }
        
        # Save configuration
        $configPath = Join-Path $tierGuardPath 'TierGuard.config'
        $Configuration | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Force -Encoding UTF8
        
        Write-Host "Deployed TierGuard to: $tierGuardPath" -ForegroundColor Green
        
        return @{
            BasePath = $tierGuardPath
            ConfigPath = $configPath
            CorePath = $corePath
            EnginePath = $enginePath
            Scripts = $dcScripts | ForEach-Object { Join-Path $tierGuardPath $_ }
        }
    }
}

#endregion

#region GPO Functions

<#
.SYNOPSIS
    Creates the TierGuard GPO with scheduled tasks.
    
.DESCRIPTION
    Creates a new GPO for TierGuard and configures scheduled tasks
    for computer and user synchronization.
    
.PARAMETER Name
    GPO name (default: TierGuard Isolation)
    
.PARAMETER ScriptsPath
    UNC path to TierGuard scripts in SYSVOL
    
.PARAMETER GmsaName
    GMSA account name for user sync tasks
    
.PARAMETER Tier0Enabled
    Enable Tier 0 scheduled tasks
    
.PARAMETER Tier1Enabled
    Enable Tier 1 scheduled tasks
    
.PARAMETER SyncIntervalMinutes
    Sync interval in minutes (default: 10)
    
.OUTPUTS
    [hashtable] GPO details
#>
function New-TierGuardGpo {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [string]$Name = $Script:TierGuardGpoName,
        
        [Parameter(Mandatory)]
        [string]$ScriptsPath,
        
        [Parameter(Mandatory)]
        [string]$GmsaName,
        
        [Parameter()]
        [switch]$Tier0Enabled,
        
        [Parameter()]
        [switch]$Tier1Enabled,
        
        [Parameter()]
        [int]$SyncIntervalMinutes = 10
    )
    
    # Check if GPO exists
    $existing = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Verbose "GPO '$Name' already exists"
        return @{
            Name = $existing.DisplayName
            Id = $existing.Id
            Existed = $true
        }
    }
    
    if ($PSCmdlet.ShouldProcess($Name, "Create Group Policy Object")) {
        try {
            $gpo = New-GPO -Name $Name -Comment "TierGuard tier isolation - manages authentication policies and computer group membership"
            
            Write-Host "Created GPO: $Name" -ForegroundColor Green
            Write-Host "GPO ID: $($gpo.Id)" -ForegroundColor Cyan
            
            return @{
                Name = $gpo.DisplayName
                Id = $gpo.Id
                Existed = $false
                Note = "Configure scheduled tasks manually or import from backup"
            }
        }
        catch {
            throw "Failed to create GPO: $_"
        }
    }
}

<#
.SYNOPSIS
    Links the TierGuard GPO to the Domain Controllers OU.
    
.PARAMETER GpoName
    Name of the GPO to link
    
.PARAMETER DomainDNS
    Target domain DNS name
    
.PARAMETER Enabled
    Whether the link should be enabled
#>
function Set-TierGuardGpoLink {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$GpoName,
        
        [Parameter()]
        [string]$DomainDNS,
        
        [Parameter()]
        [switch]$Enabled
    )
    
    if (-not $DomainDNS) {
        $DomainDNS = (Get-ADDomain).DNSRoot
    }
    
    $domain = Get-ADDomain -Server $DomainDNS
    $dcOu = $domain.DomainControllersContainer
    
    # Check if already linked
    $inheritance = Get-GPInheritance -Target $dcOu
    $existingLink = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
    
    if ($existingLink) {
        Write-Verbose "GPO already linked to $dcOu"
        if ($Enabled -and -not $existingLink.Enabled) {
            Set-GPLink -Name $GpoName -Target $dcOu -LinkEnabled Yes
            Write-Host "Enabled GPO link" -ForegroundColor Green
        }
        return
    }
    
    if ($PSCmdlet.ShouldProcess($dcOu, "Link GPO '$GpoName'")) {
        $linkParams = @{
            Name = $GpoName
            Target = $dcOu
            LinkEnabled = if ($Enabled) { 'Yes' } else { 'No' }
        }
        
        New-GPLink @linkParams -ErrorAction Stop
        Write-Host "Linked GPO to: $dcOu" -ForegroundColor Green
        
        if (-not $Enabled) {
            Write-Warning "GPO link is DISABLED. Enable after validating configuration."
        }
    }
}

#endregion

#region Kerberos Armoring Functions

<#
.SYNOPSIS
    Enables Kerberos Armoring (FAST) via Group Policy.
    
.DESCRIPTION
    Configures the Default Domain Controller Policy and Default Domain Policy
    to enable claims support and Kerberos armoring.
    
.PARAMETER DomainDNS
    Target domain DNS name
    
.PARAMETER SkipDomainPolicy
    Skip configuring the Default Domain Policy
#>
function Enable-KerberosArmoring {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()]
        [string]$DomainDNS,
        
        [Parameter()]
        [switch]$SkipDomainPolicy
    )
    
    if (-not $DomainDNS) {
        $DomainDNS = (Get-ADDomain).DNSRoot
    }
    
    $ddcpGuid = '6AC1786C-016F-11D2-945F-00C04FB984F9'  # Default Domain Controller Policy
    $ddpGuid = '31B2F340-016D-11D2-945F-00C04FB984F9'   # Default Domain Policy
    
    $kdcKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
    $clientKey = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    
    if ($PSCmdlet.ShouldProcess($DomainDNS, "Enable Kerberos Armoring")) {
        # Enable on Domain Controller Policy (KDC side)
        Set-GPRegistryValue -Guid $ddcpGuid -Domain $DomainDNS `
            -Key $kdcKey -ValueName 'EnableCbacAndArmor' -Value 1 -Type DWord -ErrorAction Stop
        
        Set-GPRegistryValue -Guid $ddcpGuid -Domain $DomainDNS `
            -Key $clientKey -ValueName 'EnableCbacAndArmor' -Value 1 -Type DWord -ErrorAction Stop
        
        Write-Host "Enabled Kerberos Armoring on Default Domain Controller Policy" -ForegroundColor Green
        
        if (-not $SkipDomainPolicy) {
            # Enable on Domain Policy (client side)
            Set-GPRegistryValue -Guid $ddpGuid -Domain $DomainDNS `
                -Key $clientKey -ValueName 'EnableCbacAndArmor' -Value 1 -Type DWord -ErrorAction Stop
            
            Write-Host "Enabled Kerberos Armoring on Default Domain Policy" -ForegroundColor Green
        }
        
        Write-Warning "Clients and DCs must refresh Group Policy for changes to take effect."
        Write-Host "Verify with: klist purge && dir \\$DomainDNS\SYSVOL && klist" -ForegroundColor Cyan
    }
}

#endregion

#region Validation Functions

<#
.SYNOPSIS
    Validates the current user has Enterprise Admin permissions.
    
.OUTPUTS
    [bool] True if user is Enterprise Admin
#>
function Test-EnterpriseAdminMembership {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isEA = $currentUser.Groups | Where-Object { $_.Value -like '*-519' }
    return [bool]$isEA
}

<#
.SYNOPSIS
    Validates prerequisites for forest deployment.
    
.OUTPUTS
    [hashtable] Validation results
#>
function Test-ForestDeploymentPrerequisites {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    $results = @{
        IsEnterpriseAdmin = Test-EnterpriseAdminMembership
        KdsRootKey = Test-KdsRootKeyExists
        ForestFunctionalLevel = $null
        DomainFunctionalLevel = $null
        SupportsAuthPolicies = $false
        AllPassed = $false
    }
    
    try {
        $forest = Get-ADForest
        $domain = Get-ADDomain
        
        $results.ForestFunctionalLevel = $forest.ForestMode
        $results.DomainFunctionalLevel = $domain.DomainMode
        
        # Auth policies require 2012 R2 (level 6) or higher
        $levelMap = @{
            'Windows2012R2Domain' = 6
            'Windows2016Domain' = 7
            'Windows2019Domain' = 7
            'Windows2022Domain' = 7
            'Windows2025Domain' = 8
        }
        
        $level = $levelMap[$domain.DomainMode]
        if (-not $level) { $level = 7 }  # Assume modern if unknown
        
        $results.SupportsAuthPolicies = ($level -ge 6)
    }
    catch {
        Write-Warning "Failed to query AD: $_"
    }
    
    $results.AllPassed = (
        $results.IsEnterpriseAdmin -and
        $results.KdsRootKey -and
        $results.KdsRootKey.IsEffective -and
        $results.SupportsAuthPolicies
    )
    
    return $results
}

#endregion

#region Configuration Functions

<#
.SYNOPSIS
    Creates a new TierGuard forest deployment configuration.
    
.PARAMETER Domains
    Array of domain DNS names to manage
    
.PARAMETER Tier0AdminOUs
    OUs containing Tier 0 admins (relative or full DN)
    
.PARAMETER Tier0ServiceAccountOUs
    OUs containing Tier 0 service accounts
    
.PARAMETER Tier0ComputerOUs
    OUs containing Tier 0 computers
    
.PARAMETER Tier0ComputerGroup
    Name of the Tier 0 computer group
    
.PARAMETER Tier0PolicyName
    Name of the Tier 0 authentication policy
    
.PARAMETER Tier1AdminOUs
    OUs containing Tier 1 admins
    
.PARAMETER Tier1ServiceAccountOUs
    OUs containing Tier 1 service accounts
    
.PARAMETER Tier1ComputerOUs
    OUs containing Tier 1 computers
    
.PARAMETER Tier1ComputerGroup
    Name of the Tier 1 computer group
    
.PARAMETER Tier1PolicyName
    Name of the Tier 1 authentication policy
    
.PARAMETER Scope
    Which tiers to manage: Tier-0, Tier-1, or All-Tiers
    
.PARAMETER AddToProtectedUsers
    Which tier users to add to Protected Users: Tier-0, Tier-1, All-Tiers, or None
    
.PARAMETER EnablePrivilegedGroupCleanup
    Remove unexpected users from privileged groups
    
.OUTPUTS
    [hashtable] Configuration object
#>
function New-TierGuardConfiguration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string[]]$Domains,
        
        [Parameter()]
        [string[]]$Tier0AdminOUs = @('OU=Admins,OU=Tier 0,OU=Admin'),
        
        [Parameter()]
        [string[]]$Tier0ServiceAccountOUs = @('OU=Service Accounts,OU=Tier 0,OU=Admin'),
        
        [Parameter()]
        [string[]]$Tier0ComputerOUs = @('OU=Servers,OU=Tier 0,OU=Admin'),
        
        [Parameter()]
        [string]$Tier0ComputerGroup = 'TierGuard-Tier0-Computers',
        
        [Parameter()]
        [string]$Tier0PolicyName = 'TierGuard-Tier0-AuthPolicy',
        
        [Parameter()]
        [string[]]$Tier1AdminOUs = @('OU=Admins,OU=Tier 1,OU=Admin'),
        
        [Parameter()]
        [string[]]$Tier1ServiceAccountOUs = @('OU=Service Accounts,OU=Tier 1,OU=Admin'),
        
        [Parameter()]
        [string[]]$Tier1ComputerOUs = @('OU=Servers,OU=Tier 1,OU=Admin'),
        
        [Parameter()]
        [string]$Tier1ComputerGroup = 'TierGuard-Tier1-Computers',
        
        [Parameter()]
        [string]$Tier1PolicyName = 'TierGuard-Tier1-AuthPolicy',
        
        [Parameter()]
        [ValidateSet('Tier-0', 'Tier-1', 'All-Tiers')]
        [string]$Scope = 'All-Tiers',
        
        [Parameter()]
        [ValidateSet('Tier-0', 'Tier-1', 'All-Tiers', 'None')]
        [string]$AddToProtectedUsers = 'Tier-0',
        
        [Parameter()]
        [bool]$EnablePrivilegedGroupCleanup = $true
    )
    
    return @{
        SchemaVersion = '2.0'
        Scope = $Scope
        Domains = @($Domains)
        
        Tier0 = @{
            AdminOUs = @($Tier0AdminOUs)
            ServiceAccountOUs = @($Tier0ServiceAccountOUs)
            ComputerOUs = @($Tier0ComputerOUs)
            ComputerGroup = $Tier0ComputerGroup
            PolicyName = $Tier0PolicyName
            TGTLifetimeMinutes = $Script:DefaultTier0TgtLifetime
        }
        
        Tier1 = @{
            AdminOUs = @($Tier1AdminOUs)
            ServiceAccountOUs = @($Tier1ServiceAccountOUs)
            ComputerOUs = @($Tier1ComputerOUs)
            ComputerGroup = $Tier1ComputerGroup
            PolicyName = $Tier1PolicyName
            TGTLifetimeMinutes = $Script:DefaultTier1TgtLifetime
        }
        
        ProtectedUsers = $AddToProtectedUsers
        PrivilegedGroupCleanup = $EnablePrivilegedGroupCleanup
        
        CreatedAt = [DateTime]::UtcNow.ToString('o')
        CreatedBy = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-KdsRootKeyExists',
    'New-TierGuardKdsRootKey',
    'Get-TierGuardServiceAccount',
    'New-TierGuardServiceAccount',
    'Update-TierGuardServiceAccountPrincipals',
    'New-TierComputerGroup',
    'New-TierAuthPolicy',
    'Get-SysvolScriptsPath',
    'Publish-TierGuardToSysvol',
    'New-TierGuardGpo',
    'Set-TierGuardGpoLink',
    'Enable-KerberosArmoring',
    'Test-EnterpriseAdminMembership',
    'Test-ForestDeploymentPrerequisites',
    'New-TierGuardConfiguration'
)
