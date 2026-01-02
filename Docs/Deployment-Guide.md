# ADTierGuard Deployment Guide

## Table of Contents

1. [Pre-Deployment Planning](#pre-deployment-planning)
2. [Environment Preparation](#environment-preparation)
3. [Module Installation](#module-installation)
4. [Configuration Setup](#configuration-setup)
5. [Kerberos Authentication Policy Creation](#kerberos-authentication-policy-creation)
6. [Phased Deployment](#phased-deployment)
7. [Monitoring and Validation](#monitoring-and-validation)
8. [Rollback Procedures](#rollback-procedures)

---

## Pre-Deployment Planning

### Assessment Checklist

Before deploying ADTierGuard, complete the following assessment:

- [ ] **Forest Functional Level** - Verify Windows Server 2012 R2 or higher
- [ ] **OU Structure** - Plan tier-specific OUs for admins, service accounts, and computers
- [ ] **Account Inventory** - Identify all privileged accounts and their tier classification
- [ ] **Service Account Audit** - Document all service accounts and their dependencies
- [ ] **Application Compatibility** - Test critical applications with Protected Users membership
- [ ] **Backup Strategy** - Ensure AD backup procedures are in place

### Recommended OU Structure

```
DC=contoso,DC=com
├── OU=ADTierGuard
│   ├── OU=Tier0
│   │   ├── OU=ADTierGuards          # Tier 0 admin user accounts
│   │   ├── OU=ServiceAccounts # Tier 0 service accounts
│   │   └── OU=Groups          # Tier 0 security groups
│   ├── OU=Tier1
│   │   ├── OU=ADTierGuards
│   │   ├── OU=ServiceAccounts
│   │   └── OU=Groups
│   └── OU=Tier2
│       ├── OU=ADTierGuards
│       ├── OU=ServiceAccounts
│       └── OU=Groups
├── OU=Servers
│   ├── OU=Tier0              # PAWs, Jump servers, PKI, etc.
│   └── OU=Tier1              # Member servers
└── OU=Workstations
    └── OU=Tier2              # End-user workstations
```

---

## Environment Preparation

### Step 1: Create OU Structure

If not already present, create the OU structure using ADSI:

```powershell
# Import the module
Import-Module .\ADTierGuard.psd1

# Get domain DN
$rootDse = Get-AdsiRootDse
$domainDN = $rootDse.defaultNamingContext

# Function to create OU
function New-AdsiOU {
    param([string]$Name, [string]$ParentDN)
    
    $parent = New-AdsiConnection -DistinguishedName $ParentDN
    $newOU = $parent.Children.Add("OU=$Name", "organizationalUnit")
    $newOU.CommitChanges()
    $newOU.Close()
    $parent.Close()
}

# Create Admin structure
New-AdsiOU -Name "Admin" -ParentDN $domainDN
New-AdsiOU -Name "Tier0" -ParentDN "OU=ADTierGuard,$domainDN"
New-AdsiOU -Name "Admins" -ParentDN "OU=Tier0,OU=ADTierGuard,$domainDN"
New-AdsiOU -Name "ServiceAccounts" -ParentDN "OU=Tier0,OU=ADTierGuard,$domainDN"
New-AdsiOU -Name "Groups" -ParentDN "OU=Tier0,OU=ADTierGuard,$domainDN"
# ... repeat for Tier1, Tier2
```

### Step 2: Create Tier Restriction Groups

```powershell
# Create the restriction groups
$groupsOU = "OU=Groups,OU=Tier0,OU=ADTierGuard,$domainDN"
$parent = New-AdsiConnection -DistinguishedName $groupsOU

# Tier 0 Restriction Group
$group0 = $parent.Children.Add("CN=TG-Tier0-RestrictionGroup", "group")
$group0.Properties["sAMAccountName"].Value = "TG-Tier0-RestrictionGroup"
$group0.Properties["groupType"].Value = -2147483646  # Global Security
$group0.Properties["description"].Value = "Computers allowed for Tier 0 authentication"
$group0.CommitChanges()
$group0.Close()

$parent.Close()
```

### Step 3: Enable Kerberos Armoring

Create a GPO with the following settings:

**GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\KDC`

| Setting | Value |
|---------|-------|
| KDC support for claims, compound authentication and Kerberos armoring | Enabled - Always provide claims |
| Provide information about previous logons to client computers | Enabled |

**GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Kerberos`

| Setting | Value |
|---------|-------|
| Kerberos client support for claims, compound authentication and Kerberos armoring | Enabled |

---

## Module Installation

### Step 1: Copy Module Files

```powershell
# Create installation directory
$installPath = "C:\ADTierGuard"
New-Item -Path $installPath -ItemType Directory -Force

# Copy module files
Copy-Item -Path ".\*" -Destination $installPath -Recurse -Force

# Create directories
New-Item -Path "$installPath\Logs" -ItemType Directory -Force
New-Item -Path "$installPath\Config" -ItemType Directory -Force
```

### Step 2: Import and Verify Module

```powershell
# Import module
Import-Module "C:\ADTierGuard\ADTierGuard.psd1" -Force

# Verify functions are available
Get-Command -Module ADTierGuard

# Test environment
Test-TierEnvironment
```

### Step 3: Create Initial Configuration

```powershell
# Copy sample configuration
Copy-Item "C:\ADTierGuard\Config\Sample-TierGuard.json" "C:\ADTierGuard\Config\TierGuard.json"

# Edit configuration for your environment
notepad "C:\ADTierGuard\Config\TierGuard.json"
```

---

## Configuration Setup

### Minimum Configuration

Edit `TierGuard.json` with your environment specifics:

```json
{
  "General": {
    "ForestScope": false,
    "LogPath": "C:\\ADTierGuard\\Logs",
    "EventLogSource": "ADTierGuard",
    "MaxParallelOperations": 8
  },
  "Tier0": {
    "Enabled": true,
    "AdminOUs": [
      "OU=ADTierGuards,OU=Tier0,OU=ADTierGuard,DC=contoso,DC=com"
    ],
    "ServiceAccountOUs": [
      "OU=ServiceAccounts,OU=Tier0,OU=ADTierGuard,DC=contoso,DC=com"
    ],
    "ComputerOUs": [
      "OU=Domain Controllers,DC=contoso,DC=com"
    ],
    "ComputerGroupName": "TG-Tier0-RestrictionGroup",
    "KerberosAuthPolicyName": "TG-Tier0-AuthPolicy",
    "AddToProtectedUsers": true,
    "EnforcePrivilegedGroupCleanup": false,
    "ExcludedAccounts": ["krbtgt", "Administrator"]
  },
  "Tier1": {
    "Enabled": false
  }
}
```

### Validate Configuration

```powershell
$validation = Initialize-TierGuard -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" -ValidateOnly

if ($validation.IsValid) {
    Write-Host "Configuration is valid" -ForegroundColor Green
    if ($validation.Warnings) {
        Write-Host "Warnings:" -ForegroundColor Yellow
        $validation.Warnings | ForEach-Object { Write-Host "  - $_" }
    }
} else {
    Write-Host "Configuration has errors" -ForegroundColor Red
}
```

---

## Kerberos Authentication Policy Creation

### Understanding the SDDL

The Kerberos Authentication Policy uses an SDDL (Security Descriptor Definition Language) to specify which computers are allowed:

```
O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(<GroupSID>)}))
```

- `O:SY` - Owner is SYSTEM
- `G:SY` - Group is SYSTEM
- `XA` - Callback Access Allowed
- `OICI` - Object Inherit, Container Inherit
- `CR` - Control Rights
- `WD` - Everyone
- `Member_of_any` - Check group membership

### Step 1: Get Group SID

```powershell
# Get the SID of the restriction group
$groupDN = "CN=TG-Tier0-RestrictionGroup,OU=Groups,OU=Tier0,OU=ADTierGuard,DC=contoso,DC=com"
$group = Get-AdsiObject -DistinguishedName $groupDN -Properties @('objectSid')
$sidBytes = $group.objectSid
$sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
Write-Host "Group SID: $($sid.Value)"
```

### Step 2: Create Authentication Policy

**Using AD PowerShell (one-time setup)**:

```powershell
# Replace with your actual SID
$groupSID = "S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx"

$sddl = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($groupSID)}))"

New-ADAuthenticationPolicy -Name "TG-Tier0-AuthPolicy" `
    -Description "Tier 0 authentication restriction policy" `
    -UserAllowedToAuthenticateFrom $sddl `
    -Enforce `
    -ProtectedFromAccidentalDeletion $true
```

**Using ADSI directly**:

```powershell
# Get configuration naming context
$rootDse = Get-AdsiRootDse
$configNC = $rootDse.configurationNamingContext

# Create policy
$policiesContainer = "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,$configNC"
$parent = New-AdsiConnection -DistinguishedName $policiesContainer

$policy = $parent.Children.Add("CN=TG-Tier0-AuthPolicy", "msDS-AuthNPolicy")
$policy.Properties["msDS-AuthNPolicyEnforced"].Value = $true
$policy.Properties["msDS-UserAllowedToAuthenticateFrom"].Value = $sddl
$policy.Properties["description"].Value = "Tier 0 authentication restriction policy"
$policy.CommitChanges()
$policy.Close()
$parent.Close()
```

### Step 3: Verify Policy

```powershell
$policies = Get-AdsiKerberosAuthenticationPolicy
$policies | Where-Object { $_.Name -like "*Tier0*" } | Format-List
```

---

## Phased Deployment

### Phase 1: Computer Group Population (Week 1-2)

**Objective**: Populate tier restriction groups without enforcing policies.

```powershell
# Run computer sync in WhatIf mode first
Invoke-TierComputerSync -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" `
    -TierLevel 0 -WhatIf

# Review output, then run for real
Invoke-TierComputerSync -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" `
    -TierLevel 0

# Verify group membership
$groupDN = "CN=TG-Tier0-RestrictionGroup,OU=Groups,OU=Tier0,OU=ADTierGuard,DC=contoso,DC=com"
$members = Get-AdsiGroupMember -GroupDN $groupDN
Write-Host "Group has $($members.Count) members"
```

**Scheduled Task**: Enable computer sync scheduled tasks.

### Phase 2: Pilot User Testing (Week 3-4)

**Objective**: Test authentication policies with pilot users.

1. Create a pilot admin account in Tier 0 AdminOU
2. Manually apply the authentication policy
3. Test authentication from Tier 0 and non-Tier 0 computers
4. Document any issues

```powershell
# Apply policy to pilot user
Set-AdsiAuthenticationPolicy `
    -UserDN "CN=PilotAdmin,OU=ADTierGuards,OU=Tier0,OU=ADTierGuard,DC=contoso,DC=com" `
    -PolicyDN "CN=TG-Tier0-AuthPolicy,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=contoso,DC=com"

# Test from Tier 0 computer - should succeed
# Test from non-Tier 0 computer - should fail with KDC error
```

### Phase 3: Production User Rollout (Week 5-6)

**Objective**: Apply policies to all tier users.

```powershell
# Run user sync in WhatIf mode
Invoke-TierUserSync -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" `
    -TierLevel 0 -WhatIf

# Review output carefully

# Run user sync - skip privileged group cleanup initially
Invoke-TierUserSync -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" `
    -TierLevel 0 -SkipPrivilegedGroupCleanup

# Monitor for issues
Get-EventLog -LogName Application -Source "ADTierGuard" -After (Get-Date).AddHours(-1)
```

### Phase 4: Privileged Group Cleanup (Week 7-8)

**Objective**: Remove unauthorized users from privileged groups.

```powershell
# First, audit current state
$privilegedGroups = Get-AdsiPrivilegedGroup
foreach ($group in $privilegedGroups) {
    $members = Get-AdsiGroupMember -GroupDN $group.distinguishedName
    Write-Host "$($group.Name): $($members.Count) members"
}

# Run with WhatIf
Invoke-TierUserSync -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" `
    -TierLevel 0 -SkipProtectedUsers -WhatIf

# Execute cleanup
Invoke-TierUserSync -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" `
    -TierLevel 0 -SkipProtectedUsers
```

### Phase 5: Tier 1 Deployment (Week 9+)

Repeat phases 1-4 for Tier 1:

1. Update configuration to enable Tier 1
2. Create Tier 1 restriction group and authentication policy
3. Run computer sync
4. Test with pilot users
5. Roll out to production

---

## Monitoring and Validation

### Event Log Monitoring

```powershell
# Create monitoring script
$events = Get-EventLog -LogName Application -Source "ADTierGuard" -After (Get-Date).AddDays(-1)

# Summary
$events | Group-Object EntryType | Select-Object Name, Count

# Errors
$events | Where-Object { $_.EntryType -eq 'Error' } | Format-List TimeGenerated, Message
```

### KDC Event Monitoring

Monitor Domain Controllers for authentication policy violations:

**Event ID 106**: A Kerberos authentication request was blocked by a Kerberos authentication policy.

```powershell
# Query KDC events on DC
$kdcEvents = Get-WinEvent -LogName "System" -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'] and EventID=106]]" -MaxEvents 100

$kdcEvents | ForEach-Object {
    [PSCustomObject]@{
        Time    = $_.TimeCreated
        User    = $_.Properties[0].Value
        Policy  = $_.Properties[1].Value
        Computer = $_.Properties[2].Value
    }
}
```

### Compliance Reporting

```powershell
# Generate compliance report
$config = Import-TierGuardConfiguration -Path "C:\ADTierGuard\Config\TierGuard.json"
$users = Get-TierUsers -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" -TierLevel 0

$report = foreach ($user in $users) {
    [PSCustomObject]@{
        User          = $user.SamAccountName
        DN            = $user.DistinguishedName
        HasPolicy     = -not [string]::IsNullOrEmpty($user.CurrentPolicy)
        PolicyName    = if ($user.CurrentPolicy) { ($user.CurrentPolicy -split ',')[0] -replace 'CN=' } else { 'None' }
        ExpectedPolicy = $config.Tier0.KerberosAuthPolicyName
        Compliant     = $user.CurrentPolicy -like "*$($config.Tier0.KerberosAuthPolicyName)*"
    }
}

$report | Export-Csv "C:\ADTierGuard\Reports\Compliance-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

---

## Rollback Procedures

### Remove Authentication Policy from User

```powershell
Remove-AdsiAuthenticationPolicy -UserDN "CN=Admin,OU=ADTierGuards,OU=Tier0,OU=ADTierGuard,DC=contoso,DC=com"
```

### Remove All Policies from Tier

```powershell
$users = Get-TierUsers -ConfigurationPath "C:\ADTierGuard\Config\TierGuard.json" -TierLevel 0

foreach ($user in $users) {
    Remove-AdsiAuthenticationPolicy -UserDN $user.DistinguishedName
    Write-Host "Removed policy from: $($user.SamAccountName)"
}
```

### Remove User from Protected Users

```powershell
$protectedUsersGroup = Get-AdsiProtectedUsersGroup
Remove-AdsiGroupMember -GroupDN $protectedUsersGroup.distinguishedName -MemberDN "CN=Admin,OU=ADTierGuards,OU=Tier0,OU=ADTierGuard,DC=contoso,DC=com"
```

### Disable Scheduled Tasks

```powershell
Get-ScheduledTask -TaskPath "\ADTierGuard\" | Disable-ScheduledTask
```

### Emergency: Delete Authentication Policy

```powershell
# This removes the policy entirely - use with caution
$policyDN = "CN=TG-Tier0-AuthPolicy,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=contoso,DC=com"
$policy = Get-AdsiObject -DistinguishedName $policyDN
$policy.DeleteTree()
```

---

## Post-Deployment Maintenance

### Regular Tasks

| Task | Frequency | Command |
|------|-----------|---------|
| Review logs | Daily | `Get-EventLog -LogName Application -Source "ADTierGuard"` |
| Verify sync | Weekly | `Invoke-TierComputerSync -WhatIf` |
| Compliance report | Monthly | Run compliance reporting script |
| Configuration backup | Monthly | `Copy-Item Config\TierGuard.json Config\TierGuard-backup-$(Get-Date -Format yyyyMMdd).json` |

### Updating Configuration

1. Edit configuration file
2. Validate: `Initialize-TierGuard -ConfigurationPath ... -ValidateOnly`
3. Run sync with `-WhatIf` first
4. Apply changes

---

*Document Version: 1.0*
*Last Updated: 2024*
