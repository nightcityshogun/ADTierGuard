# Authentication Policies and Silos - Configuration Guide

## Overview

ADTierGuard supports two approaches for Kerberos credential protection:

1. **Policy-Only** - Simple, assigns policy directly to users
2. **Policy + Silo** - Full isolation, groups users/computers/services

Both Authentication Policies and Authentication Policy Silos are **FOREST-WIDE** objects stored in the Configuration Naming Context.

## Key Concepts

### Where Objects Are Stored

```
CN=Configuration,DC=contoso,DC=com
└── CN=Services
    └── CN=AuthN Policy Configuration
        ├── CN=AuthN Policies          ← Authentication Policies
        │   ├── CN=TierGuard-Tier0-AuthPolicy
        │   └── CN=TierGuard-Tier1-AuthPolicy
        └── CN=AuthN Silos             ← Authentication Policy Silos
            ├── CN=TierGuard-Tier0-Silo
            └── CN=TierGuard-Tier1-Silo
```

### Forest-Wide Implications

| Object | Partition | Scope | Replication |
|--------|-----------|-------|-------------|
| Authentication Policy | Configuration NC | Forest-wide | All DCs in forest |
| Authentication Policy Silo | Configuration NC | Forest-wide | All DCs in forest |
| User's `msDS-AssignedAuthNPolicy` | Domain NC | Per-domain | Domain DCs only |
| User's `msDS-AssignedAuthNPolicySilo` | Domain NC | Per-domain | Domain DCs only |

## Requirements

### To Create Policies/Silos

- **Domain Functional Level**: Windows Server 2012 R2 or higher
- **Permissions**: Enterprise Admin OR delegated write access to Configuration NC
- **Best Practice**: Run from forest root domain DC

### To Assign Policies to Users

- **Permissions**: Write access to user objects in target domain
- **Can run from**: Any DC (including child domains)

## Approach Comparison

### Policy-Only Approach

```
┌─────────────────────────────────────┐
│         Authentication Policy        │
│    "TierGuard-Tier0-AuthPolicy"     │
│                                      │
│  • TGT Lifetime: 4 hours            │
│  • UserAllowedToAuthenticateFrom    │
│  • Enforced: Yes                    │
└─────────────────────────────────────┘
                  │
                  │ msDS-AssignedAuthNPolicy
                  ▼
    ┌─────────────────────────────────┐
    │            Users                │
    │  (in any domain in forest)      │
    └─────────────────────────────────┘
```

**Pros:**
- Simpler to configure
- Direct policy assignment
- Works across all domains

**Cons:**
- Less isolation
- No computer/service policy linkage
- Manual SDDL management for restrictions

### Policy + Silo Approach

```
┌─────────────────────────────────────────────────────────────────┐
│                  Authentication Policy Silo                      │
│                "TierGuard-Tier0-Silo"                           │
│                                                                  │
│  ┌───────────────────┐ ┌───────────────────┐                    │
│  │ User AuthN Policy │ │Computer AuthN Pol │                    │
│  │ TierGuard-Tier0-  │ │ TierGuard-Tier0-  │                    │
│  │ AuthPolicy        │ │ AuthPolicy        │                    │
│  └───────────────────┘ └───────────────────┘                    │
│                                                                  │
│  Members (msDS-AuthNPolicySiloMembers):                         │
│  • CN=T0-Admin1,OU=Tier0-Admins,DC=contoso,DC=com              │
│  • CN=DC01,OU=Domain Controllers,DC=contoso,DC=com             │
│  • CN=PAW01,OU=Tier0-PAWs,DC=contoso,DC=com                    │
└─────────────────────────────────────────────────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
         ▼                     ▼                     ▼
    ┌─────────┐          ┌─────────┐          ┌─────────┐
    │  Users  │          │Computers│          │  PAWs   │
    │         │          │  (DCs)  │          │         │
    │ msDS-   │          │ msDS-   │          │ msDS-   │
    │ Assigned│          │ Assigned│          │ Assigned│
    │ AuthN   │          │ AuthN   │          │ AuthN   │
    │ Policy  │          │ Policy  │          │ Policy  │
    │ Silo    │          │ Silo    │          │ Silo    │
    └─────────┘          └─────────┘          └─────────┘
```

**Pros:**
- Full credential isolation
- Users can only authenticate to silo computers
- Computers can only accept silo user auth
- Built-in SDDL generation

**Cons:**
- More complex setup
- Must manage both policy and silo membership
- Requires careful planning

## ADTierGuard Configuration

### Sample Configuration (config.json)

```json
{
  "General": {
    "ForestScope": true,
    "Prefix": "TierGuard"
  },
  "Tier0": {
    "Enabled": true,
    "KerberosPolicy": {
      "Enabled": true,
      "PolicyName": "TierGuard-Tier0-AuthPolicy",
      "TGTLifetimeMinutes": 240,
      "UseSilo": true,
      "SiloName": "TierGuard-Tier0-Silo"
    }
  },
  "Tier1": {
    "Enabled": true,
    "KerberosPolicy": {
      "Enabled": true,
      "PolicyName": "TierGuard-Tier1-AuthPolicy",
      "TGTLifetimeMinutes": 480,
      "UseSilo": false
    }
  }
}
```

### Initialization Script

```powershell
# Import module
Import-Module .\ADTierGuard.psd1

# Check prerequisites
$prereq = Test-AuthPolicyPrerequisites -RequireForestRoot
if (-not $prereq.CanProceed) {
    $prereq.Issues | ForEach-Object { Write-Error $_ }
    return
}

# Show forest context
$prereq.Context | Format-List

# Initialize Tier 0 with Silo
$tier0 = Initialize-TierAuthenticationPolicy `
    -TierLevel 0 `
    -UseSilo `
    -PAWGroupDN "CN=Tier0-PAWs,OU=Tier0,DC=contoso,DC=com" `
    -Verbose

# Initialize Tier 1 without Silo (policy-only)
$tier1 = Initialize-TierAuthenticationPolicy `
    -TierLevel 1 `
    -Verbose

# Check status
Get-TierAuthenticationStatus | ConvertTo-Json -Depth 5
```

### Adding Users to Silo

```powershell
# Add user to Tier 0 silo
Add-TierSiloMember `
    -SiloName "TierGuard-Tier0-Silo" `
    -MemberDN "CN=T0-Admin,OU=Tier0-Admins,DC=contoso,DC=com"

# Add PAW computer to silo
Add-TierSiloMember `
    -SiloName "TierGuard-Tier0-Silo" `
    -MemberDN "CN=PAW01,OU=Tier0-PAWs,DC=contoso,DC=com"
```

### Assigning Policy Directly (no silo)

```powershell
# Assign policy to user
Set-UserAuthenticationPolicy `
    -UserDN "CN=T1-Admin,OU=Tier1-Admins,DC=contoso,DC=com" `
    -PolicyDN "CN=TierGuard-Tier1-AuthPolicy,CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services,CN=Configuration,DC=contoso,DC=com"
```

## SDDL Reference

### Policy SDDL for UserAllowedToAuthenticateFrom

**With Silo (allows silo members OR PAW group):**
```
O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "TierGuard-Tier0-Silo") || (Member_of_any {SID(S-1-5-21-...)}))
```

**Without Silo (PAW group only):**
```
O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID(S-1-5-21-...)}))
```

## Multi-Domain Forest Considerations

```
contoso.com (Forest Root)
├── CN=Configuration
│   └── AuthN Policies + Silos (FOREST-WIDE)
│
├── child.contoso.com
│   └── Users can be assigned policies/silos
│       (msDS-AssignedAuthNPolicy in domain partition)
│
└── emea.contoso.com
    └── Users can be assigned policies/silos
        (msDS-AssignedAuthNPolicy in domain partition)
```

### Key Points for Multi-Domain:

1. **Create policies/silos from forest root** (or with Enterprise Admin)
2. **Sync scripts can run from any domain** (they only assign existing policies)
3. **Silo members can be from any domain** (DN references work cross-domain)
4. **Enterprise/Schema Admins** exist only in forest root - always use Policy+Silo for them

## Troubleshooting

### Understanding the "Accounts" Section in ADAC

When viewing an Authentication Policy in Active Directory Administrative Center (ADAC), you'll see an "Accounts" section. This can be confusing because:

**The "Accounts" section shows accounts via `msDS-AuthNPolicyMembers`** - This is direct policy membership (rarely used).

**ADTierGuard uses a different approach** - It sets `msDS-AssignedAuthNPolicy` on the USER objects, not the policy.

Both approaches are valid, but they appear differently in ADAC:
- **Direct Policy Membership** (msDS-AuthNPolicyMembers): Shows in policy's "Accounts" section
- **User Attribute Assignment** (msDS-AssignedAuthNPolicy): Shows on user object, NOT in policy's Accounts section

To verify ADTierGuard is working:
```powershell
# Check user's assigned policy (ADTierGuard's approach)
$user = [ADSI]"LDAP://CN=Admin-User,OU=Tier 0,OU=ADTierGuard,DC=domain,DC=com"
$user.Properties['msDS-AssignedAuthNPolicy']
```

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Cannot create policy" | Missing Enterprise Admin | Run from forest root with EA permissions |
| "Functional level too low" | Pre-2012 R2 domain | Upgrade domain functional level |
| Policy not enforced | User not in silo member list | Add user to silo AND set user's silo attribute |
| Auth still works from non-PAW | SDDL incorrect | Verify PAW group SID in policy SDDL |

### Verification Commands

```powershell
# Check if user has policy assigned
$user = [ADSI]"LDAP://CN=T0-Admin,OU=Tier0-Admins,DC=contoso,DC=com"
$user.Properties['msDS-AssignedAuthNPolicy']
$user.Properties['msDS-AssignedAuthNPolicySilo']

# Check policy exists
Get-TierAuthenticationPolicy -Name "TierGuard-Tier0-AuthPolicy"

# Check silo members
$silo = Get-TierAuthenticationSilo -Name "TierGuard-Tier0-Silo"
$silo.'msDS-AuthNPolicySiloMembers'

# Full status
Get-TierAuthenticationStatus
```

## Best Practices

1. **Always start in audit mode** - Set `Enforced = $false` initially
2. **Test thoroughly** before enforcement
3. **Document all PAW computers** in the PAW group
4. **Use silos for Tier 0** - Maximum isolation for highest privilege
5. **Policy-only is acceptable for Tier 1** - Simpler management
6. **Monitor authentication failures** in Security event logs
7. **Have break-glass accounts** excluded from policies

## Event Log Monitoring

After enabling policies, monitor:
- **Event ID 4820** - Kerberos TGT denied due to authentication policy
- **Event ID 4821** - Kerberos service ticket denied due to authentication policy
- **Event ID 4822** - NTLM authentication denied due to authentication policy
