# ADTierGuard - Architecture & UML Diagrams

## 1. Installation Flow

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Enterprise Admin
    participant Script as Install-ADTierGuard.ps1
    participant ADSI as ADSI/P-Invoke
    participant AD as Active Directory
    participant SYSVOL as SYSVOL

    Admin->>Script: .\Install-ADTierGuard.ps1 -Scope All
    
    rect rgb(240, 248, 255)
        Note over Script,AD: Phase 1: Forest Discovery
        Script->>ADSI: Get RootDSE
        ADSI->>AD: LDAP://RootDSE
        AD-->>ADSI: defaultNamingContext, configurationNamingContext
        ADSI-->>Script: Forest Root DN, Config NC
        Script->>ADSI: Enumerate Partitions Container
        ADSI->>AD: Search for all domains
        AD-->>Script: Domain list (FQDN, DN, DC)
    end
    
    rect rgb(255, 248, 240)
        Note over Script,AD: Phase 2: OU Creation (All Domains)
        loop For Each Domain
            Script->>ADSI: Create OU=ADTierGuard
            ADSI->>AD: LDAP Create
            Script->>ADSI: Create OU=Tier 0, OU=Tier 1
            Script->>ADSI: Create OU=Users, OU=Computers, etc.
        end
    end
    
    rect rgb(240, 255, 240)
        Note over Script,SYSVOL: Phase 3: Script Deployment
        loop For Each Domain
            Script->>SYSVOL: Copy Scripts/*.ps1
            Script->>SYSVOL: Copy Core/*.psm1
            Script->>SYSVOL: Write config.json
        end
    end
    
    rect rgb(255, 240, 255)
        Note over Script,AD: Phase 4: Security Objects (Forest Root)
        Script->>ADSI: Create GMSA ADTierGuard-svc
        ADSI->>AD: CN=Managed Service Accounts
        Script->>ADSI: Create Tier0-Computers (Universal)
        Script->>ADSI: Create Tier1-Computers (Universal)
        ADSI-->>Script: Group SIDs
    end
    
    rect rgb(255, 255, 240)
        Note over Script,AD: Phase 5: Authentication Policies (Config NC)
        Script->>Script: Build SDDL with Group SIDs
        Script->>ADSI: P/Invoke ConvertStringSecurityDescriptorToSecurityDescriptor
        ADSI-->>Script: Binary Security Descriptor
        Script->>ADSI: Create Tier0-RestrictedAuth policy
        ADSI->>AD: CN=AuthN Policies,CN=Configuration
        Script->>ADSI: Create Tier0-Silo
        ADSI->>AD: CN=AuthN Silos,CN=Configuration
    end
    
    rect rgb(240, 255, 255)
        Note over Script,AD: Phase 6: GPO Deployment (All Domains)
        loop For Each Domain
            Script->>ADSI: Create GPO object
            Script->>SYSVOL: Write ScheduledTasks.xml
            Script->>ADSI: Link GPO to DC OU
        end
    end
    
    rect rgb(255, 245, 238)
        Note over Script,AD: Phase 7: Kerberos Armoring
        loop For Each Domain
            Script->>Script: Build Registry.pol binary
            Script->>SYSVOL: Write to Default DC Policy
            Script->>SYSVOL: Write to Default Domain Policy
            Script->>ADSI: Update GPO versionNumber
        end
    end
    
    Script-->>Admin: Installation Complete
```

## 2. Component Architecture

```mermaid
flowchart TB
    subgraph Installer["Install-ADTierGuard.ps1"]
        PInvoke["P/Invoke<br/>SDDL Converter"]
        RegPol["Registry.pol<br/>Binary Writer"]
    end
    
    subgraph Scripts["Scripts (SYSVOL)"]
        CompSync["Invoke-TierComputerSync.ps1"]
        UserSync["Invoke-TierUserSync.ps1"]
        GMSACtx["Set-GMSAContext.ps1"]
    end
    
    subgraph Core["Core Modules"]
        ADSI["AdsiOperations.psm1"]
        Auth["AuthPolicyManager.psm1"]
        Forest["ForestTopology.psm1"]
        Sync["SyncUtilities.psm1"]
        Config["ConfigurationManager.psm1"]
    end
    
    subgraph Engine["Engine"]
        Runspace["RunspaceEngine.psm1<br/>Parallel Processing"]
    end
    
    subgraph AD["Active Directory"]
        ConfigNC["Configuration NC<br/>• AuthN Policies<br/>• AuthN Silos"]
        DomainNC["Domain NC<br/>• Users<br/>• Groups<br/>• Computers"]
        SYSVOL["SYSVOL<br/>• Scripts<br/>• GPO Files"]
    end
    
    subgraph GPO["Group Policy"]
        Tasks["Scheduled Tasks<br/>• Computer Sync (SYSTEM)<br/>• User Sync (GMSA)<br/>• GMSA Context Switch"]
    end
    
    Installer --> ConfigNC
    Installer --> DomainNC
    Installer --> SYSVOL
    PInvoke --> ConfigNC
    RegPol --> SYSVOL
    
    Scripts --> Core
    Core --> AD
    Runspace --> ADSI
    
    GPO --> Scripts
    Tasks --> CompSync
    Tasks --> UserSync
    Tasks --> GMSACtx
```

## 3. Authentication Policy SDDL Structure

```mermaid
flowchart LR
    subgraph SDDL["SDDL String"]
        Owner["O:SY<br/>Owner: SYSTEM"]
        Group["G:SY<br/>Group: SYSTEM"]
        DACL["D:"]
    end
    
    subgraph ACE["Conditional ACE (XA)"]
        Type["XA<br/>Callback Allow"]
        Flags["OICI<br/>Inherit"]
        Rights["CR<br/>Control Right"]
        Trustee["WD<br/>Everyone"]
    end
    
    subgraph Condition["Condition Expression"]
        EDCheck["Member_of {SID(ED)}<br/>Enterprise Domain Controllers"]
        OR1[" || "]
        GroupCheck["Member_of_any {SID(...)}<br/>Tier0-Computers Group"]
    end
    
    SDDL --> ACE --> Condition
    
    subgraph Result["Evaluation Result"]
        Allow["✓ TGT Issued<br/>Computer is DC or in Tier0-Computers"]
        Deny["✗ KDC_ERR_POLICY<br/>Computer not authorized"]
    end
    
    Condition --> Result
```

## 4. User Sync Workflow

```mermaid
flowchart TD
    Start([Scheduled Task Trigger]) --> LoadConfig[Load Configuration<br/>from SYSVOL]
    LoadConfig --> GetPolicy[Get Auth Policy DN<br/>from Configuration NC]
    GetPolicy --> PolicyExists{Policy Exists?}
    
    PolicyExists -->|No| Error[Log Error:<br/>Run Install-ADTierGuard.ps1]
    PolicyExists -->|Yes| SearchUsers[Search Tier OUs<br/>for User Objects]
    
    SearchUsers --> FilterSvc[Exclude Service Account OUs]
    FilterSvc --> CheckPolicy{User has<br/>correct policy?}
    
    CheckPolicy -->|No| ApplyPolicy[Set msDS-AssignedAuthNPolicy<br/>via ADSI]
    CheckPolicy -->|Yes| SkipPolicy[Skip - Already applied]
    
    ApplyPolicy --> Tier0Check{Tier 0?}
    SkipPolicy --> Tier0Check
    
    Tier0Check -->|Yes| ProtectedUsers[Add to Protected Users<br/>Group]
    Tier0Check -->|No| NextUser
    
    ProtectedUsers --> PrivCleanup[Remove from unauthorized<br/>privileged groups:<br/>• Domain Admins<br/>• Enterprise Admins<br/>• Schema Admins<br/>• etc.]
    
    PrivCleanup --> NextUser{More Users?}
    NextUser -->|Yes| CheckPolicy
    NextUser -->|No| LogResults[Write Event Log<br/>Summary]
    
    LogResults --> End([Complete])
    Error --> End
```

## 5. Computer Sync Workflow

```mermaid
flowchart TD
    Start([Scheduled Task Trigger]) --> LoadConfig[Load Configuration]
    LoadConfig --> GetGroup[Get Tier Computer Group<br/>Tier0-Computers or Tier1-Computers]
    
    GetGroup --> SearchOU[Search Computer OUs<br/>for computer objects]
    SearchOU --> ExcludeDC{Exclude Domain<br/>Controllers?}
    
    ExcludeDC -->|Tier 1| FilterDC[Remove DCs from list]
    ExcludeDC -->|Tier 0| IncludeDC[Include DCs]
    
    FilterDC --> GetMembers[Get Current Group Members]
    IncludeDC --> GetMembers
    
    GetMembers --> Compare[Compare:<br/>OU Computers vs Group Members]
    
    Compare --> ToAdd[Computers to Add<br/>In OU, not in group]
    Compare --> ToRemove[Computers to Remove<br/>In group, not in OU]
    
    ToAdd --> ParallelAdd[Parallel Add to Group<br/>RunspaceEngine]
    ToRemove --> ParallelRemove[Parallel Remove from Group<br/>RunspaceEngine]
    
    ParallelAdd --> LogAdd[Log: Computer Added<br/>Event ID 1100]
    ParallelRemove --> LogRemove[Log: Computer Removed<br/>Event ID 1101]
    
    LogAdd --> Summary[Write Summary<br/>Event ID 1001]
    LogRemove --> Summary
    
    Summary --> End([Complete])
```

## 6. GMSA Context Switch Flow

```mermaid
sequenceDiagram
    autonumber
    participant Task as Scheduled Task<br/>(SYSTEM)
    participant Script as Set-GMSAContext.ps1
    participant ADSI as ADSI
    participant AD as Active Directory
    participant TaskSched as Task Scheduler
    
    Note over Task: Runs hourly and on GPO refresh
    
    Task->>Script: Execute with -GMSAName param
    
    Script->>ADSI: Search for GMSA
    ADSI->>AD: LDAP Search<br/>CN=Managed Service Accounts
    AD-->>ADSI: GMSA objectSid
    ADSI-->>Script: GMSA SID
    
    Script->>ADSI: Get Domain Controllers
    ADSI->>AD: Search userAccountControl=8192
    AD-->>ADSI: DC list
    ADSI-->>Script: DC SIDs
    
    Script->>ADSI: Update GMSA msDS-GroupMSAMembership
    ADSI->>AD: Write security descriptor
    AD-->>ADSI: Success
    Note over Script,AD: DCs can now retrieve GMSA password
    
    loop For each User Sync Task
        Script->>TaskSched: Get-ScheduledTask
        TaskSched-->>Script: Current principal
        
        alt Already GMSA
            Script->>Script: Skip
        else Running as SYSTEM
            Script->>TaskSched: Set-ScheduledTask<br/>-Principal (GMSA SID)
            TaskSched-->>Script: Updated
        end
    end
    
    Script-->>Task: Complete
```

## 7. Kerberos Armoring Registry Settings

```mermaid
flowchart TB
    subgraph KDC["KDC Settings (Domain Controllers)"]
        KDCPath["HKLM\SOFTWARE\Microsoft\Windows\<br/>CurrentVersion\Policies\System\KDC\Parameters"]
        KDCEnable["EnableCbacAndArmor = 1"]
        KDCLevel["CbacAndArmorLevel = 2"]
    end
    
    subgraph Client["Client Settings (All Computers)"]
        ClientPath["HKLM\SOFTWARE\Microsoft\Windows\<br/>CurrentVersion\Policies\System\Kerberos\Parameters"]
        ClientEnable["EnableCbacAndArmor = 1"]
    end
    
    subgraph GPO["GPO Deployment"]
        DCGPO["Default Domain Controllers Policy<br/>Registry.pol"]
        DomainGPO["Default Domain Policy<br/>Registry.pol"]
    end
    
    DCGPO --> KDC
    DomainGPO --> Client
    
    subgraph Binary["Registry.pol Format"]
        Header["PReg Header<br/>0x67655250 0x00000001"]
        Entry["[key;value;type;size;data]<br/>UTF-16LE encoded"]
    end
    
    GPO --> Binary
```

## 8. Forest-Wide Deployment

```mermaid
flowchart TB
    subgraph Forest["Active Directory Forest"]
        subgraph ForestRoot["Forest Root: praevia.local"]
            FR_DC["FR-AD01<br/>Domain Controller"]
            FR_Config["Configuration NC<br/>• Tier0-RestrictedAuth<br/>• Tier1-RestrictedAuth<br/>• Tier0-Silo<br/>• Tier1-Silo"]
            FR_GMSA["ADTierGuard-svc$<br/>GMSA"]
            FR_Groups["Universal Groups<br/>• Tier0-Computers<br/>• Tier1-Computers"]
        end
        
        subgraph Child1["Child Domain: child.praevia.local"]
            C1_DC["C1-AD01<br/>Domain Controller"]
            C1_OU["OU=ADTierGuard<br/>Local OU Structure"]
            C1_GPO["GPO: ADTierGuard<br/>Tier Isolation"]
        end
        
        subgraph Child2["External Trust: fabrikam.local"]
            C2_DC["FAB-AD01<br/>Domain Controller"]
            C2_OU["OU=ADTierGuard<br/>Local OU Structure"]
            C2_GPO["GPO: ADTierGuard<br/>Tier Isolation"]
        end
        
        subgraph GrandChild["Grandchild: gr.child.praevia.local"]
            GC_DC["GR-AD01<br/>Domain Controller"]
            GC_OU["OU=ADTierGuard<br/>Local OU Structure"]
            GC_GPO["GPO: ADTierGuard<br/>Tier Isolation"]
        end
    end
    
    FR_Config -.->|Policy Reference| C1_DC
    FR_Config -.->|Policy Reference| C2_DC
    FR_Config -.->|Policy Reference| GC_DC
    
    FR_Groups -.->|Universal Group| C1_DC
    FR_Groups -.->|Universal Group| C2_DC
    FR_Groups -.->|Universal Group| GC_DC
```

## 9. State Diagram - User Protection

```mermaid
stateDiagram-v2
    [*] --> Unprotected : User Created
    
    Unprotected --> InTierOU : User moved to<br/>OU=Users,OU=Tier 0,OU=ADTierGuard
    
    InTierOU --> PolicyApplied : User Sync runs<br/>Sets msDS-AssignedAuthNPolicy
    
    PolicyApplied --> FullyProtected : Tier 0 Only:<br/>• Add to Protected Users<br/>• Remove from unauthorized groups
    
    PolicyApplied --> PolicyApplied : Tier 1:<br/>Policy only, no Protected Users
    
    FullyProtected --> FullyProtected : Ongoing sync<br/>maintains state
    
    FullyProtected --> Stale : User moved out<br/>of Tier OU
    
    Stale --> Unprotected : Next sync removes<br/>policy and protections
    
    state FullyProtected {
        [*] --> HasPolicy
        HasPolicy --> InProtectedUsers
        InProtectedUsers --> CleanedGroups
    }
```

## 10. Scheduled Task Execution Timeline

```mermaid
gantt
    title ADTierGuard Scheduled Tasks - 1 Hour Timeline
    dateFormat HH:mm
    axisFormat %H:%M
    
    section Computer Sync
    Tier 0 Computers    :t0c1, 00:00, 2m
    Tier 1 Computers    :t1c1, 00:05, 2m
    Tier 0 Computers    :t0c2, 00:10, 2m
    Tier 1 Computers    :t1c2, 00:15, 2m
    Tier 0 Computers    :t0c3, 00:20, 2m
    Tier 1 Computers    :t1c3, 00:25, 2m
    Tier 0 Computers    :t0c4, 00:30, 2m
    Tier 1 Computers    :t1c4, 00:35, 2m
    Tier 0 Computers    :t0c5, 00:40, 2m
    Tier 1 Computers    :t1c5, 00:45, 2m
    Tier 0 Computers    :t0c6, 00:50, 2m
    Tier 1 Computers    :t1c6, 00:55, 2m
    
    section User Sync (Disabled by default)
    Tier 0 Users        :crit, t0u1, 00:00, 3m
    Tier 1 Users        :crit, t1u1, 00:00, 3m
    
    section GMSA Context
    GMSA Switch         :gmsa1, 00:00, 1m
```

## 11. OU Structure

```mermaid
flowchart TB
    subgraph Domain["DC=domain,DC=com"]
        ADTierGuard["OU=ADTierGuard"]
        
        subgraph Tier0["OU=Tier 0"]
            T0Users["OU=Users<br/>Tier 0 Admin Accounts"]
            T0Svc["OU=Service Accounts<br/>Tier 0 Service Accounts"]
            T0Comp["OU=Computers<br/>Tier 0 PAWs, Jump Servers"]
            T0Groups["OU=Groups<br/>Tier 0 Security Groups"]
        end
        
        subgraph Tier1["OU=Tier 1"]
            T1Users["OU=Users<br/>Tier 1 Admin Accounts"]
            T1Svc["OU=Service Accounts<br/>Tier 1 Service Accounts"]
            T1Comp["OU=Computers<br/>Tier 1 Member Servers"]
            T1Groups["OU=Groups<br/>Tier 1 Security Groups"]
        end
        
        ADTierGuard --> Tier0
        ADTierGuard --> Tier1
    end
    
    style T0Users fill:#ff9999
    style T0Svc fill:#ffcc99
    style T0Comp fill:#99ff99
    style T0Groups fill:#9999ff
```

## 12. Event IDs Reference

```mermaid
flowchart LR
    subgraph Computer["Computer Events (1xxx)"]
        C1000["1000: Sync Started"]
        C1001["1001: Sync Completed"]
        C1100["1100: Added to Group"]
        C1101["1101: Removed from Group"]
        C1900["1900: Sync Failed"]
    end
    
    subgraph User["User Events (2xxx)"]
        U2000["2000: Sync Started"]
        U2001["2001: Sync Completed"]
        U2100["2100: Policy Applied"]
        U2101["2101: Added to Protected Users"]
        U2102["2102: Removed from Priv Group"]
        U2900["2900: Sync Failed"]
    end
    
    subgraph Config["Config Events (3xxx)"]
        CF3000["3000: Config Loaded"]
        CF3001["3001: Config Error"]
    end
```
