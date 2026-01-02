#Requires -Version 5.1
<#
.SYNOPSIS
    Test ADTierGuard components before full installation
    
.DESCRIPTION
    Tests:
    1. P/Invoke SDDL conversion for conditional ACEs
    2. Registry.pol binary format
    3. ADSI connectivity to configuration partition
    4. Schema class availability (msDS-AuthNPolicy, msDS-AuthNPolicySilo)
#>

$ErrorActionPreference = 'Stop'

Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
Write-Host "  ADTierGuard Pre-Installation Test" -ForegroundColor Cyan
Write-Host ("=" * 60) + "`n" -ForegroundColor Cyan

#region Test 1: P/Invoke SDDL Converter
Write-Host "[TEST 1] P/Invoke SDDL Converter" -ForegroundColor Yellow

$sddlConverterCode = @'
using System;
using System.Runtime.InteropServices;

public class SddlConverterTest
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
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out pSD, out size))
            {
                int error = Marshal.GetLastWin32Error();
                throw new Exception("Win32 error: " + error);
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
    Write-Host "  [OK] P/Invoke type loaded" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -like "*already exists*") {
        Write-Host "  [OK] P/Invoke type already loaded" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# Test simple SDDL
try {
    $simpleSDDL = "O:SYG:SYD:(A;;GA;;;BA)"
    $bytes = [SddlConverterTest]::ConvertSddlToBinary($simpleSDDL)
    Write-Host "  [OK] Simple SDDL converted: $($bytes.Length) bytes" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Simple SDDL: $_" -ForegroundColor Red
}

# Test conditional ACE SDDL (the critical one for auth policies)
try {
    # Using a sample SID format - ED = Enterprise Domain Controllers (S-1-5-9)
    $conditionalSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of {SID(ED)}))"
    $bytes = [SddlConverterTest]::ConvertSddlToBinary($conditionalSDDL)
    Write-Host "  [OK] Conditional ACE (Member_of ED) converted: $($bytes.Length) bytes" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Conditional ACE (ED): $_" -ForegroundColor Red
}

# Test with a full domain SID
try {
    $fullSDDL = "O:SYG:SYD:(XA;OICI;CR;;;WD;((Member_of {SID(ED)}) || (Member_of_any {SID(S-1-5-21-1234567890-1234567890-1234567890-1001)})))"
    $bytes = [SddlConverterTest]::ConvertSddlToBinary($fullSDDL)
    Write-Host "  [OK] Full conditional ACE (ED || Group) converted: $($bytes.Length) bytes" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Full conditional ACE: $_" -ForegroundColor Red
}

#endregion

#region Test 2: Registry.pol Format
Write-Host "`n[TEST 2] Registry.pol Binary Format" -ForegroundColor Yellow

$testPolPath = Join-Path $env:TEMP "test_registry.pol"

try {
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    
    # Header
    $bw.Write([uint32]0x67655250)  # PReg
    $bw.Write([uint32]0x00000001)  # Version 1
    
    $encoding = [System.Text.Encoding]::Unicode
    
    # Test entry
    $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
    $valueName = "EnableCbacAndArmor"
    
    $bw.Write([byte[]]@(0x5B, 0x00))  # [
    $bw.Write($encoding.GetBytes($key))
    $bw.Write([byte[]]@(0x00, 0x00))  # null
    $bw.Write([byte[]]@(0x3B, 0x00))  # ;
    $bw.Write($encoding.GetBytes($valueName))
    $bw.Write([byte[]]@(0x00, 0x00))  # null
    $bw.Write([byte[]]@(0x3B, 0x00))  # ;
    $bw.Write([uint32]4)              # REG_DWORD
    $bw.Write([byte[]]@(0x3B, 0x00))  # ;
    $bw.Write([uint32]4)              # size
    $bw.Write([byte[]]@(0x3B, 0x00))  # ;
    $bw.Write([uint32]1)              # data
    $bw.Write([byte[]]@(0x5D, 0x00))  # ]
    
    $bw.Flush()
    $polBytes = $ms.ToArray()
    $bw.Close()
    $ms.Close()
    
    [System.IO.File]::WriteAllBytes($testPolPath, $polBytes)
    
    # Verify header
    $readBytes = [System.IO.File]::ReadAllBytes($testPolPath)
    $header = [System.BitConverter]::ToUInt32($readBytes, 0)
    if ($header -eq 0x67655250) {
        Write-Host "  [OK] Registry.pol created: $($polBytes.Length) bytes, valid PReg header" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Invalid header: $header" -ForegroundColor Red
    }
    
    Remove-Item $testPolPath -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "  [FAIL] Registry.pol: $_" -ForegroundColor Red
}

#endregion

#region Test 3: ADSI Forest Connectivity
Write-Host "`n[TEST 3] ADSI Forest Connectivity" -ForegroundColor Yellow

try {
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $configNC = $rootDSE.configurationNamingContext.Value
    $defaultNC = $rootDSE.defaultNamingContext.Value
    
    Write-Host "  [OK] RootDSE accessible" -ForegroundColor Green
    Write-Host "       Config NC: $configNC" -ForegroundColor Gray
    Write-Host "       Default NC: $defaultNC" -ForegroundColor Gray
} catch {
    Write-Host "  [FAIL] Cannot connect to RootDSE: $_" -ForegroundColor Red
    exit 1
}

#endregion

#region Test 4: Authentication Policy Container
Write-Host "`n[TEST 4] Authentication Policy Configuration" -ForegroundColor Yellow

try {
    $authNConfigPath = "CN=AuthN Policy Configuration,CN=Services,$configNC"
    $authNConfig = [ADSI]"LDAP://$authNConfigPath"
    
    if ($authNConfig.distinguishedName) {
        Write-Host "  [OK] AuthN Policy Configuration container exists" -ForegroundColor Green
        
        # Check for sub-containers
        $policiesPath = "CN=AuthN Policies,$authNConfigPath"
        $silosPath = "CN=AuthN Silos,$authNConfigPath"
        
        try {
            $policies = [ADSI]"LDAP://$policiesPath"
            if ($policies.distinguishedName) {
                Write-Host "  [OK] AuthN Policies container exists" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [WARN] AuthN Policies container not found (may need 2012R2 DFL)" -ForegroundColor Yellow
        }
        
        try {
            $silos = [ADSI]"LDAP://$silosPath"
            if ($silos.distinguishedName) {
                Write-Host "  [OK] AuthN Silos container exists" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [WARN] AuthN Silos container not found (may need 2012R2 DFL)" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "  [FAIL] Cannot access AuthN Policy Configuration: $_" -ForegroundColor Red
    Write-Host "       Ensure domain functional level is Windows Server 2012 R2 or higher" -ForegroundColor Yellow
}

#endregion

#region Test 5: Default Domain Policies
Write-Host "`n[TEST 5] Default GPO Access" -ForegroundColor Yellow

try {
    $policiesContainer = "CN=Policies,CN=System,$defaultNC"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$policiesContainer")
    
    $searcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=Default Domain Controllers Policy))"
    $dcPolicy = $searcher.FindOne()
    if ($dcPolicy) {
        Write-Host "  [OK] Default Domain Controllers Policy found: $($dcPolicy.Properties['name'][0])" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Default Domain Controllers Policy not found" -ForegroundColor Yellow
    }
    
    $searcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=Default Domain Policy))"
    $domainPolicy = $searcher.FindOne()
    if ($domainPolicy) {
        Write-Host "  [OK] Default Domain Policy found: $($domainPolicy.Properties['name'][0])" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Default Domain Policy not found" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [FAIL] Cannot enumerate GPOs: $_" -ForegroundColor Red
}

#endregion

#region Test 6: Enterprise Admin Check
Write-Host "`n[TEST 6] Permissions Check" -ForegroundColor Yellow

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isEA = $currentUser.Groups | Where-Object { $_.Value -like "*-519" }
$isDA = $currentUser.Groups | Where-Object { $_.Value -like "*-512" }

if ($isEA) {
    Write-Host "  [OK] Running as Enterprise Admin" -ForegroundColor Green
} elseif ($isDA) {
    Write-Host "  [WARN] Running as Domain Admin (not Enterprise Admin)" -ForegroundColor Yellow
    Write-Host "       Enterprise Admin is required for forest-wide deployment" -ForegroundColor Yellow
} else {
    Write-Host "  [WARN] Not running as privileged admin" -ForegroundColor Yellow
}

#endregion

Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
Write-Host "  Test Complete" -ForegroundColor Cyan
Write-Host ("=" * 60) + "`n" -ForegroundColor Cyan
