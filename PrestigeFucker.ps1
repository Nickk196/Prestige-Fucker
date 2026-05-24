<#
.SYNOPSIS
    Scans javaw.exe process memory for known Prestige Client signatures.
.DESCRIPTION
    Uses Windows API via P/Invoke to enumerate and read memory regions
    of the javaw.exe process, then searches for a curated list of
    signature strings indicative of Prestige Client injection.
.NOTES
    Requires elevated (Administrator) privileges to open other processes.
    Compatible with PowerShell 5.1+ and PowerShell 7+.
#>

 $code = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class MemScan
{
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VMOperation = 0x00000008,
        VMRead = 0x00000010,
        VMWrite = 0x00000020,
        DupHandle = 0x00000040,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }

    [Flags]
    public enum AllocationProtect : uint
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        Guard = 0x100,
        NoChange = 0x400,
        Image = 0x1000000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public AllocationProtect AllocationProtect;
        public IntPtr RegionSize;
        public MemoryProtection State;
        public MemoryProtection Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        ProcessAccessFlags processAccess,
        bool bInheritHandle,
        int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        IntPtr lpBuffer,
        uint dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    // Enumerate all memory regions in C# to avoid PowerShell [ref] struct bugs
    public static List<MEMORY_BASIC_INFORMATION> EnumerateRegions(IntPtr hProcess)
    {
        var regions = new List<MEMORY_BASIC_INFORMATION>();
        IntPtr address = IntPtr.Zero;
        int mbiSize = Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
        IntPtr pMbi = Marshal.AllocHGlobal(mbiSize);

        try
        {
            while (true)
            {
                int ret = VirtualQueryEx(hProcess, address, pMbi, (uint)mbiSize);
                if (ret == 0) break;

                MEMORY_BASIC_INFORMATION mbi =
                    (MEMORY_BASIC_INFORMATION)Marshal.PtrToStructure(pMbi, typeof(MEMORY_BASIC_INFORMATION));
                regions.Add(mbi);

                long next = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (next <= 0) break;
                address = new IntPtr(next);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pMbi);
        }

        return regions;
    }
}
'@

Add-Type -TypeDefinition $code -Language CSharp

# ── Exclusion list (addresses or strings to skip) ─────────────────────────
 $blacklist = @(
    '()Ldev/zprestige/prestige/a7;'
)

# ── Signature Database ────────────────────────────────────────────────────

 $signatures = @(
    # Core API / Management layer
    'dev/zprestige/prestige/api/module/Module'
    'dev/zprestige/prestige/client/management/ModuleManager'
    'dev/zprestige/prestige/client/Prestige'
    'dev/zprestige/prestige/client/management/SocialsManager'
    'dev/zprestige/prestige/api/module/Category'
    'dev/zprestige/prestige/api/setting/BindSetting'
    'dev/zprestige/prestige/client/management/ConfigManager'
    'dev/zprestige/prestige/api/setting/ColorSetting'
    'dev/zprestige/prestige/api/setting/BooleanSetting'
    'dev/zprestige/prestige/api/setting/IntSetting'
    'dev/zprestige/prestige/api/setting/FloatSetting'
    'dev/zprestige/prestige/api/setting/ModeSetting'
    'dev/zprestige/prestige/api/setting/MinMaxSetting'
    'dev/zprestige/prestige/api/setting/StringSetting'
    'dev/zprestige/prestige/api/setting/MultiModeSetting'
    'dev/zprestige/prestige/api/setting/Setting'

    # Reflective method descriptors
    'dev/zprestige/prestige/client/management/ModuleManager.setMainColor'
    'dev/zprestige/prestige/client/management/ModuleManager.setMenuBind'
    'dev/zprestige/prestige/client/management/ModuleManager.getModuleList'
    'dev/zprestige/prestige/client/Prestige.moduleManager'
    'dev/zprestige/prestige/client/Prestige.configManager'
    'dev/zprestige/prestige/client/Prestige.socialsManager'
    'dev/zprestige/prestige/api/module/Module.getName'
    'dev/zprestige/prestige/api/module/Module.getDescription'
    'dev/zprestige/prestige/api/module/Module.isEnabled'
    'dev/zprestige/prestige/api/module/Module.getCategory'
    'dev/zprestige/prestige/api/module/Module.getAllSettings'
    'dev/zprestige/prestige/api/setting/Setting.getName'
    'dev/zprestige/prestige/api/setting/Setting.getDescription'
    'dev/zprestige/prestige/api/setting/Setting.isVisible'
    'dev/zprestige/prestige/api/setting/Setting.getValue'
    'dev/zprestige/prestige/api/setting/Setting.setValue'

    # Setting sub-class descriptors
    'dev/zprestige/prestige/api/setting/IntSetting.getMin'
    'dev/zprestige/prestige/api/setting/IntSetting.getMax'
    'dev/zprestige/prestige/api/setting/FloatSetting.getMin'
    'dev/zprestige/prestige/api/setting/FloatSetting.getMax'
    'dev/zprestige/prestige/api/setting/ModeSetting.getValues'
    'dev/zprestige/prestige/api/setting/MultiModeSetting.getValues'
    'dev/zprestige/prestige/api/setting/MultiModeSetting.getValuesValues'
    'dev/zprestige/prestige/api/setting/MultiModeSetting.setValue'
    'dev/zprestige/prestige/api/setting/BindSetting.isHold'
    'dev/zprestige/prestige/api/setting/BindSetting.setHold'
    'dev/zprestige/prestige/api/setting/MinMaxSetting.getMinValue'
    'dev/zprestige/prestige/api/setting/MinMaxSetting.getMaxValue'
    'dev/zprestige/prestige/api/setting/MinMaxSetting.setMinValue'
    'dev/zprestige/prestige/api/setting/MinMaxSetting.getMin'
    'dev/zprestige/prestige/api/setting/MinMaxSetting.setMaxValue'
    'dev/zprestige/prestige/api/setting/MinMaxSetting.getMax'

    # Socials / Config management
    'dev/zprestige/prestige/client/management/SocialsManager.addFriend'
    'dev/zprestige/prestige/client/management/SocialsManager.removeFriend'
    'dev/zprestige/prestige/client/management/SocialsManager.getPlayerList'
    'dev/zprestige/prestige/client/management/SocialsManager.getFriends'
    'dev/zprestige/prestige/client/management/ConfigManager.load'
    'dev/zprestige/prestige/client/management/ConfigManager.save'

    # Constants, loader, and native bridge
    'dev/zprestige/prestige/Constants'
    'dev/zprestige/prestige/loader/PrestigeClient'
    'dev.zprestige.prestige.Native'
    'dev.zprestige.prestige.client.Prestige'

    # Branding / UI strings
    '@Prestige'
    'Prestige Client'
    'Initializing Prestige'
    'Initializing Prestige Client'
    'Pre-launch Prestige Client'
    'Prestige Client Initialized'
    'Prestige Client initialized'
    'Prestige Client initialization failed'
    'Prestige ready to use'
    'Prestige is ready to use'
    'PrestigeClassLoader'
    'PrestigeClient.java'
    'Failed to load Prestige main class'
    'Failed to create Prestige main instance'
    '_Prestige_Status_'

    # C2 / API endpoints
    'https://api.prestigeclient.vip'
    'https://prestigeclient.vip/'
    'api.prestigeclient.vip'

    # Embedded resource paths
    'assets/prestige/icons/categories/'
    'assets/prestige/sounds/hover.wav'
    'assets/prestige/sounds/pop.wav'
    'assets/prestige/sounds/pop2.wav'
    'assets/prestige/sounds/pop3.wav'
    'assets/prestige/sounds/success.wav'
    'assets/prestige/sounds/popup.wav'
    'assets/prestige/sounds/intro.wav'
    'assets/prestige/sounds/dropdown.wav'
    'assets/prestige/sounds/woosh.wav'
    'assets/prestige/icons/other/'
    'assets/prestige/icons/logo.png'

    # Build-path artefacts left in the binary
    'Prestige-Injection'
    'Prestige-Classloader-Injector'
    'Prestige Software Development'
    'JNI_Auth'

    # DES encryption marker
    'DES&dev/zprestige/prestige/client/Prestige'
)

# Pre-convert signatures to byte arrays for fast comparison
 $sigBytes = foreach ($s in $signatures) {
    @{ String = $s; Bytes = [System.Text.Encoding]::UTF8.GetBytes($s) }
}

# ── Helper: Readable memory protection filter ─────────────────────────────
function Test-ReadableProtect([uint32]$protect) {
    $readable = [uint32](
        [MemScan+MemoryProtection]::ReadOnly -bor
        [MemScan+MemoryProtection]::ReadWrite -bor
        [MemScan+MemoryProtection]::ExecuteRead -bor
        [MemScan+MemoryProtection]::ExecuteReadWrite -bor
        [MemScan+MemoryProtection]::WriteCopy -bor
        [MemScan+MemoryProtection]::ExecuteWriteCopy
    )
    return ($protect -band $readable) -ne 0
}

# ── Main Scan Logic ───────────────────────────────────────────────────────

Write-Host ''
Write-Host '  ╔══════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '  ║       Prestige Client Memory Scanner for javaw.exe     ║' -ForegroundColor Cyan
Write-Host '  ╚══════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host ''

# Check admin
 $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[!] WARNING: Not running as Administrator.' -ForegroundColor Yellow
    Write-Host '    Scan may fail to open javaw.exe. Re-run in an elevated shell.' -ForegroundColor Yellow
    Write-Host ''
}

# Locate javaw processes
 $procs = Get-Process -Name 'javaw' -ErrorAction SilentlyContinue
if (-not $procs -or $procs.Count -eq 0) {
    Write-Host '[x] No javaw.exe process found. Is Minecraft running?' -ForegroundColor Red
    exit 1
}

Write-Host "[i] Found $($procs.Count) javaw.exe process(es):" -ForegroundColor White
foreach ($p in $procs) {
    Write-Host ("    PID {0,-8} Started: {1}" -f $p.Id, $p.StartTime) -ForegroundColor Gray
}
Write-Host ''

# ── MEM_COMMIT constant (0x1000) — what VirtualQueryEx actually returns for State
$MEM_COMMIT = [uint32]0x1000

# Scan each process
 $totalHits = 0

foreach ($proc in $procs) {
    # FIX 1: renamed from $pid (reserved PS variable) to $procId
    $procId = $proc.Id
    Write-Host ("── Scanning PID {0} ──" -f $procId) -ForegroundColor White

    $access = [MemScan+ProcessAccessFlags]::VMRead -bor `
              [MemScan+ProcessAccessFlags]::QueryInformation -bor `
              [MemScan+ProcessAccessFlags]::QueryLimitedInformation
    $hProc = [MemScan]::OpenProcess($access, $false, $procId)

    if ($hProc -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host ("    [x] OpenProcess failed (Win32 error $err — " +
                     'access denied or process protected)') -ForegroundColor Red
        Write-Host ''
        continue
    }

    # Enumerate all memory regions via C# (avoids PS [ref] struct bug)
    $regions = [MemScan]::EnumerateRegions($hProc)

    $processHits = @{}
    $regionCount = 0
    $bytesScanned = [long]0
    $bufferSize = 4 * 1024 * 1024  # 4 MB read chunks
    $buffer = New-Object byte[] $bufferSize

    foreach ($mbi in $regions) {
        $regionSize = $mbi.RegionSize.ToInt64()
        $stateVal   = [uint32]$mbi.State
        $protect    = [uint32]$mbi.Protect
        $baseAddress = $mbi.BaseAddress

        # FIX 2: compare State against the real MEM_COMMIT value (0x1000),
        # not against MemoryProtection enum entries (which are protection flags,
        # not state flags — this was why Prestige was never detected).
        $committed = ($stateVal -eq $MEM_COMMIT)

        if ($committed -and (Test-ReadableProtect $protect)) {
            $regionCount++
            $bytesScanned += $regionSize

            # Read the region in chunks
            $offset = 0
            while ($offset -lt $regionSize) {
                $toRead = [Math]::Min($bufferSize, $regionSize - $offset)
                $bytesRead = [IntPtr]::Zero
                $readAddr = [IntPtr]::new($baseAddress.ToInt64() + $offset)

                $ok = [MemScan]::ReadProcessMemory(
                    $hProc, $readAddr, $buffer, $toRead, [ref] $bytesRead)

                if ($ok -and $bytesRead.ToInt64() -gt 0) {
                    $readLen = $bytesRead.ToInt64()

                    # Search for each signature in this chunk
                    foreach ($sig in $sigBytes) {
                        # Skip blacklisted strings
                        $skip = $false
                        foreach ($bl in $blacklist) {
                            if ($sig.String -eq $bl) { $skip = $true; break }
                        }
                        if ($skip) { continue }

                        $sigLen = $sig.Bytes.Length
                        if ($sigLen -gt $readLen) { continue }

                        $maxIdx = $readLen - $sigLen
                        for ($i = 0; $i -le $maxIdx; $i++) {
                            $match = $true
                            for ($j = 0; $j -lt $sigLen; $j++) {
                                if ($buffer[$i + $j] -ne $sig.Bytes[$j]) {
                                    $match = $false
                                    break
                                }
                            }
                            if ($match) {
                                $hitAddr = '0x{0:x}' -f ($readAddr.ToInt64() + $i)
                                if (-not $processHits.ContainsKey($sig.String)) {
                                    $processHits[$sig.String] = [System.Collections.Generic.List[string]]::new()
                                }
                                if ($hitAddr -notin $processHits[$sig.String]) {
                                    $processHits[$sig.String].Add($hitAddr)
                                }
                                $i += $sigLen - 1
                            }
                        }
                    }
                }
                $offset += $toRead
            }
        }
    }

    [MemScan]::CloseHandle($hProc)

    # ── Report Results ────────────────────────────────────────────────
    $hitCount = 0
    foreach ($key in $processHits.Keys) {
        $hitCount += $processHits[$key].Count
    }
    $totalHits += $hitCount

    Write-Host ("    Regions scanned : {0:N0}" -f $regionCount) -ForegroundColor DarkGray
    Write-Host ("    Data scanned    : {0:N2} MB" -f ($bytesScanned / 1MB)) -ForegroundColor DarkGray
    Write-Host ''

    if ($hitCount -eq 0) {
        Write-Host '    [OK] No Prestige Client signatures detected.' -ForegroundColor Green
    } else {
        Write-Host ("    [!!] {0} signature hit(s) found:" -f $hitCount) -ForegroundColor Red
        Write-Host ''

        $categories = @{
            'API / Module System'    = @('dev/zprestige/prestige/api/', 'dev/zprestige/prestige/client/management/')
            'Loader / Native Bridge' = @('dev/zprestige/prestige/loader/', 'dev.zprestige.prestige.Native', 'PrestigeClassLoader', 'PrestigeClient.java')
            'Client Entry Point'     = @('dev/zprestige/prestige/client/Prestige', 'dev.zprestige.prestige.client.Prestige')
            'Constants'              = @('dev/zprestige/prestige/Constants')
            'Branding / Status'      = @('@Prestige', 'Prestige Client', 'Initializing Prestige', 'Pre-launch', 'ready to use', 'initialized', 'failed', '_Prestige_Status_')
            'C2 / API Endpoints'     = @('api.prestigeclient.vip', 'prestigeclient.vip')
            'Embedded Resources'     = @('assets/prestige/')
            'Build Path Artefacts'   = @('Prestige-Injection', 'Prestige-Classloader-Injector', 'Prestige Software Development', 'JNI_Auth')
            'Encryption Marker'      = @('DES&dev/zprestige')
            'Obfuscated Classes'     = @('dev/zprestige/prestige/', 'dev.zprestige.prestige.')
        }

        foreach ($cat in $categories.Keys) {
            $catHits = @{}
            foreach ($sig in $processHits.Keys) {
                foreach ($pattern in $categories[$cat]) {
                    if ($sig -like "*$pattern*") {
                        # For obfuscated classes, exclude already-categorized ones
                        if ($cat -eq 'Obfuscated Classes') {
                            $isOther = $false
                            foreach ($otherCat in $categories.Keys) {
                                if ($otherCat -eq 'Obfuscated Classes') { continue }
                                foreach ($op in $categories[$otherCat]) {
                                    if ($sig -like "*$op*") { $isOther = $true; break }
                                }
                                if ($isOther) { break }
                            }
                            if ($isOther) { continue }
                        }
                        $catHits[$sig] = $processHits[$sig]
                        break
                    }
                }
            }
            if ($catHits.Count -gt 0) {
                Write-Host ("    ┌─ {0}" -f $cat) -ForegroundColor Yellow
                $catKeys = @($catHits.Keys)
                for ($si = 0; $si -lt $catKeys.Count; $si++) {
                    $sig = $catKeys[$si]
                    $addrs = $catHits[$sig]
                    $prefix = if ($si -lt ($catKeys.Count - 1)) { '├' } else { '└' }
                    Write-Host ("    {0}─ " -f $prefix) -NoNewline -ForegroundColor DarkGray
                    Write-Host $sig -ForegroundColor White
                    for ($ai = 0; $ai -lt $addrs.Count; $ai++) {
                        $a = $addrs[$ai]
                        $innerPrefix = if ($ai -lt ($addrs.Count - 1)) { '│  ' } else { '   ' }
                        $addrPrefix = if ($ai -lt ($addrs.Count - 1)) { '├' } else { '└' }
                        Write-Host ("    {0}{1}─ {2} ({3} bytes)" -f $innerPrefix, $addrPrefix, $a, $sig.Length) -ForegroundColor DarkCyan
                    }
                }
                Write-Host ''
            }
        }
    }
    Write-Host ''
}

# ── Summary ──────────────────────────────────────────────────────────────
Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
if ($totalHits -eq 0) {
    Write-Host '  RESULT: CLEAN — No Prestige Client signatures found.' -ForegroundColor Green
} else {
    Write-Host ("  RESULT: DETECTED — {0} Prestige Client signature(s) across {1} process(es)." -f $totalHits, $procs.Count) -ForegroundColor Red
    Write-Host ''
    Write-Host '  Prestige Client appears to be injected into the target process.' -ForegroundColor Yellow
    Write-Host '  Detected components:' -ForegroundColor Yellow
    Write-Host '    • Module/Setting API layer' -ForegroundColor DarkYellow
    Write-Host '    • JNI classloader injector' -ForegroundColor DarkYellow
    Write-Host '    • Native DLL bridge (dev.zprestige.prestige.Native)' -ForegroundColor DarkYellow
    Write-Host '    • C2 endpoint: api.prestigeclient.vip' -ForegroundColor DarkYellow
    Write-Host '    • ImGui GUI (assets/prestige/)' -ForegroundColor DarkYellow
}
Write-Host '═══════════════════════════════════════════════════════════════' -ForegroundColor Cyan
Write-Host ''
