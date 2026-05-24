<#
.SYNOPSIS
    Scans javaw.exe process memory for known Prestige Client signatures.
.DESCRIPTION
    All memory enumeration and scanning is handled in C# via P/Invoke to
    completely bypass PowerShell 5.1's [ref] struct marshalling bug.
.NOTES
    Requires elevated (Administrator) privileges.
#>

 $CSharpCode = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class PrestigeScanner
{
    [Flags]
    public enum ProcessAccessFlags : uint
    {
        VMRead = 0x00000010,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000
    }

    [Flags]
    public enum MemoryProtection : uint
    {
        NoAccess = 0x01, ReadOnly = 0x02, ReadWrite = 0x04, WriteCopy = 0x08,
        Execute = 0x10, ExecuteRead = 0x20, ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80, Guard = 0x100, NoChange = 0x400
    }

    [Flags]
    public enum AllocationProtect : uint
    {
        Commit = 0x1000, Reserve = 0x2000, Decommit = 0x4000, Release = 0x8000
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
    private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, IntPtr lpBuffer, uint dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static List<MEMORY_BASIC_INFORMATION> EnumerateRegions(IntPtr hProcess)
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

                MEMORY_BASIC_INFORMATION mbi = (MEMORY_BASIC_INFORMATION)Marshal.PtrToStructure(pMbi, typeof(MEMORY_BASIC_INFORMATION));
                regions.Add(mbi);

                long next = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (next <= 0) break;
                address = new IntPtr(next);
            }
        }
        finally { Marshal.FreeHGlobal(pMbi); }

        return regions;
    }

    public static string ScanProcess(int targetPid, byte[][] signatures, string[] sigNames, string[] blacklist, out int regionCount, out long bytesScanned)
    {
        regionCount = 0;
        bytesScanned = 0;
        var hits = new Dictionary<string, List<long>>();
        var blackSet = new HashSet<string>(blacklist);

        IntPtr hProc = OpenProcess(ProcessAccessFlags.VMRead | ProcessAccessFlags.QueryInformation | ProcessAccessFlags.QueryLimitedInformation, false, targetPid);
        if (hProc == IntPtr.Zero) return "ACCESS_DENIED";

        try
        {
            var regions = EnumerateRegions(hProc);
            byte[] buffer = new byte[4 * 1024 * 1024];

            foreach (var mbi in regions)
            {
                uint protect = (uint)mbi.Protect;
                bool readable = (protect & 0x02) != 0 || (protect & 0x04) != 0 || 
                                (protect & 0x20) != 0 || (protect & 0x40) != 0 ||
                                (protect & 0x08) != 0 || (protect & 0x80) != 0;

                if (!readable) continue;

                long regionSize = mbi.RegionSize.ToInt64();
                long baseAddr = mbi.BaseAddress.ToInt64();
                long offset = 0;
                regionCount++;
                bytesScanned += regionSize;

                while (offset < regionSize)
                {
                    int toRead = (int)Math.Min(buffer.Length, regionSize - offset);
                    IntPtr bytesRead;

                    if (ReadProcessMemory(hProc, new IntPtr(baseAddr + offset), buffer, toRead, out bytesRead) && bytesRead.ToInt64() > 0)
                    {
                        int readLen = bytesRead.ToInt32();

                        for (int s = 0; s < signatures.Length; s++)
                        {
                            if (blackSet.Contains(sigNames[s])) continue;

                            byte[] sig = signatures[s];
                            int sigLen = sig.Length;
                            if (sigLen > readLen) continue;

                            int maxIdx = readLen - sigLen;
                            for (int i = 0; i <= maxIdx; i++)
                            {
                                bool match = true;
                                for (int j = 0; j < sigLen; j++)
                                {
                                    if (buffer[i + j] != sig[j]) { match = false; break; }
                                }

                                if (match)
                                {
                                    long hitAddr = baseAddr + offset + i;
                                    if (!hits.ContainsKey(sigNames[s]))
                                        hits[sigNames[s]] = new List<long>();

                                    if (!hits[sigNames[s]].Contains(hitAddr))
                                        hits[sigNames[s]].Add(hitAddr);

                                    i += sigLen - 1;
                                }
                            }
                        }
                    }
                    offset += toRead;
                }
            }
        }
        finally { CloseHandle(hProc); }

        if (hits.Count == 0) return "CLEAN";
        
        var sb = new System.Text.StringBuilder();
        foreach (var kvp in hits)
        {
            sb.Append("HIT|" + kvp.Key + "|");
            for (int i = 0; i < kvp.Value.Count; i++)
            {
                if (i > 0) sb.Append(",");
                sb.Append("0x" + kvp.Value[i].ToString("x"));
            }
            sb.Append("\n");
        }
        return sb.ToString();
    }
}
'@

Add-Type -TypeDefinition $CSharpCode -Language CSharp

# ── Exclusion list ────────────────────────────────────────────────────────
 $blacklist = @(
    '()Ldev/zprestige/prestige/a7;'
)

# ── Signature Database ────────────────────────────────────────────────────
 $signatures = @(
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
    'dev/zprestige/prestige/client/management/SocialsManager.addFriend'
    'dev/zprestige/prestige/client/management/SocialsManager.removeFriend'
    'dev/zprestige/prestige/client/management/SocialsManager.getPlayerList'
    'dev/zprestige/prestige/client/management/SocialsManager.getFriends'
    'dev/zprestige/prestige/client/management/ConfigManager.load'
    'dev/zprestige/prestige/client/management/ConfigManager.save'
    'dev/zprestige/prestige/Constants'
    'dev/zprestige/prestige/loader/PrestigeClient'
    'dev.zprestige.prestige.Native'
    'dev.zprestige.prestige.client.Prestige'
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
    'https://api.prestigeclient.vip'
    'https://prestigeclient.vip/'
    'api.prestigeclient.vip'
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
    'Prestige-Injection'
    'Prestige-Classloader-Injector'
    'Prestige Software Development'
    'JNI_Auth'
    'DES&dev/zprestige/prestige/client/Prestige'
)

# ── Prepare arrays for C# ─────────────────────────────────────────────────
 $sigNameArray = [string[]]$signatures
 $sigByteArray = New-Object byte[][] ($signatures.Count)
for ($i = 0; $i -lt $signatures.Count; $i++) {
    $sigByteArray[$i] = [System.Text.Encoding]::UTF8.GetBytes($signatures[$i])
}
 $blacklistArray = [string[]]$blacklist

# ── Main Logic ────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  ╔══════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '  ║       Prestige Client Memory Scanner for javaw.exe     ║' -ForegroundColor Cyan
Write-Host '  ╚══════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host ''

 $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[!] WARNING: Not running as Administrator.' -ForegroundColor Yellow
    Write-Host '    Scan may fail to open javaw.exe. Re-run in an elevated shell.' -ForegroundColor Yellow
    Write-Host ''
}

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

 $totalHits = 0

foreach ($proc in $procs) {
    $procId = $proc.Id
    Write-Host ("── Scanning PID {0} ──" -f $procId) -ForegroundColor White

    $regionCount = 0
    $bytesScanned = [long]0
    
    $result = [PrestigeScanner]::ScanProcess($procId, $sigByteArray, $sigNameArray, $blacklistArray, [ref] $regionCount, [ref] $bytesScanned)

    Write-Host ("    Regions scanned : {0:N0}" -f $regionCount) -ForegroundColor DarkGray
    Write-Host ("    Data scanned    : {0:N2} MB" -f ($bytesScanned / 1MB)) -ForegroundColor DarkGray
    Write-Host ''

    if ($result -eq "ACCESS_DENIED") {
        Write-Host '    [x] Access denied. Run as Administrator.' -ForegroundColor Red
    } elseif ($result -eq "CLEAN") {
        Write-Host '    [OK] No Prestige Client signatures detected.' -ForegroundColor Green
    } else {
        $processHits = @{}
        $hitCount = 0
        
        foreach ($line in $result -split "`n") {
            if ($line -match '^HIT\|(.+?)\|(.+)$') {
                $sig = $matches[1]
                $addrs = $matches[2] -split ','
                $processHits[$sig] = $addrs
                $hitCount += $addrs.Count
            }
        }
        $totalHits += $hitCount

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
