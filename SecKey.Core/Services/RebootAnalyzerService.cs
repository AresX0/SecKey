using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SecKey.Core.Services
{
    /// <summary>
    /// Service for analyzing unexpected system reboots and crashes.
    /// </summary>
    public class RebootAnalyzerService
    {
        #region Event IDs and Constants

        // System Event Log IDs
        private const int EVENT_KERNEL_POWER_CRITICAL = 41;      // Kernel-Power: Unexpected shutdown
        private const int EVENT_BUGCHECK = 1001;                  // BugCheck (BSOD)
        private const int EVENT_EVENT_LOG_STARTED = 6005;         // Event log service started
        private const int EVENT_EVENT_LOG_STOPPED = 6006;         // Event log service stopped (clean shutdown)
        private const int EVENT_UNEXPECTED_SHUTDOWN = 6008;       // Previous shutdown was unexpected
        private const int EVENT_SYSTEM_SHUTDOWN = 1074;           // User-initiated shutdown/restart
        private const int EVENT_DISK_ERROR = 7;                   // Disk error
        private const int EVENT_NTFS_ERROR = 55;                  // NTFS file system error
        
        // Application Event Log IDs
        private const int EVENT_WER_CRASH = 1001;                 // Windows Error Reporting
        private const int EVENT_APP_HANG = 1002;                  // Application hang
        private const int EVENT_APP_ERROR = 1000;                 // Application error

        // Memory dump locations
        private static readonly string[] DumpLocations = new[]
        {
            @"C:\Windows\MEMORY.DMP",
            @"C:\Windows\Minidump",
            @"C:\Windows\LiveKernelReports"
        };

        #endregion

        #region Models

        public class RebootEvent
        {
            public DateTime TimeStamp { get; set; }
            public string EventType { get; set; } = "";
            public string Source { get; set; } = "";
            public int EventId { get; set; }
            public string Description { get; set; } = "";
            public string RootCause { get; set; } = "";
            public string Severity { get; set; } = "Info";
            public string SuggestedFix { get; set; } = "";
            public string RawData { get; set; } = "";
        }

        public class CrashDumpInfo
        {
            public string FilePath { get; set; } = "";
            public string FileName { get; set; } = "";
            public DateTime CreatedTime { get; set; }
            public long FileSize { get; set; }
            public string FileSizeFormatted => FormatFileSize(FileSize);
            public string DumpType { get; set; } = "";
            
            private static string FormatFileSize(long bytes)
            {
                string[] sizes = { "B", "KB", "MB", "GB" };
                int order = 0;
                double size = bytes;
                while (size >= 1024 && order < sizes.Length - 1)
                {
                    order++;
                    size /= 1024;
                }
                return $"{size:0.##} {sizes[order]}";
            }
        }

        public class AnalysisResult
        {
            public List<RebootEvent> UnexpectedReboots { get; set; } = new();
            public List<RebootEvent> CleanShutdowns { get; set; } = new();
            public List<RebootEvent> BSODEvents { get; set; } = new();
            public List<RebootEvent> ApplicationCrashes { get; set; } = new();
            public List<RebootEvent> HardwareErrors { get; set; } = new();
            public List<CrashDumpInfo> CrashDumps { get; set; } = new();
            public Dictionary<string, int> RootCauseSummary { get; set; } = new();
            public DateTime AnalysisTime { get; set; } = DateTime.Now;
            public int DaysAnalyzed { get; set; }
            public string SystemUptime { get; set; } = "";
            public DateTime LastBootTime { get; set; }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Analyzes system logs for unexpected reboots and crashes.
        /// </summary>
        public async Task<AnalysisResult> AnalyzeAsync(
            int daysToAnalyze = 30,
            IProgress<string>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var result = new AnalysisResult
            {
                DaysAnalyzed = daysToAnalyze
            };

            progress?.Report("Getting system uptime...");
            GetSystemUptime(result);

            progress?.Report("Analyzing System Event Log...");
            await AnalyzeSystemLogAsync(result, daysToAnalyze, cancellationToken);

            progress?.Report("Analyzing Application Event Log...");
            await AnalyzeApplicationLogAsync(result, daysToAnalyze, cancellationToken);

            progress?.Report("Scanning for crash dumps...");
            await ScanCrashDumpsAsync(result, cancellationToken);

            progress?.Report("Analyzing Kernel-Power events...");
            await AnalyzeKernelPowerAsync(result, daysToAnalyze, cancellationToken);

            progress?.Report("Generating root cause summary...");
            GenerateRootCauseSummary(result);

            progress?.Report("Analysis complete.");
            return result;
        }

        #endregion

        #region Private Methods

        private void GetSystemUptime(AnalysisResult result)
        {
            try
            {
                var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
                result.LastBootTime = DateTime.Now - uptime;
                
                if (uptime.Days > 0)
                    result.SystemUptime = $"{uptime.Days}d {uptime.Hours}h {uptime.Minutes}m";
                else if (uptime.Hours > 0)
                    result.SystemUptime = $"{uptime.Hours}h {uptime.Minutes}m {uptime.Seconds}s";
                else
                    result.SystemUptime = $"{uptime.Minutes}m {uptime.Seconds}s";
            }
            catch
            {
                result.SystemUptime = "Unknown";
            }
        }

        private async Task AnalyzeSystemLogAsync(AnalysisResult result, int days, CancellationToken ct)
        {
            await Task.Run(() =>
            {
                try
                {
                    var startTime = DateTime.Now.AddDays(-days);
                    var query = new EventLogQuery("System", PathType.LogName,
                        $"*[System[TimeCreated[@SystemTime >= '{startTime:yyyy-MM-ddTHH:mm:ss}']]]");

                    using var reader = new EventLogReader(query);
                    EventRecord? record;

                    while ((record = reader.ReadEvent()) != null)
                    {
                        ct.ThrowIfCancellationRequested();

                        var eventId = record.Id;
                        var provider = record.ProviderName ?? "";
                        var time = record.TimeCreated ?? DateTime.MinValue;
                        var description = "";
                        
                        try { description = record.FormatDescription() ?? ""; }
                        catch { description = "Unable to format description"; }

                        var rebootEvent = new RebootEvent
                        {
                            TimeStamp = time,
                            EventId = eventId,
                            Source = provider,
                            Description = description.Length > 500 ? description.Substring(0, 500) + "..." : description,
                            RawData = description
                        };

                        // Categorize events
                        switch (eventId)
                        {
                            case EVENT_KERNEL_POWER_CRITICAL:
                                rebootEvent.EventType = "Unexpected Shutdown";
                                rebootEvent.Severity = "Critical";
                                rebootEvent.RootCause = AnalyzeKernelPowerEvent(description);
                                rebootEvent.SuggestedFix = GetKernelPowerFix(rebootEvent.RootCause);
                                result.UnexpectedReboots.Add(rebootEvent);
                                break;

                            case EVENT_BUGCHECK:
                                if (provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) ||
                                    description.Contains("bugcheck", StringComparison.OrdinalIgnoreCase))
                                {
                                    rebootEvent.EventType = "Blue Screen (BSOD)";
                                    rebootEvent.Severity = "Critical";
                                    rebootEvent.RootCause = AnalyzeBugCheck(description);
                                    rebootEvent.SuggestedFix = GetBugCheckFix(rebootEvent.RootCause);
                                    result.BSODEvents.Add(rebootEvent);
                                }
                                break;

                            case EVENT_UNEXPECTED_SHUTDOWN:
                                rebootEvent.EventType = "Unexpected Shutdown Detected";
                                rebootEvent.Severity = "Warning";
                                rebootEvent.RootCause = "Previous shutdown was not clean";
                                rebootEvent.SuggestedFix = "Check for power issues, hardware failures, or system crashes before this event.";
                                result.UnexpectedReboots.Add(rebootEvent);
                                break;

                            case EVENT_SYSTEM_SHUTDOWN:
                                rebootEvent.EventType = "User/System Shutdown";
                                rebootEvent.Severity = "Info";
                                rebootEvent.RootCause = AnalyzeShutdownReason(description);
                                rebootEvent.SuggestedFix = "This was an expected shutdown.";
                                result.CleanShutdowns.Add(rebootEvent);
                                break;

                            case EVENT_EVENT_LOG_STARTED:
                                rebootEvent.EventType = "System Started";
                                rebootEvent.Severity = "Info";
                                rebootEvent.RootCause = "System boot completed";
                                result.CleanShutdowns.Add(rebootEvent);
                                break;

                            case EVENT_EVENT_LOG_STOPPED:
                                rebootEvent.EventType = "Clean Shutdown";
                                rebootEvent.Severity = "Info";
                                rebootEvent.RootCause = "Event log stopped normally";
                                result.CleanShutdowns.Add(rebootEvent);
                                break;

                            case EVENT_DISK_ERROR:
                            case EVENT_NTFS_ERROR:
                                rebootEvent.EventType = "Disk/NTFS Error";
                                rebootEvent.Severity = "Warning";
                                rebootEvent.RootCause = "Storage subsystem error";
                                rebootEvent.SuggestedFix = "Run chkdsk, check SMART status, consider replacing drive if errors persist.";
                                result.HardwareErrors.Add(rebootEvent);
                                break;
                        }

                        record.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    result.UnexpectedReboots.Add(new RebootEvent
                    {
                        TimeStamp = DateTime.Now,
                        EventType = "Analysis Error",
                        Severity = "Error",
                        Description = $"Could not read System log: {ex.Message}",
                        RootCause = "Access denied or log unavailable"
                    });
                }
            }, ct);
        }

        private async Task AnalyzeApplicationLogAsync(AnalysisResult result, int days, CancellationToken ct)
        {
            await Task.Run(() =>
            {
                try
                {
                    var startTime = DateTime.Now.AddDays(-days);
                    var query = new EventLogQuery("Application", PathType.LogName,
                        $"*[System[TimeCreated[@SystemTime >= '{startTime:yyyy-MM-ddTHH:mm:ss}']]]" +
                        $"[System[(EventID=1000 or EventID=1001 or EventID=1002)]]");

                    using var reader = new EventLogReader(query);
                    EventRecord? record;

                    while ((record = reader.ReadEvent()) != null)
                    {
                        ct.ThrowIfCancellationRequested();

                        var eventId = record.Id;
                        var provider = record.ProviderName ?? "";
                        var time = record.TimeCreated ?? DateTime.MinValue;
                        var description = "";

                        try { description = record.FormatDescription() ?? ""; }
                        catch { description = "Unable to format description"; }

                        var crashEvent = new RebootEvent
                        {
                            TimeStamp = time,
                            EventId = eventId,
                            Source = provider,
                            Description = description.Length > 500 ? description.Substring(0, 500) + "..." : description,
                            RawData = description
                        };

                        switch (eventId)
                        {
                            case EVENT_APP_ERROR:
                                crashEvent.EventType = "Application Error";
                                crashEvent.Severity = "Warning";
                                crashEvent.RootCause = ExtractFaultingApplication(description);
                                crashEvent.SuggestedFix = "Update the application, check for corrupted files, or reinstall.";
                                result.ApplicationCrashes.Add(crashEvent);
                                break;

                            case EVENT_WER_CRASH:
                                if (provider.Contains("Windows Error Reporting", StringComparison.OrdinalIgnoreCase))
                                {
                                    crashEvent.EventType = "Windows Error Report";
                                    crashEvent.Severity = "Warning";
                                    crashEvent.RootCause = ExtractWERDetails(description);
                                    crashEvent.SuggestedFix = "Check Windows Error Reporting for more details.";
                                    result.ApplicationCrashes.Add(crashEvent);
                                }
                                break;

                            case EVENT_APP_HANG:
                                crashEvent.EventType = "Application Hang";
                                crashEvent.Severity = "Warning";
                                crashEvent.RootCause = ExtractFaultingApplication(description);
                                crashEvent.SuggestedFix = "Application became unresponsive. Check for resource issues or deadlocks.";
                                result.ApplicationCrashes.Add(crashEvent);
                                break;
                        }

                        record.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    result.ApplicationCrashes.Add(new RebootEvent
                    {
                        TimeStamp = DateTime.Now,
                        EventType = "Analysis Error",
                        Severity = "Error",
                        Description = $"Could not read Application log: {ex.Message}"
                    });
                }
            }, ct);
        }

        private async Task AnalyzeKernelPowerAsync(AnalysisResult result, int days, CancellationToken ct)
        {
            await Task.Run(() =>
            {
                try
                {
                    var startTime = DateTime.Now.AddDays(-days);
                    var query = new EventLogQuery("System", PathType.LogName,
                        $"*[System[Provider[@Name='Microsoft-Windows-Kernel-Power']]]" +
                        $"[System[TimeCreated[@SystemTime >= '{startTime:yyyy-MM-ddTHH:mm:ss}']]]");

                    using var reader = new EventLogReader(query);
                    EventRecord? record;

                    while ((record = reader.ReadEvent()) != null)
                    {
                        ct.ThrowIfCancellationRequested();

                        var eventId = record.Id;
                        var time = record.TimeCreated ?? DateTime.MinValue;
                        var description = "";

                        try { description = record.FormatDescription() ?? ""; }
                        catch { description = "Unable to format description"; }

                        // Only process if not already in unexpected reboots
                        if (!result.UnexpectedReboots.Any(r => Math.Abs((r.TimeStamp - time).TotalSeconds) < 5))
                        {
                            if (eventId == 41 || description.Contains("unexpected", StringComparison.OrdinalIgnoreCase))
                            {
                                var powerEvent = new RebootEvent
                                {
                                    TimeStamp = time,
                                    EventId = eventId,
                                    EventType = "Kernel Power Event",
                                    Source = "Microsoft-Windows-Kernel-Power",
                                    Severity = "Critical",
                                    Description = description.Length > 500 ? description.Substring(0, 500) + "..." : description,
                                    RootCause = AnalyzeKernelPowerEvent(description),
                                    RawData = description
                                };
                                powerEvent.SuggestedFix = GetKernelPowerFix(powerEvent.RootCause);
                                result.UnexpectedReboots.Add(powerEvent);
                            }
                        }

                        record.Dispose();
                    }
                }
                catch { /* Kernel-Power log may not be accessible */ }
            }, ct);
        }

        private async Task ScanCrashDumpsAsync(AnalysisResult result, CancellationToken ct)
        {
            await Task.Run(() =>
            {
                foreach (var location in DumpLocations)
                {
                    ct.ThrowIfCancellationRequested();

                    try
                    {
                        if (File.Exists(location))
                        {
                            // Single file (MEMORY.DMP)
                            var info = new FileInfo(location);
                            result.CrashDumps.Add(new CrashDumpInfo
                            {
                                FilePath = location,
                                FileName = info.Name,
                                CreatedTime = info.CreationTime,
                                FileSize = info.Length,
                                DumpType = "Full Memory Dump"
                            });
                        }
                        else if (Directory.Exists(location))
                        {
                            // Directory (Minidump folder)
                            foreach (var file in Directory.GetFiles(location, "*.dmp"))
                            {
                                ct.ThrowIfCancellationRequested();

                                var info = new FileInfo(file);
                                result.CrashDumps.Add(new CrashDumpInfo
                                {
                                    FilePath = file,
                                    FileName = info.Name,
                                    CreatedTime = info.CreationTime,
                                    FileSize = info.Length,
                                    DumpType = location.Contains("Minidump") ? "Minidump" : 
                                               location.Contains("LiveKernel") ? "Live Kernel Dump" : "Memory Dump"
                                });
                            }
                        }
                    }
                    catch { /* Skip inaccessible locations */ }
                }

                // Sort by date
                result.CrashDumps = result.CrashDumps.OrderByDescending(d => d.CreatedTime).ToList();
            }, ct);
        }

        private void GenerateRootCauseSummary(AnalysisResult result)
        {
            var causes = new Dictionary<string, int>();

            foreach (var evt in result.UnexpectedReboots.Concat(result.BSODEvents))
            {
                var cause = string.IsNullOrEmpty(evt.RootCause) ? "Unknown" : evt.RootCause;
                
                // Normalize causes
                if (cause.Contains("power", StringComparison.OrdinalIgnoreCase))
                    cause = "Power Supply Issue";
                else if (cause.Contains("driver", StringComparison.OrdinalIgnoreCase))
                    cause = "Driver Problem";
                else if (cause.Contains("memory", StringComparison.OrdinalIgnoreCase) || 
                         cause.Contains("ram", StringComparison.OrdinalIgnoreCase))
                    cause = "Memory/RAM Issue";
                else if (cause.Contains("overheat", StringComparison.OrdinalIgnoreCase) ||
                         cause.Contains("thermal", StringComparison.OrdinalIgnoreCase))
                    cause = "Overheating";
                else if (cause.Contains("disk", StringComparison.OrdinalIgnoreCase) ||
                         cause.Contains("storage", StringComparison.OrdinalIgnoreCase))
                    cause = "Storage Issue";
                else if (cause.Contains("hardware", StringComparison.OrdinalIgnoreCase))
                    cause = "Hardware Failure";
                else if (cause.Contains("windows update", StringComparison.OrdinalIgnoreCase))
                    cause = "Windows Update";

                if (causes.ContainsKey(cause))
                    causes[cause]++;
                else
                    causes[cause] = 1;
            }

            result.RootCauseSummary = causes.OrderByDescending(kv => kv.Value)
                .ToDictionary(kv => kv.Key, kv => kv.Value);
        }

        #endregion

        #region Analysis Helpers

        private string AnalyzeKernelPowerEvent(string description)
        {
            if (string.IsNullOrEmpty(description))
                return "Power loss or hardware failure";

            if (description.Contains("BugcheckCode", StringComparison.OrdinalIgnoreCase))
            {
                // Extract bugcheck code
                var match = System.Text.RegularExpressions.Regex.Match(description, @"BugcheckCode\s*[:=]\s*(0x[0-9A-Fa-f]+|\d+)");
                if (match.Success)
                    return $"BSOD with code {match.Groups[1].Value}";
            }

            if (description.Contains("PowerButtonTimestamp", StringComparison.OrdinalIgnoreCase))
                return "Power button pressed or power loss";

            if (description.Contains("SleepInProgress", StringComparison.OrdinalIgnoreCase))
                return "Crash during sleep/hibernate transition";

            if (description.Contains("thermal", StringComparison.OrdinalIgnoreCase) ||
                description.Contains("overheat", StringComparison.OrdinalIgnoreCase))
                return "Possible overheating";

            return "Sudden power loss or critical system failure";
        }

        private string AnalyzeBugCheck(string description)
        {
            if (string.IsNullOrEmpty(description))
                return "System crash (BSOD)";

            // Common bugcheck codes
            var bugCheckPatterns = new Dictionary<string, string>
            {
                { "0x0000009F", "Driver Power State Failure" },
                { "0x00000116", "VIDEO_TDR_FAILURE (Graphics driver timeout)" },
                { "0x00000124", "WHEA_UNCORRECTABLE_ERROR (Hardware error)" },
                { "0x0000007E", "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED" },
                { "0x0000001E", "KMODE_EXCEPTION_NOT_HANDLED" },
                { "0x00000050", "PAGE_FAULT_IN_NONPAGED_AREA (Memory issue)" },
                { "0x0000000A", "IRQL_NOT_LESS_OR_EQUAL (Driver issue)" },
                { "0x0000003B", "SYSTEM_SERVICE_EXCEPTION" },
                { "0x000000D1", "DRIVER_IRQL_NOT_LESS_OR_EQUAL" },
                { "0x000000BE", "ATTEMPTED_WRITE_TO_READONLY_MEMORY" },
                { "0x000000EF", "CRITICAL_PROCESS_DIED" },
                { "0x00000133", "DPC_WATCHDOG_VIOLATION" },
                { "0x000001CA", "SYNTHETIC_WATCHDOG_TIMEOUT" },
            };

            foreach (var pattern in bugCheckPatterns)
            {
                if (description.Contains(pattern.Key, StringComparison.OrdinalIgnoreCase))
                    return pattern.Value;
            }

            // Try to extract driver name
            var driverMatch = System.Text.RegularExpressions.Regex.Match(description, @"caused by driver\s*[:=]?\s*(\S+\.sys)", 
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (driverMatch.Success)
                return $"Driver crash: {driverMatch.Groups[1].Value}";

            return "System crash - check minidump for details";
        }

        private string AnalyzeShutdownReason(string description)
        {
            if (string.IsNullOrEmpty(description))
                return "Shutdown initiated";

            if (description.Contains("Windows Update", StringComparison.OrdinalIgnoreCase))
                return "Windows Update restart";

            if (description.Contains("user", StringComparison.OrdinalIgnoreCase))
                return "User-initiated shutdown";

            if (description.Contains("power button", StringComparison.OrdinalIgnoreCase))
                return "Power button pressed";

            if (description.Contains("restart", StringComparison.OrdinalIgnoreCase))
                return "System restart requested";

            return "Planned shutdown";
        }

        private string ExtractFaultingApplication(string description)
        {
            var match = System.Text.RegularExpressions.Regex.Match(description, 
                @"Faulting application name:\s*(\S+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match.Success)
                return $"Application crash: {match.Groups[1].Value}";

            match = System.Text.RegularExpressions.Regex.Match(description,
                @"Faulting module name:\s*(\S+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match.Success)
                return $"Module crash: {match.Groups[1].Value}";

            return "Application error";
        }

        private string ExtractWERDetails(string description)
        {
            var match = System.Text.RegularExpressions.Regex.Match(description,
                @"Application:\s*(\S+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (match.Success)
                return $"Crash report for: {match.Groups[1].Value}";

            return "Windows Error Report generated";
        }

        private string GetKernelPowerFix(string rootCause)
        {
            if (rootCause.Contains("BSOD", StringComparison.OrdinalIgnoreCase))
                return "Check Device Manager for driver issues. Run Windows Memory Diagnostic. Check crash dumps for details.";
            
            if (rootCause.Contains("power", StringComparison.OrdinalIgnoreCase))
                return "Check power supply unit (PSU). Ensure all power connections are secure. Consider UPS for power protection.";
            
            if (rootCause.Contains("overheat", StringComparison.OrdinalIgnoreCase))
                return "Clean dust from fans and heatsinks. Check thermal paste. Improve airflow. Monitor temperatures.";
            
            if (rootCause.Contains("sleep", StringComparison.OrdinalIgnoreCase))
                return "Update chipset and BIOS. Disable hybrid sleep. Check power management settings.";

            return "Check hardware connections. Run system diagnostics. Update BIOS and drivers.";
        }

        private string GetBugCheckFix(string rootCause)
        {
            if (rootCause.Contains("VIDEO_TDR", StringComparison.OrdinalIgnoreCase) ||
                rootCause.Contains("Graphics", StringComparison.OrdinalIgnoreCase))
                return "Update graphics drivers. Check GPU temperatures. Reduce overclock if applied.";

            if (rootCause.Contains("WHEA", StringComparison.OrdinalIgnoreCase) ||
                rootCause.Contains("Hardware", StringComparison.OrdinalIgnoreCase))
                return "Check RAM with Windows Memory Diagnostic. Check CPU temps. Run hardware diagnostics.";

            if (rootCause.Contains("Memory", StringComparison.OrdinalIgnoreCase) ||
                rootCause.Contains("PAGE_FAULT", StringComparison.OrdinalIgnoreCase))
                return "Run Windows Memory Diagnostic (mdsched.exe). Check for RAM issues. Update drivers.";

            if (rootCause.Contains("DRIVER", StringComparison.OrdinalIgnoreCase) ||
                rootCause.Contains("IRQL", StringComparison.OrdinalIgnoreCase))
                return "Update all drivers, especially chipset, storage, and network. Check recently installed software.";

            if (rootCause.Contains("CRITICAL_PROCESS", StringComparison.OrdinalIgnoreCase))
                return "Run sfc /scannow and DISM repair commands. Check for malware. Consider system restore.";

            if (rootCause.Contains(".sys", StringComparison.OrdinalIgnoreCase))
                return $"Update or reinstall the driver mentioned. Check manufacturer website for updates.";

            return "Analyze minidump with WinDbg. Update drivers and Windows. Check hardware health.";
        }

        #endregion
    }
}
