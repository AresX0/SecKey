using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using Microsoft.Win32;
using SecKey.App.Services;

namespace SecKey.App.ViewModels;

public sealed class ForensicsAnalyzerViewModel : BindableBase
{
    private readonly NativeSecurityPortService _service = new();

    private string _statusMessage = "Ready";
    private string _filterText = string.Empty;
    private bool _isAnalyzing;
    private TimeSpan _analysisDuration;
    private int _totalFindings;
    private int _criticalFindings;
    private int _highFindings;
    private int _mediumFindings;
    private int _lowFindings;
    private string _memoryUsage = "N/A";
    private int _suspiciousProcesses;
    private int _filesScanned;
    private int _suspiciousFiles;
    private int _startupEntries;
    private int _suspiciousRegistry;
    private int _eventsScanned;
    private int _suspiciousEvents;

    public ForensicsAnalyzerViewModel()
    {
        CaptureSnapshotCommand = new RelayCommand(_ => CaptureSnapshot(false), _ => !IsAnalyzing);
        RunDeepAnalysisCommand = new RelayCommand(_ => CaptureSnapshot(true), _ => !IsAnalyzing);
        ExportSnapshotCommand = new RelayCommand(_ => ExportSnapshot(), _ => Processes.Count > 0);
        ExportHtmlReportCommand = new RelayCommand(_ => ExportHtmlReport(), _ => Findings.Count > 0);
        ClearCommand = new RelayCommand(_ => ClearResults(), _ => !IsAnalyzing);
    }

    public ObservableCollection<ProcessSnapshot> Processes { get; } = [];
    public ObservableCollection<TimelineEntry> Timeline { get; } = [];
    public ObservableCollection<ForensicsFinding> Findings { get; } = [];
    public ObservableCollection<ProcessMemoryInfo> TopProcesses { get; } = [];
    public ObservableCollection<SuspiciousFileInfo> SuspiciousFilesList { get; } = [];
    public ObservableCollection<RegistryEntryInfo> RegistryEntries { get; } = [];
    public ObservableCollection<SecurityEventInfo> SecurityEventsList { get; } = [];

    public string FilterText
    {
        get => _filterText;
        set
        {
            if (SetProperty(ref _filterText, value))
                CaptureSnapshot(false);
        }
    }

    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }
    public bool IsAnalyzing { get => _isAnalyzing; set => SetProperty(ref _isAnalyzing, value); }
    public TimeSpan AnalysisDuration { get => _analysisDuration; set => SetProperty(ref _analysisDuration, value); }
    
    public int TotalFindings { get => _totalFindings; set => SetProperty(ref _totalFindings, value); }
    public int CriticalFindings { get => _criticalFindings; set => SetProperty(ref _criticalFindings, value); }
    public int HighFindings { get => _highFindings; set => SetProperty(ref _highFindings, value); }
    public int MediumFindings { get => _mediumFindings; set => SetProperty(ref _mediumFindings, value); }
    public int LowFindings { get => _lowFindings; set => SetProperty(ref _lowFindings, value); }
    
    public string MemoryUsage { get => _memoryUsage; set => SetProperty(ref _memoryUsage, value); }
    public int SuspiciousProcesses { get => _suspiciousProcesses; set => SetProperty(ref _suspiciousProcesses, value); }
    public int FilesScanned { get => _filesScanned; set => SetProperty(ref _filesScanned, value); }
    public int SuspiciousFiles { get => _suspiciousFiles; set => SetProperty(ref _suspiciousFiles, value); }
    public int StartupEntries { get => _startupEntries; set => SetProperty(ref _startupEntries, value); }
    public int SuspiciousRegistry { get => _suspiciousRegistry; set => SetProperty(ref _suspiciousRegistry, value); }
    public int EventsScanned { get => _eventsScanned; set => SetProperty(ref _eventsScanned, value); }
    public int SuspiciousEvents { get => _suspiciousEvents; set => SetProperty(ref _suspiciousEvents, value); }

    public System.Windows.Input.ICommand CaptureSnapshotCommand { get; }
    public System.Windows.Input.ICommand RunDeepAnalysisCommand { get; }
    public System.Windows.Input.ICommand ExportSnapshotCommand { get; }
    public System.Windows.Input.ICommand ExportHtmlReportCommand { get; }
    public System.Windows.Input.ICommand ClearCommand { get; }

    private void CaptureSnapshot(bool deep)
    {
        var started = DateTime.UtcNow;
        IsAnalyzing = true;
        try
        {
            var all = _service.CaptureProcessSnapshot(deep ? 500 : 200);
            Processes.Clear();
            Timeline.Clear();
            Findings.Clear();

            IEnumerable<ProcessSnapshot> filtered = all;
            if (!string.IsNullOrWhiteSpace(FilterText))
            {
                filtered = filtered.Where(x =>
                    x.Name.Contains(FilterText, StringComparison.OrdinalIgnoreCase)
                    || x.Path.Contains(FilterText, StringComparison.OrdinalIgnoreCase)
                    || x.Pid.ToString().Contains(FilterText, StringComparison.OrdinalIgnoreCase));
            }

            foreach (var item in filtered)
            {
                Processes.Add(item);
            }

            foreach (var evt in _service.CaptureRecentTimeline(deep ? 1200 : 400))
            {
                if (string.IsNullOrWhiteSpace(FilterText)
                    || evt.Source.Contains(FilterText, StringComparison.OrdinalIgnoreCase)
                    || evt.Message.Contains(FilterText, StringComparison.OrdinalIgnoreCase))
                {
                    Timeline.Add(evt);
                }
            }

            BuildFindings(deep);
            AnalysisDuration = DateTime.UtcNow - started;

            StatusMessage = $"Analysis complete. Processes={Processes.Count}, Timeline={Timeline.Count}, Findings={Findings.Count}";
            ((RelayCommand)ExportSnapshotCommand).RaiseCanExecuteChanged();
            ((RelayCommand)ExportHtmlReportCommand).RaiseCanExecuteChanged();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Forensics snapshot failed: {ex.Message}";
        }
        finally
        {
            IsAnalyzing = false;
            ((RelayCommand)CaptureSnapshotCommand).RaiseCanExecuteChanged();
            ((RelayCommand)RunDeepAnalysisCommand).RaiseCanExecuteChanged();
            ((RelayCommand)ClearCommand).RaiseCanExecuteChanged();
        }
    }

    private void ExportSnapshot()
    {
        try
        {
            var target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics");
            Directory.CreateDirectory(target);
            var file = Path.Combine(target, $"process-snapshot-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
            using var sw = new StreamWriter(file);
            sw.WriteLine("Name,Pid,WorkingSetMb,Responding,Path");
            foreach (var p in Processes)
            {
                sw.WriteLine($"\"{p.Name}\",{p.Pid},{p.WorkingSetMb},{p.Responding},\"{p.Path.Replace("\"", "''")}\"");
            }

            StatusMessage = $"Snapshot exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    private void ExportHtmlReport()
    {
        try
        {
            var target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Forensics");
            Directory.CreateDirectory(target);
            var file = Path.Combine(target, $"forensics-report-{DateTime.Now:yyyyMMdd-HHmmss}.html");

            var sb = new StringBuilder();
            sb.AppendLine("<html><head><meta charset='utf-8'><title>SecKey Forensics Report</title>");
            sb.AppendLine("<style>body{font-family:Segoe UI;padding:20px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;}th{background:#f4f6f8;} .crit{color:#b91c1c;font-weight:bold;} .warn{color:#c2410c;font-weight:bold;}</style>");
            sb.AppendLine("</head><body>");
            sb.AppendLine($"<h2>SecKey Forensics Report</h2><p>Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
            sb.AppendLine($"<p>Duration: {AnalysisDuration.TotalSeconds:F1}s | Critical: {CriticalFindings} | High: {HighFindings} | Medium: {MediumFindings} | Low: {LowFindings}</p>");
            sb.AppendLine("<h3>Findings</h3><table><tr><th>Severity</th><th>Title</th><th>Description</th><th>Source</th></tr>");
            foreach (var finding in Findings)
            {
                var cls = finding.Severity == "Critical" ? "crit" : finding.Severity == "Warning" ? "warn" : string.Empty;
                sb.AppendLine($"<tr><td class='{cls}'>{finding.Severity}</td><td>{Escape(finding.Title)}</td><td>{Escape(finding.Description)}</td><td>{Escape(finding.Source)}</td></tr>");
            }
            sb.AppendLine("</table></body></html>");

            File.WriteAllText(file, sb.ToString());
            StatusMessage = $"HTML report exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"HTML export failed: {ex.Message}";
        }
    }

    private void BuildFindings(bool deep)
    {
        TopProcesses.Clear();
        SuspiciousFilesList.Clear();
        RegistryEntries.Clear();
        SecurityEventsList.Clear();

        TotalFindings = 0;
        CriticalFindings = 0;
        HighFindings = 0;
        MediumFindings = 0;
        LowFindings = 0;
        SuspiciousProcesses = 0;
        FilesScanned = Processes.Count;
        SuspiciousFiles = 0;
        StartupEntries = Timeline.Count;
        SuspiciousRegistry = 0;
        EventsScanned = Timeline.Count;
        SuspiciousEvents = 0;

        try
        {
            var totalMemory = GC.GetTotalMemory(false) / (1024.0 * 1024.0);
            MemoryUsage = $"{totalMemory:F1} MB";
        }
        catch { MemoryUsage = "N/A"; }

        foreach (var proc in Processes)
        {
            if (!string.IsNullOrWhiteSpace(proc.Path) && proc.Path.StartsWith(Path.GetTempPath(), StringComparison.OrdinalIgnoreCase))
            {
                AddFinding("Medium", "Process running from temp path", proc.Path, proc.Name);
                SuspiciousProcesses++;
            }

            if (proc.WorkingSetMb > (deep ? 1500 : 900))
            {
                AddFinding("Low", "High memory process", $"{proc.WorkingSetMb} MB", proc.Name);
            }

            if (!proc.Responding)
            {
                AddFinding("High", "Unresponsive process", "Process not responding", proc.Name);
                SuspiciousProcesses++;
            }
            
            if (TopProcesses.Count < 25)
            {
                TopProcesses.Add(new ProcessMemoryInfo(proc.Name, proc.Pid, proc.WorkingSetMb, proc.Responding));
            }
        }

        foreach (var evt in Timeline)
        {
            if (SecurityEventsList.Count < 200)
            {
                SecurityEventsList.Add(new SecurityEventInfo(evt.Timestamp, evt.Level, evt.Message));
            }

            if (evt.Level.Contains("error", StringComparison.OrdinalIgnoreCase)
                || evt.Message.Contains("fail", StringComparison.OrdinalIgnoreCase)
                || evt.Message.Contains("denied", StringComparison.OrdinalIgnoreCase))
            {
                AddFinding("Critical", "Error event in timeline", evt.Message, evt.Source);
                SuspiciousEvents++;
            }
        }

        if (deep)
        {
            RunDeepArtifactChecks();
            RunDeepRegistryChecks();
        }

        if (Findings.Count == 0)
            AddFinding("Low", "No high-risk indicators found", "Analysis completed without flagged artifacts.", "Analyzer");
    }

    private void RunDeepArtifactChecks()
    {
        var roots = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
        };

        var suspiciousExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".ps1", ".vbs", ".js", ".hta", ".exe", ".dll", ".bat", ".cmd"
        };

        foreach (var root in roots.Where(Directory.Exists))
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Take(3000);
            }
            catch
            {
                continue;
            }

            foreach (var file in files)
            {
                FilesScanned++;

                try
                {
                    var ext = Path.GetExtension(file);
                    if (!suspiciousExt.Contains(ext))
                    {
                        continue;
                    }

                    var info = new FileInfo(file);
                    var recentlyTouched = info.LastWriteTimeUtc >= DateTime.UtcNow.AddDays(-7);
                    var suspiciousName = file.Contains("payload", StringComparison.OrdinalIgnoreCase)
                                         || file.Contains("mimikatz", StringComparison.OrdinalIgnoreCase)
                                         || file.Contains("invoke-", StringComparison.OrdinalIgnoreCase)
                                         || file.Contains("backdoor", StringComparison.OrdinalIgnoreCase);

                    if (!recentlyTouched && !suspiciousName)
                    {
                        continue;
                    }

                    SuspiciousFiles++;
                    var sev = suspiciousName ? "High" : "Medium";
                    AddFinding(sev, "Suspicious file artifact", file, "FileSystem");

                    if (SuspiciousFilesList.Count < 500)
                    {
                        SuspiciousFilesList.Add(new SuspiciousFileInfo(Path.GetFileName(file), file, sev));
                    }
                }
                catch
                {
                    // Continue scanning best-effort.
                }
            }
        }
    }

    private void RunDeepRegistryChecks()
    {
        var runKeys = new[]
        {
            (Hive: Registry.CurrentUser, Path: @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Hive: Registry.CurrentUser, Path: @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Hive: Registry.LocalMachine, Path: @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (Hive: Registry.LocalMachine, Path: @"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        };

        foreach (var keyDef in runKeys)
        {
            try
            {
                using var key = keyDef.Hive.OpenSubKey(keyDef.Path, false);
                if (key is null)
                {
                    continue;
                }

                foreach (var name in key.GetValueNames())
                {
                    StartupEntries++;
                    var value = key.GetValue(name)?.ToString() ?? string.Empty;
                    var suspicious = value.Contains("AppData\\Local\\Temp", StringComparison.OrdinalIgnoreCase)
                                  || value.Contains("powershell", StringComparison.OrdinalIgnoreCase)
                                  || value.Contains("-enc", StringComparison.OrdinalIgnoreCase)
                                  || value.Contains("wscript", StringComparison.OrdinalIgnoreCase)
                                  || value.Contains("mshta", StringComparison.OrdinalIgnoreCase);

                    if (!suspicious)
                    {
                        continue;
                    }

                    SuspiciousRegistry++;
                    AddFinding("High", "Suspicious startup registry entry", $"{name} = {value}", keyDef.Path);

                    if (RegistryEntries.Count < 500)
                    {
                        RegistryEntries.Add(new RegistryEntryInfo($"{keyDef.Path}\\{name}", value));
                    }
                }
            }
            catch
            {
                // Some hives/keys can be inaccessible depending on privileges.
            }
        }
    }

    private void AddFinding(string severity, string title, string description, string source)
    {
        Findings.Add(new ForensicsFinding(severity, title, description, source));
        TotalFindings++;
        if (severity == "Critical") CriticalFindings++;
        else if (severity == "High") HighFindings++;
        else if (severity == "Medium") MediumFindings++;
        else LowFindings++;
        
        if (severity == "Critical" || severity == "High")
        {
            SuspiciousFilesList.Add(new SuspiciousFileInfo(title, source, severity));
            RegistryEntries.Add(new RegistryEntryInfo(source, title));
            SecurityEventsList.Add(new SecurityEventInfo(DateTime.Now, severity, title));
        }
    }

    private void ClearResults()
    {
        Processes.Clear();
        Timeline.Clear();
        Findings.Clear();
        TopProcesses.Clear();
        SuspiciousFilesList.Clear();
        RegistryEntries.Clear();
        SecurityEventsList.Clear();
        TotalFindings = 0;
        CriticalFindings = 0;
        HighFindings = 0;
        MediumFindings = 0;
        LowFindings = 0;
        SuspiciousProcesses = 0;
        FilesScanned = 0;
        SuspiciousFiles = 0;
        StartupEntries = 0;
        SuspiciousRegistry = 0;
        EventsScanned = 0;
        SuspiciousEvents = 0;
        MemoryUsage = "N/A";
        AnalysisDuration = TimeSpan.Zero;
        StatusMessage = "Cleared.";
    }

    private static string Escape(string s) => (s ?? string.Empty).Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
}

public sealed record ForensicsFinding(string Severity, string Title, string Description, string Source);
public sealed record ProcessMemoryInfo(string Name, int Pid, long MemoryMb, bool Responding);
public sealed record SuspiciousFileInfo(string FileName, string Source, string Severity);
public sealed record RegistryEntryInfo(string Path, string Value);
public sealed record SecurityEventInfo(DateTime Timestamp, string Level, string Message);
