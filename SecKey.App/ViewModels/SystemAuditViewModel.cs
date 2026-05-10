using System.Collections.ObjectModel;
using System.IO;
using System.Security.Principal;
using SecKey.Core.Services;

namespace SecKey.App.ViewModels;

public sealed class SystemAuditViewModel : BindableBase
{
    private readonly ISystemAuditService _service;

    private bool _isAuditing;
    private string _statusMessage = "Ready to audit";
    private int _totalIssues;
    private int _criticalIssues;
    private int _warningIssues;
    private int _auditProgressPercent;
    private string _progressMessage = "Idle";
    private string _selectedUsername = string.Empty;
    private string _newPassword = string.Empty;
    private string _selectedCategory = "All";
    private string _selectedSeverity = "All";
    private ObservableCollection<AuditItem> _allItems = [];

    public SystemAuditViewModel(ISystemAuditService service)
    {
        _service = service;
        RunFullAuditCommand = new AsyncRelayCommand(RunFullAuditAsync, () => !IsAuditing);
        RunFirewallAuditCommand = new AsyncRelayCommand(RunFirewallAuditAsync, () => !IsAuditing);
        RunUpdatesAuditCommand = new AsyncRelayCommand(RunUpdatesAuditAsync, () => !IsAuditing);
        RunStartupAuditCommand = new AsyncRelayCommand(RunStartupAuditAsync, () => !IsAuditing);
        ScanElevatedUsersCommand = new AsyncRelayCommand(ScanElevatedUsersAsync, () => !IsAuditing);
        ScanCriticalAclsCommand = new AsyncRelayCommand(ScanCriticalAclsAsync, () => !IsAuditing);
        ScanOutboundTrafficCommand = new AsyncRelayCommand(ScanOutboundTrafficAsync, () => !IsAuditing);
        ScanInboundTrafficCommand = new AsyncRelayCommand(ScanInboundTrafficAsync, () => !IsAuditing);
        OpenUsersAndGroupsCommand = new RelayCommand(_ => _service.OpenUsersAndGroups());
        DisableUserCommand = new AsyncRelayCommand(DisableUserAsync, () => !IsAuditing && !string.IsNullOrWhiteSpace(SelectedUsername));
        DeleteUserCommand = new AsyncRelayCommand(DeleteUserAsync, () => !IsAuditing && !string.IsNullOrWhiteSpace(SelectedUsername));
        ResetPasswordCommand = new AsyncRelayCommand(ResetPasswordAsync, () => !IsAuditing && !string.IsNullOrWhiteSpace(SelectedUsername) && !string.IsNullOrWhiteSpace(NewPassword));
        FixIssueCommand = new AsyncRelayCommand<AuditItem>(FixIssueAsync, item => !IsAuditing && item is not null && item.CanAutoFix);
        FixAllCommand = new AsyncRelayCommand(FixAllAsync, () => !IsAuditing && AuditItems.Any(x => x.CanAutoFix));
        ExportReportCommand = new RelayCommand(_ => ExportReport(), _ => AuditItems.Count > 0);
        ClearCommand = new RelayCommand(_ => Clear());

        // Seed the tab with data on first open so users can immediately verify functionality.
        _ = RunFullAuditAsync();
    }

    public ObservableCollection<AuditItem> AuditItems { get; } = [];

    public bool IsElevated
    {
        get
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    public bool NeedsElevation => !IsElevated;

    public bool IsAuditing
    {
        get => _isAuditing;
        set
        {
            if (SetProperty(ref _isAuditing, value))
                RaiseCommandStates();
        }
    }

    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }
    public int TotalIssues { get => _totalIssues; set => SetProperty(ref _totalIssues, value); }
    public int CriticalIssues { get => _criticalIssues; set => SetProperty(ref _criticalIssues, value); }
    public int WarningIssues { get => _warningIssues; set => SetProperty(ref _warningIssues, value); }
    public int AuditProgressPercent { get => _auditProgressPercent; set => SetProperty(ref _auditProgressPercent, value); }
    public string ProgressMessage { get => _progressMessage; set => SetProperty(ref _progressMessage, value); }

    public string SelectedUsername
    {
        get => _selectedUsername;
        set
        {
            if (SetProperty(ref _selectedUsername, value))
                RaiseCommandStates();
        }
    }

    public string NewPassword
    {
        get => _newPassword;
        set
        {
            if (SetProperty(ref _newPassword, value))
                RaiseCommandStates();
        }
    }

    public string SelectedCategory
    {
        get => _selectedCategory;
        set
        {
            if (SetProperty(ref _selectedCategory, value))
                ApplyFilters();
        }
    }

    public string SelectedSeverity
    {
        get => _selectedSeverity;
        set
        {
            if (SetProperty(ref _selectedSeverity, value))
                ApplyFilters();
        }
    }

    public ObservableCollection<string> Categories { get; } = ["All"];
    public ObservableCollection<string> Severities { get; } = ["All", "Critical", "Warning", "Info"];

    public System.Windows.Input.ICommand RunFullAuditCommand { get; }
    public System.Windows.Input.ICommand RunFirewallAuditCommand { get; }
    public System.Windows.Input.ICommand RunUpdatesAuditCommand { get; }
    public System.Windows.Input.ICommand RunStartupAuditCommand { get; }
    public System.Windows.Input.ICommand ScanElevatedUsersCommand { get; }
    public System.Windows.Input.ICommand ScanCriticalAclsCommand { get; }
    public System.Windows.Input.ICommand ScanOutboundTrafficCommand { get; }
    public System.Windows.Input.ICommand ScanInboundTrafficCommand { get; }
    public System.Windows.Input.ICommand OpenUsersAndGroupsCommand { get; }
    public System.Windows.Input.ICommand DisableUserCommand { get; }
    public System.Windows.Input.ICommand DeleteUserCommand { get; }
    public System.Windows.Input.ICommand ResetPasswordCommand { get; }
    public System.Windows.Input.ICommand FixIssueCommand { get; }
    public System.Windows.Input.ICommand FixAllCommand { get; }
    public System.Windows.Input.ICommand ExportReportCommand { get; }
    public System.Windows.Input.ICommand ClearCommand { get; }

    private async Task RunFullAuditAsync() => await ExecuteAndAppendAsync("Running full system audit...", _service.RunFullAudit);
    private async Task RunFirewallAuditAsync() => await ExecuteAndAppendAsync("Auditing firewall...", _service.AuditFirewall);
    private async Task RunUpdatesAuditAsync() => await ExecuteAndAppendAsync("Auditing updates...", _service.AuditWindowsUpdates);
    private async Task RunStartupAuditAsync() => await ExecuteAndAppendAsync("Auditing startup items...", _service.AuditStartupItems);
    private async Task ScanElevatedUsersAsync() => await ExecuteAndAppendAsync("Scanning elevated users...", _service.ScanElevatedUsers);
    private async Task ScanCriticalAclsAsync() => await ExecuteAndAppendAsync("Scanning critical ACLs...", _service.ScanCriticalAcls);
    private async Task ScanOutboundTrafficAsync() => await ExecuteAndAppendAsync("Scanning outbound traffic...", _service.ScanOutboundTraffic);
    private async Task ScanInboundTrafficAsync() => await ExecuteAndAppendAsync("Scanning inbound traffic...", _service.ScanInboundTraffic);

    private async Task DisableUserAsync()
    {
        IsAuditing = true;
        try
        {
            var ok = await _service.DisableUser(SelectedUsername.Trim());
            StatusMessage = ok ? $"Disabled user: {SelectedUsername}" : $"Failed to disable user: {SelectedUsername}";
        }
        finally { IsAuditing = false; }
    }

    private async Task DeleteUserAsync()
    {
        IsAuditing = true;
        try
        {
            var ok = await _service.DeleteUser(SelectedUsername.Trim());
            StatusMessage = ok ? $"Deleted user: {SelectedUsername}" : $"Failed to delete user: {SelectedUsername}";
        }
        finally { IsAuditing = false; }
    }

    private async Task ResetPasswordAsync()
    {
        IsAuditing = true;
        try
        {
            var ok = await _service.ResetUserPassword(SelectedUsername.Trim(), NewPassword);
            StatusMessage = ok ? $"Password reset for: {SelectedUsername}" : $"Failed to reset password for: {SelectedUsername}";
        }
        finally { IsAuditing = false; }
    }

    private async Task FixIssueAsync(AuditItem? item)
    {
        if (item is null) return;
        IsAuditing = true;
        try
        {
            var ok = await _service.FixIssue(item);
            StatusMessage = ok ? $"Attempted fix for: {item.Name}" : $"Fix failed for: {item.Name}";
        }
        finally { IsAuditing = false; }
    }

    private async Task ExecuteAndAppendAsync(string busyMessage, Func<Task<List<AuditItem>>> loader)
    {
        IsAuditing = true;
        AuditProgressPercent = 0;
        ProgressMessage = "Starting";
        StatusMessage = busyMessage;
        try
        {
            _allItems.Clear();
            Categories.Clear();
            Categories.Add("All");

            var items = await loader();
            var total = Math.Max(items.Count, 1);
            var index = 0;
            foreach (var item in items)
            {
                _allItems.Add(item);
                if (!Categories.Contains(item.Category))
                    Categories.Add(item.Category);

                index++;
                AuditProgressPercent = (int)Math.Round(index * 100.0 / total);
                ProgressMessage = $"Processing {index}/{total} findings";
            }

            ApplyFilters();
            AuditProgressPercent = 100;
            ProgressMessage = "Completed";
            StatusMessage = $"Audit complete: {TotalIssues} issues ({CriticalIssues} critical, {WarningIssues} warnings).";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Audit failed: {ex.Message}";
            ProgressMessage = "Failed";
        }
        finally
        {
            IsAuditing = false;
        }
    }

    private void ApplyFilters()
    {
        AuditItems.Clear();
        var filtered = _allItems.Where(x => 
            (SelectedCategory == "All" || x.Category == SelectedCategory) &&
            (SelectedSeverity == "All" || x.Severity.ToString() == SelectedSeverity)
        ).ToList();
        
        foreach (var item in filtered)
            AuditItems.Add(item);
        
        UpdateStatistics();
    }

    private async Task FixAllAsync()
    {
        IsAuditing = true;
        AuditProgressPercent = 0;
        ProgressMessage = "Starting fixes";
        try
        {
            var fixable = AuditItems.Where(x => x.CanAutoFix).ToList();
            StatusMessage = $"Fixing {fixable.Count} issues...";
            var fixed_count = 0;
            var index = 0;
            
            foreach (var item in fixable)
            {
                try
                {
                    var ok = await _service.FixIssue(item);
                    if (ok)
                    {
                        item.Status = AuditStatus.Pass;
                        fixed_count++;
                    }
                }
                catch { }

                index++;
                AuditProgressPercent = fixable.Count == 0 ? 100 : (int)Math.Round(index * 100.0 / fixable.Count);
                ProgressMessage = $"Fixing {index}/{fixable.Count}";
            }
            
            UpdateStatistics();
            AuditProgressPercent = 100;
            ProgressMessage = "Fix complete";
            StatusMessage = $"Fixed {fixed_count} of {fixable.Count} issues.";
        }
        finally
        {
            IsAuditing = false;
        }
    }

    private void UpdateStatistics()
    {
        TotalIssues = AuditItems.Count;
        CriticalIssues = AuditItems.Count(x => x.Severity == AuditSeverity.Critical || x.Status == AuditStatus.Fail);
        WarningIssues = AuditItems.Count(x => x.Severity == AuditSeverity.Warning);
        ((RelayCommand)ExportReportCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)FixAllCommand).RaiseCanExecuteChanged();
    }

    private void ExportReport()
    {
        try
        {
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Reports");
            Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, $"system-audit-{DateTime.Now:yyyyMMdd-HHmmss}.csv");
            using var sw = new StreamWriter(path);
            sw.WriteLine("Category,Name,Description,Severity,Status,Details,FixAction,CanAutoFix");
            foreach (var item in AuditItems)
            {
                sw.WriteLine($"\"{Csv(item.Category)}\",\"{Csv(item.Name)}\",\"{Csv(item.Description)}\",\"{item.Severity}\",\"{item.Status}\",\"{Csv(item.Details)}\",\"{Csv(item.FixAction ?? string.Empty)}\",\"{item.CanAutoFix}\"");
            }

            StatusMessage = $"Exported report: {path}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    private static string Csv(string s) => s.Replace("\"", "''").Replace("\r", " ").Replace("\n", " ");

    private void Clear()
    {
        AuditItems.Clear();
        _allItems.Clear();
        Categories.Clear();
        Categories.Add("All");
        SelectedCategory = "All";
        SelectedSeverity = "All";
        AuditProgressPercent = 0;
        ProgressMessage = "Idle";
        UpdateStatistics();
        StatusMessage = "Cleared.";
    }

    private void RaiseCommandStates()
    {
        ((AsyncRelayCommand)RunFullAuditCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)RunFirewallAuditCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)RunUpdatesAuditCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)RunStartupAuditCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)ScanElevatedUsersCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)ScanCriticalAclsCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)ScanOutboundTrafficCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)ScanInboundTrafficCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)DisableUserCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)DeleteUserCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)ResetPasswordCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)FixAllCommand).RaiseCanExecuteChanged();
    }
}
