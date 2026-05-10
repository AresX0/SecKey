using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecKey.Core.Services;

namespace SecKey.App.ViewModels;

public partial class SystemHardeningViewModel : ObservableObject
{
    private readonly SystemAuditService _service;
    private CancellationTokenSource? _cts;

    [ObservableProperty]
    private bool isRunning;

    [ObservableProperty]
    private string statusMessage = "Ready";

    [ObservableProperty]
    private ObservableCollection<AuditItem> auditResults = new();

    [ObservableProperty]
    private int criticalCount;

    [ObservableProperty]
    private int warningCount;

    [ObservableProperty]
    private int passCount;

    public SystemHardeningViewModel()
    {
        _service = new SystemAuditService();
    }

    [RelayCommand]
    public async Task RunFullAudit()
    {
        if (IsRunning) return;

        IsRunning = true;
        CriticalCount = 0;
        WarningCount = 0;
        PassCount = 0;
        AuditResults.Clear();
        _cts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<string>(msg => StatusMessage = msg);
            StatusMessage = "Running system hardening audit...";

            var results = await _service.RunFullAudit();

            foreach (var item in results)
            {
                AuditResults.Add(item);

                switch (item.Severity)
                {
                    case AuditSeverity.Critical:
                        CriticalCount++;
                        break;
                    case AuditSeverity.Warning:
                        WarningCount++;
                        break;
                    case AuditSeverity.Info:
                        PassCount++;
                        break;
                }
            }

            StatusMessage = $"Audit complete: {CriticalCount} critical, {WarningCount} warnings, {PassCount} info";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Audit cancelled";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally
        {
            IsRunning = false;
            _cts?.Dispose();
        }
    }

    [RelayCommand]
    public async Task FixIssue(AuditItem? auditItem)
    {
        if (auditItem?.CanAutoFix != true) return;

        try
        {
            StatusMessage = $"Fixing: {auditItem.Name}...";
            await _service.FixIssue(auditItem);
            StatusMessage = $"Fixed: {auditItem.Name}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error fixing issue: {ex.Message}";
        }
    }

    [RelayCommand]
    public void Cancel()
    {
        _cts?.Cancel();
    }
}
