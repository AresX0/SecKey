using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecKey.Core.Services;

namespace SecKey.App.ViewModels;

public partial class RebootAnalyzerViewModel : ObservableObject
{
    private readonly RebootAnalyzerService _service;
    private CancellationTokenSource? _cts;

    [ObservableProperty]
    private bool isRunning;

    [ObservableProperty]
    private string statusMessage = "Ready";

    [ObservableProperty]
    private string systemUptime = "Unknown";

    [ObservableProperty]
    private DateTime lastBootTime;

    [ObservableProperty]
    private int daysToAnalyze = 30;

    [ObservableProperty]
    private ObservableCollection<RebootAnalyzerService.RebootEvent> unexpectedReboots = new();

    [ObservableProperty]
    private ObservableCollection<RebootAnalyzerService.RebootEvent> bsodEvents = new();

    [ObservableProperty]
    private ObservableCollection<RebootAnalyzerService.RebootEvent> applicationCrashes = new();

    [ObservableProperty]
    private ObservableCollection<RebootAnalyzerService.CrashDumpInfo> crashDumps = new();

    [ObservableProperty]
    private ObservableCollection<RebootAnalyzerService.RebootEvent> cleanShutdowns = new();

    [ObservableProperty]
    private ObservableCollection<KeyValuePair<string, int>> rootCauseSummary = new();

    public RebootAnalyzerViewModel()
    {
        _service = new RebootAnalyzerService();
    }

    [RelayCommand]
    public async Task AnalyzeReboots()
    {
        if (IsRunning) return;

        IsRunning = true;
        UnexpectedReboots.Clear();
        BsodEvents.Clear();
        ApplicationCrashes.Clear();
        CrashDumps.Clear();
        CleanShutdowns.Clear();
        RootCauseSummary.Clear();
        _cts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<string>(msg => StatusMessage = msg);
            StatusMessage = "Analyzing system reboots...";

            var result = await _service.AnalyzeAsync(DaysToAnalyze, progress, _cts.Token);

            SystemUptime = result.SystemUptime;
            LastBootTime = result.LastBootTime;

            foreach (var reboot in result.UnexpectedReboots)
                UnexpectedReboots.Add(reboot);

            foreach (var bsod in result.BSODEvents)
                BsodEvents.Add(bsod);

            foreach (var crash in result.ApplicationCrashes)
                ApplicationCrashes.Add(crash);

            foreach (var dump in result.CrashDumps)
                CrashDumps.Add(dump);

            foreach (var shutdown in result.CleanShutdowns)
                CleanShutdowns.Add(shutdown);

            foreach (var item in result.RootCauseSummary)
                RootCauseSummary.Add(item);

            StatusMessage = $"Analysis complete: unexpected={result.UnexpectedReboots.Count}, bsod={result.BSODEvents.Count}, app crashes={result.ApplicationCrashes.Count}, clean shutdowns={result.CleanShutdowns.Count}";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Analysis cancelled";
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
    public void Cancel()
    {
        _cts?.Cancel();
    }
}
