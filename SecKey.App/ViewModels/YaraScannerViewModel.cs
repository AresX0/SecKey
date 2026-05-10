using System.Collections.ObjectModel;
using SecKey.App.Services;

namespace SecKey.App.ViewModels;

public sealed class YaraScannerViewModel : BindableBase
{
    private readonly NativeSecurityPortService _service = new();
    private CancellationTokenSource? _cts;

    private string _targetPath = string.Empty;
    private string _rulesInput = "HighEntropyString|[A-Za-z0-9+/]{120,}={0,2}|regex\nPowerShellDownload|Invoke-WebRequest|literal\nSuspiciousCmd|cmd.exe /c|literal|case";
    private string _statusMessage = "Ready";
    private bool _isScanning;

    public YaraScannerViewModel()
    {
        ScanCommand = new AsyncRelayCommand(ScanAsync, () => !IsScanning && !string.IsNullOrWhiteSpace(TargetPath));
        CancelCommand = new RelayCommand(_ => Cancel(), _ => IsScanning);
    }

    public ObservableCollection<YaraLiteMatch> Matches { get; } = [];

    public string TargetPath
    {
        get => _targetPath;
        set
        {
            if (SetProperty(ref _targetPath, value))
            {
                ((AsyncRelayCommand)ScanCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public string RulesInput { get => _rulesInput; set => SetProperty(ref _rulesInput, value); }
    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            if (SetProperty(ref _isScanning, value))
            {
                ((AsyncRelayCommand)ScanCommand).RaiseCanExecuteChanged();
                ((RelayCommand)CancelCommand).RaiseCanExecuteChanged();
            }
        }
    }

    public System.Windows.Input.ICommand ScanCommand { get; }
    public System.Windows.Input.ICommand CancelCommand { get; }

    private async Task ScanAsync()
    {
        IsScanning = true;
        _cts = new CancellationTokenSource();
        Matches.Clear();

        try
        {
            StatusMessage = "Parsing YARA rules...";
            var rules = _service.ParseYaraLiteRules(RulesInput);
            if (rules.Count == 0)
            {
                StatusMessage = "No valid rules found. Use RuleName|pattern|regex|case format.";
                return;
            }

            StatusMessage = "Scanning files...";
            var found = await _service.ScanWithYaraLiteAsync(TargetPath, rules, _cts.Token);
            foreach (var match in found)
            {
                Matches.Add(match);
            }

            StatusMessage = $"Scan complete: {Matches.Count} matches across {rules.Count} rules.";
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Scan cancelled.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Scan failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void Cancel() => _cts?.Cancel();
}
