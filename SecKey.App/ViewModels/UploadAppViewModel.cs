using System.Collections.ObjectModel;
using System.IO;
using System.Net.Http;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using SecKey.App.Services;
using SecKey.Graph;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;
using SecKey.Graph.Services.Win32Lob;

namespace SecKey.App.ViewModels;

public sealed partial class UploadAppViewModel : ObservableObject
{
    private readonly AuthState _auth;
    public ObservableCollection<string> LogLines { get; } = new();

    [ObservableProperty] private string? _appFolder;
    [ObservableProperty] private string _intuneWinAppUtilPath =
        Path.Combine(Environment.CurrentDirectory, "IntuneWinAppUtil.exe");
    [ObservableProperty] private double _progress;
    [ObservableProperty] private string? _stage;
    [ObservableProperty] private bool _busy;

    public UploadAppViewModel(AuthState auth) => _auth = auth;

    [RelayCommand]
    private void BrowseFolder()
    {
        var dlg = new OpenFolderDialog { Title = "Select IntuneApps\\<AppName> folder" };
        if (dlg.ShowDialog() == true) AppFolder = dlg.FolderName;
    }

    [RelayCommand]
    private void BrowseTool()
    {
        var dlg = new OpenFileDialog { Filter = "IntuneWinAppUtil.exe|IntuneWinAppUtil.exe|All|*.*" };
        if (dlg.ShowDialog() == true) IntuneWinAppUtilPath = dlg.FileName;
    }

    [RelayCommand]
    private async Task RunAsync()
    {
        if (string.IsNullOrEmpty(AppFolder) || _auth.TokenProvider is null)
        {
            LogLines.Add("App folder is required and you must be signed in.");
            return;
        }
        Busy = true;
        LogLines.Clear();
        try
        {
            var http = new HttpClient();
            var graph = new GraphHttpClient(http, _auth.TokenProvider, NullLogger<GraphHttpClient>.Instance);
            var packager = new IntuneWinAppUtilRunner(IntuneWinAppUtilPath, NullLogger<IntuneWinAppUtilRunner>.Instance);
            var uploader = new Win32LobUploader(graph, http, NullLogger<Win32LobUploader>.Instance);
            var apps = new IntuneApplicationService(graph);
            var groups = new EntraIdGroupService(graph);
            var orchestrator = new IntuneAppOrchestrator(packager, uploader, apps, groups,
                NullLogger<IntuneAppOrchestrator>.Instance);

            var progress = new Progress<UploadProgress>(p =>
            {
                Stage = p.Stage.ToString();
                Progress = p.Fraction * 100;
                LogLines.Add($"[{p.Stage}] {p.Fraction:P0} {p.Message}");
            });

            var result = await orchestrator.ImportAsync(AppFolder, progress);
            LogLines.Add("Done. App id: " + result?["id"]?.GetValue<string>());
        }
        catch (Exception ex)
        {
            LogLines.Add("ERROR: " + ex.Message);
        }
        finally { Busy = false; }
    }
}
