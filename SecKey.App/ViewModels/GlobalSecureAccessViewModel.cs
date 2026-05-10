using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using SecKey.App.Services;

namespace SecKey.App.ViewModels;

public sealed class GlobalSecureAccessViewModel : BindableBase
{
    private readonly NativeSecurityPortService _service = new();
    private readonly INativeDeploymentSettingsService _nativeSettings;

    private string _workspaceRoot = string.Empty;
    private string _statusMessage = "Ready";
    private string _selectedFilePreview = string.Empty;

    public GlobalSecureAccessViewModel(INativeDeploymentSettingsService nativeSettings)
    {
        _nativeSettings = nativeSettings;
        WorkspaceRoot = ResolveWorkspaceRoot();
        RefreshCommand = new RelayCommand(_ => Refresh());
        OpenSelectedCommand = new RelayCommand(_ => OpenSelected(), _ => SelectedFile is not null);
        OpenFolderCommand = new RelayCommand(_ => OpenFolder(), _ => SelectedFile is not null);
        ExportPreviewCommand = new RelayCommand(_ => ExportPreview(), _ => !string.IsNullOrWhiteSpace(SelectedFilePreview));
        SaveSettingCommand = new RelayCommand(param => SaveSetting(param as DeploymentSettingItemViewModel), param => param is DeploymentSettingItemViewModel);
        NavigateToSettingCommand = new RelayCommand(param => NavigateToSetting(param as DeploymentSettingItemViewModel), param => param is DeploymentSettingItemViewModel);
        InitializeSettingsInventory();
        Refresh();
    }

    public ObservableCollection<string> PolicyFiles { get; } = [];
    public ObservableCollection<DeploymentSettingItemViewModel> SettingsInventory { get; } = [];

    public string? SelectedFile
    {
        get => _selectedFile;
        set
        {
            if (SetProperty(ref _selectedFile, value))
                LoadPreview();
        }
    }
    private string? _selectedFile;

    public string WorkspaceRoot { get => _workspaceRoot; set => SetProperty(ref _workspaceRoot, value); }
    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }
    public string SelectedFilePreview { get => _selectedFilePreview; set => SetProperty(ref _selectedFilePreview, value); }

    public System.Windows.Input.ICommand RefreshCommand { get; }
    public System.Windows.Input.ICommand OpenSelectedCommand { get; }
    public System.Windows.Input.ICommand OpenFolderCommand { get; }
    public System.Windows.Input.ICommand ExportPreviewCommand { get; }
    public System.Windows.Input.ICommand SaveSettingCommand { get; }
    public System.Windows.Input.ICommand NavigateToSettingCommand { get; }

    private void InitializeSettingsInventory()
    {
        SettingsInventory.Clear();
        foreach (var setting in _nativeSettings.GetSettingsForScope("Global Secure Access"))
        {
            SettingsInventory.Add(new DeploymentSettingItemViewModel(
                setting.Key,
                setting.Scope,
                setting.DisplayName,
                setting.Description,
                setting.Source,
                setting.Value,
                setting.EditScope));
        }
    }

    private void Refresh()
    {
        PolicyFiles.Clear();
        var files = _service.ReadGsaPolicyFiles(WorkspaceRoot);
        foreach (var file in files)
        {
            PolicyFiles.Add(file);
        }

        StatusMessage = $"Found {PolicyFiles.Count} Global Secure Access policy files.";
    }

    private void OpenSelected()
    {
        if (string.IsNullOrWhiteSpace(SelectedFile) || !File.Exists(SelectedFile))
        {
            return;
        }

        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = SelectedFile,
            UseShellExecute = true
        });
    }

    private void OpenFolder()
    {
        if (string.IsNullOrWhiteSpace(SelectedFile) || !File.Exists(SelectedFile))
            return;

        var folder = Path.GetDirectoryName(SelectedFile);
        if (string.IsNullOrWhiteSpace(folder))
            return;

        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = folder,
            UseShellExecute = true
        });
    }

    private void LoadPreview()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(SelectedFile) || !File.Exists(SelectedFile))
            {
                SelectedFilePreview = string.Empty;
                return;
            }

            var content = File.ReadAllText(SelectedFile);
            SelectedFilePreview = content.Length > 8000 ? content[..8000] + "\n... (truncated)" : content;
            StatusMessage = $"Loaded preview: {Path.GetFileName(SelectedFile)}";
            ((RelayCommand)ExportPreviewCommand).RaiseCanExecuteChanged();
            ((RelayCommand)OpenSelectedCommand).RaiseCanExecuteChanged();
            ((RelayCommand)OpenFolderCommand).RaiseCanExecuteChanged();
        }
        catch (Exception ex)
        {
            SelectedFilePreview = string.Empty;
            StatusMessage = $"Preview failed: {ex.Message}";
        }
    }

    private void ExportPreview()
    {
        try
        {
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Exports");
            Directory.CreateDirectory(folder);
            var file = Path.Combine(folder, $"gsa-preview-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            File.WriteAllText(file, new StringBuilder(SelectedFilePreview).ToString());
            StatusMessage = $"Preview exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    private void SaveSetting(DeploymentSettingItemViewModel? setting)
    {
        if (setting is null)
            return;

        _nativeSettings.SaveValue(setting.Key, setting.Value);
        setting.Source = "native-code+override";
        StatusMessage = $"Saved setting '{setting.DisplayName}'.";
    }

    private void NavigateToSetting(DeploymentSettingItemViewModel? setting)
    {
        if (setting is null)
            return;

        StatusMessage = $"Edit '{setting.DisplayName}' in this tab and click Save.";
    }

    private static string ResolveWorkspaceRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (Directory.Exists(Path.Combine(current.FullName, "source"))
                && Directory.Exists(Path.Combine(current.FullName, "archive")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        return Directory.GetCurrentDirectory();
    }
}
