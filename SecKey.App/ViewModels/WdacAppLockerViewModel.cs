using System.Collections.ObjectModel;
using System.IO;
using SecKey.App.Services;

namespace SecKey.App.ViewModels;

public sealed class WdacAppLockerViewModel : BindableBase
{
    private readonly NativeSecurityPortService _service = new();
    private readonly INativeDeploymentSettingsService _nativeSettings;

    private string _workspaceRoot = string.Empty;
    private string _decodedXml = string.Empty;
    private string _statusMessage = "Ready";
    private string _profileFilter = string.Empty;

    public WdacAppLockerViewModel(INativeDeploymentSettingsService nativeSettings)
    {
        _nativeSettings = nativeSettings;
        WorkspaceRoot = ResolveWorkspaceRoot();
        RefreshCommand = new RelayCommand(_ => Refresh());
        DecodeSelectedCommand = new RelayCommand(_ => DecodeSelected(), _ => SelectedProfile is not null);
        ExportDecodedCommand = new RelayCommand(_ => ExportDecoded(), _ => !string.IsNullOrWhiteSpace(DecodedXml));
        OpenSelectedProfileCommand = new RelayCommand(_ => OpenSelectedProfile(), _ => SelectedProfile is not null);
        SaveSettingCommand = new RelayCommand(param => SaveSetting(param as DeploymentSettingItemViewModel), param => param is DeploymentSettingItemViewModel);
        NavigateToSettingCommand = new RelayCommand(param => NavigateToSetting(param as DeploymentSettingItemViewModel), param => param is DeploymentSettingItemViewModel);
        InitializeSettingsInventory();
        Refresh();
    }

    public ObservableCollection<string> Profiles { get; } = [];
    public ObservableCollection<string> FilteredProfiles { get; } = [];
    public ObservableCollection<DeploymentSettingItemViewModel> SettingsInventory { get; } = [];

    public string? SelectedProfile { get; set; }

    public string WorkspaceRoot { get => _workspaceRoot; set => SetProperty(ref _workspaceRoot, value); }
    public string DecodedXml { get => _decodedXml; set => SetProperty(ref _decodedXml, value); }
    public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }
    public string ProfileFilter
    {
        get => _profileFilter;
        set
        {
            if (SetProperty(ref _profileFilter, value))
                ApplyFilter();
        }
    }

    public System.Windows.Input.ICommand RefreshCommand { get; }
    public System.Windows.Input.ICommand DecodeSelectedCommand { get; }
    public System.Windows.Input.ICommand ExportDecodedCommand { get; }
    public System.Windows.Input.ICommand OpenSelectedProfileCommand { get; }
    public System.Windows.Input.ICommand SaveSettingCommand { get; }
    public System.Windows.Input.ICommand NavigateToSettingCommand { get; }

    private void InitializeSettingsInventory()
    {
        SettingsInventory.Clear();
        foreach (var setting in _nativeSettings.GetSettingsForScope("WDAC / AppLocker"))
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
        Profiles.Clear();
        var files = _service.ReadWdacAppLockerProfiles(WorkspaceRoot);
        foreach (var file in files)
        {
            Profiles.Add(file);
        }

        ApplyFilter();

        StatusMessage = $"Found {Profiles.Count} WDAC/AppLocker profiles.";
    }

    private void ApplyFilter()
    {
        FilteredProfiles.Clear();
        foreach (var profile in Profiles)
        {
            if (string.IsNullOrWhiteSpace(ProfileFilter)
                || Path.GetFileName(profile).Contains(ProfileFilter, StringComparison.OrdinalIgnoreCase)
                || profile.Contains(ProfileFilter, StringComparison.OrdinalIgnoreCase))
            {
                FilteredProfiles.Add(profile);
            }
        }
    }

    private void DecodeSelected()
    {
        if (string.IsNullOrWhiteSpace(SelectedProfile) || !File.Exists(SelectedProfile))
        {
            return;
        }

        var selectedProfile = SelectedProfile;
        DecodedXml = _service.DecodeEmbeddedPolicyXml(selectedProfile);
        if (string.IsNullOrWhiteSpace(DecodedXml))
        {
            StatusMessage = "No embedded AppLocker/WDAC XML payload found.";
            return;
        }

        StatusMessage = $"Decoded policy XML from {Path.GetFileName(SelectedProfile)}.";
        ((RelayCommand)ExportDecodedCommand).RaiseCanExecuteChanged();
    }

    private void ExportDecoded()
    {
        try
        {
            var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Policies");
            Directory.CreateDirectory(folder);
            var file = Path.Combine(folder, $"policy-{DateTime.Now:yyyyMMdd-HHmmss}.xml");
            File.WriteAllText(file, DecodedXml);
            StatusMessage = $"Decoded XML exported: {file}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    private void OpenSelectedProfile()
    {
        if (string.IsNullOrWhiteSpace(SelectedProfile) || !File.Exists(SelectedProfile))
            return;

        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = SelectedProfile,
            UseShellExecute = true
        });
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
