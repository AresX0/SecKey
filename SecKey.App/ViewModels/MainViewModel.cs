using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Win32;
using SecKey.App.Services;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;

namespace SecKey.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly IServiceProvider _sp;
    private readonly AuthState _auth;

    [ObservableProperty] private object? _currentView;
    [ObservableProperty] private bool _isDarkMode = false;
    public string AuthStatus => _auth.StatusMessage ?? "Not signed in";

    private sealed class AppSettingsExport
    {
        public bool IsDarkMode { get; set; }
        public EntraConfig EntraConfig { get; set; } = new();
        public DateTime ExportedAtUtc { get; set; }
        public string Version { get; set; } = "1.0";
    }

    public MainViewModel(IServiceProvider sp, AuthState auth)
    {
        _sp = sp;
        _auth = auth;
        _auth.PropertyChanged += (_, __) => OnPropertyChanged(nameof(AuthStatus));
        if (_auth.IsSignedIn)
            ShowDashboard();
        else
            ShowLogin();
        ApplyTheme(IsDarkMode);
    }

    // Navigation Commands
    [RelayCommand] private void ShowLogin() => CurrentView = _sp.GetRequiredService<LoginViewModel>();
    [RelayCommand] private void ShowDashboard() => CurrentView = _sp.GetRequiredService<DashboardViewModel>();
    [RelayCommand] private void ShowApps() => CurrentView = _sp.GetRequiredService<IntuneAppsViewModel>();
    [RelayCommand] private void ShowUpload() => CurrentView = _sp.GetRequiredService<UploadAppViewModel>();
    [RelayCommand] private void ShowPolicies() => CurrentView = _sp.GetRequiredService<PoliciesViewModel>();
    [RelayCommand] private void ShowInfrastructure() => CurrentView = _sp.GetRequiredService<InfrastructureViewModel>();
    [RelayCommand] private void ShowGroups() => CurrentView = _sp.GetRequiredService<GroupsViewModel>();
    [RelayCommand] private void ShowCa() => CurrentView = _sp.GetRequiredService<ConditionalAccessViewModel>();
    [RelayCommand] private void ShowDeviceTagging() => CurrentView = _sp.GetRequiredService<DeviceTaggingViewModel>();
    
    // Security Analysis Commands
    [RelayCommand] private void ShowSecurityAnalyzer() => CurrentView = _sp.GetRequiredService<SecurityAnalyzerViewModel>();
    [RelayCommand] private void ShowSystemHardening() => CurrentView = _sp.GetRequiredService<SystemHardeningViewModel>();
    [RelayCommand] private void ShowRebootAnalyzer() => CurrentView = _sp.GetRequiredService<RebootAnalyzerViewModel>();
    [RelayCommand] private void ShowFileIntegrity() => CurrentView = _sp.GetRequiredService<FileIntegrityViewModel>();
    [RelayCommand] private void ShowIntuneBackup() => CurrentView = _sp.GetRequiredService<IntuneBackupViewModel>();
    [RelayCommand] private void ShowCertificateManager() => CurrentView = _sp.GetRequiredService<CertificateManagerViewModel>();
    [RelayCommand] private void ShowSecureWipe() => CurrentView = _sp.GetRequiredService<SecureWipeViewModel>();
    [RelayCommand] private void ShowNetworkTraffic() => CurrentView = _sp.GetRequiredService<NetworkTrafficViewModel>();
    [RelayCommand] private void ShowHashScanner() => CurrentView = _sp.GetRequiredService<HashScannerViewModel>();
    [RelayCommand] private void ShowCredentialManager() => CurrentView = _sp.GetRequiredService<CredentialManagerViewModel>();
    [RelayCommand] private void ShowEncryptedClipboard() => CurrentView = _sp.GetRequiredService<EncryptedClipboardViewModel>();
    [RelayCommand] private void ShowSshKeyManager() => CurrentView = _sp.GetRequiredService<SshKeyManagerViewModel>();
    [RelayCommand] private void ShowFileEncryption() => CurrentView = _sp.GetRequiredService<FileEncryptionToolViewModel>();
    [RelayCommand] private void ShowSecurityVault() => CurrentView = _sp.GetRequiredService<SecurityVaultViewModel>();
    [RelayCommand] private void ShowYaraScanner() => CurrentView = _sp.GetRequiredService<YaraScannerViewModel>();
    [RelayCommand] private void ShowCveSearch() => CurrentView = _sp.GetRequiredService<CveSearchViewModel>();
    [RelayCommand] private void ShowForensicsAnalyzer() => CurrentView = _sp.GetRequiredService<ForensicsAnalyzerViewModel>();
    [RelayCommand] private void ShowAdvancedForensics() => CurrentView = _sp.GetRequiredService<AdvancedForensicsViewModel>();
    [RelayCommand] private void ShowGlobalSecureAccess() => CurrentView = _sp.GetRequiredService<GlobalSecureAccessViewModel>();
    [RelayCommand] private void ShowWdacAppLocker() => CurrentView = _sp.GetRequiredService<WdacAppLockerViewModel>();
    [RelayCommand]
    private void ShowSystemAudit()
    {
        try
        {
            CurrentView = _sp.GetRequiredService<SystemAuditViewModel>();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Failed to open System Audit: {ex.Message}", "SecKey", MessageBoxButton.OK, MessageBoxImage.Error);
            CurrentView = _sp.GetRequiredService<LoginViewModel>();
        }
    }

    // File Menu Commands
    [RelayCommand]
    private void ExportSettings()
    {
        try
        {
            var dialog = new SaveFileDialog
            {
                Title = "Export SecKey Settings",
                Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*",
                FileName = $"SecKey.Settings.{DateTime.Now:yyyyMMdd_HHmmss}.json"
            };

            if (dialog.ShowDialog() != true)
                return;

            var export = new AppSettingsExport
            {
                IsDarkMode = IsDarkMode,
                EntraConfig = EntraConfigService.Instance.Load(),
                ExportedAtUtc = DateTime.UtcNow
            };

            var json = JsonSerializer.Serialize(export, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dialog.FileName, json);

            MessageBox.Show($"Settings exported to:\n{dialog.FileName}", "SecKey", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Export failed: {ex.Message}", "SecKey", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private void ImportSettings()
    {
        try
        {
            var dialog = new OpenFileDialog
            {
                Title = "Import SecKey Settings",
                Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
            };

            if (dialog.ShowDialog() != true)
                return;

            var json = File.ReadAllText(dialog.FileName);
            var imported = JsonSerializer.Deserialize<AppSettingsExport>(json);
            if (imported == null)
            {
                MessageBox.Show("Invalid settings file.", "SecKey", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            EntraConfigService.Instance.Save(imported.EntraConfig ?? new EntraConfig());
            IsDarkMode = imported.IsDarkMode;
            ApplyTheme(IsDarkMode);

            MessageBox.Show("Settings imported successfully.", "SecKey", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Import failed: {ex.Message}", "SecKey", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private void Exit()
    {
        System.Windows.Application.Current.Shutdown();
    }

    // View Menu Commands
    [RelayCommand]
    private void Refresh()
    {
        if (CurrentView == null)
            return;

        try
        {
            var currentType = CurrentView.GetType();
            CurrentView = _sp.GetRequiredService(currentType);
        }
        catch
        {
            // If the current view model type is not directly registered by concrete type,
            // keep current view unchanged.
        }
    }

    [RelayCommand]
    private void ToggleDarkMode()
    {
        IsDarkMode = !IsDarkMode;
        ApplyTheme(IsDarkMode);
    }

    private static void ApplyTheme(bool dark)
    {
        var appResources = Application.Current.Resources;

        if (dark)
        {
            SetBrush(appResources, "WindowBackgroundBrush", "#101826");
            SetBrush(appResources, "WindowForegroundBrush", "#E5E7EB");
            SetBrush(appResources, "SectionHeaderBrush", "#1E3A8A");
            SetBrush(appResources, "StatusPanelBrush", "#172334");
            SetBrush(appResources, "StatusPanelBorderBrush", "#31435D");
            SetBrush(appResources, "CardBrush", "#111827");
            SetBrush(appResources, "ControlBackgroundBrush", "#0F172A");
            SetBrush(appResources, "SecondaryTextBrush", "#94A3B8");
            SetBrush(appResources, "ErrorBackgroundBrush", "#3A1E1E");
        }
        else
        {
            SetBrush(appResources, "WindowBackgroundBrush", "#F3F6FB");
            SetBrush(appResources, "WindowForegroundBrush", "#1F2937");
            SetBrush(appResources, "SectionHeaderBrush", "#1E3A8A");
            SetBrush(appResources, "StatusPanelBrush", "#ECF1FA");
            SetBrush(appResources, "StatusPanelBorderBrush", "#C9D2E3");
            SetBrush(appResources, "CardBrush", "#FFFFFF");
            SetBrush(appResources, "ControlBackgroundBrush", "#FFFFFF");
            SetBrush(appResources, "SecondaryTextBrush", "#6B7280");
            SetBrush(appResources, "ErrorBackgroundBrush", "#FFF5F5");
        }

        if (Application.Current.MainWindow != null)
        {
            var winResources = Application.Current.MainWindow.Resources;
            if (dark)
            {
                SetBrush(winResources, "SidebarBackgroundBrush", "#0B1322");
                SetBrush(winResources, "SidebarButtonBrush", "#1A253A");
                SetBrush(winResources, "SidebarButtonHoverBrush", "#2C3E63");
                SetBrush(winResources, "SidebarButtonPressedBrush", "#3B5998");
                SetBrush(winResources, "MainSurfaceBrush", "#0F172A");
            }
            else
            {
                SetBrush(winResources, "SidebarBackgroundBrush", "#111A2C");
                SetBrush(winResources, "SidebarButtonBrush", "#1B2740");
                SetBrush(winResources, "SidebarButtonHoverBrush", "#2A3B5F");
                SetBrush(winResources, "SidebarButtonPressedBrush", "#345084");
                SetBrush(winResources, "MainSurfaceBrush", "#F3F6FB");
            }
        }
    }

    private static void SetBrush(ResourceDictionary resources, string key, string hex)
    {
        resources[key] = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
    }

    // Help Menu Commands
    [RelayCommand]
    private void OpenHelp()
    {
        string helpFile = "SecKey-Help.html";
        string helpPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", helpFile);
        if (!System.IO.File.Exists(helpPath))
        {
            helpPath = System.IO.Path.Combine("C:", "Projects", "SecureKeyboard", "SecKey-Help.html");
        }
        if (System.IO.File.Exists(helpPath))
        {
            Process.Start(new ProcessStartInfo { FileName = helpPath, UseShellExecute = true });
        }
        else
        {
            System.Windows.MessageBox.Show("Help file not found: " + helpPath, "SecKey - Error");
        }
    }

    [RelayCommand]
    private void OpenSkipReasons()
    {
        string skipFile = "DEPLOYMENT-SKIP-REASONS.md";
        string skipPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", skipFile);
        if (!System.IO.File.Exists(skipPath))
        {
            skipPath = System.IO.Path.Combine("C:", "Projects", "SecureKeyboard", "DEPLOYMENT-SKIP-REASONS.md");
        }
        if (System.IO.File.Exists(skipPath))
        {
            Process.Start(new ProcessStartInfo { FileName = skipPath, UseShellExecute = true });
        }
        else
        {
            System.Windows.MessageBox.Show("Skip reasons file not found: " + skipPath, "SecKey - Error");
        }
    }

    [RelayCommand]
    private void OpenAbout()
    {
        System.Windows.MessageBox.Show(
            "SecKey v1.0 - Intune Configuration Manager\n\n" +
            "A comprehensive tenant security deployment tool for Azure Entra ID and Microsoft Intune.\n\n" +
            "© 2026 SecKey Project\n" +
            "Licensed under MIT License",
            "About SecKey");
    }

    // Settings Menu Commands
    [RelayCommand]
    private void OpenPreferences()
    {
        var vm = _sp.GetRequiredService<PreferencesViewModel>();
        var win = new Views.PreferencesWindow(vm)
        {
            Owner = Application.Current.MainWindow
        };
        win.ShowDialog();
        // Re-apply dark mode in case user toggled it in preferences
        ApplyTheme(IsDarkMode);
    }

    [RelayCommand]
    private void OpenLogs()
    {
        string logDir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "SecKey", "Logs");
        
        if (System.IO.Directory.Exists(logDir))
        {
            Process.Start(new ProcessStartInfo { FileName = logDir, UseShellExecute = true });
        }
        else
        {
            System.Windows.MessageBox.Show("Logs directory not found: " + logDir, "SecKey - Error");
        }
    }

    [RelayCommand]
    private void OpenAdvanced()
    {
        // Advanced options reuse the Preferences window (all config in one place)
        var vm = _sp.GetRequiredService<PreferencesViewModel>();
        var win = new Views.PreferencesWindow(vm)
        {
            Owner = Application.Current.MainWindow
        };
        win.ShowDialog();
        ApplyTheme(IsDarkMode);
    }

    public bool NavigateToScope(string scope)
    {
        switch (scope)
        {
            case "Dashboard":
                ShowDashboard();
                return true;
            case "Intune Apps":
                ShowApps();
                return true;
            case "Groups":
                ShowGroups();
                return true;
            case "Policies":
                ShowPolicies();
                return true;
            case "Infrastructure":
                ShowInfrastructure();
                return true;
            case "Conditional Access":
                ShowCa();
                return true;
            case "Device Tagging":
                ShowDeviceTagging();
                return true;
            default:
                return false;
        }
    }
}
