using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using SecKey.App.Services;
using System.Diagnostics;

namespace SecKey.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly IServiceProvider _sp;
    private readonly AuthState _auth;

    [ObservableProperty] private object? _currentView;
    [ObservableProperty] private bool _isDarkMode = true;
    public string AuthStatus => _auth.StatusMessage ?? "Not signed in";

    public MainViewModel(IServiceProvider sp, AuthState auth)
    {
        _sp = sp;
        _auth = auth;
        _auth.PropertyChanged += (_, __) => OnPropertyChanged(nameof(AuthStatus));
        ShowLogin();
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

    // File Menu Commands
    [RelayCommand]
    private void ExportSettings()
    {
        // Placeholder - to be implemented with export functionality
        System.Windows.MessageBox.Show("Export Settings feature coming soon.", "SecKey");
    }

    [RelayCommand]
    private void ImportSettings()
    {
        // Placeholder - to be implemented with import functionality
        System.Windows.MessageBox.Show("Import Settings feature coming soon.", "SecKey");
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
        System.Windows.MessageBox.Show("Refreshing data...", "SecKey");
        // Placeholder - implement refresh logic
    }

    [RelayCommand]
    private void ToggleDarkMode()
    {
        IsDarkMode = !IsDarkMode;
        // Placeholder - implement theme switching
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
        System.Windows.MessageBox.Show("Preferences dialog coming soon.", "SecKey");
        // Placeholder - implement preferences window
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
        System.Windows.MessageBox.Show("Advanced Options coming soon.", "SecKey");
        // Placeholder - implement advanced settings
    }
}
