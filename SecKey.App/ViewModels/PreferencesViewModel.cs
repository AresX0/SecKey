using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using SecKey.App.Services;

namespace SecKey.App.ViewModels
{
    public partial class PreferencesViewModel : ObservableObject
    {
        private readonly EntraConfigService _configService;

        [ObservableProperty] private string _tenantId = "";
        [ObservableProperty] private string _graphClientId = "";
        [ObservableProperty] private bool _isDarkMode;
        [ObservableProperty] private string _backupDirectory = "";

        public string DataDirectory => EntraConfigService.DataDirectory;

        public PreferencesViewModel(EntraConfigService configService)
        {
            _configService = configService;
            Load();
        }

        private void Load()
        {
            var config = _configService.Load();
            TenantId = config.TenantId ?? "common";
            GraphClientId = config.GraphClientId ?? "";
            BackupDirectory = config.BackupDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SecKey", "IntuneBackups");
        }

        [RelayCommand]
        private void BrowseBackupDirectory()
        {
            var dlg = new OpenFolderDialog
            {
                Title = "Select Default Backup Directory",
                InitialDirectory = BackupDirectory
            };
            if (dlg.ShowDialog() == true)
                BackupDirectory = dlg.FolderName;
        }

        [RelayCommand]
        private void OpenDataDirectory()
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                Process.Start(new ProcessStartInfo { FileName = DataDirectory, UseShellExecute = true });
            }
            catch { }
        }

        [RelayCommand]
        private void OpenLogDirectory()
        {
            string logDir = Path.Combine(DataDirectory, "Logs");
            try
            {
                Directory.CreateDirectory(logDir);
                Process.Start(new ProcessStartInfo { FileName = logDir, UseShellExecute = true });
            }
            catch { }
        }

        [RelayCommand]
        private void ToggleDarkMode()
        {
            // IsDarkMode is toggled by the CheckBox binding; apply the theme live
            ApplyTheme(IsDarkMode);
        }

        [RelayCommand]
        private void Save(Window? window)
        {
            var config = _configService.Load();
            config.TenantId = TenantId?.Trim() ?? "common";
            config.GraphClientId = GraphClientId?.Trim() ?? "";
            config.BackupDirectory = BackupDirectory?.Trim() ?? "";
            _configService.Save(config);
            window?.Close();
        }

        [RelayCommand]
        private void Cancel(Window? window)
        {
            window?.Close();
        }

        private static void ApplyTheme(bool dark)
        {
            var resources = Application.Current.Resources;
            if (dark)
            {
                resources["WindowBackgroundBrush"] = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#0B1220"));
                resources["WindowForegroundBrush"] = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F3F7FF"));
            }
            else
            {
                resources["WindowBackgroundBrush"] = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#F3F6FB"));
                resources["WindowForegroundBrush"] = new System.Windows.Media.SolidColorBrush(
                    (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#1F2937"));
            }
        }
    }
}
