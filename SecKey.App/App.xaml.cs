using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecKey.App.Services;
using SecKey.App.ViewModels;
using SecKey.Core.Services;
using SecKey.Graph;
using SecKey.Graph.Auth;

namespace SecKey.App;

public partial class App : Application
{
    public IServiceProvider Services { get; private set; } = null!;
    public static new App Current => (App)Application.Current;

    private static void WriteCrashLog(string source, Exception? ex)
    {
        try
        {
            var logDir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey");
            System.IO.Directory.CreateDirectory(logDir);
            var crashLog = System.IO.Path.Combine(logDir, "crash.log");
            System.IO.File.AppendAllText(crashLog, $"[{DateTime.Now:O}] {source}\n{ex}\n\n");
        }
        catch
        {
            // Swallow logging failures.
        }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        AppDomain.CurrentDomain.UnhandledException += (s, a) =>
            WriteCrashLog("AppDomain.UnhandledException", a.ExceptionObject as Exception);
        DispatcherUnhandledException += (s, a) =>
        {
            WriteCrashLog("Dispatcher.UnhandledException", a.Exception);
            MessageBox.Show(
                $"An unexpected error occurred and was logged to %LocalAppData%\\SecKey\\crash.log.\n\n{a.Exception.Message}",
                "SecKey Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            a.Handled = true;
        };
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, a) =>
        {
            WriteCrashLog("TaskScheduler.UnobservedTaskException", a.Exception);
            a.SetObserved();
        };

        try
        {
            var services = new ServiceCollection();
            services.AddLogging(b => b.AddDebug().SetMinimumLevel(LogLevel.Information));

        // Default auth options; the Login page replaces the registered ITokenProvider with a configured one.
        var defaultOptions = new AuthOptions
        {
            Mode = AuthMode.Interactive,
            TenantId = "common",
            Scopes = new[]
            {
                "https://graph.microsoft.com/Directory.ReadWrite.All",
                "https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All",
                "https://graph.microsoft.com/DeviceManagementConfiguration.ReadWrite.All",
                "https://graph.microsoft.com/DeviceManagementScripts.ReadWrite.All",
                "https://graph.microsoft.com/DeviceManagementServiceConfig.ReadWrite.All",
                "https://graph.microsoft.com/Group.ReadWrite.All",
                "https://graph.microsoft.com/User.ReadWrite.All",
                "https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess"
            }
        };
        services.AddSecKeyAuth(defaultOptions);
        services.AddSecKeyGraph();
        services.AddTransient<ISystemAuditService, SystemAuditService>();
        services.AddSingleton<INativeDeploymentSettingsService, NativeDeploymentSettingsService>();
        services.AddSingleton<AppSettingsExchangeService>();
        services.AddSingleton<AppUpdateService>();

        services.AddSingleton<EntraConfigService>(_ => EntraConfigService.Instance);
        services.AddSingleton<AuthState>();
        services.AddSingleton<MainViewModel>();
        services.AddTransient<LoginViewModel>();
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<IntuneAppsViewModel>();
        services.AddTransient<InfrastructureViewModel>();
        services.AddTransient<PoliciesViewModel>();
        services.AddTransient<GroupsViewModel>();
        services.AddTransient<ConditionalAccessViewModel>();
        services.AddTransient<UploadAppViewModel>();
        services.AddTransient<DeviceTaggingViewModel>();
        services.AddTransient<SecurityAnalyzerViewModel>();
        services.AddTransient<SystemHardeningViewModel>();
        services.AddTransient<RebootAnalyzerViewModel>();
        services.AddTransient<FileIntegrityViewModel>();
            services.AddTransient<IntuneBackupViewModel>();
            services.AddTransient<CertificateManagerViewModel>();
            services.AddTransient<SecureWipeViewModel>();
            services.AddTransient<NetworkTrafficViewModel>();
            services.AddTransient<HashScannerViewModel>();
            services.AddTransient<CredentialManagerViewModel>();
            services.AddTransient<EncryptedClipboardViewModel>();
            services.AddTransient<SshKeyManagerViewModel>();
            services.AddTransient<FileEncryptionToolViewModel>();
            services.AddTransient<SecurityVaultViewModel>();
            services.AddTransient<YaraScannerViewModel>();
            services.AddTransient<CveSearchViewModel>();
            services.AddTransient<ForensicsAnalyzerViewModel>();
            services.AddTransient<AdvancedForensicsViewModel>();
            services.AddTransient<GlobalSecureAccessViewModel>();
            services.AddTransient<WdacAppLockerViewModel>();
            services.AddTransient<SystemAuditViewModel>();
            services.AddTransient<PreferencesViewModel>();

            Services = services.BuildServiceProvider();

            var window = new MainWindow { DataContext = Services.GetRequiredService<MainViewModel>() };
            window.Show();
        }
        catch (Exception ex)
        {
            WriteCrashLog("Startup", ex);
            MessageBox.Show(
                $"SecKey failed to start. Details were logged to %LocalAppData%\\SecKey\\crash.log.\n\n{ex}",
                "Startup Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(-1);
        }
    }
}

