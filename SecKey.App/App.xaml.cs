using System.Diagnostics;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecKey.App.Services;
using SecKey.App.ViewModels;
using SecKey.App.Views;
using SecKey.Core.Services;
using SecKey.Graph;
using SecKey.Graph.Auth;

namespace SecKey.App;

public partial class App : Application
{
    public IServiceProvider Services { get; private set; } = null!;
    public static new App Current => (App)Application.Current;
    private SplashScreenWindow? _splashScreen;
    private readonly Stopwatch _startupStopwatch = Stopwatch.StartNew();

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

        _splashScreen = new SplashScreenWindow();
        MainWindow = _splashScreen;
        _splashScreen.Show();
        _splashScreen.Dispatcher.Invoke(() => { }, System.Windows.Threading.DispatcherPriority.Render);

        Dispatcher.BeginInvoke(new Action(async () =>
        {
            try
            {
                await InitializeApplicationAsync();
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
        }));
    }

    private async Task InitializeApplicationAsync()
    {
        try
        {
            _splashScreen?.UpdateStatus("Preparing app services...");

            var services = await Task.Run(() =>
            {
                var collection = new ServiceCollection();
                collection.AddLogging(b => b.AddDebug().SetMinimumLevel(LogLevel.Information));

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

                collection.AddSecKeyAuth(defaultOptions);
                collection.AddSecKeyGraph();
                collection.AddTransient<ISystemAuditService, SystemAuditService>();
                collection.AddSingleton<INativeDeploymentSettingsService, NativeDeploymentSettingsService>();
                collection.AddSingleton<AppSettingsExchangeService>();
                collection.AddSingleton<AppUpdateService>();
                collection.AddSingleton<BaselineContentBootstrapService>();

                collection.AddSingleton<EntraConfigService>(_ => EntraConfigService.Instance);
                collection.AddSingleton<AuthState>();
                collection.AddSingleton<MainViewModel>();
                collection.AddTransient<LoginViewModel>();
                collection.AddTransient<DashboardViewModel>();
                collection.AddTransient<IntuneAppsViewModel>();
                collection.AddTransient<InfrastructureViewModel>();
                collection.AddTransient<PoliciesViewModel>();
                collection.AddTransient<GroupsViewModel>();
                collection.AddTransient<ConditionalAccessViewModel>();
                collection.AddTransient<UploadAppViewModel>();
                collection.AddTransient<DeviceTaggingViewModel>();
                collection.AddTransient<SecurityAnalyzerViewModel>();
                collection.AddTransient<SystemHardeningViewModel>();
                collection.AddTransient<RebootAnalyzerViewModel>();
                collection.AddTransient<FileIntegrityViewModel>();
                collection.AddTransient<IntuneBackupViewModel>();
                collection.AddTransient<CertificateManagerViewModel>();
                collection.AddTransient<SecureWipeViewModel>();
                collection.AddTransient<NetworkTrafficViewModel>();
                collection.AddTransient<HashScannerViewModel>();
                collection.AddTransient<CredentialManagerViewModel>();
                collection.AddTransient<EncryptedClipboardViewModel>();
                collection.AddTransient<SshKeyManagerViewModel>();
                collection.AddTransient<FileEncryptionToolViewModel>();
                collection.AddTransient<SecurityVaultViewModel>();
                collection.AddTransient<YaraScannerViewModel>();
                collection.AddTransient<CveSearchViewModel>();
                collection.AddTransient<ForensicsAnalyzerViewModel>();
                collection.AddTransient<AdvancedForensicsViewModel>();
                collection.AddTransient<GlobalSecureAccessViewModel>();
                collection.AddTransient<WdacAppLockerViewModel>();
                collection.AddTransient<SystemAuditViewModel>();
                collection.AddTransient<PreferencesViewModel>();

                return collection.BuildServiceProvider();
            });

            Services = services;

            _splashScreen?.UpdateStatus("Seeding baseline content...");
            try
            {
                await Task.Run(() => Services.GetRequiredService<BaselineContentBootstrapService>().EnsureBaselineContent());
            }
            catch (Exception bootstrapEx)
            {
                WriteCrashLog("BaselineContentBootstrap", bootstrapEx);
            }

            _splashScreen?.UpdateStatus("Loading workspace...");
            var minimumSplashTime = TimeSpan.FromSeconds(6);
            var remainingSplashTime = minimumSplashTime - _startupStopwatch.Elapsed;
            if (remainingSplashTime > TimeSpan.Zero)
                await Task.Delay(remainingSplashTime);

            await Dispatcher.InvokeAsync(() =>
            {
                var window = new MainWindow { DataContext = Services.GetRequiredService<MainViewModel>() };
                MainWindow = window;
                window.Show();
                _splashScreen?.Close();
                _splashScreen = null;
            });
        }
        catch
        {
            _splashScreen?.Close();
            _splashScreen = null;
            throw;
        }
    }
}

