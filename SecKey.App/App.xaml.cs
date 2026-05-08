using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecKey.App.Services;
using SecKey.App.ViewModels;
using SecKey.Graph;
using SecKey.Graph.Auth;

namespace SecKey.App;

public partial class App : Application
{
    public IServiceProvider Services { get; private set; } = null!;
    public static new App Current => (App)Application.Current;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddDebug().SetMinimumLevel(LogLevel.Information));

        // Default auth options; the Login page replaces the registered ITokenProvider with a configured one.
        var defaultOptions = new AuthOptions { Mode = AuthMode.Interactive, TenantId = "common" };
        services.AddSecKeyAuth(defaultOptions);
        services.AddSecKeyGraph();

        services.AddSingleton<AuthState>();
        services.AddSingleton<MainViewModel>();
        services.AddTransient<LoginViewModel>();
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<IntuneAppsViewModel>();
        services.AddTransient<PoliciesViewModel>();
        services.AddTransient<GroupsViewModel>();
        services.AddTransient<ConditionalAccessViewModel>();
        services.AddTransient<UploadAppViewModel>();

        Services = services.BuildServiceProvider();

        var window = new MainWindow { DataContext = Services.GetRequiredService<MainViewModel>() };
        window.Show();
    }
}

