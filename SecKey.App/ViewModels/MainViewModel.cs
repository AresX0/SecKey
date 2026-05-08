using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using SecKey.App.Services;

namespace SecKey.App.ViewModels;

public sealed partial class MainViewModel : ObservableObject
{
    private readonly IServiceProvider _sp;
    private readonly AuthState _auth;

    [ObservableProperty] private object? _currentView;
    public string AuthStatus => _auth.StatusMessage ?? "Not signed in";

    public MainViewModel(IServiceProvider sp, AuthState auth)
    {
        _sp = sp;
        _auth = auth;
        _auth.PropertyChanged += (_, __) => OnPropertyChanged(nameof(AuthStatus));
        ShowLogin();
    }

    [RelayCommand] private void ShowLogin() => CurrentView = _sp.GetRequiredService<LoginViewModel>();
    [RelayCommand] private void ShowDashboard() => CurrentView = _sp.GetRequiredService<DashboardViewModel>();
    [RelayCommand] private void ShowApps() => CurrentView = _sp.GetRequiredService<IntuneAppsViewModel>();
    [RelayCommand] private void ShowUpload() => CurrentView = _sp.GetRequiredService<UploadAppViewModel>();
    [RelayCommand] private void ShowPolicies() => CurrentView = _sp.GetRequiredService<PoliciesViewModel>();
    [RelayCommand] private void ShowGroups() => CurrentView = _sp.GetRequiredService<GroupsViewModel>();
    [RelayCommand] private void ShowCa() => CurrentView = _sp.GetRequiredService<ConditionalAccessViewModel>();
}
