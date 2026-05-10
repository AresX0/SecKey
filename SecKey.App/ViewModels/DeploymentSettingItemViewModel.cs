using CommunityToolkit.Mvvm.ComponentModel;

namespace SecKey.App.ViewModels;

public sealed partial class DeploymentSettingItemViewModel : ObservableObject
{
    public string Key { get; }
    public string Scope { get; }
    public string DisplayName { get; }
    public string Description { get; }
    [ObservableProperty] private string _source;
    public string EditScope { get; }

    [ObservableProperty] private string _value;

    public DeploymentSettingItemViewModel(
        string key,
        string scope,
        string displayName,
        string description,
        string source,
        string value,
        string editScope)
    {
        Key = key;
        Scope = scope;
        DisplayName = displayName;
        Description = description;
        _source = source;
        _value = value;
        EditScope = editScope;
    }
}
