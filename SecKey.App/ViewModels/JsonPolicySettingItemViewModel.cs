using CommunityToolkit.Mvvm.ComponentModel;

namespace SecKey.App.ViewModels;

public sealed partial class JsonPolicySettingItemViewModel : ObservableObject
{
    public string Category { get; }
    public string DisplayName { get; }
    public string RelativeFilePath { get; }
    public string JsonPath { get; }
    public string ValueType { get; }
    public string AzurePortalUrl { get; }
    public string AbsoluteFilePath { get; }

    [ObservableProperty] private string _value;

    public JsonPolicySettingItemViewModel(
        string category,
        string displayName,
        string relativeFilePath,
        string absoluteFilePath,
        string jsonPath,
        string value,
        string valueType,
        string azurePortalUrl)
    {
        Category = category;
        DisplayName = displayName;
        RelativeFilePath = relativeFilePath;
        AbsoluteFilePath = absoluteFilePath;
        JsonPath = jsonPath;
        _value = value;
        ValueType = valueType;
        AzurePortalUrl = azurePortalUrl;
    }
}
