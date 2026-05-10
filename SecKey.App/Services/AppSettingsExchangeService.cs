using System.IO;
using System.Text.Json;

namespace SecKey.App.Services;

public sealed class AppSettingsDocument
{
    public bool IsDarkMode { get; set; }
    public EntraConfig EntraConfig { get; set; } = new();
    public Dictionary<string, string> DeploymentSettingOverrides { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public DateTime ExportedAtUtc { get; set; }
    public string Version { get; set; } = "2.0";
}

public sealed class AppSettingsExchangeService
{
    private readonly EntraConfigService _entraConfigService;
    private readonly INativeDeploymentSettingsService _nativeSettingsService;

    public AppSettingsExchangeService(
        EntraConfigService entraConfigService,
        INativeDeploymentSettingsService nativeSettingsService)
    {
        _entraConfigService = entraConfigService;
        _nativeSettingsService = nativeSettingsService;
    }

    public void ExportToFile(string filePath, bool isDarkMode)
    {
        var document = new AppSettingsDocument
        {
            IsDarkMode = isDarkMode,
            EntraConfig = _entraConfigService.Load(),
            DeploymentSettingOverrides = _nativeSettingsService.GetAllOverrides()
                .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase),
            ExportedAtUtc = DateTime.UtcNow,
            Version = "2.0"
        };

        var json = JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(filePath, json);
    }

    public AppSettingsDocument ImportFromFile(string filePath)
    {
        var json = File.ReadAllText(filePath);
        var imported = JsonSerializer.Deserialize<AppSettingsDocument>(json)
            ?? throw new InvalidOperationException("Invalid settings file.");

        _entraConfigService.Save(imported.EntraConfig ?? new EntraConfig());
        _nativeSettingsService.ReplaceOverrides(imported.DeploymentSettingOverrides ??
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

        return imported;
    }
}
