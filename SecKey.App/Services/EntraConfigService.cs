using System;
using System.IO;
using System.Text.Json;

namespace SecKey.App.Services
{
    /// <summary>
    /// Lightweight Entra config service used by the ported AD Security Analyzer.
    /// Stores app registration configuration in %LocalAppData%\SecKey\entra-config.json.
    /// </summary>
    public class EntraConfigService
    {
        private static EntraConfigService? _instance;
        public static EntraConfigService Instance => _instance ??= new EntraConfigService();

        public const string GenericClientId = "00000000-0000-0000-0000-000000000000";
        public const string MsGraphPowerShellClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e";

        public static string DataDirectory =>
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey");

        public string ConfigFilePath => Path.Combine(DataDirectory, "entra-config.json");

        private EntraConfig? _cached;

        public EntraConfig Load()
        {
            if (_cached != null) return _cached;
            try
            {
                if (File.Exists(ConfigFilePath))
                {
                    var json = File.ReadAllText(ConfigFilePath);
                    _cached = JsonSerializer.Deserialize<EntraConfig>(json) ?? new EntraConfig();
                    return _cached;
                }
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
            _cached = new EntraConfig();
            return _cached;
        }

        public void Save(EntraConfig config)
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                File.WriteAllText(ConfigFilePath,
                    JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }));
                _cached = config;
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
        }

        public string GetGraphClientId()
        {
            var config = Load();
            return string.IsNullOrWhiteSpace(config.GraphClientId) || config.GraphClientId == GenericClientId
                ? MsGraphPowerShellClientId
                : config.GraphClientId;
        }

        public string GetTenantId()
        {
            var config = Load();
            return string.IsNullOrWhiteSpace(config.TenantId) ? "common" : config.TenantId;
        }
    }

    public class EntraConfig
    {
        public string ClientId { get; set; } = "";
        public string TenantId { get; set; } = "common";
        public string GraphClientId { get; set; } = "";
        public string BackupDirectory { get; set; } = "";
    }
}
