using System.Text.Json.Nodes;
using SecKey.App.Services;
using Xunit;

namespace SecKey.Tests;

public sealed class JsonPolicySettingsServiceIntegrationTests
{
    [Fact]
    public void SaveAndReset_RoundTrips_ManagedJsonValues()
    {
        var root = Path.Combine(Path.GetTempPath(), "seckey-tests", Guid.NewGuid().ToString("N"));
        var jsonDir = Path.Combine(root, "JSON", "Groups");
        var snapshot = Path.Combine(root, "snapshot");
        Directory.CreateDirectory(jsonDir);

        var groupJson = Path.Combine(jsonDir, "seckey.groups.json");
        File.WriteAllText(groupJson, """
{
  "displayName": "SECKEY-Admins",
  "enabled": true,
  "priority": 1
}
""");

        var deployJsonPath = Path.Combine(root, "JSON", "seckey.deploy.json");
        File.WriteAllText(deployJsonPath, """
{
  "commandList": [
    {
      "parameters": {
        "JSONFileList": [
          "[PROJECTPATH]\\JSON\\Groups\\seckey.groups.json"
        ]
      }
    }
  ]
}
""");

        // optional manifest can be empty without commandList in this test.
        File.WriteAllText(Path.Combine(root, "JSON", "seckey.optional.deploy.json"), "{}");

        var service = new JsonPolicySettingsService(snapshot);

        var settings = service.LoadAllSettings(root);
        var displayNameSetting = settings.First(s => s.JsonPath.EndsWith(".displayName", StringComparison.Ordinal));
        displayNameSetting.Value = "SECKEY-Operators";

        var ok = service.SaveSetting(displayNameSetting, out var error);
        Assert.True(ok, error);

        var updated = JsonNode.Parse(File.ReadAllText(groupJson));
        Assert.Equal("SECKEY-Operators", updated?["displayName"]?.GetValue<string>());

        var savedCount = service.SaveCurrentAsDefaults(root);
        Assert.True(savedCount >= 1);

        // Drift away from baseline, then reset to saved defaults.
        File.WriteAllText(groupJson, """
{
  "displayName": "BROKEN",
  "enabled": false,
  "priority": 99
}
""");

        var restored = service.ResetToSavedDefaults(root);
        Assert.True(restored >= 1);

        var resetDoc = JsonNode.Parse(File.ReadAllText(groupJson));
        Assert.Equal("SECKEY-Operators", resetDoc?["displayName"]?.GetValue<string>());
        Assert.Equal(true, resetDoc?["enabled"]?.GetValue<bool>());
        Assert.Equal(1, resetDoc?["priority"]?.GetValue<int>());
    }
}
