using SecKey.App.Services;
using Xunit;

namespace SecKey.Tests;

public sealed class AppSettingsExchangeServiceTests
{
    [Fact]
    public void ExportImport_RoundTrips_DarkMode_EntraConfig_And_NativeOverrides()
    {
        var testRoot = Path.Combine(Path.GetTempPath(), "seckey-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testRoot);

        var entraPath = Path.Combine(testRoot, "entra-config.json");
        var nativePath = Path.Combine(testRoot, "deployment-settings.json");
        var exportPath = Path.Combine(testRoot, "settings-export.json");

        var entra = new EntraConfigService(entraPath);
        var native = new NativeDeploymentSettingsService(nativePath);
        var service = new AppSettingsExchangeService(entra, native);

        entra.Save(new EntraConfig
        {
            TenantId = "contoso-tenant",
            ClientId = "client-id-1",
            GraphClientId = "graph-id-1",
            BackupDirectory = "C:/tmp/backup"
        });
        native.SaveValue("tenant.namingPrefix", "SECKEY");
        native.SaveValue("intuneapps.ring", "prod");

        service.ExportToFile(exportPath, isDarkMode: true);

        // Change local state before import to prove import overwrites.
        entra.Save(new EntraConfig { TenantId = "other" });
        native.SaveValue("tenant.namingPrefix", "OTHER");

        var imported = service.ImportFromFile(exportPath);

        Assert.True(imported.IsDarkMode);
        Assert.Equal("contoso-tenant", entra.Load().TenantId);
        Assert.Equal("client-id-1", entra.Load().ClientId);

        var overrides = native.GetAllOverrides();
        Assert.Equal("SECKEY", overrides["tenant.namingPrefix"]);
        Assert.Equal("prod", overrides["intuneapps.ring"]);
    }
}
