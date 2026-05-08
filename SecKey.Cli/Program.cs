using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecKey.Core;
using SecKey.Graph;
using SecKey.Graph.Auth;
using SecKey.Graph.Services;
using SecKey.Graph.Services.AzureAD;
using SecKey.Graph.Services.Intune;
using SecKey.Graph.Services.Win32Lob;

if (args.Length == 0)
{
    PrintUsage();
    return 0;
}

var services = new ServiceCollection();
services.AddLogging(b => b.AddSimpleConsole(o => o.SingleLine = true).SetMinimumLevel(LogLevel.Information));

var tenantId = Environment.GetEnvironmentVariable("SECKEY_TENANT") ?? "common";
var clientId = Environment.GetEnvironmentVariable("SECKEY_CLIENT") ?? "14d82eec-204b-4c2f-b7e8-296a70dab67e";
var clientSecret = Environment.GetEnvironmentVariable("SECKEY_SECRET");
var mode = string.IsNullOrEmpty(clientSecret) ? AuthMode.Interactive : AuthMode.ClientCredentials;

services.AddSecKeyAuth(new AuthOptions
{
    TenantId = tenantId,
    ClientId = clientId,
    ClientSecret = clientSecret,
    Mode = mode,
    Scopes = string.IsNullOrEmpty(clientSecret)
        ? new[]
        {
            "https://graph.microsoft.com/Directory.ReadWrite.All",
            "https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All",
            "https://graph.microsoft.com/DeviceManagementConfiguration.ReadWrite.All",
            "https://graph.microsoft.com/DeviceManagementServiceConfig.ReadWrite.All",
            "https://graph.microsoft.com/Group.ReadWrite.All",
            "https://graph.microsoft.com/User.ReadWrite.All",
            "https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess"
        }
        : new[] { "https://graph.microsoft.com/.default" }
});
services.AddSecKeyGraph();

await using var sp = services.BuildServiceProvider();
var cmd = args[0].ToLowerInvariant();

try
{
    switch (cmd)
    {
        case "list-apps":
            await ListAsync(sp.GetRequiredService<IntuneApplicationService>());
            break;
        case "list-groups":
            await ListAsync(sp.GetRequiredService<AADGroupService>());
            break;
        case "list-compliance":
            await ListAsync(sp.GetRequiredService<DeviceCompliancePolicyService>());
            break;
        case "list-config":
            await ListAsync(sp.GetRequiredService<DeviceConfigurationService>());
            break;
        case "list-ca":
            await ListAsync(sp.GetRequiredService<ConditionalAccessPolicyService>());
            break;
        case "import-app" when args.Length >= 2:
        {
            var orch = sp.GetRequiredService<IntuneAppOrchestrator>();
            var progress = new Progress<UploadProgress>(p =>
                Console.WriteLine($"[{p.Stage}] {p.Fraction:P0} {p.Message}"));
            var result = await orch.ImportAsync(args[1], progress);
            Console.WriteLine($"App: {result?["id"]?.GetValue<string>()}");
            break;
        }
        case "import-policies" when args.Length >= 2:
        {
            var importer = sp.GetRequiredService<PolicyImporter>();
            var svc = sp.GetRequiredService<DeviceCompliancePolicyService>();
            var created = await importer.ImportFromDirectoryAsync(svc, args[1]);
            Console.WriteLine($"Created {created.Count} policies");
            break;
        }
        default:
            PrintUsage();
            return 2;
    }
}
catch (SecKeyException ex)
{
    Console.Error.WriteLine($"ERROR: {ex.Message}");
    if (ex.ResponseBody is not null) Console.Error.WriteLine(ex.ResponseBody);
    return 1;
}
return 0;

static async Task ListAsync(GraphServiceBase svc)
{
    var arr = await svc.ListAsync();
    foreach (var n in arr)
    {
        var name = n?["displayName"]?.GetValue<string>();
        var id = n?["id"]?.GetValue<string>();
        Console.WriteLine($"{id}  {name}");
    }
}

static void PrintUsage()
{
    Console.WriteLine("SecKey CLI - usage:");
    Console.WriteLine("  list-apps");
    Console.WriteLine("  list-groups");
    Console.WriteLine("  list-compliance");
    Console.WriteLine("  list-config");
    Console.WriteLine("  list-ca");
    Console.WriteLine("  import-app <appFolder>");
    Console.WriteLine("  import-policies <jsonDirectory>");
    Console.WriteLine();
    Console.WriteLine("Auth: set SECKEY_TENANT, SECKEY_CLIENT, optional SECKEY_SECRET (app-only).");
}
