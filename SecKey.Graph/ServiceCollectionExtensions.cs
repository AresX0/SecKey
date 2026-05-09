using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SecKey.Graph.Auth;
using SecKey.Graph.Services;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;
using SecKey.Graph.Services.Win32Lob;

namespace SecKey.Graph;

public static class ServiceCollectionExtensions
{
    /// <summary>Registers all SecKey Graph services. Caller must provide an ITokenProvider via AddAuth.</summary>
    public static IServiceCollection AddSecKeyGraph(this IServiceCollection services)
    {
        services.AddHttpClient<GraphHttpClient>();
        services.AddHttpClient("AzureBlob");

        services.AddSingleton<DeviceCompliancePolicyService>();
        services.AddSingleton<DeviceConfigurationService>();
        services.AddSingleton<GroupPolicyConfigurationService>();
        services.AddSingleton<DeviceSettingsCatalogService>();
        services.AddSingleton<EnrollmentStatusPageService>();
        services.AddSingleton<DeviceEnrollmentRestrictionService>();
        services.AddSingleton<AutopilotProfileService>();
        services.AddSingleton<IntuneRoleService>();
        services.AddSingleton<IntuneRoleScopeTagService>();
        services.AddSingleton<ProactiveRemediationService>();
        services.AddSingleton<IntuneApplicationService>();
        services.AddSingleton<EndpointSecurityPolicyService>();

        services.AddSingleton<EntraIdUserService>();
        services.AddSingleton<EntraIdGroupService>();
        services.AddSingleton<ConditionalAccessPolicyService>();
        services.AddSingleton<NamedLocationService>();
        services.AddSingleton<AuthenticationContextService>();
        services.AddSingleton<AuthenticationStrengthService>();
        services.AddSingleton<AppRegistrationService>();
        services.AddSingleton<PimAssignmentService>();
        services.AddSingleton<EntraIdDeviceService>();

        services.AddSingleton<PolicyImporter>();
        services.AddSingleton<EndpointSecurityImporter>();
        services.AddSingleton(sp =>
        {
            var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient("AzureBlob");
            var graph = sp.GetRequiredService<GraphHttpClient>();
            var log = sp.GetService<Microsoft.Extensions.Logging.ILogger<Win32LobUploader>>()
                      ?? NullLogger<Win32LobUploader>.Instance;
            return new Win32LobUploader(graph, http, log);
        });
        services.AddSingleton<IntuneAppOrchestrator>();

        return services;
    }

    public static IServiceCollection AddSecKeyAuth(this IServiceCollection services, AuthOptions options)
    {
        services.AddSingleton(options);
        services.AddSingleton<ITokenProvider, MsalTokenProvider>(sp => new MsalTokenProvider(options));
        return services;
    }
}
