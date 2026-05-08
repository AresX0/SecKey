using System.Text.Json.Nodes;

namespace SecKey.Graph.Services.Intune;

public sealed class DeviceCompliancePolicyService : GraphServiceBase
{
    public DeviceCompliancePolicyService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/deviceCompliancePolicies";

    public Task SetAssignmentsAsync(string policyId, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["assignments"] = assignments };
        return Client.PostAsync($"{Resource}/{policyId}/assign", body, UseBeta, ct);
    }
}

public sealed class DeviceConfigurationService : GraphServiceBase
{
    public DeviceConfigurationService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/deviceConfigurations";

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["assignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class GroupPolicyConfigurationService : GraphServiceBase
{
    public GroupPolicyConfigurationService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/groupPolicyConfigurations";

    public Task<JsonNode?> GetDefinitionAsync(string id, CancellationToken ct = default)
        => Client.GetAsync($"{Resource}/{id}/definitionValues?$expand=definition", UseBeta, ct);

    public Task<JsonNode?> SetDefinitionValueAsync(string configId, JsonNode body, CancellationToken ct = default)
        => Client.PostAsync($"{Resource}/{configId}/definitionValues", body, UseBeta, ct);

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["assignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class DeviceSettingsCatalogService : GraphServiceBase
{
    public DeviceSettingsCatalogService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/configurationPolicies";

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["assignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class EnrollmentStatusPageService : GraphServiceBase
{
    public EnrollmentStatusPageService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/deviceEnrollmentConfigurations";

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["enrollmentConfigurationAssignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class DeviceEnrollmentRestrictionService : GraphServiceBase
{
    public DeviceEnrollmentRestrictionService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/deviceEnrollmentConfigurations";

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["enrollmentConfigurationAssignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class AutopilotProfileService : GraphServiceBase
{
    public AutopilotProfileService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/windowsAutopilotDeploymentProfiles";

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["assignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class IntuneRoleService : GraphServiceBase
{
    public IntuneRoleService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/roleDefinitions";
}

public sealed class IntuneRoleScopeTagService : GraphServiceBase
{
    public IntuneRoleScopeTagService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/roleScopeTags";

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["assignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class ProactiveRemediationService : GraphServiceBase
{
    public ProactiveRemediationService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/deviceHealthScripts";

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["deviceHealthScriptAssignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class IntuneApplicationService : GraphServiceBase
{
    public IntuneApplicationService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceAppManagement/mobileApps";

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["mobileAppAssignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }
}

public sealed class EndpointSecurityPolicyService : GraphServiceBase
{
    public EndpointSecurityPolicyService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "deviceManagement/intents";

    /// <summary>Gets all Endpoint Security baseline templates.</summary>
    public async Task<JsonArray> ListTemplatesAsync(CancellationToken ct = default)
    {
        var node = await Client.GetAsync(
            "deviceManagement/templates?$filter=(isof('microsoft.graph.securityBaselineTemplate'))",
            UseBeta, ct);
        return node?["value"]?.AsArray() ?? new JsonArray();
    }

    /// <summary>Creates an Endpoint Security policy instance from a template.</summary>
    public Task<JsonNode?> CreateInstanceAsync(string templateId, JsonNode body, CancellationToken ct = default)
        => Client.PostAsync($"deviceManagement/templates/{templateId}/createInstance", body, UseBeta, ct);

    public Task SetAssignmentsAsync(string id, JsonArray assignments, CancellationToken ct = default)
    {
        var body = new JsonObject { ["assignments"] = assignments };
        return Client.PostAsync($"{Resource}/{id}/assign", body, UseBeta, ct);
    }

    /// <summary>Returns the first intent matching display name (case-sensitive, like the PS module).</summary>
    public async Task<JsonNode?> FindByDisplayNameAsync(string displayName, CancellationToken ct = default)
    {
        var arr = await ListAsync(ct);
        foreach (var n in arr)
        {
            if (n?["displayName"]?.GetValue<string>() == displayName)
                return n;
        }
        return null;
    }
}
