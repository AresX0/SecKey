using System.Text.Json.Nodes;
using SecKey.Core.Utilities;

namespace SecKey.Graph.Services.EntraID;

public sealed class EntraIdUserService : GraphServiceBase
{
    public EntraIdUserService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "users";
    protected override bool UseBeta => false;

    public async Task<string> GetDefaultDomainAsync(CancellationToken ct = default)
    {
        var node = await Client.GetAsync("domains?$filter=isDefault eq true", false, ct);
        return (node?["value"] as JsonArray)?.FirstOrDefault()?["id"]?.GetValue<string>()
               ?? throw new InvalidOperationException("Default domain not found");
    }

    public async Task<JsonNode?> CreateAsync(string displayName, string mailNickname, string? domainOverride = null, CancellationToken ct = default)
    {
        var domain = domainOverride ?? await GetDefaultDomainAsync(ct);
        var body = new JsonObject
        {
            ["displayName"] = displayName,
            ["accountEnabled"] = true,
            ["mailNickname"] = mailNickname,
            ["userPrincipalName"] = $"{mailNickname}@{domain}",
            ["passwordProfile"] = new JsonObject
            {
                ["password"] = PasswordGenerator.Generate(32),
                ["forceChangePasswordNextSignIn"] = true
            }
        };
        return await Client.PostAsync(Resource, body, false, ct);
    }

    public override async Task<JsonNode?> GetByDisplayNameAsync(string displayName, CancellationToken ct = default)
    {
        var node = await Client.GetAsync($"{Resource}?$filter=displayName eq '{Uri.EscapeDataString(displayName)}'", false, ct);
        return (node?["value"] as JsonArray)?.FirstOrDefault();
    }
}

public sealed class EntraIdGroupService : GraphServiceBase
{
    public EntraIdGroupService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "groups";
    protected override bool UseBeta => false;

    public async Task<JsonNode?> CreateAsync(string displayName, string? description, string? membershipRule, bool isAssignableToRole, CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["displayName"] = displayName,
            ["description"] = description,
            ["mailEnabled"] = false,
            ["mailNickname"] = (displayName + "-Group").Replace(" ", "-"),
            ["securityEnabled"] = true,
            ["isAssignableToRole"] = isAssignableToRole
        };
        if (!string.IsNullOrEmpty(membershipRule) && !string.Equals(membershipRule, "Static", StringComparison.OrdinalIgnoreCase))
        {
            body["groupTypes"] = new JsonArray("DynamicMembership");
            body["membershipRule"] = membershipRule;
            body["membershipRuleProcessingState"] = "On";
        }
        return await Client.PostAsync(Resource, body, false, ct);
    }

    public override async Task<JsonNode?> GetByDisplayNameAsync(string displayName, CancellationToken ct = default)
    {
        var node = await Client.GetAsync($"{Resource}?$filter=displayName eq '{Uri.EscapeDataString(displayName)}'", false, ct);
        return (node?["value"] as JsonArray)?.FirstOrDefault();
    }

    public Task<JsonNode?> ListMembersAsync(string groupId, CancellationToken ct = default)
        => Client.GetAsync($"{Resource}/{groupId}/members", false, ct);

    public Task AddMemberAsync(string groupId, string memberId, CancellationToken ct = default)
        => Client.PostAsync($"{Resource}/{groupId}/members/$ref",
            new JsonObject { ["@odata.id"] = $"https://graph.microsoft.com/v1.0/directoryObjects/{memberId}" },
            false, ct);

    public Task RemoveMemberAsync(string groupId, string memberId, CancellationToken ct = default)
        => Client.DeleteAsync($"{Resource}/{groupId}/members/{memberId}/$ref", false, ct);
}

public sealed class ConditionalAccessPolicyService : GraphServiceBase
{
    public ConditionalAccessPolicyService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "identity/conditionalAccess/policies";
    protected override bool UseBeta => false;
}

public sealed class NamedLocationService : GraphServiceBase
{
    public NamedLocationService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "identity/conditionalAccess/namedLocations";
    protected override bool UseBeta => false;
}

public sealed class AppRegistrationService : GraphServiceBase
{
    public AppRegistrationService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "applications";
    protected override bool UseBeta => false;

    public Task<JsonNode?> CreateAsync(string displayName, CancellationToken ct = default)
        => Client.PostAsync(Resource, new JsonObject { ["displayName"] = displayName }, false, ct);

    public Task<JsonNode?> AddPasswordAsync(string appObjectId, string keyName, CancellationToken ct = default)
        => Client.PostAsync($"{Resource}/{appObjectId}/addPassword",
            new JsonObject { ["passwordCredential"] = new JsonObject { ["displayName"] = keyName } }, false, ct);
}

public sealed class PimAssignmentService : GraphServiceBase
{
    public PimAssignmentService(GraphHttpClient c) : base(c) { }
    /// <summary>Active role assignments. For schedule-based, use Schedules instead.</summary>
    protected override string Resource => "roleManagement/directory/roleAssignments";
    protected override bool UseBeta => false;

    public Task<JsonNode?> ListSchedulesAsync(CancellationToken ct = default)
        => Client.GetAsync("roleManagement/directory/roleAssignmentSchedules", false, ct);

    public Task<JsonNode?> CreateScheduleRequestAsync(JsonNode body, CancellationToken ct = default)
        => Client.PostAsync("roleManagement/directory/roleAssignmentScheduleRequests", body, false, ct);

    public Task<JsonNode?> ListEligibleSchedulesAsync(CancellationToken ct = default)
        => Client.GetAsync("roleManagement/directory/roleEligibilitySchedules", false, ct);

    public Task<JsonNode?> CreateEligibilityRequestAsync(JsonNode body, CancellationToken ct = default)
        => Client.PostAsync("roleManagement/directory/roleEligibilityScheduleRequests", body, false, ct);
}

public sealed class EntraIdDeviceService : GraphServiceBase
{
    public EntraIdDeviceService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "devices";
    protected override bool UseBeta => false;

    public Task<JsonNode?> SetExtensionAttributeAsync(string deviceId, string name, string value, CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["extensionAttributes"] = new JsonObject { [name] = value }
        };
        return Client.PatchAsync($"{Resource}/{deviceId}", body, false, ct);
    }
}
