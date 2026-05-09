using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecKey.Core;
using SecKey.Core.Utilities;

namespace SecKey.Graph.Services.EntraID;

public sealed class EntraIdUserService : GraphServiceBase
{
    public EntraIdUserService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "users";
    protected override bool UseBeta => false;

    public async Task<string> GetDefaultDomainAsync(CancellationToken ct = default)
    {
        var node = await Client.GetAsync("domains?$select=id,isDefault,isInitial", false, ct);
        var domains = node?["value"] as JsonArray;
        if (domains is null || domains.Count == 0)
            throw new InvalidOperationException("No domains were returned by Graph.");

        var defaultDomain = domains
            .OfType<JsonObject>()
            .FirstOrDefault(d => d["isDefault"]?.GetValue<bool>() == true)?["id"]?.GetValue<string>();
        if (!string.IsNullOrWhiteSpace(defaultDomain))
            return defaultDomain;

        var initialDomain = domains
            .OfType<JsonObject>()
            .FirstOrDefault(d => d["isInitial"]?.GetValue<bool>() == true)?["id"]?.GetValue<string>();
        if (!string.IsNullOrWhiteSpace(initialDomain))
            return initialDomain;

        return domains.OfType<JsonObject>().FirstOrDefault()?["id"]?.GetValue<string>()
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
        var mailNickname = BuildMailNickname(displayName);
        var body = new JsonObject
        {
            ["displayName"] = displayName,
            ["description"] = description,
            ["mailEnabled"] = false,
            ["mailNickname"] = mailNickname,
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

    private static string BuildMailNickname(string displayName)
    {
        // Graph rejects many special characters in mailNickname and enforces length constraints.
        var candidate = Regex.Replace(displayName.ToLowerInvariant(), "[^a-z0-9._-]+", "-");
        candidate = Regex.Replace(candidate, "-{2,}", "-").Trim('-', '.');

        if (string.IsNullOrWhiteSpace(candidate))
            candidate = "seckey-group";

        if (!candidate.EndsWith("-group", StringComparison.OrdinalIgnoreCase))
            candidate += "-group";

        return candidate.Length <= 64 ? candidate : candidate[..64].TrimEnd('-', '.');
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

public sealed class AuthenticationContextService : GraphServiceBase
{
    public AuthenticationContextService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "identity/conditionalAccess/authenticationContextClassReferences";
    protected override bool UseBeta => false;

    // The Graph API for authenticationContextClassReferences does not support POST.
    // Creation is done via PATCH to a caller-assigned ID (c1-c25).
    public override async Task<JsonNode?> CreateAsync(JsonNode body, CancellationToken ct = default)
    {
        var nextId = await GetNextAvailableIdAsync(ct);
        return await UpdateAsync(nextId, body, ct);
    }

    private async Task<string> GetNextAvailableIdAsync(CancellationToken ct)
    {
        var existing = await ListAsync(ct);
        var usedIds = existing
            .OfType<System.Text.Json.Nodes.JsonObject>()
            .Select(n => n["id"]?.GetValue<string>() ?? string.Empty)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i <= 25; i++)
        {
            var candidate = $"c{i}";
            if (!usedIds.Contains(candidate))
                return candidate;
        }
        throw new InvalidOperationException("No available authentication context IDs (c1-c25).");
    }
}

public sealed class AuthenticationStrengthService : GraphServiceBase
{
    public AuthenticationStrengthService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "policies/authenticationStrengthPolicies";
    protected override bool UseBeta => false;

    public override async Task<JsonNode?> UpdateAsync(string id, JsonNode body, CancellationToken ct = default)
    {
        // Graph requires using the updateAllowedCombinations action to update the combinations property
        var actionPath = $"{Resource}/{id}/updateAllowedCombinations";
        return await Client.PostAsync(actionPath, body, false, ct);
    }

    public override async Task DeleteAsync(string id, CancellationToken ct = default)
    {
        try
        {
            await Client.DeleteAsync($"{Resource}/{id}", false, ct);
        }
        catch (SecKeyException ex) when (ex.StatusCode == 400 && ex.Message.Contains("referenced by one or more Conditional Access policies"))
        {
            // Authentication strength policies in use by CA policies cannot be deleted directly.
            // This is expected and non-fatal; skip the deletion silently.
        }
    }
}

public sealed class AdministrativeUnitService : GraphServiceBase
{
    public AdministrativeUnitService(GraphHttpClient c) : base(c) { }
    protected override string Resource => "administrativeUnits";
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

    private static string EscapeODataString(string value) => value.Replace("'", "''");

    private static string AttributeName(int number)
    {
        if (number < 1 || number > 15)
            throw new ArgumentOutOfRangeException(nameof(number), "Extension attribute number must be between 1 and 15.");
        return $"extensionAttribute{number}";
    }

    public async Task<JsonArray> ListWindowsAsync(CancellationToken ct = default)
    {
        var arr = new JsonArray();
        var query = $"{Resource}?$filter=operatingSystem eq 'Windows'&$select=id,displayName,operatingSystem";
        await foreach (var n in Client.PagedAsync(query, false, ct))
            arr.Add(n.DeepClone());
        return arr;
    }

    public async Task<JsonNode?> GetWindowsByDisplayNameAsync(string displayName, CancellationToken ct = default)
    {
        var safeName = EscapeODataString(displayName);
        var query =
            $"{Resource}?$filter=displayName eq '{safeName}' and operatingSystem eq 'Windows'&$select=id,displayName,operatingSystem";
        var node = await Client.GetAsync(query, false, ct);
        return (node?["value"] as JsonArray)?.FirstOrDefault();
    }

    public Task<JsonNode?> SetExtensionAttributeAsync(string deviceId, int number, string value, CancellationToken ct = default)
        => SetExtensionAttributeAsync(deviceId, AttributeName(number), value, ct);

    public Task<JsonNode?> SetExtensionAttributeAsync(string deviceId, string name, string value, CancellationToken ct = default)
    {
        var body = new JsonObject
        {
            ["extensionAttributes"] = new JsonObject { [name] = value }
        };
        return Client.PatchAsync($"{Resource}/{deviceId}", body, false, ct);
    }
}
