using SecKey.App.Services;
using SecKey.Graph.Services.EntraID;
using SecKey.Graph.Services.Intune;

namespace SecKey.App.ViewModels;

public sealed class DashboardViewModel : GraphPageViewModel
{
    public DashboardViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override async IAsyncEnumerable<EntityRow> LoadAsync()
    {
        var c = BuildClient();
        yield return new(null, "Apps", (await new IntuneApplicationService(c).ListAsync()).Count + " items");
        yield return new(null, "Compliance", (await new DeviceCompliancePolicyService(c).ListAsync()).Count + " items");
        yield return new(null, "Configuration", (await new DeviceConfigurationService(c).ListAsync()).Count + " items");
        yield return new(null, "Settings Catalog", (await new DeviceSettingsCatalogService(c).ListAsync()).Count + " items");
        yield return new(null, "Groups", (await new EntraIdGroupService(c).ListAsync()).Count + " items");
        yield return new(null, "Conditional Access", (await new ConditionalAccessPolicyService(c).ListAsync()).Count + " items");
    }
}

public sealed class IntuneAppsViewModel : GraphPageViewModel
{
    public IntuneAppsViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override IAsyncEnumerable<EntityRow> LoadAsync()
        => GraphPageHelpers.ListAsRowsAsync(new IntuneApplicationService(BuildClient()));
}

public sealed class PoliciesViewModel : GraphPageViewModel
{
    public PoliciesViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override async IAsyncEnumerable<EntityRow> LoadAsync()
    {
        var c = BuildClient();
        await foreach (var r in GraphPageHelpers.ListAsRowsAsync(new DeviceCompliancePolicyService(c)))
            yield return r with { Description = "Compliance" };
        await foreach (var r in GraphPageHelpers.ListAsRowsAsync(new DeviceConfigurationService(c)))
            yield return r with { Description = "Configuration" };
        await foreach (var r in GraphPageHelpers.ListAsRowsAsync(new DeviceSettingsCatalogService(c)))
            yield return r with { Description = "Settings Catalog" };
    }
}

public sealed class GroupsViewModel : GraphPageViewModel
{
    public GroupsViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override IAsyncEnumerable<EntityRow> LoadAsync()
        => GraphPageHelpers.ListAsRowsAsync(new EntraIdGroupService(BuildClient()));
}

public sealed class ConditionalAccessViewModel : GraphPageViewModel
{
    public ConditionalAccessViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp) { }
    protected override IAsyncEnumerable<EntityRow> LoadAsync()
        => GraphPageHelpers.ListAsRowsAsync(new ConditionalAccessPolicyService(BuildClient()));
}
