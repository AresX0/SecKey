using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecKey.Core;
using SecKey.App.Services;
using SecKey.Graph.Services.EntraID;

namespace SecKey.App.ViewModels;

public sealed partial class DeviceTaggingViewModel : GraphPageViewModel
{
    [ObservableProperty] private EntityRow? _selectedDevice;
    [ObservableProperty] private string? _deviceName;
    [ObservableProperty] private int _extensionAttributeNumber = 1;
    [ObservableProperty] private string _attributeValue = "SECKEY";

    public DeviceTaggingViewModel(AuthState auth, IServiceProvider sp) : base(auth, sp)
    {
        InitializeSettingsInventory("Device Tagging");
    }

    protected override async IAsyncEnumerable<EntityRow> LoadAsync()
    {
        var svc = new EntraIdDeviceService(BuildClient());
        var devices = await svc.ListWindowsAsync();
        foreach (var d in devices)
        {
            yield return new EntityRow(
                d?["id"]?.GetValue<string>(),
                d?["displayName"]?.GetValue<string>(),
                d?["operatingSystem"]?.GetValue<string>());
        }
    }

    [RelayCommand]
    private async Task SetAttributeAsync()
    {
        if (ExtensionAttributeNumber < 1 || ExtensionAttributeNumber > 15)
        {
            StatusMessage = "Extension attribute number must be between 1 and 15.";
            return;
        }

        Busy = true;
        try
        {
            var svc = new EntraIdDeviceService(BuildClient());

            var effectiveDeviceName = string.IsNullOrWhiteSpace(DeviceName)
                ? SelectedDevice?.DisplayName
                : DeviceName;

            if (string.IsNullOrWhiteSpace(effectiveDeviceName))
            {
                StatusMessage = "Choose a device from the list or enter a device name.";
                return;
            }

            var device = await svc.GetWindowsByDisplayNameAsync(effectiveDeviceName.Trim());
            if (device is null)
            {
                StatusMessage = $"No Windows device found with displayName '{effectiveDeviceName}'.";
                return;
            }

            var id = device["id"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(id))
            {
                StatusMessage = "Device lookup returned no id.";
                return;
            }

            await svc.SetExtensionAttributeAsync(id, ExtensionAttributeNumber, AttributeValue);
            StatusMessage = $"Updated {effectiveDeviceName}: extensionAttribute{ExtensionAttributeNumber} = {AttributeValue}";
        }
        catch (SecKeyException ex) when (ex.StatusCode == 403)
        {
            StatusMessage = "Access denied (403) updating extension attributes. Ensure delegated/app permissions include Device.ReadWrite.All or Directory.ReadWrite.All and your account has a device-management admin role.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
        }
        finally
        {
            Busy = false;
        }
    }
}
