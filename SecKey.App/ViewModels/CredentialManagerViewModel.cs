using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecKey.App.ViewModels;

public sealed partial class CredentialItem : ObservableObject
{
    [ObservableProperty] private string key = string.Empty;
    [ObservableProperty] private string username = string.Empty;
    [ObservableProperty] private string encryptedPassword = string.Empty;
    [ObservableProperty] private DateTime updatedAt = DateTime.UtcNow;
}

public sealed partial class CredentialManagerViewModel : ObservableObject
{
    private readonly string _storePath;

    [ObservableProperty] private string key = string.Empty;
    [ObservableProperty] private string username = string.Empty;
    [ObservableProperty] private string password = string.Empty;
    [ObservableProperty] private string statusMessage = "Ready";
    [ObservableProperty] private CredentialItem? selectedItem;
    public ObservableCollection<CredentialItem> Credentials { get; } = new();

    public CredentialManagerViewModel()
    {
        var folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecKey", "Credentials");
        Directory.CreateDirectory(folder);
        _storePath = Path.Combine(folder, "credentials.json");
        Load();
    }

    [RelayCommand]
    private void SaveCredential()
    {
        if (string.IsNullOrWhiteSpace(Key) || string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password))
        {
            StatusMessage = "Key, username, and password are required.";
            return;
        }

        var encrypted = Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(Password), null, DataProtectionScope.CurrentUser));
        var existing = Credentials.FirstOrDefault(c => c.Key.Equals(Key, StringComparison.OrdinalIgnoreCase));
        if (existing is null)
        {
            Credentials.Add(new CredentialItem { Key = Key.Trim(), Username = Username.Trim(), EncryptedPassword = encrypted, UpdatedAt = DateTime.UtcNow });
        }
        else
        {
            existing.Username = Username.Trim();
            existing.EncryptedPassword = encrypted;
            existing.UpdatedAt = DateTime.UtcNow;
        }

        Persist();
        Password = string.Empty;
        StatusMessage = "Credential saved.";
    }

    [RelayCommand]
    private void LoadSelected()
    {
        if (SelectedItem is null) return;
        Key = SelectedItem.Key;
        Username = SelectedItem.Username;
        try
        {
            var bytes = Convert.FromBase64String(SelectedItem.EncryptedPassword);
            Password = Encoding.UTF8.GetString(ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser));
            StatusMessage = "Credential decrypted to editor fields.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Decrypt failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private void DeleteSelected()
    {
        if (SelectedItem is null) return;
        Credentials.Remove(SelectedItem);
        Persist();
        StatusMessage = "Credential deleted.";
    }

    [RelayCommand]
    private void ClearEditor()
    {
        Key = string.Empty;
        Username = string.Empty;
        Password = string.Empty;
        StatusMessage = "Editor cleared.";
    }

    private void Load()
    {
        try
        {
            Credentials.Clear();
            if (!File.Exists(_storePath)) return;
            var json = File.ReadAllText(_storePath);
            var items = JsonSerializer.Deserialize<CredentialItem[]>(json) ?? [];
            foreach (var item in items.OrderBy(i => i.Key))
                Credentials.Add(item);
            StatusMessage = $"Loaded {Credentials.Count} credentials.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Load failed: {ex.Message}";
        }
    }

    private void Persist()
    {
        var json = JsonSerializer.Serialize(Credentials.ToArray(), new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_storePath, json);
    }
}
