using System;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace SecKey.App.ViewModels;

public sealed partial class EncryptedClipboardViewModel : ObservableObject
{
    [ObservableProperty] private string plainText = string.Empty;
    [ObservableProperty] private string encryptedText = string.Empty;
    [ObservableProperty] private string statusMessage = "Ready";

    [RelayCommand]
    private void EncryptToClipboard()
    {
        try
        {
            var bytes = Encoding.UTF8.GetBytes(PlainText ?? string.Empty);
            var protectedBytes = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
            EncryptedText = Convert.ToBase64String(protectedBytes);
            Clipboard.SetText(EncryptedText);
            StatusMessage = "Encrypted text copied to clipboard.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Encrypt failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private void DecryptEncryptedText()
    {
        try
        {
            var input = string.IsNullOrWhiteSpace(EncryptedText) ? Clipboard.GetText() : EncryptedText;
            var bytes = Convert.FromBase64String(input);
            var plain = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
            PlainText = Encoding.UTF8.GetString(plain);
            StatusMessage = "Decrypted successfully.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Decrypt failed: {ex.Message}";
        }
    }
}
