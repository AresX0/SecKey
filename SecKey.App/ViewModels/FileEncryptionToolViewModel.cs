using System;
using System.IO;
using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;

namespace SecKey.App.ViewModels;

public sealed partial class FileEncryptionToolViewModel : ObservableObject
{
    [ObservableProperty] private string inputFile = string.Empty;
    [ObservableProperty] private string password = string.Empty;
    [ObservableProperty] private string statusMessage = "Ready";

    [RelayCommand]
    private void BrowseInputFile()
    {
        var dlg = new OpenFileDialog { Title = "Select file to encrypt/decrypt", Filter = "All files (*.*)|*.*" };
        if (dlg.ShowDialog() == true) InputFile = dlg.FileName;
    }

    [RelayCommand]
    private void EncryptFile()
    {
        if (!Validate()) return;
        try
        {
            var output = InputFile + ".seckey";
            using var aes = Aes.Create();
            var salt = RandomNumberGenerator.GetBytes(16);
            var key = Rfc2898DeriveBytes.Pbkdf2(Password, salt, 100_000, HashAlgorithmName.SHA256, 32);
            aes.Key = key;
            aes.IV = RandomNumberGenerator.GetBytes(16);

            using var fsOut = new FileStream(output, FileMode.Create, FileAccess.Write);
            fsOut.Write(salt, 0, salt.Length);
            fsOut.Write(aes.IV, 0, aes.IV.Length);
            using var crypto = new CryptoStream(fsOut, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using var fsIn = new FileStream(InputFile, FileMode.Open, FileAccess.Read);
            fsIn.CopyTo(crypto);
            StatusMessage = $"Encrypted to {output}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Encrypt failed: {ex.Message}";
        }
    }

    [RelayCommand]
    private void DecryptFile()
    {
        if (!Validate()) return;
        try
        {
            var output = InputFile.EndsWith(".seckey", StringComparison.OrdinalIgnoreCase)
                ? InputFile[..^7]
                : InputFile + ".decrypted";

            using var fsIn = new FileStream(InputFile, FileMode.Open, FileAccess.Read);
            var salt = new byte[16];
            var iv = new byte[16];
            fsIn.ReadExactly(salt);
            fsIn.ReadExactly(iv);

            using var aes = Aes.Create();
            var key = Rfc2898DeriveBytes.Pbkdf2(Password, salt, 100_000, HashAlgorithmName.SHA256, 32);
            aes.Key = key;
            aes.IV = iv;

            using var crypto = new CryptoStream(fsIn, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using var fsOut = new FileStream(output, FileMode.Create, FileAccess.Write);
            crypto.CopyTo(fsOut);
            StatusMessage = $"Decrypted to {output}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Decrypt failed: {ex.Message}";
        }
    }

    private bool Validate()
    {
        if (string.IsNullOrWhiteSpace(InputFile) || !File.Exists(InputFile))
        {
            StatusMessage = "Select a valid file.";
            return false;
        }
        if (string.IsNullOrWhiteSpace(Password))
        {
            StatusMessage = "Password is required.";
            return false;
        }
        return true;
    }
}
