using System.Security.Cryptography;

namespace SecKey.Core.Utilities;

/// <summary>Generates cryptographically random passwords (mirrors private New-Password.ps1).</summary>
public static class PasswordGenerator
{
    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Digits = "0123456789";
    private const string Symbols = "!@#$%^&*()-_=+[]{};:,.<>?";

    public static string Generate(int length = 32)
    {
        if (length < 4) throw new ArgumentOutOfRangeException(nameof(length));
        var chars = (Lower + Upper + Digits + Symbols).ToCharArray();
        Span<char> buffer = stackalloc char[length];
        // Ensure at least one of each class
        buffer[0] = Lower[RandomNumberGenerator.GetInt32(Lower.Length)];
        buffer[1] = Upper[RandomNumberGenerator.GetInt32(Upper.Length)];
        buffer[2] = Digits[RandomNumberGenerator.GetInt32(Digits.Length)];
        buffer[3] = Symbols[RandomNumberGenerator.GetInt32(Symbols.Length)];
        for (int i = 4; i < length; i++) buffer[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
        // Shuffle
        for (int i = buffer.Length - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (buffer[i], buffer[j]) = (buffer[j], buffer[i]);
        }
        return new string(buffer);
    }
}
