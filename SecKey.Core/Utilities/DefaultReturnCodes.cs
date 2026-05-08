namespace SecKey.Core.Utilities;

/// <summary>Standard Win32 LOB return codes (mirrors private/Get-DefaultReturnCodes.ps1).</summary>
public static class DefaultReturnCodes
{
    public static IReadOnlyList<object> Get() => new object[]
    {
        new { returnCode = 0,    type = "success" },
        new { returnCode = 1707, type = "success" },
        new { returnCode = 3010, type = "softReboot" },
        new { returnCode = 1641, type = "hardReboot" },
        new { returnCode = 1618, type = "retry" }
    };
}
