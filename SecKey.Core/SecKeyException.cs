namespace SecKey.Core;

/// <summary>Exception type representing a Graph or service failure (analog of New-Exception.ps1).</summary>
public sealed class SecKeyException : Exception
{
    public string? RequestUri { get; }
    public string? ResponseBody { get; }
    public int? StatusCode { get; }

    public SecKeyException(string message, Exception? inner = null,
        string? requestUri = null, string? responseBody = null, int? statusCode = null)
        : base(message, inner)
    {
        RequestUri = requestUri;
        ResponseBody = responseBody;
        StatusCode = statusCode;
    }
}
