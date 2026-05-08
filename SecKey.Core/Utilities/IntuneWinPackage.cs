using System.IO.Compression;
using System.Xml.Linq;

namespace SecKey.Core.Utilities;

/// <summary>
/// Reads detection.xml and inner package files from an .intunewin archive
/// (ports private/Intune/Get-IntuneWinXML.ps1 and Get-IntuneWinFile.ps1).
/// </summary>
public sealed class IntuneWinPackage : IDisposable
{
    private readonly ZipArchive _archive;
    public string SourcePath { get; }
    public XDocument DetectionXml { get; }

    public IntuneWinPackage(string sourcePath)
    {
        if (!File.Exists(sourcePath))
            throw new FileNotFoundException("intunewin file not found", sourcePath);

        SourcePath = sourcePath;
        _archive = ZipFile.OpenRead(sourcePath);

        var det = _archive.Entries.FirstOrDefault(e => e.FullName.EndsWith("/Metadata/Detection.xml", StringComparison.OrdinalIgnoreCase)
                                                    || e.FullName.EndsWith("\\Metadata\\Detection.xml", StringComparison.OrdinalIgnoreCase)
                                                    || e.FullName.EndsWith("Detection.xml", StringComparison.OrdinalIgnoreCase))
                  ?? throw new InvalidOperationException("Detection.xml not found inside intunewin file");

        using var s = det.Open();
        DetectionXml = XDocument.Load(s);
    }

    public string GetApplicationInfo(string element)
        => DetectionXml.Descendants("ApplicationInfo").Elements(element).FirstOrDefault()?.Value
           ?? throw new InvalidOperationException($"ApplicationInfo/{element} missing");

    public string FileName => GetApplicationInfo("FileName");
    public string SetupFile => GetApplicationInfo("SetupFile");
    public long UnencryptedContentSize => long.Parse(GetApplicationInfo("UnencryptedContentSize"));

    public XElement EncryptionInfo
        => DetectionXml.Descendants("EncryptionInfo").FirstOrDefault()
           ?? throw new InvalidOperationException("EncryptionInfo missing in Detection.xml");

    public XElement? MsiInfo => DetectionXml.Descendants("MsiInfo").FirstOrDefault();

    /// <summary>Extracts the inner encrypted payload to a temp file and returns the path.</summary>
    public string ExtractInnerFile(string innerFileName)
    {
        var entry = _archive.Entries.FirstOrDefault(e =>
            e.FullName.EndsWith("/Contents/" + innerFileName, StringComparison.OrdinalIgnoreCase) ||
            e.FullName.EndsWith("\\Contents\\" + innerFileName, StringComparison.OrdinalIgnoreCase) ||
            e.Name.Equals(innerFileName, StringComparison.OrdinalIgnoreCase))
            ?? throw new FileNotFoundException($"{innerFileName} not found inside intunewin");

        var temp = Path.Combine(Path.GetTempPath(), $"seckey-{Guid.NewGuid():N}-{innerFileName}");
        using (var src = entry.Open())
        using (var dst = File.Create(temp))
            src.CopyTo(dst);
        return temp;
    }

    public void Dispose() => _archive.Dispose();
}
