using System.IO;

namespace SecKey.App.Services;

public sealed class BaselineContentBootstrapService
{
    private static readonly string[] ContentFolders = ["JSON", "IntuneApps", "RemediationScripts"];

    private readonly string _cacheRoot;

    public BaselineContentBootstrapService()
    {
        _cacheRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SecKey",
            "BaselineContent");
    }

    public void EnsureBaselineContent()
    {
        Directory.CreateDirectory(_cacheRoot);

        var appBase = AppContext.BaseDirectory;
        foreach (var folder in ContentFolders)
        {
            var appFolder = Path.Combine(appBase, folder);
            var cacheFolder = Path.Combine(_cacheRoot, folder);

            var appExists = Directory.Exists(appFolder);
            var cacheExists = Directory.Exists(cacheFolder);

            if (appExists && !cacheExists)
            {
                CopyDirectory(appFolder, cacheFolder);
            }
            else if (!appExists && cacheExists)
            {
                CopyDirectory(cacheFolder, appFolder);
            }
        }
    }

    private static void CopyDirectory(string sourceDirectory, string destinationDirectory)
    {
        if (!Directory.Exists(sourceDirectory))
            return;

        Directory.CreateDirectory(destinationDirectory);

        foreach (var sourceFile in Directory.EnumerateFiles(sourceDirectory, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(sourceDirectory, sourceFile);
            var destinationFile = Path.Combine(destinationDirectory, relativePath);
            var destinationPath = Path.GetDirectoryName(destinationFile);
            if (!string.IsNullOrWhiteSpace(destinationPath))
                Directory.CreateDirectory(destinationPath);

            File.Copy(sourceFile, destinationFile, overwrite: true);
        }
    }
}