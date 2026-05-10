using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Windows;

namespace SecKey.App.Views;

public partial class SplashScreenWindow : Window
{
    private static readonly Uri GitHubIntroVideoUri = new("https://raw.githubusercontent.com/AresX0/PlatypusToolsNew/main/PlatypusTools.UI/Assets/platypus_swimming.mp4", UriKind.Absolute);
    private readonly List<Uri> _videoCandidates = new();
    private int _videoCandidateIndex = -1;

    public SplashScreenWindow()
    {
        InitializeComponent();
        VersionText.Text = $"Version {GetVersionText()}";
        Loaded += (_, _) => TryStartVideo();
    }

    public void UpdateStatus(string message)
    {
        if (Dispatcher.CheckAccess())
        {
            StatusText.Text = message;
            return;
        }

        _ = Dispatcher.InvokeAsync(() => StatusText.Text = message);
    }

    private void TryStartVideo()
    {
        try
        {
            _videoCandidates.Clear();
            _videoCandidateIndex = -1;

            var localCandidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "Assets", "PlatypusToolsIntro.mp4"),
                Path.Combine(AppContext.BaseDirectory, "Assets", "platypus_swimming.mp4"),
                Path.Combine(AppContext.BaseDirectory, "platypus_swimming.mp4")
            };

            foreach (var candidate in localCandidates)
            {
                if (File.Exists(candidate))
                    _videoCandidates.Add(new Uri(candidate, UriKind.Absolute));
            }

            _videoCandidates.Add(GitHubIntroVideoUri);
            PlayNextVideoCandidate();
        }
        catch
        {
            // Keep the fallback logo visible if the video cannot load.
        }
    }

    private void PlayNextVideoCandidate()
    {
        if (_videoCandidates.Count == 0)
            return;

        _videoCandidateIndex++;
        if (_videoCandidateIndex >= _videoCandidates.Count)
            return;

        try
        {
            CornerVideo.Source = _videoCandidates[_videoCandidateIndex];
            CornerVideo.Play();
        }
        catch
        {
            PlayNextVideoCandidate();
        }
    }

    private void CornerVideo_MediaOpened(object sender, RoutedEventArgs e)
    {
        try
        {
            CornerVideo.Play();
        }
        catch
        {
            // Ignore playback failures; the fallback logo remains visible.
        }
    }

    private void CornerVideo_MediaEnded(object sender, RoutedEventArgs e)
    {
        try
        {
            CornerVideo.Position = TimeSpan.Zero;
            CornerVideo.Play();
        }
        catch
        {
        }
    }

    private void CornerVideo_MediaFailed(object sender, ExceptionRoutedEventArgs e)
    {
        PlayNextVideoCandidate();
    }

    private static string GetVersionText()
    {
        var executablePath = Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath))
            return "unknown";

        var fileVersion = FileVersionInfo.GetVersionInfo(executablePath).FileVersion;
        return string.IsNullOrWhiteSpace(fileVersion) ? "unknown" : fileVersion;
    }
}