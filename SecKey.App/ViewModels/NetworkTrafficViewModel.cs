using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace SecKey.App.ViewModels
{
    public class TrafficConnectionInfo
    {
        public string Protocol { get; set; } = "";
        public string LocalAddress { get; set; } = "";
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = "";
        public int RemotePort { get; set; }
        public string State { get; set; } = "";
        public int ProcessId { get; set; }
        public string ProcessName { get; set; } = "";
        public string DisplayLocal => $"{LocalAddress}:{LocalPort}";
        public string DisplayRemote => RemotePort > 0 ? $"{RemoteAddress}:{RemotePort}" : "*";
    }

    public class NetworkInterfaceInfo : BindableBase
    {
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public string Speed { get; set; } = "";
        public string Status { get; set; } = "";

        private string _bytesSent = "0";
        public string BytesSent { get => _bytesSent; set => SetProperty(ref _bytesSent, value); }

        private string _bytesReceived = "0";
        public string BytesReceived { get => _bytesReceived; set => SetProperty(ref _bytesReceived, value); }

        private string _sendRate = "0 B/s";
        public string SendRate { get => _sendRate; set => SetProperty(ref _sendRate, value); }

        private string _receiveRate = "0 B/s";
        public string ReceiveRate { get => _receiveRate; set => SetProperty(ref _receiveRate, value); }

        // For rate calculation
        public long PrevSent { get; set; }
        public long PrevReceived { get; set; }
        public string InterfaceId { get; set; } = "";
    }

    public class NetworkTrafficViewModel : BindableBase, IDisposable
    {
        private CancellationTokenSource? _cts;
        private bool _disposed;

        public NetworkTrafficViewModel()
        {
            StartMonitoringCommand = new RelayCommand(_ => StartMonitoring(), _ => !IsMonitoring);
            StopMonitoringCommand = new RelayCommand(_ => StopMonitoring(), _ => IsMonitoring);
            RefreshConnectionsCommand = new RelayCommand(async _ => await RefreshConnectionsAsync());
            CopyConnectionCommand = new RelayCommand(param =>
            {
                if (param is TrafficConnectionInfo conn)
                    Clipboard.SetText($"{conn.Protocol} {conn.DisplayLocal} → {conn.DisplayRemote} ({conn.State}) PID:{conn.ProcessId} {conn.ProcessName}");
            });

            LoadInterfaces();
        }

        public ObservableCollection<NetworkInterfaceInfo> Interfaces { get; } = new();
        public ObservableCollection<TrafficConnectionInfo> Connections { get; } = new();

        private bool _isMonitoring;
        public bool IsMonitoring { get => _isMonitoring; set => SetProperty(ref _isMonitoring, value); }

        private string _statusMessage = "Ready — Start monitoring to track bandwidth.";
        public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }

        private int _refreshInterval = 2;
        public int RefreshInterval { get => _refreshInterval; set => SetProperty(ref _refreshInterval, Math.Max(1, value)); }

        private int _connectionCount;
        public int ConnectionCount { get => _connectionCount; set => SetProperty(ref _connectionCount, value); }

        public ICommand StartMonitoringCommand { get; }
        public ICommand StopMonitoringCommand { get; }
        public ICommand RefreshConnectionsCommand { get; }
        public ICommand CopyConnectionCommand { get; }

        private void LoadInterfaces()
        {
            Interfaces.Clear();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                            n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
            {
                var stats = ni.GetIPv4Statistics();
                Interfaces.Add(new NetworkInterfaceInfo
                {
                    Name = ni.Name,
                    InterfaceId = ni.Id,
                    Type = ni.NetworkInterfaceType.ToString(),
                    Speed = FormatSpeed(ni.Speed),
                    Status = ni.OperationalStatus.ToString(),
                    BytesSent = FormatBytes(stats.BytesSent),
                    BytesReceived = FormatBytes(stats.BytesReceived),
                    PrevSent = stats.BytesSent,
                    PrevReceived = stats.BytesReceived
                });
            }
        }

        private void StartMonitoring()
        {
            _cts = new CancellationTokenSource();
            IsMonitoring = true;
            StatusMessage = "Monitoring...";
            _ = MonitorLoopAsync(_cts.Token);
        }

        private void StopMonitoring()
        {
            _cts?.Cancel();
            IsMonitoring = false;
            StatusMessage = "Monitoring stopped.";
        }

        private async Task MonitorLoopAsync(CancellationToken ct)
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(RefreshInterval * 1000, ct);
                    UpdateInterfaceStats();
                    await RefreshConnectionsAsync();
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                StatusMessage = $"Monitor error: {ex.Message}";
                IsMonitoring = false;
            }
        }

        private void UpdateInterfaceStats()
        {
            Application.Current.Dispatcher.Invoke(() =>
            {
                foreach (var iface in Interfaces)
                {
                    try
                    {
                        var ni = NetworkInterface.GetAllNetworkInterfaces()
                            .FirstOrDefault(n => n.Id == iface.InterfaceId);
                        if (ni == null) continue;

                        var stats = ni.GetIPv4Statistics();
                        var sentDelta = stats.BytesSent - iface.PrevSent;
                        var recvDelta = stats.BytesReceived - iface.PrevReceived;

                        iface.SendRate = FormatRate(sentDelta, RefreshInterval);
                        iface.ReceiveRate = FormatRate(recvDelta, RefreshInterval);
                        iface.BytesSent = FormatBytes(stats.BytesSent);
                        iface.BytesReceived = FormatBytes(stats.BytesReceived);

                        iface.PrevSent = stats.BytesSent;
                        iface.PrevReceived = stats.BytesReceived;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Interface stat update error: {ex.Message}");
                    }
                }
            });
        }

        private async Task RefreshConnectionsAsync()
        {
            try
            {
                var connections = await Task.Run(() =>
                {
                    var list = new System.Collections.Generic.List<TrafficConnectionInfo>();

                    var ipProps = IPGlobalProperties.GetIPGlobalProperties();

                    foreach (var tcp in ipProps.GetActiveTcpConnections())
                    {
                        string procName = "";
                        try
                        {
                            // GetActiveTcpConnections doesn't expose PID, use 0
                        }
                        catch { }

                        list.Add(new TrafficConnectionInfo
                        {
                            Protocol = "TCP",
                            LocalAddress = tcp.LocalEndPoint.Address.ToString(),
                            LocalPort = tcp.LocalEndPoint.Port,
                            RemoteAddress = tcp.RemoteEndPoint.Address.ToString(),
                            RemotePort = tcp.RemoteEndPoint.Port,
                            State = tcp.State.ToString(),
                            ProcessId = 0,
                            ProcessName = procName
                        });
                    }

                    foreach (var listener in ipProps.GetActiveTcpListeners())
                    {
                        list.Add(new TrafficConnectionInfo
                        {
                            Protocol = "TCP",
                            LocalAddress = listener.Address.ToString(),
                            LocalPort = listener.Port,
                            RemoteAddress = "*",
                            RemotePort = 0,
                            State = "LISTENING"
                        });
                    }

                    foreach (var udp in ipProps.GetActiveUdpListeners())
                    {
                        list.Add(new TrafficConnectionInfo
                        {
                            Protocol = "UDP",
                            LocalAddress = udp.Address.ToString(),
                            LocalPort = udp.Port,
                            RemoteAddress = "*",
                            RemotePort = 0,
                            State = "—"
                        });
                    }

                    return list.OrderBy(c => c.Protocol).ThenBy(c => c.LocalPort).ToList();
                });

                Application.Current.Dispatcher.Invoke(() =>
                {
                    Connections.Clear();
                    foreach (var c in connections)
                        Connections.Add(c);
                    ConnectionCount = connections.Count;
                });
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"RefreshConnections error: {ex.Message}");
            }
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024.0 / 1024.0:F1} MB";
            return $"{bytes / 1024.0 / 1024.0 / 1024.0:F2} GB";
        }

        private static string FormatRate(long bytes, int intervalSec)
        {
            var perSec = bytes / Math.Max(1, intervalSec);
            if (perSec < 1024) return $"{perSec} B/s";
            if (perSec < 1024 * 1024) return $"{perSec / 1024.0:F1} KB/s";
            return $"{perSec / 1024.0 / 1024.0:F1} MB/s";
        }

        private static string FormatSpeed(long bitsPerSec)
        {
            if (bitsPerSec < 1_000_000) return $"{bitsPerSec / 1000.0:F0} Kbps";
            if (bitsPerSec < 1_000_000_000) return $"{bitsPerSec / 1_000_000.0:F0} Mbps";
            return $"{bitsPerSec / 1_000_000_000.0:F1} Gbps";
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                _cts?.Cancel();
                _cts?.Dispose();
            }
        }
    }
}
