using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using SecKey.Core.Services;

namespace SecKey.App.ViewModels
{
    public class CertificateManagerViewModel : BindableBase
    {
        private readonly CertificateManagerService _service = new();
        private System.Collections.Generic.List<CertificateInfo> _allCertificates = new();

        public CertificateManagerViewModel()
        {
            Certificates = new ObservableCollection<CertificateInfo>();
            StoreLocations = new ObservableCollection<string> { "All Stores", "CurrentUser - My", "LocalMachine - My", "CurrentUser - Root", "LocalMachine - Root", "CurrentUser - CA", "LocalMachine - CA" };
            SelectedStoreLocation = "All Stores";

            RefreshCommand = new RelayCommand(async _ => await LoadCertificatesAsync());
            ExportCommand = new RelayCommand(_ => ExportCertificate(), _ => SelectedCertificate != null);
            CopyThumbprintCommand = new RelayCommand(_ => CopyThumbprint(), _ => SelectedCertificate != null);
            CopyDetailsCommand = new RelayCommand(_ => CopyDetails(), _ => SelectedCertificate != null);

            _ = LoadCertificatesAsync();
        }

        public ObservableCollection<CertificateInfo> Certificates { get; }
        public ObservableCollection<string> StoreLocations { get; }

        private CertificateInfo? _selectedCertificate;
        public CertificateInfo? SelectedCertificate
        {
            get => _selectedCertificate;
            set
            {
                if (SetProperty(ref _selectedCertificate, value))
                    RaisePropertyChanged(nameof(CertDetails));
            }
        }

        private string _selectedStoreLocation = "All Stores";
        public string SelectedStoreLocation
        {
            get => _selectedStoreLocation;
            set
            {
                if (SetProperty(ref _selectedStoreLocation, value))
                    ApplyFilter();
            }
        }

        private string _searchQuery = "";
        public string SearchQuery
        {
            get => _searchQuery;
            set
            {
                if (SetProperty(ref _searchQuery, value))
                    ApplyFilter();
            }
        }

        private bool _showExpiredOnly;
        public bool ShowExpiredOnly
        {
            get => _showExpiredOnly;
            set
            {
                if (SetProperty(ref _showExpiredOnly, value))
                    ApplyFilter();
            }
        }

        private bool _showExpiringOnly;
        public bool ShowExpiringOnly
        {
            get => _showExpiringOnly;
            set
            {
                if (SetProperty(ref _showExpiringOnly, value))
                    ApplyFilter();
            }
        }

        private string _statusMessage = "";
        public string StatusMessage { get => _statusMessage; set => SetProperty(ref _statusMessage, value); }

        private bool _isLoading;
        public bool IsLoading { get => _isLoading; set => SetProperty(ref _isLoading, value); }

        public string CertDetails => SelectedCertificate != null ? _service.GetCertificateDetails(SelectedCertificate) : "";

        public ICommand RefreshCommand { get; }
        public ICommand ExportCommand { get; }
        public ICommand CopyThumbprintCommand { get; }
        public ICommand CopyDetailsCommand { get; }

        private async Task LoadCertificatesAsync()
        {
            try
            {
                IsLoading = true;
                StatusMessage = "Loading certificates...";

                _allCertificates = await _service.GetAllCertificatesAsync();
                ApplyFilter();

                StatusMessage = $"Loaded {_allCertificates.Count} certificates.";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }

        private void ApplyFilter()
        {
            var filtered = _allCertificates.AsEnumerable();

            // Store location filter
            if (SelectedStoreLocation != "All Stores")
            {
                var parts = SelectedStoreLocation.Split(" - ");
                if (parts.Length == 2)
                {
                    filtered = filtered.Where(c =>
                        c.StoreLocation == parts[0] && c.StoreName == parts[1]);
                }
            }

            // Search filter
            if (!string.IsNullOrWhiteSpace(SearchQuery))
                filtered = _service.Search(filtered.ToList(), SearchQuery);

            // Status filters
            if (ShowExpiredOnly)
                filtered = filtered.Where(c => c.IsExpired);
            if (ShowExpiringOnly)
                filtered = filtered.Where(c => !c.IsExpired && c.DaysUntilExpiry <= 30);

            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                Certificates.Clear();
                foreach (var cert in filtered)
                    Certificates.Add(cert);
            });
        }

        private void ExportCertificate()
        {
            if (SelectedCertificate == null) return;

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Certificate|*.cer|All Files|*.*",
                DefaultExt = ".cer",
                FileName = $"{SelectedCertificate.SubjectShort}.cer"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    Enum.TryParse<StoreName>(SelectedCertificate.StoreName, out var storeName);
                    Enum.TryParse<StoreLocation>(SelectedCertificate.StoreLocation, out var storeLocation);
                    _service.ExportCertificate(SelectedCertificate.Thumbprint, dialog.FileName, storeName, storeLocation);
                    StatusMessage = $"Certificate exported to {dialog.FileName}";
                }
                catch (Exception ex)
                {
                    StatusMessage = $"Error exporting: {ex.Message}";
                }
            }
        }

        private void CopyThumbprint()
        {
            if (SelectedCertificate == null) return;
            try
            {
                System.Windows.Clipboard.SetText(SelectedCertificate.Thumbprint);
                StatusMessage = "Thumbprint copied to clipboard.";
            }
            catch { }
        }

        private void CopyDetails()
        {
            if (SelectedCertificate == null) return;
            try
            {
                System.Windows.Clipboard.SetText(CertDetails);
                StatusMessage = "Certificate details copied to clipboard.";
            }
            catch { }
        }
    }
}
