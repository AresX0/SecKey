using System.Windows;
using SecKey.App.ViewModels;

namespace SecKey.App.Views
{
    public partial class PreferencesWindow : Window
    {
        public PreferencesWindow(PreferencesViewModel viewModel)
        {
            InitializeComponent();
            DataContext = viewModel;
        }
    }
}
