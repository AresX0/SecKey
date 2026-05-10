using System.Windows.Controls;
using SecKey.App.ViewModels;

namespace SecKey.App.Views;

public partial class SecurityVaultView : UserControl
{
    public SecurityVaultView()
    {
        InitializeComponent();
    }

    private void MasterPasswordBox_PasswordChanged(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is SecurityVaultViewModel vm && sender is PasswordBox box)
        {
            vm.MasterPasswordInput = box.Password;
        }
    }
}
