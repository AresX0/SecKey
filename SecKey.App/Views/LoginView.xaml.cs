using System.Windows.Controls;
using SecKey.App.ViewModels;

namespace SecKey.App.Views;

public partial class LoginView : UserControl
{
    public LoginView() => InitializeComponent();

    private void SecretBox_PasswordChanged(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is LoginViewModel vm && sender is PasswordBox pb)
            vm.ClientSecret = pb.Password;
    }
}
