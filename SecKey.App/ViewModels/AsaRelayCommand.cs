using System;
using System.Windows.Input;

namespace SecKey.App.ViewModels
{
    /// <summary>
    /// Delegate-based ICommand used by ported AD Security Analyzer view-model.
    /// Lives in SecKey.App.ViewModels so files in this namespace bind to it directly
    /// without needing a using directive (avoiding collision with CommunityToolkit.Mvvm.Input.RelayCommand).
    /// </summary>
    public class AsaRelayCommand : ICommand
    {
        private readonly Action<object?> _execute;
        private readonly Func<object?, bool>? _canExecute;

        public AsaRelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
        {
            _execute = execute ?? throw new ArgumentNullException(nameof(execute));
            _canExecute = canExecute;
        }

        public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

        public void Execute(object? parameter)
        {
            try { _execute(parameter); }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    $"Error executing command: {ex.Message}\n\n{ex}",
                    "Command Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Error);
            }
        }

        public event EventHandler? CanExecuteChanged
        {
            add => CommandManager.RequerySuggested += value;
            remove => CommandManager.RequerySuggested -= value;
        }

        public void RaiseCanExecuteChanged() => CommandManager.InvalidateRequerySuggested();
    }
}
