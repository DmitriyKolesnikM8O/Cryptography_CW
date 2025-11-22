using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;


using CryptoApp.ViewModels; 
using CryptoApp.Views;


namespace CryptoApp
{
    public partial class App : Application
    {
        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                desktop.MainWindow = new MainWindow
                {
                    // Теперь компилятор знает, где найти MainViewModel
                    DataContext = new MainViewModel(), 
                };
            }

            base.OnFrameworkInitializationCompleted();
        }
    }
}