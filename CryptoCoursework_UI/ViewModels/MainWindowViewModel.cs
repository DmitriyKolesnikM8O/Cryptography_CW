using CryptoCoursework_UI.ViewModels.Tabs;

namespace CryptoCoursework_UI.ViewModels;

public partial class MainWindowViewModel : ViewModelBase
{
    public DesViewModel DesTabViewModel { get; } = new DesViewModel();

    public RsaViewModel RsaTabViewModel { get; } = new RsaViewModel();
    public RijndaelViewModel RijndaelTabViewModel { get; } = new RijndaelViewModel();



    public DiffieHellmanViewModel DhTabViewModel { get; } = new DiffieHellmanViewModel();
}
