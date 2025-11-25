using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

// Используем Enums из DES
using CryptoLib.DES.Modes; 
// Используем CipherContext из New
using CryptoLib.New.Modes; 

namespace CryptoCoursework_UI.ViewModels.Tabs
{
    public partial class Loki97ViewModel : ViewModelBase
    {
        [ObservableProperty] private string _inputFilePath = "";
        [ObservableProperty] private string _outputFilePath = "";
        [ObservableProperty] private string _keyHex = "";
        [ObservableProperty] private string _ivHex = "";
        [ObservableProperty] private string _statusMessage = "Готово к работе.";
        [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsIvVisible))] private CipherMode _selectedMode = CipherMode.CBC;
        [ObservableProperty] private PaddingMode _selectedPadding = PaddingMode.PKCS7;
        [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(GenerateKeyAndIvCommand))] [NotifyCanExecuteChangedFor(nameof(EncryptCommand))] [NotifyCanExecuteChangedFor(nameof(DecryptCommand))] private bool _isBusy = false;

        public List<CipherMode> CipherModes { get; } = Enum.GetValues<CipherMode>().ToList();
        public List<PaddingMode> PaddingModes { get; } = Enum.GetValues<PaddingMode>().ToList();
        public bool IsIvVisible => SelectedMode != CipherMode.ECB;

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task SelectInputFile()
        {
            var file = await DoOpenFilePickerAsync("Выберите файл");
            if (file is not null) InputFilePath = file.Path.LocalPath;
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task SelectOutputFile()
        {
            var file = await DoSaveFilePickerAsync("Сохранить результат как");
            if (file is not null) OutputFilePath = file.Path.LocalPath;
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private void GenerateKeyAndIv()
        {
            try
            {
                var rnd = new Random();
                // LOKI97 поддерживает 128, 192, 256 бит. Сделаем 256 (32 байта).
                byte[] key = new byte[32];
                rnd.NextBytes(key);
                KeyHex = BitConverter.ToString(key).Replace("-", "");

                if (IsIvVisible)
                {
                    // Блок LOKI97 всегда 16 байт (128 бит)
                    byte[] iv = new byte[16];
                    rnd.NextBytes(iv);
                    IvHex = BitConverter.ToString(iv).Replace("-", "");
                }
                else { IvHex = ""; }
                StatusMessage = "Ключ (256 бит) и IV сгенерированы.";
            }
            catch (Exception ex) { StatusMessage = $"Ошибка: {ex.Message}"; }
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task Encrypt() => await RunProcess(true);

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task Decrypt() => await RunProcess(false);

        private async Task RunProcess(bool encrypt)
        {
            if (!ValidateInputs(encrypt)) return;
            IsBusy = true;
            StatusMessage = encrypt ? "Шифрование..." : "Дешифрование...";

            try
            {
                byte[] key = HexStringToByteArray(KeyHex);
                // При дешифровке IV читаем из файла (если не ECB), но для UI оставим возможность ввода
                // В CipherContextLOKI97 методы для файлов сами не пишут IV, поэтому будем делать это руками (как в DES)
                byte[]? iv = IsIvVisible ? HexStringToByteArray(IvHex) : null;

                // Создаем контекст
                var context = new CipherContextLOKI97(key, SelectedMode, SelectedPadding, iv);

                await Task.Run(async () =>
                {
                    await using var inStream = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read);
                    await using var outStream = new FileStream(OutputFilePath, FileMode.Create, FileAccess.Write);

                    if (encrypt)
                    {
                        // Пишем IV в начало файла
                        if (iv != null) await outStream.WriteAsync(iv, 0, iv.Length);
                        await context.EncryptAsync(inStream, outStream);
                    }
                    else
                    {
                        // Читаем IV из файла
                        if (IsIvVisible)
                        {
                            byte[] fileIv = new byte[16];
                            int read = await inStream.ReadAsync(fileIv, 0, 16);
                            if (read < 16) throw new IOException("Файл слишком короткий (нет IV).");
                            // Пересоздаем контекст с правильным IV из файла
                            context = new CipherContextLOKI97(key, SelectedMode, SelectedPadding, fileIv);
                        }
                        await context.DecryptAsync(inStream, outStream);
                    }
                });

                StatusMessage = encrypt ? "Файл зашифрован!" : "Файл расшифрован!";
            }
            catch (Exception ex) { StatusMessage = $"Ошибка: {ex.Message}"; }
            finally { IsBusy = false; }
        }

        private bool CanExecuteCommands() => !IsBusy;

        private bool ValidateInputs(bool isDecrypt)
        {
            if (string.IsNullOrEmpty(InputFilePath) || !File.Exists(InputFilePath)) { StatusMessage = "Нет входного файла."; return false; }
            if (string.IsNullOrEmpty(OutputFilePath)) { StatusMessage = "Нет пути сохранения."; return false; }
            if (string.IsNullOrEmpty(KeyHex)) { StatusMessage = "Нет ключа."; return false; }
            // При дешифровке IV берется из файла, проверять поле ввода не обязательно
            if (IsIvVisible && !isDecrypt && string.IsNullOrEmpty(IvHex)) { StatusMessage = "Нет IV."; return false; }
            return true;
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("-", "").Replace(" ", "").Trim();
            if (hex.Length % 2 != 0) throw new ArgumentException("Неверный Hex");
            return Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16)).ToArray();
        }

        private static async Task<IStorageFile?> DoOpenFilePickerAsync(string title)
        {
            if (Application.Current?.ApplicationLifetime is not IClassicDesktopStyleApplicationLifetime desktop || desktop.MainWindow is null) return null;
            var files = await desktop.MainWindow.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = title, AllowMultiple = false });
            return files.Any() ? files[0] : null;
        }

        private static async Task<IStorageFile?> DoSaveFilePickerAsync(string title)
        {
            if (Application.Current?.ApplicationLifetime is not IClassicDesktopStyleApplicationLifetime desktop || desktop.MainWindow is null) return null;
            return await desktop.MainWindow.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = title });
        }
    }
}