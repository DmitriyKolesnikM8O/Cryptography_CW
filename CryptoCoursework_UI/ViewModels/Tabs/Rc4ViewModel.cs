using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CryptoLib.New.Algorithms.RC4;

namespace CryptoCoursework_UI.ViewModels.Tabs
{
    public partial class Rc4ViewModel : ViewModelBase
    {
        [ObservableProperty] private string _inputFilePath = "";
        [ObservableProperty] private string _outputFilePath = "";
        [ObservableProperty] private string _keyHex = "";
        [ObservableProperty] private string _statusMessage = "Готов к работе.";
        [ObservableProperty] private bool _isBusy = false;

        [RelayCommand]
        private async Task SelectInputFile()
        {
            var file = await DoOpenFilePickerAsync("Выберите файл для RC4");
            if (file is not null) InputFilePath = file.Path.LocalPath;
        }

        [RelayCommand]
        private async Task SelectOutputFile()
        {
            var file = await DoSaveFilePickerAsync("Куда сохранить результат?");
            if (file is not null) OutputFilePath = file.Path.LocalPath;
        }

        [RelayCommand]
        private void GenerateKey()
        {
            try
            {
                var rnd = new Random();
                // RC4 поддерживает ключи от 1 до 256 байт. Возьмем 16 байт (128 бит).
                byte[] key = new byte[16];
                rnd.NextBytes(key);
                KeyHex = BitConverter.ToString(key).Replace("-", "");
                StatusMessage = "Сгенерирован ключ (128 бит).";
            }
            catch (Exception ex) { StatusMessage = $"Ошибка: {ex.Message}"; }
        }

        [RelayCommand]
        private async Task ProcessFile()
        {
            if (string.IsNullOrEmpty(InputFilePath) || string.IsNullOrEmpty(OutputFilePath)) 
            { 
                StatusMessage = "Выберите файлы."; return; 
            }
            if (string.IsNullOrEmpty(KeyHex)) 
            { 
                StatusMessage = "Введите ключ."; return; 
            }

            IsBusy = true;
            StatusMessage = "Обработка...";

            try
            {
                byte[] key = HexStringToByteArray(KeyHex);
                
                // RC4 симметричен: Encrypt и Decrypt — это одна и та же операция XOR.
                // Главное — каждый раз создавать новый экземпляр, чтобы сбросить состояние S-Box.
                var rc4 = new RC4Algorithm(key);

                await Task.Run(async () =>
                {
                    await rc4.ProcessFileAsync(InputFilePath, OutputFilePath);
                });

                StatusMessage = "Операция завершена успешно!";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Ошибка: {ex.Message}";
            }
            finally
            {
                IsBusy = false;
            }
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("-", "").Replace(" ", "").Trim();
            if (hex.Length % 2 != 0) throw new ArgumentException("Неверный формат Hex.");
            return Enumerable.Range(0, hex.Length / 2)
                             .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
                             .ToArray();
        }

        // Хелперы диалогов
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