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
using CryptoLib.DES.Modes;

namespace CryptoApp.ViewModels
{
    
    public partial class MainViewModel : ObservableObject
    {
    
        [ObservableProperty] private string _inputFilePath = "";
        [ObservableProperty] private string _outputFilePath = "";
        [ObservableProperty] private string _keyHex = "";
        [ObservableProperty] private string _ivHex = "";
        [ObservableProperty] private string _statusMessage = "Готово к работе.";
        [ObservableProperty] [NotifyPropertyChangedFor(nameof(IsIvVisible))] private CipherMode _selectedMode = CipherMode.CBC;
        [ObservableProperty] private string _selectedAlgorithm = "DES";
        [ObservableProperty] [NotifyCanExecuteChangedFor(nameof(GenerateKeyAndIvCommand))] [NotifyCanExecuteChangedFor(nameof(EncryptFileCommand))] [NotifyCanExecuteChangedFor(nameof(DecryptFileCommand))] private bool _isBusy = false;

        
        public List<string> Algorithms { get; } = new() { "DES", "DEAL-128", "DEAL-192", "DEAL-256" };
        public List<CipherMode> CipherModes => Enum.GetValues<CipherMode>().ToList();
        public bool IsIvVisible => SelectedMode != CipherMode.ECB;

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task SelectInputFile()
        {
            var file = await DoOpenFilePickerAsync("Выберите исходный файл");
            if (file is not null) InputFilePath = file.Path.LocalPath;
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task SelectOutputFile()
        {
            var file = await DoSaveFilePickerAsync("Укажите файл для результата");
            if (file is not null) OutputFilePath = file.Path.LocalPath;
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private void GenerateKeyAndIv()
        {
            try
            {
                var rnd = new Random();
                int keySize = SelectedAlgorithm switch
                {
                    "DES" => 8,
                    "DEAL-128" => 16,
                    "DEAL-192" => 24,
                    "DEAL-256" => 32,
                    _ => 0
                };
                byte[] key = Enumerable.Range(0, keySize).Select(_ => (byte)rnd.Next(256)).ToArray();
                KeyHex = BitConverter.ToString(key);

                if (IsIvVisible)
                {
                    int ivSize = SelectedAlgorithm == "DES" ? 8 : 16;
                    byte[] iv = Enumerable.Range(0, ivSize).Select(_ => (byte)rnd.Next(256)).ToArray();
                    IvHex = BitConverter.ToString(iv);
                }
                else { IvHex = ""; }
                StatusMessage = "Ключ и IV сгенерированы.";
            }
            catch (Exception ex) { StatusMessage = $"Ошибка генерации: {ex.Message}"; }
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task EncryptFile()
        {
            if (!ValidateInputs()) return;
            IsBusy = true;
            StatusMessage = "Идет шифрование...";

            try
            {
                string algoName = SelectedAlgorithm.StartsWith("DEAL") ? "DEAL" : "DES";
                byte[] key = HexStringToByteArray(KeyHex);
                byte[]? iv = IsIvVisible ? HexStringToByteArray(IvHex) : null;
                var padding = (SelectedMode == CipherMode.CFB || SelectedMode == CipherMode.OFB || SelectedMode == CipherMode.CTR) ? PaddingMode.Zeros : PaddingMode.PKCS7;
                var context = new CipherContext(key, SelectedMode, padding, iv, new KeyValuePair<string, object>("Algorithm", algoName));

                await Task.Run(async () =>
                {
                    await using var inputFileStream = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read);
                    await using var outputFileStream = new FileStream(OutputFilePath, FileMode.Create, FileAccess.Write);
                    if (iv != null) await outputFileStream.WriteAsync(iv, 0, iv.Length);
                    await context.EncryptAsync(inputFileStream, outputFileStream);
                });

                StatusMessage = "Файл успешно зашифрован!";
            }
            catch (Exception ex) { StatusMessage = $"Ошибка шифрования: {ex.Message}"; }
            finally { IsBusy = false; }
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task DecryptFile()
        {
            if (!ValidateInputs(isDecrypt: true)) return;
            IsBusy = true;
            StatusMessage = "Идет дешифрование...";

            try
            {
                string algoName = SelectedAlgorithm.StartsWith("DEAL") ? "DEAL" : "DES";
                byte[] key = HexStringToByteArray(KeyHex);
                byte[]? iv = null;
                var padding = (SelectedMode == CipherMode.CFB || SelectedMode == CipherMode.OFB || SelectedMode == CipherMode.CTR) ? PaddingMode.Zeros : PaddingMode.PKCS7;

                await Task.Run(async () =>
                {
                    await using var inputFileStream = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read);
                    await using var outputFileStream = new FileStream(OutputFilePath, FileMode.Create, FileAccess.Write);

                    if (IsIvVisible)
                    {
                        int ivSize = algoName == "DES" ? 8 : 16;
                        iv = new byte[ivSize];
                        int bytesRead = await inputFileStream.ReadAsync(iv, 0, iv.Length);
                        if (bytesRead < iv.Length) throw new IOException("Не удалось прочитать IV из файла.");
                    }

                    var context = new CipherContext(key, SelectedMode, padding, iv, new KeyValuePair<string, object>("Algorithm", algoName));
                    await context.DecryptAsync(inputFileStream, outputFileStream);
                });

                StatusMessage = "Файл успешно расшифрован!";
            }
            catch (Exception ex) { StatusMessage = $"Ошибка дешифрования: {ex.Message}"; }
            finally { IsBusy = false; }
        }

        private bool CanExecuteCommands() => !IsBusy;

        private bool ValidateInputs(bool isDecrypt = false)
        {
            if (string.IsNullOrEmpty(InputFilePath) || !File.Exists(InputFilePath)) { StatusMessage = "Ошибка: Выберите корректный исходный файл."; return false; }
            if (string.IsNullOrEmpty(OutputFilePath)) { StatusMessage = "Ошибка: Укажите путь для файла-результата."; return false; }
            if (string.IsNullOrEmpty(KeyHex)) { StatusMessage = "Ошибка: Укажите или сгенерируйте ключ."; return false; }
            if (IsIvVisible && !isDecrypt && string.IsNullOrEmpty(IvHex)) { StatusMessage = "Ошибка: Укажите или сгенерируйте IV для этого режима."; return false; }
            return true;
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("-", "").Trim();
            if (hex.Length % 2 != 0) throw new ArgumentException("Hex-строка должна иметь четное число символов.");
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