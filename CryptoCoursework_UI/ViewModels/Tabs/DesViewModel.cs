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

namespace CryptoCoursework_UI.ViewModels.Tabs
{
    public partial class DesViewModel : ViewModelBase
    {
        [ObservableProperty] private string _inputFilePath = "";
        [ObservableProperty] private string _outputFilePath = "";
        [ObservableProperty] private string _keyHex = "";
        [ObservableProperty] private string _ivHex = "";
        [ObservableProperty] private string _statusMessage = "Готово к работе.";
        
        [ObservableProperty] 
        [NotifyPropertyChangedFor(nameof(IsIvVisible))] 
        private CipherMode _selectedMode = CipherMode.CBC;
        
        [ObservableProperty] private string _selectedAlgorithm = "DES";
        
        [ObservableProperty] 
        [NotifyCanExecuteChangedFor(nameof(GenerateKeyAndIvCommand))] 
        [NotifyCanExecuteChangedFor(nameof(EncryptFileCommand))] 
        [NotifyCanExecuteChangedFor(nameof(DecryptFileCommand))] 
        private bool _isBusy = false;

        public List<string> Algorithms { get; } = new() { "DES", "TripleDES", "DEAL-128", "DEAL-192", "DEAL-256" };
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
                    "TripleDES" => 24,
                    "DEAL-128" => 16,
                    "DEAL-192" => 24,
                    "DEAL-256" => 32,
                    _ => 8
                };
                
                byte[] key = new byte[keySize];
                rnd.NextBytes(key);
                KeyHex = BitConverter.ToString(key).Replace("-", "");

                if (IsIvVisible)
                {
                    int ivSize = SelectedAlgorithm.Contains("DEAL") ? 16 : 8;
                    byte[] iv = new byte[ivSize];
                    rnd.NextBytes(iv);
                    IvHex = BitConverter.ToString(iv).Replace("-", "");
                }
                else { IvHex = ""; }
                
                StatusMessage = $"Ключ ({keySize*8} бит) и IV сгенерированы.";
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
                // 1. Подготовка данных
                byte[] key = HexStringToByteArray(KeyHex);
                byte[]? iv = IsIvVisible ? HexStringToByteArray(IvHex) : null;
                
                // Для потоковых режимов паддинг нулями
                var padding = (SelectedMode == CipherMode.CFB || SelectedMode == CipherMode.OFB || SelectedMode == CipherMode.CTR) 
                              ? PaddingMode.Zeros 
                              : PaddingMode.PKCS7;

                // 2. Создание контекста
                // ВАЖНО: Передаем SelectedAlgorithm ("TripleDES", "DEAL-128" и т.д.) как есть.
                // CipherContext внутри разберется, что с ним делать.
                var additionalParams = new KeyValuePair<string, object>[] 
                { 
                    new("Algorithm", SelectedAlgorithm) 
                };

                var context = new CipherContext(key, SelectedMode, padding, iv, additionalParams);

                // 3. Выполнение
                await Task.Run(async () =>
                {
                    await using var inputFileStream = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read);
                    await using var outputFileStream = new FileStream(OutputFilePath, FileMode.Create, FileAccess.Write);
                    
                    // Пишем IV в начало файла, если он есть (чтобы потом расшифровать)
                    if (iv != null) 
                    {
                        await outputFileStream.WriteAsync(iv, 0, iv.Length);
                    }
                    
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
                byte[] key = HexStringToByteArray(KeyHex);
                byte[]? iv = null;
                var padding = (SelectedMode == CipherMode.CFB || SelectedMode == CipherMode.OFB || SelectedMode == CipherMode.CTR) 
                              ? PaddingMode.Zeros 
                              : PaddingMode.PKCS7;

                var additionalParams = new KeyValuePair<string, object>[] 
                { 
                    new("Algorithm", SelectedAlgorithm) 
                };

                await Task.Run(async () =>
                {
                    await using var inputFileStream = new FileStream(InputFilePath, FileMode.Open, FileAccess.Read);
                    await using var outputFileStream = new FileStream(OutputFilePath, FileMode.Create, FileAccess.Write);

                    if (IsIvVisible)
                    {
                        // Определяем размер IV для чтения из файла
                        int ivSize = SelectedAlgorithm.Contains("DEAL") ? 16 : 8;
                        
                        iv = new byte[ivSize];
                        int bytesRead = await inputFileStream.ReadAsync(iv, 0, iv.Length);
                        
                        if (bytesRead < iv.Length) 
                            throw new IOException($"Не удалось прочитать IV ({ivSize} байт) из начала файла.");
                    }

                    var context = new CipherContext(key, SelectedMode, padding, iv, additionalParams);
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
            
            // При дешифровке IV читается из файла, поэтому проверять поле ввода не нужно
            if (IsIvVisible && !isDecrypt && string.IsNullOrEmpty(IvHex)) { StatusMessage = "Ошибка: Укажите или сгенерируйте IV для этого режима."; return false; }
            
            return true;
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            hex = hex.Replace("-", "").Replace(" ", "").Trim();
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