using Avalonia.Controls;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CryptoLib.Rijndael.Algorithms.Rijndael;
using CryptoLib.Rijndael.Algorithms.Rijndael.Enums;
using CryptoLib.Rijndael.Interfaces;
using CryptoLib.Rijndael.Modes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace CryptoApp.ViewModels
{
    public partial class MainViewModel : ObservableObject
    {
        // Свойства для UI
        [ObservableProperty]
        [NotifyPropertyChangedFor(nameof(IsNotBusy))]
        private bool _isBusy;

        public bool IsNotBusy => !IsBusy;

        [ObservableProperty]
        private string _sourceFilePath = string.Empty;

        [ObservableProperty]
        private string _targetFilePath = string.Empty;

        [ObservableProperty]
        private string _password = string.Empty;

        [ObservableProperty]
        private double _progress;

        [ObservableProperty]
        private string _statusText = "Готов к работе.";

        // Свойства для ComboBox'ов
        public List<CryptoLib.Rijndael.Modes.CipherMode> CipherModes { get; } = Enum.GetValues<CryptoLib.Rijndael.Modes.CipherMode>().ToList();
        public List<CryptoLib.Rijndael.Modes.PaddingMode> PaddingModes { get; } = Enum.GetValues<CryptoLib.Rijndael.Modes.PaddingMode>().ToList();

        [ObservableProperty]
        private CryptoLib.Rijndael.Modes.CipherMode _selectedCipherMode;

        [ObservableProperty]
        private CryptoLib.Rijndael.Modes.PaddingMode _selectedPaddingMode;

        // Команды для кнопок

        [RelayCommand]
        [Obsolete]
        private async Task SelectSourceFile()
        {
            var dialog = new OpenFileDialog();
            var result = await dialog.ShowAsync(new Window());
            if (result != null && result.Length > 0)
            {
                SourceFilePath = result[0];
            }
        }

        [RelayCommand]
        [Obsolete]
        private async Task SelectTargetFile()
        {
            var dialog = new SaveFileDialog();
            var result = await dialog.ShowAsync(new Window());
            if (!string.IsNullOrEmpty(result))
            {
                TargetFilePath = result;
            }
        }

        [RelayCommand]
        private async Task Encrypt()
        {
            await RunCryptoOperation(isEncrypting: true);
        }

        [RelayCommand]
        private async Task Decrypt()
        {
            await RunCryptoOperation(isEncrypting: false);
        }

        // Основная логика

        private async Task RunCryptoOperation(bool isEncrypting)
        {
            if (IsBusy) return;
            if (string.IsNullOrEmpty(SourceFilePath) || string.IsNullOrEmpty(TargetFilePath) || string.IsNullOrEmpty(Password))
            {
                StatusText = "Ошибка: Укажите исходный файл, файл для результата и пароль.";
                return;
            }

            IsBusy = true;
            StatusText = isEncrypting ? "Шифрование..." : "Дешифрование...";
            Progress = 0;

            try
            {
                // Используем стандартный PBKDF2 для получения ключа и IV из пароля.
                var salt = Encoding.UTF8.GetBytes("somesalt123");
                using var rfc2898 = new Rfc2898DeriveBytes(Password, salt, 10000, HashAlgorithmName.SHA256);

                var key = rfc2898.GetBytes(32); // 256-битный ключ
                var iv = rfc2898.GetBytes(16);  // 128-битный IV

                ISymmetricCipher rijndael = new RijndaelCipher(KeySize.K256, BlockSize.B128);
                var context = new CipherContext(rijndael, key, SelectedCipherMode, SelectedPaddingMode, iv);

                if (isEncrypting)
                {
                    await context.EncryptAsync(SourceFilePath, TargetFilePath);
                    StatusText = "Шифрование успешно завершено!";
                }
                else
                {
                    await context.DecryptAsync(SourceFilePath, TargetFilePath);
                    StatusText = "Дешифрование успешно завершено!";
                }
                Progress = 100;
            }
            catch (Exception ex)
            {
                StatusText = $"Ошибка: {ex.Message}";
                Progress = 0;
            }
            finally
            {
                IsBusy = false;
            }
        }

        [ObservableProperty]
        private string _polynomialToFactorString = "100100010001"; // Пример: x^11+x^8+x^4+1

        [ObservableProperty]
        private string _factorizationResult = string.Empty;

        [RelayCommand]
        private void FactorizePolynomial()
        {
            FactorizationResult = string.Empty;

            if (string.IsNullOrWhiteSpace(PolynomialToFactorString))
            {
                FactorizationResult = "Ошибка: введите полином.";
                return;
            }

            try
            {
                
                var polynomial = new BigInteger(0);
                foreach (char c in PolynomialToFactorString)
                {
                    polynomial <<= 1;
                    if (c == '1') polynomial |= 1;
                    else if (c != '0') throw new FormatException("Строка должна содержать только 0 и 1.");
                }

                
                var factors = CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField.GaloisFieldMath.FactorizePolynomial(polynomial);

                if (factors.Count == 0)
                {
                    FactorizationResult = "Полином не имеет множителей (или равен 0/1).";
                    return;
                }

                var resultBuilder = new StringBuilder();
                resultBuilder.AppendLine("Найденные неприводимые множители:");
                foreach (var factor in factors)
                {
                    resultBuilder.AppendLine($"  -> {FormatPolynomial(factor.Key)} (степень: {factor.Value})");
                }
                FactorizationResult = resultBuilder.ToString();
            }
            catch (Exception ex)
            {
                FactorizationResult = $"Произошла ошибка: {ex.Message}";
            }
        }

        // Чисто для красоты вывода
        private string FormatPolynomial(BigInteger poly)
        {
            if (poly.IsZero) return "0";
            if (poly == 1) return "1";

            var sb = new StringBuilder();
            for (int i = (int)poly.GetBitLength() - 1; i >= 0; i--)
            {
                if ((poly & (BigInteger.One << i)) != 0)
                {
                    if (sb.Length > 0)
                    {
                        sb.Append(" + ");
                    }

                    if (i == 0)
                    {
                        sb.Append("1");
                    }
                    else if (i == 1)
                    {
                        sb.Append("x");
                    }
                    else
                    {
                        sb.Append($"x^{i}");
                    }
                }
            }
            return sb.ToString();
        }
        
        [ObservableProperty]
        private string _operandAString = "53";

        [ObservableProperty]
        private string _operandBString = "CA";

        [ObservableProperty]
        private string _gfCalculationResult = string.Empty;

        
        public List<byte> IrreduciblePolynomials { get; }

        [ObservableProperty]
        private byte _selectedPolynomial;

        
        public MainViewModel()
        {
        
            IrreduciblePolynomials = CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField.GaloisFieldMath.FindAllIrreduciblePolynomials();
            // Выбираем по умолчанию стандартный полином AES
            SelectedPolynomial = 0x1B;
        }

        [RelayCommand]
        private void CalculateGf()
        {
            try
            {
                
                byte operandA = Convert.ToByte(OperandAString, 16);
                byte operandB = Convert.ToByte(OperandBString, 16);

                
                byte sum = CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField.GaloisFieldMath.Add(operandA, operandB);
                byte product = CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField.GaloisFieldMath.Multiply(operandA, operandB, SelectedPolynomial);
                byte inverseA = CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField.GaloisFieldMath.Inverse(operandA, SelectedPolynomial);
                byte inverseB = CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField.GaloisFieldMath.Inverse(operandB, SelectedPolynomial);

                var resultBuilder = new StringBuilder();
                resultBuilder.AppendLine($"A + B       = 0x{sum:X2}");
                resultBuilder.AppendLine($"A * B (mod 0x{SelectedPolynomial:X2}) = 0x{product:X2}");
                resultBuilder.AppendLine($"Inverse(A)  = 0x{inverseA:X2}");
                resultBuilder.AppendLine($"Inverse(B)  = 0x{inverseB:X2}");

                GfCalculationResult = resultBuilder.ToString();
            }
            catch (Exception ex)
            {
                GfCalculationResult = $"Ошибка: {ex.Message}. Вводите байты в HEX-формате (например, FF, 0A, 1B).";
            }
        }
    }
}