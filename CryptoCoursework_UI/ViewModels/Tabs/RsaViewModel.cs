using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CryptoLib.RSA.Core;
using CryptoLib.RSA.Enums;
using CryptoLib.RSA.Interfaces;
using CryptoLib.RSA.Primality.Implementations;
using CryptoLib.RSA.RSA;
using CryptoLib.RSA.RSA.Models;
using CryptoLib.RSA.Attacks;
using CryptoLib.RSA.Attacks.Models;

namespace CryptoCoursework_UI.ViewModels.Tabs
{
    public partial class RsaViewModel : ViewModelBase
    {
        //Свойства для вкладки RSA
        [ObservableProperty] private int _selectedBitLength = 256;
        public List<int> AvailableBitLengths { get; } = new List<int> { 128, 256, 512, 1024 };

        [ObservableProperty] private PrimalityTestType _selectedTestType = PrimalityTestType.MillerRabin;
        public IEnumerable<PrimalityTestType> TestTypes => Enum.GetValues(typeof(PrimalityTestType)).Cast<PrimalityTestType>();

        [ObservableProperty] private string _publicKeyE = "";
        [ObservableProperty] private string _publicKeyN = "";
        [ObservableProperty] private string _privateKeyD = "";

        [ObservableProperty] private string _messageToEncrypt = "123456789";
        [ObservableProperty] private string _encryptedMessage = "";
        [ObservableProperty] private string _decryptedMessage = "";

        // Свойства для вкладки "Тестер простоты"
        [ObservableProperty] private string _numberToTest = "15485863";
        [ObservableProperty] private PrimalityTestType _selectedTestTypeForCheck = PrimalityTestType.MillerRabin;
        [ObservableProperty] private string _primalityTestResult = "";
        [ObservableProperty] private bool? _isResultPrime = null;

        // --- Общие свойства ---
        [ObservableProperty] private string _statusMessage = "Готово к работе.";
        [ObservableProperty][NotifyCanExecuteChangedFor(nameof(GenerateKeysCommand))][NotifyCanExecuteChangedFor(nameof(EncryptCommand))][NotifyCanExecuteChangedFor(nameof(DecryptCommand))][NotifyCanExecuteChangedFor(nameof(CheckPrimalityCommand))] private bool _isBusy = false;

        // --- Сервисы и константы ---
        private readonly ICryptoMathService _mathService = new CryptoMathService();
        private RsaKeyPair? _currentKeyPair;
        private const double Probability = 0.9999;
        private const double PrimalityCheckProbability = 0.9999;

        // Команды для вкладки RSA
        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private async Task GenerateKeysAsync()
        {
            IsBusy = true;
            StatusMessage = "Идет генерация ключей...";
            ClearFields();

            try
            {
                await Task.Run(() =>
                {
                    var rsaService = new RsaService(SelectedTestType, Probability, SelectedBitLength);
                    _currentKeyPair = rsaService.GenerateKeyPair();
                });

                if (_currentKeyPair != null)
                {
                    PublicKeyE = _currentKeyPair.PublicKey.E.ToString();
                    PublicKeyN = _currentKeyPair.PublicKey.N.ToString();
                    PrivateKeyD = _currentKeyPair.PrivateKey.D.ToString();
                    StatusMessage = "Ключи успешно сгенерированы!";
                }
            }
            catch (Exception ex) { StatusMessage = $"Ошибка: {ex.Message}"; }
            finally { IsBusy = false; }
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private void Encrypt()
        {
            if (_currentKeyPair == null) { StatusMessage = "Сначала сгенерируйте ключи."; return; }
            try
            {
                var rsaService = new RsaService(SelectedTestType, Probability, SelectedBitLength);
                var message = BigInteger.Parse(MessageToEncrypt);
                var encrypted = rsaService.Encrypt(message, _currentKeyPair.PublicKey);
                EncryptedMessage = encrypted.ToString();
                StatusMessage = "Сообщение успешно зашифровано.";
            }
            catch (Exception ex) { StatusMessage = $"Ошибка шифрования: {ex.Message}"; }
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private void Decrypt()
        {
            if (_currentKeyPair == null || string.IsNullOrEmpty(EncryptedMessage)) { StatusMessage = "Сначала зашифруйте сообщение."; return; }
            try
            {
                var rsaService = new RsaService(SelectedTestType, Probability, SelectedBitLength);
                var encrypted = BigInteger.Parse(EncryptedMessage);
                var decrypted = rsaService.Decrypt(encrypted, _currentKeyPair.PrivateKey);
                DecryptedMessage = decrypted.ToString();
                StatusMessage = "Сообщение успешно расшифровано.";
            }
            catch (Exception ex) { StatusMessage = $"Ошибка дешифрования: {ex.Message}"; }
        }

        // Команда для вкладки "Тестер простоты"
        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private void CheckPrimality()
        {
            IsBusy = true;
            StatusMessage = "Выполняется проверка на простоту...";
            IsResultPrime = null;

            try
            {
                if (!BigInteger.TryParse(NumberToTest, out var number)) { PrimalityTestResult = "Ошибка: Введите корректное целое число."; return; }

                IPrimalityTest primalityTest = SelectedTestTypeForCheck switch
                {
                    PrimalityTestType.Fermat => new FermatTest(_mathService),
                    PrimalityTestType.SoloveyStrassen => new SoloveyStrassenTest(_mathService),
                    PrimalityTestType.MillerRabin => new MillerRabinTest(_mathService),
                    _ => throw new InvalidOperationException("Выбран неизвестный тест")
                };

                bool isPrime = primalityTest.IsPrime(number, PrimalityCheckProbability);

                if (isPrime) { PrimalityTestResult = $"Число, вероятно, простое (с вероятностью > {PrimalityCheckProbability:P2})."; IsResultPrime = true; }
                else { PrimalityTestResult = "Число является составным."; IsResultPrime = false; }

                StatusMessage = "Проверка завершена.";
            }
            catch (Exception ex) { PrimalityTestResult = $"Ошибка: {ex.Message}"; }
            finally { IsBusy = false; }
        }

        private bool CanExecuteCommands() => !IsBusy;
        private void ClearFields() { _currentKeyPair = null; PublicKeyE = ""; PublicKeyN = ""; PrivateKeyD = ""; EncryptedMessage = ""; DecryptedMessage = ""; }
            

        [ObservableProperty]
        private string _wienersAttackE = "";

        [ObservableProperty]
        private string _wienersAttackN = "";

        [ObservableProperty]
        private string _wienersAttackResultStatus = "";

        [ObservableProperty]
        private string? _wienersAttackFoundD;

        [ObservableProperty]
        private string? _wienersAttackFoundPhi;

        [ObservableProperty]
        private IReadOnlyList<ContinuedFraction>? _wienersAttackConvergents;

        private readonly IWienersAttackService _wienersAttackService = new WienersAttackService();

        [RelayCommand]
        private void PreloadWeakKey()
        {
            WienersAttackE = "17993";
            WienersAttackN = "90581";
            StatusMessage = "Уязвимый ключ загружен.";
            ClearWienersAttackResults();
        }

        [RelayCommand(CanExecute = nameof(CanExecuteCommands))]
        private void ExecuteWienersAttack()
        {
            IsBusy = true;
            StatusMessage = "Выполняется атака Винера...";
            ClearWienersAttackResults();

            try
            {
                if (!BigInteger.TryParse(WienersAttackE, out var e) || !BigInteger.TryParse(WienersAttackN, out var n))
                {
                    WienersAttackResultStatus = "Ошибка: E и N должны быть корректными числами.";
                    return;
                }

                var weakPublicKey = new RsaPublicKey(e, n);
                var result = _wienersAttackService.Attack(weakPublicKey);

                // Обновляем UI результатами
                WienersAttackConvergents = result.Convergents;
                if (result.IsSuccessful)
                {
                    WienersAttackResultStatus = "УСПЕХ: Секретный ключ найден!";
                    WienersAttackFoundD = result.FoundD.ToString();
                    WienersAttackFoundPhi = result.FoundPhi.ToString();
                }
                else
                {
                    WienersAttackResultStatus = "Атака не удалась. Ключ, вероятно, не уязвим.";
                }

                StatusMessage = "Атака Винера завершена.";
            }
            catch (Exception ex)
            {
                WienersAttackResultStatus = $"Ошибка: {ex.Message}";
            }
            finally
            {
                IsBusy = false;
            }
        }

        private void ClearWienersAttackResults()
        {
            WienersAttackResultStatus = "";
            WienersAttackFoundD = null;
            WienersAttackFoundPhi = null;
            WienersAttackConvergents = null;
        }
    }
}