using System;
using System.Collections.Generic; // Добавил для списков
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

using CryptoLib.New.Protocols.DiffieHellman;
using CryptoLib.New.Modes;
using CryptoLib.DES.Modes; // Enums

using System.IO;

namespace CryptoCoursework_UI.ViewModels.Tabs
{
    public partial class DiffieHellmanViewModel : ViewModelBase
    {
        private DiffieHellmanProtocol? _aliceProtocol;
        private DiffieHellmanProtocol? _bobProtocol;

        [ObservableProperty] private string _statusMessage = "Нажмите 'Начать обмен', чтобы сгенерировать ключи.";
        [ObservableProperty][NotifyCanExecuteChangedFor(nameof(CalculateSecretCommand))] private bool _keysGenerated = false;
        [ObservableProperty][NotifyCanExecuteChangedFor(nameof(TestEncryptionCommand))] private bool _secretCalculated = false;

        [ObservableProperty] private string _paramP = "";
        [ObservableProperty] private string _paramG = "";

        [ObservableProperty] private string _alicePrivateKey = "";
        [ObservableProperty] private string _alicePublicKey = "";
        [ObservableProperty] private string _aliceCalculatedSecret = "";

        [ObservableProperty] private string _bobPrivateKey = "";
        [ObservableProperty] private string _bobPublicKey = "";
        [ObservableProperty] private string _bobCalculatedSecret = "";

        [ObservableProperty] private string _messageToSend = "Привет! Это секретное сообщение.";
        [ObservableProperty] private string _encryptedHex = "";
        [ObservableProperty] private string _decryptedMessage = "";
        [ObservableProperty] private string _derivedKeyHex = "";

        // --- НОВЫЕ СВОЙСТВА ДЛЯ ВЫБОРА РЕЖИМА И ПАДДИНГА ---
        [ObservableProperty] private CipherMode _selectedMode = CipherMode.CBC;
        [ObservableProperty] private PaddingMode _selectedPadding = PaddingMode.PKCS7;

        // Списки для UI
        public List<CipherMode> CipherModes { get; } = Enum.GetValues<CipherMode>().ToList();
        public List<PaddingMode> PaddingModes { get; } = Enum.GetValues<PaddingMode>().ToList();
        // ---------------------------------------------------

        [RelayCommand]
        private async Task GenerateKeys()
        {
            StatusMessage = "Генерация параметров и ключей...";
            await Task.Run(() =>
            {
                _aliceProtocol = new DiffieHellmanProtocol();
                _bobProtocol = new DiffieHellmanProtocol(_aliceProtocol.P, _aliceProtocol.G);
            });

            ParamP = _aliceProtocol!.P.ToString();
            ParamG = _aliceProtocol!.G.ToString();
            AlicePrivateKey = "(Скрыт) " + _aliceProtocol.GetHashCode();
            AlicePublicKey = _aliceProtocol.PublicKey.ToString();
            BobPrivateKey = "(Скрыт) " + _bobProtocol!.GetHashCode();
            BobPublicKey = _bobProtocol.PublicKey.ToString();

            AliceCalculatedSecret = "";
            BobCalculatedSecret = "";
            DerivedKeyHex = "";
            EncryptedHex = "";
            DecryptedMessage = "";

            KeysGenerated = true;
            SecretCalculated = false;
            StatusMessage = "Ключи сгенерированы.";
        }

        [RelayCommand(CanExecute = nameof(KeysGenerated))]
        private void CalculateSecret()
        {
            if (_aliceProtocol == null || _bobProtocol == null) return;

            var aliceSecret = _aliceProtocol.CalculateSharedSecret(_bobProtocol.PublicKey);
            var bobSecret = _bobProtocol.CalculateSharedSecret(_aliceProtocol.PublicKey);

            AliceCalculatedSecret = aliceSecret.ToString();
            BobCalculatedSecret = bobSecret.ToString();

            if (aliceSecret == bobSecret)
            {
                StatusMessage = "УСПЕХ: Общие секреты совпадают!";
                SecretCalculated = true;
                byte[] keyBytes = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, 32);
                DerivedKeyHex = BitConverter.ToString(keyBytes).Replace("-", "");
            }
            else
            {
                StatusMessage = "ОШИБКА: Секреты не совпали.";
            }
        }

        [RelayCommand(CanExecute = nameof(SecretCalculated))]
        private async Task TestEncryption()
        {
            try
            {
                byte[] key = HexStringToByteArray(DerivedKeyHex);

                // Генерируем IV только если режим не ECB
                byte[]? iv = null;
                if (SelectedMode != CipherMode.ECB)
                {
                    iv = new byte[16]; // LOKI97 Block Size
                    new Random().NextBytes(iv);
                }

                // --- АЛИСА ШИФРУЕТ ---
                var aliceContext = new CipherContextLOKI97(key, SelectedMode, SelectedPadding, iv);
                byte[] inputBytes = Encoding.UTF8.GetBytes(MessageToSend);

                // Используем MemoryStream, чтобы CipherContext сам рассчитал длину с паддингом
                byte[] encryptedBytes;
                using (var inputStream = new MemoryStream(inputBytes))
                using (var outputStream = new MemoryStream())
                {
                    await aliceContext.EncryptAsync(inputStream, outputStream);
                    encryptedBytes = outputStream.ToArray();
                }

                // Форматируем вывод шифротекста (IV + Data)
                string ivStr = iv != null ? BitConverter.ToString(iv).Replace("-", "") + " | " : "";
                EncryptedHex = ivStr + BitConverter.ToString(encryptedBytes).Replace("-", "");

                StatusMessage = $"Алиса зашифровала ({SelectedMode}/{SelectedPadding}).";

                // --- БОБ ДЕШИФРУЕТ ---
                var bobContext = new CipherContextLOKI97(key, SelectedMode, SelectedPadding, iv);
                byte[] decryptedBytes;

                using (var inputStream = new MemoryStream(encryptedBytes))
                using (var outputStream = new MemoryStream())
                {
                    // CipherContext корректно снимет паддинг и запишет в outputStream 
                    // ТОЛЬКО полезные байты. Никакого мусора.
                    await bobContext.DecryptAsync(inputStream, outputStream);
                    decryptedBytes = outputStream.ToArray();
                }

                // Превращаем чистые байты в строку. Никаких TrimEnd не нужно.
                DecryptedMessage = Encoding.UTF8.GetString(decryptedBytes);

                StatusMessage += " Боб расшифровал.";
            }
            catch (Exception ex)
            {
                // Если паддинг неверный (например, при неверном ключе), вылетит ошибка
                StatusMessage = $"Ошибка: {ex.Message}";
                DecryptedMessage = "ОШИБКА ДЕШИФРОВКИ";
            }
        }

        private static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length / 2)
                             .Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16))
                             .ToArray();
        }
    }
}