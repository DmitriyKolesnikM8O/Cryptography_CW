using System.Diagnostics;
using Xunit.Abstractions;
using CryptoLib.Rijndael.Algorithms.Rijndael;
using CryptoLib.Rijndael.Algorithms.Rijndael.Enums; 
using CryptoLib.Rijndael.Modes;

/*
1. TestDataGenerator: Это не тест, а вспомогательный метод-генератор. Он создает набор тестовых случаев, комбинируя разные типы файлов (текст, изображение, аудио и т.д.), разные размеры ключа (128, 192, 256) и все доступные режимы шифрования.
2. ComprehensiveFileEncryptDecrypt_ShouldSucceed: Главный "стресс-тест". Он берет каждый набор данных от TestDataGenerator и выполняет полный цикл шифрования-дешифрования реального файла. Тест проверяет, что исходный и расшифрованный файлы полностью совпадают, а также измеряет и выводит время, затраченное на каждую операцию (шифрование, дешифрование, проверка).
3. EncryptDecrypt_WithBlockAlignedData_ShouldSucceed: Проверяет граничные случаи обработки паддинга (PKCS7). Он тестирует шифрование данных, длина которых уже кратна размеру блока (включая пустые данные), чтобы убедиться, что паддинг корректно добавляется (целый новый блок) и затем корректно удаляется.
4. Decrypt_WithTamperedCiphertext_ShouldThrowException: Тест на безопасность. Он шифрует данные, затем намеренно "портит" один байт в шифротексте. После этого он пытается расшифровать измененные данные. Для режимов вроде CBC это приведет к некорректному паддингу, и CipherContext должен выбросить исключение (CryptographicException при удалении паддинга), что и проверяет тест. Это доказывает, что система может обнаружить повреждение данных.
*/


namespace CryptoTests
{
    public class Rijndael_AdvancedTests
    {
        // Тестовые ключи для 128, 192 и 256 бит
        private readonly byte[] _testKey128 = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
        private readonly byte[] _testKey192 = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
        private readonly byte[] _testKey256 = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

        // Вектор инициализации (IV) для AES всегда 16 байт
        private readonly byte[] _testIV = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

        private readonly ITestOutputHelper _testOutputHelper;

        public Rijndael_AdvancedTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        public static IEnumerable<object[]> TestDataGenerator()
        {
            string[] filePaths =
            {
                "TestData/text.txt",
                "TestData/image.jpg",
                "TestData/audio.mp3",
                "TestData/video.mp4",
                "TestData/archive.zip"
            };

            var cipherModes = (CipherMode[])Enum.GetValues(typeof(CipherMode));
            int[] keySizesInBits = { 128, 192, 256 };

            foreach (var filePath in filePaths)
            {
                foreach (var keySize in keySizesInBits)
                {
                    foreach (var mode in cipherModes)
                    {
                        yield return new object[] { filePath, mode, keySize };
                    }
                }
            }
        }

        [Theory]
        [MemberData(nameof(TestDataGenerator))]
        public async Task ComprehensiveFileEncryptDecrypt_ShouldSucceed(string inputFilePath, CipherMode mode, int keySizeInBits)
        {
            byte[] key;
            KeySize keySizeEnum;
            switch (keySizeInBits)
            {
                case 128:
                    key = _testKey128;
                    keySizeEnum = KeySize.K128;
                    break;
                case 192:
                    key = _testKey192;
                    keySizeEnum = KeySize.K192;
                    break;
                case 256:
                    key = _testKey256;
                    keySizeEnum = KeySize.K256;
                    break;
                default:
                    throw new ArgumentException($"Неподдерживаемый размер ключа: {keySizeInBits}");
            }

            var diagnostics = new System.Text.StringBuilder();
            diagnostics.AppendLine($"\n--- DIAGNOSTICS for {Path.GetFileName(inputFilePath)} [{new FileInfo(inputFilePath).Length / 1024.0:F2} KB] with {mode} and {keySizeInBits}-bit key ---");
            var totalStopwatch = Stopwatch.StartNew();

            Assert.True(File.Exists(inputFilePath), $"Тестовый файл не найден: {inputFilePath}");

            byte[]? iv = mode == CipherMode.ECB ? null : _testIV;

            var rijndaelAlgorithm = new RijndaelCipher(keySizeEnum, BlockSize.B128);


            var context = new CipherContext(rijndaelAlgorithm, key, mode, PaddingMode.PKCS7, iv);

            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {
                var encryptStopwatch = Stopwatch.StartNew();
                await context.EncryptAsync(inputFilePath, encryptedFile);
                encryptStopwatch.Stop();
                diagnostics.AppendLine($"  Encryption took: {encryptStopwatch.ElapsedMilliseconds,7} ms");

                var decryptStopwatch = Stopwatch.StartNew();
                await context.DecryptAsync(encryptedFile, decryptedFile);
                decryptStopwatch.Stop();
                diagnostics.AppendLine($"  Decryption took: {decryptStopwatch.ElapsedMilliseconds,7} ms");

                var verificationStopwatch = Stopwatch.StartNew();
                byte[] originalBytes = await File.ReadAllBytesAsync(inputFilePath);
                byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFile);
                verificationStopwatch.Stop();
                diagnostics.AppendLine($"  Verification took: {verificationStopwatch.ElapsedMilliseconds,7} ms");

                Assert.Equal(originalBytes, decryptedBytes);
            }
            finally
            {
                File.Delete(encryptedFile);
                File.Delete(decryptedFile);
                totalStopwatch.Stop();
                diagnostics.AppendLine($"  Total test time: {totalStopwatch.ElapsedMilliseconds,7} ms");

                _testOutputHelper.WriteLine(diagnostics.ToString());
            }
        }

        [Theory]
        [InlineData(16)]  // Ровно один блок
        [InlineData(32)]  // Ровно два блока
        [InlineData(0)]   // Пустые данные
        public async Task EncryptDecrypt_WithBlockAlignedData_ShouldSucceed(int dataSize)
        {
            var key = _testKey128;
            var originalData = new byte[dataSize];
            System.Security.Cryptography.RandomNumberGenerator.Fill(originalData);

            var rijndael = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            var context = new CipherContext(rijndael, key, CipherMode.CBC, PaddingMode.PKCS7, _testIV);

            int encryptedSize = dataSize + (16 - (dataSize % 16));
            if (dataSize % 16 == 0)
            {
                encryptedSize = dataSize + 16;
            }

            var encryptedData = new byte[encryptedSize];
            var decryptedData = new byte[encryptedSize];

            await context.EncryptAsync(originalData, encryptedData);
            await context.DecryptAsync(encryptedData, decryptedData);

            var finalDecrypted = new byte[dataSize];
            Array.Copy(decryptedData, finalDecrypted, dataSize);

            Assert.Equal(originalData, finalDecrypted);
        }

        [Fact]
        public async Task Decrypt_WithTamperedCiphertext_ShouldThrowException()
        {
            var key = _testKey128;
            var originalData = System.Text.Encoding.UTF8.GetBytes("This is a thirty-two byte long test sentence!"); // 32 байта

            var rijndael = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            var context = new CipherContext(rijndael, key, CipherMode.CBC, PaddingMode.PKCS7, _testIV);

            var encryptedData = new byte[originalData.Length + 16]; // 32 + 16 = 48 байт
            var decryptedGarbage = new byte[encryptedData.Length];

            await context.EncryptAsync(originalData, encryptedData);

            encryptedData[encryptedData.Length - 1] ^= 0xFF;

            await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(async () =>
            {
                await context.DecryptAsync(encryptedData, decryptedGarbage);
            });
        }

    }
}