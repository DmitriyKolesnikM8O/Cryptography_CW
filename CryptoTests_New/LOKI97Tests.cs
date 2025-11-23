using Xunit;
using Xunit.Abstractions; // Для вывода логов
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics; // Для Stopwatch
using System.Text;        // Для StringBuilder

// Подключаем наше ядро LOKI97
using CryptoLib.New.Algorithms.LOKI97;
// Подключаем НОВЫЙ контекст
using CryptoLib.New.Modes; 
// Подключаем Enums
using CryptoLib.DES.Modes; 

namespace CryptoTests_New
{
    public class LOKI97Tests
    {
        private readonly ITestOutputHelper _output;

        // Внедряем помощник вывода через конструктор
        public LOKI97Tests(ITestOutputHelper output)
        {
            _output = output;
        }

        // ==========================================
        // 1. Unit Tests для самого алгоритма (ядро)
        // ==========================================

        [Fact]
        public void LOKI97_Core_EncryptDecrypt_128BitKey_ShouldWork()
        {
            byte[] key = new byte[16];
            for (int i = 0; i < 16; i++) key[i] = (byte)i;

            byte[] block = new byte[16];
            Array.Fill(block, (byte)0xAA);

            var loki = new LOKI97Algorithm();
            loki.SetRoundKeys(key);

            byte[] encrypted = loki.EncryptBlock(block);
            byte[] decrypted = loki.DecryptBlock(encrypted);

            Assert.NotEqual(block, encrypted);
            Assert.Equal(block, decrypted);
        }

        [Fact]
        public void LOKI97_Core_EncryptDecrypt_256BitKey_ShouldWork()
        {
            byte[] key = new byte[32];
            new Random().NextBytes(key);

            byte[] block = new byte[16];
            new Random().NextBytes(block);

            var loki = new LOKI97Algorithm();
            loki.SetRoundKeys(key);

            byte[] enc = loki.EncryptBlock(block);
            byte[] dec = loki.DecryptBlock(enc);

            Assert.Equal(block, dec);
        }

        // ==========================================
        // 2. Advanced Integration Tests (Files + Context + Logs)
        // ==========================================

        public static IEnumerable<object[]> TestDataGenerator()
        {
            string[] filePaths =
            {
                "TestData/text.txt",
                "TestData/image.jpg"
            };

            var modes = Enum.GetValues<CipherMode>();

            foreach (var path in filePaths)
            {
                foreach (var mode in modes)
                {
                    yield return new object[] { path, mode };
                }
            }
        }

        [Theory]
        [MemberData(nameof(TestDataGenerator))]
        public async Task LOKI97_CipherContext_FileTest(string inputFilePath, CipherMode mode)
        {
            // 1. Настройка диагностики
            var diagnostics = new StringBuilder();
            string fileName = Path.GetFileName(inputFilePath);
            double fileSizeKb = File.Exists(inputFilePath) ? new FileInfo(inputFilePath).Length / 1024.0 : 0;

            diagnostics.AppendLine($"\n--- DIAGNOSTICS for {fileName} [{fileSizeKb:F2} KB] with LOKI97, {mode} ---");
            var totalStopwatch = Stopwatch.StartNew();

            // 2. Arrange
            if (!File.Exists(inputFilePath))
            {
                _output.WriteLine($"File not found: {inputFilePath}. Skipping.");
                return;
            }

            byte[] key = new byte[24]; // 192 bit key
            new Random().NextBytes(key);

            byte[] iv = new byte[16]; // 128 bit IV
            new Random().NextBytes(iv);
            if (mode == CipherMode.ECB) iv = null;

            // Используем CipherContextLOKI97
            var context = new CipherContextLOKI97(key, mode, PaddingMode.PKCS7, iv);

            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {
                // 3. Act - Encryption
                var encryptStopwatch = Stopwatch.StartNew();
                await context.EncryptAsync(inputFilePath, encryptedFile);
                encryptStopwatch.Stop();
                diagnostics.AppendLine($"  Encryption took: {encryptStopwatch.ElapsedMilliseconds,7} ms");

                // 4. Act - Decryption
                var contextDecrypt = new CipherContextLOKI97(key, mode, PaddingMode.PKCS7, iv);

                var decryptStopwatch = Stopwatch.StartNew();
                await contextDecrypt.DecryptAsync(encryptedFile, decryptedFile);
                decryptStopwatch.Stop();
                diagnostics.AppendLine($"  Decryption took: {decryptStopwatch.ElapsedMilliseconds,7} ms");

                // 5. Assert - Verification
                var verificationStopwatch = Stopwatch.StartNew();
                byte[] originalBytes = await File.ReadAllBytesAsync(inputFilePath);
                byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFile);
                verificationStopwatch.Stop();
                diagnostics.AppendLine($"  Verification took: {verificationStopwatch.ElapsedMilliseconds,7} ms");

                Assert.Equal(originalBytes, decryptedBytes);
            }
            finally
            {
                // Cleanup & Output
                if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                if (File.Exists(decryptedFile)) File.Delete(decryptedFile);

                totalStopwatch.Stop();
                diagnostics.AppendLine($"  Total test time: {totalStopwatch.ElapsedMilliseconds,7} ms");

                // Вывод в консоль теста
                _output.WriteLine(diagnostics.ToString());
            }
        }

        [Fact]
        public void LOKI97_DifferentPolynomials_ShouldProduceDifferentCiphertext()
        {
            byte[] key = new byte[16];
            byte[] block = new byte[16];
            
            var loki1 = new LOKI97Algorithm((byte)0x1B); // AES poly
            loki1.SetRoundKeys(key);
            byte[] enc1 = loki1.EncryptBlock(block);

            var loki2 = new LOKI97Algorithm((byte)0x1D); // Other poly
            loki2.SetRoundKeys(key);
            byte[] enc2 = loki2.EncryptBlock(block);

            Assert.NotEqual(enc1, enc2);
        }
    }
}