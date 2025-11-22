using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CryptoLib.DES.Interfaces;
using CryptoLib.DES.Modes;
using Xunit;
using Xunit.Abstractions;

namespace CryptoTests
{
    public class DEAL_AdvancedTests
    {
        // --- 1. ЗАМЕНА КЛЮЧЕЙ И ВЕКТОРОВ НА СООТВЕТСТВУЮЩИЕ DEAL ---

        // Ключ для DEAL-128 (16 байт)
        private readonly byte[] _testKey128 = 
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };

        // Вектор инициализации для DEAL (16 байт, т.к. размер блока 128 бит)
        private readonly byte[] _testIV128 = 
        {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        };

        // ----------------------------------------------------------------

        private readonly ITestOutputHelper _testOutputHelper;

        public DEAL_AdvancedTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        // Этот метод можно оставить без изменений, он универсален
        public static IEnumerable<object[]> TestDataGenerator()
        {
            string[] filePaths = 
            {
                "TestData/text.txt",
                "TestData/image.jpg",
                // "TestData/audio.mp3",
                // "TestData/video.mp4",
                // "TestData/archive.zip"
            };

            var cipherModes = Enum.GetValues<CipherMode>();

            foreach (var filePath in filePaths)
            {
                foreach (var mode in cipherModes)
                {
                    yield return new object[] { filePath, mode };
                }
            }
        }

        [Theory]
        [MemberData(nameof(TestDataGenerator))]
        public async Task DEAL128_ComprehensiveFileEncryptDecrypt_ShouldSucceed(string inputFilePath, CipherMode mode)
        {
            var diagnostics = new System.Text.StringBuilder();
            diagnostics.AppendLine($"\n--- DIAGNOSTICS for {Path.GetFileName(inputFilePath)} [{new FileInfo(inputFilePath).Length / 1024.0:F2} KB] with DEAL-128, {mode} ---");
            var totalStopwatch = System.Diagnostics.Stopwatch.StartNew();

            // Arrange
            Assert.True(File.Exists(inputFilePath), $"Тестовый файл не найден: {inputFilePath}");

            // Используем 16-байтный IV для DEAL
            byte[]? iv = mode == CipherMode.ECB ? null : _testIV128;
            
            // --- 2. КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: ЯВНО УКАЗЫВАЕМ АЛГОРИТМ DEAL ---
            var context = new CipherContext(
                _testKey128, 
                mode, 
                PaddingMode.PKCS7, 
                iv,
                // Этот параметр говорит CipherContext использовать DEAL, а не авто-определять по ключу
                new KeyValuePair<string, object>("Algorithm", "DEAL")
            );
            // -------------------------------------------------------------

            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {
                // Act
                var encryptStopwatch = System.Diagnostics.Stopwatch.StartNew();
                await context.EncryptAsync(inputFilePath, encryptedFile);
                encryptStopwatch.Stop();
                diagnostics.AppendLine($"  Encryption took: {encryptStopwatch.ElapsedMilliseconds,7} ms");

                var decryptStopwatch = System.Diagnostics.Stopwatch.StartNew();
                await context.DecryptAsync(encryptedFile, decryptedFile);
                decryptStopwatch.Stop();
                diagnostics.AppendLine($"  Decryption took: {decryptStopwatch.ElapsedMilliseconds,7} ms");

                // Assert
                var verificationStopwatch = System.Diagnostics.Stopwatch.StartNew();
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
    }
}