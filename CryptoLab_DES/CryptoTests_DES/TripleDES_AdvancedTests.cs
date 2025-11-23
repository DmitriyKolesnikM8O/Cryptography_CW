using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CryptoLib.DES.Modes;
using Xunit;
using Xunit.Abstractions;

namespace CryptoTests
{
    public class TripleDES_AdvancedTests
    {

        // Ключ для TripleDES (24 байта / 192 бита)
        // Схема EDE использует 3 ключа по 8 байт
        private readonly byte[] _testKey3DES = 
        {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // K1
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // K2
            0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67  // K3
        };

        
        private readonly byte[] _testIV64 = 
        {
            0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF
        };


        private readonly ITestOutputHelper _testOutputHelper;

        public TripleDES_AdvancedTests(ITestOutputHelper testOutputHelper)
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
                "TestData/archive.zip",
                "TestData/video.mp4",
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
        public async Task TripleDES_ComprehensiveFileEncryptDecrypt_ShouldSucceed(string inputFilePath, CipherMode mode)
        {
            var diagnostics = new System.Text.StringBuilder();
            diagnostics.AppendLine($"\n--- DIAGNOSTICS for {Path.GetFileName(inputFilePath)} [{new FileInfo(inputFilePath).Length / 1024.0:F2} KB] with TripleDES, {mode} ---");
            var totalStopwatch = System.Diagnostics.Stopwatch.StartNew();


            Assert.True(File.Exists(inputFilePath), $"Тестовый файл не найден: {inputFilePath}. Убедитесь, что папка TestData скопирована в output directory.");


            byte[]? iv = mode == CipherMode.ECB ? null : _testIV64;
            

            var context = new CipherContext(
                _testKey3DES, 
                mode, 
                PaddingMode.PKCS7, 
                iv,

                new KeyValuePair<string, object>("Algorithm", "TripleDES")
            );


            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {

                var encryptStopwatch = System.Diagnostics.Stopwatch.StartNew();
                await context.EncryptAsync(inputFilePath, encryptedFile);
                encryptStopwatch.Stop();
                diagnostics.AppendLine($"  Encryption took: {encryptStopwatch.ElapsedMilliseconds,7} ms");


                var decryptStopwatch = System.Diagnostics.Stopwatch.StartNew();
                await context.DecryptAsync(encryptedFile, decryptedFile);
                decryptStopwatch.Stop();
                diagnostics.AppendLine($"  Decryption took: {decryptStopwatch.ElapsedMilliseconds,7} ms");

                var verificationStopwatch = System.Diagnostics.Stopwatch.StartNew();
                byte[] originalBytes = await File.ReadAllBytesAsync(inputFilePath);
                byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFile);
                verificationStopwatch.Stop();
                diagnostics.AppendLine($"  Verification took: {verificationStopwatch.ElapsedMilliseconds,7} ms");
                
                Assert.Equal(originalBytes, decryptedBytes);
            }
            finally
            {

                if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
                
                totalStopwatch.Stop();
                diagnostics.AppendLine($"  Total test time: {totalStopwatch.ElapsedMilliseconds,7} ms");
                
                _testOutputHelper.WriteLine(diagnostics.ToString());
            }
        }
    }
}