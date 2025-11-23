using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Threading.Tasks;
using CryptoLib.RSA.Enums;
using CryptoLib.RSA.RSA;
using CryptoLib.RSA.RSA.Models;
using Xunit;
using Xunit.Abstractions;

namespace CryptoTests
{
    public class RSA_AdvancedTests
    {
        private readonly ITestOutputHelper _output;
        private const int KeySize = 1024;

        public RSA_AdvancedTests(ITestOutputHelper testOutputHelper)
        {
            _output = testOutputHelper;
        }

        public static IEnumerable<object[]> TestDataGenerator()
        {
            
            string[] filePaths =
            {
                "TestData/text.txt",
                "TestData/image.jpg",
                "TestData/video.mp4",
                "TestData/audio.mp3",
                "TestData/archive.zip",
            };

            foreach (var filePath in filePaths)
            {
                yield return new object[] { filePath };
            }
        }

        [Theory]
        [MemberData(nameof(TestDataGenerator))]
        public void RSA_ComprehensiveFileEncryptDecrypt_ShouldSucceed(string inputFilePath)
        {
            var diagnostics = new System.Text.StringBuilder();
            diagnostics.AppendLine($"\n--- DIAGNOSTICS for {Path.GetFileName(inputFilePath)} ---");
            var totalStopwatch = System.Diagnostics.Stopwatch.StartNew();

            
            if (!File.Exists(inputFilePath))
            {
                _output.WriteLine($"File not found: {inputFilePath}. Skipping.");
                return;
            }

            // RSA ОЧЕНЬ медленный. Если файл большой (> 20KB), тест будет идти вечность.
            string limitedInputFile = CreateLimitedTestFile(inputFilePath);
            long fileSize = new FileInfo(limitedInputFile).Length;
            diagnostics.AppendLine($"Testing on file size: {fileSize} bytes");

            var rsaService = new RsaService(PrimalityTestType.MillerRabin, 0.99, KeySize);
            var keys = rsaService.GenerateKeyPair();
            
            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {
                
                _output.WriteLine("Starting Encryption...");
                var encryptStopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                RsaFileCipher.EncryptFileStream(limitedInputFile, encryptedFile, rsaService, keys.PublicKey, 
                    prog => _output.WriteLine($"Encrypting: {prog}%"));
                
                encryptStopwatch.Stop();
                diagnostics.AppendLine($"  Encryption took:  {encryptStopwatch.ElapsedMilliseconds,7} ms");

                
                _output.WriteLine("Starting Decryption...");
                var decryptStopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                RsaFileCipher.DecryptFileStream(encryptedFile, decryptedFile, rsaService, keys.PrivateKey,
                    prog => _output.WriteLine($"Decrypting: {prog}%"));
                
                decryptStopwatch.Stop();
                diagnostics.AppendLine($"  Decryption took:  {decryptStopwatch.ElapsedMilliseconds,7} ms");

                
                byte[] originalBytes = File.ReadAllBytes(limitedInputFile);
                byte[] decryptedBytes = File.ReadAllBytes(decryptedFile);
                
                Assert.Equal(originalBytes, decryptedBytes);
            }
            finally
            {
                
                if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
                if (limitedInputFile != inputFilePath && File.Exists(limitedInputFile)) File.Delete(limitedInputFile);

                totalStopwatch.Stop();
                _output.WriteLine(diagnostics.ToString());
            }
        }

        // Создает временный файл с первыми 10KB данных, если исходный слишком большой
        private string CreateLimitedTestFile(string originalPath)
        {
            const int MaxSize = 10 * 1024;
            var fileInfo = new FileInfo(originalPath);
            
            if (fileInfo.Length <= MaxSize) return originalPath;

            string tempPath = Path.GetTempFileName();
            using (var source = new FileStream(originalPath, FileMode.Open, FileAccess.Read))
            using (var dest = new FileStream(tempPath, FileMode.Create, FileAccess.Write))
            {
                byte[] buffer = new byte[MaxSize];
                source.Read(buffer, 0, MaxSize);
                dest.Write(buffer, 0, MaxSize);
            }
            return tempPath;
        }
    }

    /// <summary>
    /// Исправленный статический помощник для потокового шифрования RSA.
    /// Теперь корректно обрабатывает бинарные нули, добавляя маркерный байт.
    /// </summary>
    public static class RsaFileCipher
    {
        public static void EncryptFileStream(string inputFile, string outputFile, RsaService rsa, RsaPublicKey key, Action<int> onProgress)
        {
            int keySizeBytes = GetKeyByteSize(key.N);
            
            int inputBlockSize = keySizeBytes - 2; 
            
            int outputBlockSize = keySizeBytes;

            long totalLength = new FileInfo(inputFile).Length;
            long processed = 0;

            using (var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                byte[] buffer = new byte[inputBlockSize];
                int bytesRead;
                int lastProgress = 0;

                while ((bytesRead = inputStream.Read(buffer, 0, inputBlockSize)) > 0)
                {

                    byte[] chunk = new byte[bytesRead];
                    Array.Copy(buffer, chunk, bytesRead);

                    byte[] fullBlock = new byte[chunk.Length + 2];
                    Array.Copy(chunk, fullBlock, chunk.Length);
                    fullBlock[chunk.Length] = 0x01;     // Маркер, который не даст пропасть нулям
                    fullBlock[chunk.Length + 1] = 0x00; // Знак +

                    BigInteger m = new BigInteger(fullBlock);

                    BigInteger c = rsa.Encrypt(m, key);

                    byte[] encryptedBlock = c.ToByteArray();
                    byte[] finalBlock = FitToSize(encryptedBlock, outputBlockSize);
                    
                    outputStream.Write(finalBlock, 0, finalBlock.Length);


                    processed += bytesRead;
                    int percent = (int)((processed * 100) / totalLength);
                    if (percent >= lastProgress + 10)
                    {
                        onProgress?.Invoke(percent);
                        lastProgress = percent;
                    }
                }
            }
        }

        public static void DecryptFileStream(string inputFile, string outputFile, RsaService rsa, RsaPrivateKey key, Action<int> onProgress)
        {
            int keySizeBytes = GetKeyByteSize(key.N);
            int inputBlockSize = keySizeBytes;

            long totalLength = new FileInfo(inputFile).Length;
            long processed = 0;

            using (var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                byte[] buffer = new byte[inputBlockSize];
                int bytesRead;
                int lastProgress = 0;

                while ((bytesRead = inputStream.Read(buffer, 0, inputBlockSize)) > 0)
                {
                    if (bytesRead != inputBlockSize)
                        throw new Exception("Encrypted file corrupted: wrong block size");

                    byte[] positiveChunk = new byte[inputBlockSize + 1];
                    Array.Copy(buffer, positiveChunk, inputBlockSize);
                    positiveChunk[inputBlockSize] = 0x00;

                    BigInteger c = new BigInteger(positiveChunk);

                    BigInteger m = rsa.Decrypt(c, key);

                    byte[] decryptedWithPadding = m.ToByteArray();
                
                    int endIndex = decryptedWithPadding.Length - 1;
                    if (endIndex >= 0 && decryptedWithPadding[endIndex] == 0x00)
                    {
                        endIndex--;
                    }
                    
                    if (endIndex >= 0 && decryptedWithPadding[endIndex] == 0x01)
                    {                    

                        outputStream.Write(decryptedWithPadding, 0, endIndex);
                    }
                    else
                    {
                        throw new Exception("Decryption error: Marker byte missing.");
                    }

            
                    processed += bytesRead;
                    int percent = (int)((processed * 100) / totalLength);
                    if (percent >= lastProgress + 10)
                    {
                        onProgress?.Invoke(percent);
                        lastProgress = percent;
                    }
                }
            }
        }

        private static int GetKeyByteSize(BigInteger n)
        {
            byte[] bytes = n.ToByteArray();
            if (bytes.Length > 0 && bytes[bytes.Length - 1] == 0)
                return bytes.Length - 1;
            return bytes.Length;
        }

        private static byte[] FitToSize(byte[] input, int targetSize)
        {
            byte[] result = new byte[targetSize];
            int bytesToCopy = Math.Min(input.Length, targetSize);
            
            // Если массив длиннее только на 1 нулевой байт (знак), то это нормально
            if (input.Length == targetSize + 1 && input[input.Length - 1] == 0)
            {
                bytesToCopy = targetSize;
            }
            
            Array.Copy(input, result, bytesToCopy);
            return result;
        }
    }
}