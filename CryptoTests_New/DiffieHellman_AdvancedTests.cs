using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;


using CryptoLib.New.Protocols.DiffieHellman;
using DesModes = CryptoLib.DES.Modes;

namespace CryptoTests_New
{
    public class DiffieHellman_AdvancedTests
    {
        private readonly ITestOutputHelper _output;

        public DiffieHellman_AdvancedTests(ITestOutputHelper output)
        {
            _output = output;
        }

        public static IEnumerable<object[]> TestDataGenerator()
        {
            
            string[] filePaths =
            {
                "TestData/text.txt",
                "TestData/image.jpg",
                // "TestData/audio.mp3",
                // "TestData/archive.zip",
                // "TestData/video.mp4",
            };

            foreach (var filePath in filePaths)
            {
                yield return new object[] { filePath };
            }
        }

        [Theory]
        [MemberData(nameof(TestDataGenerator))]
        public async Task DH_SecureFileTransfer_Simulation_ShouldWork(string inputFilePath)
        {
            

            var diagnostics = new System.Text.StringBuilder();
            diagnostics.AppendLine($"\n--- DH SECURE TRANSFER SIMULATION: {Path.GetFileName(inputFilePath)} ---");

            if (!File.Exists(inputFilePath))
            {
                _output.WriteLine($"File not found: {inputFilePath}. Check TestData copy settings.");
                return;
            }

            
            // 1. Алиса и Боб генерируют свои пары DH
            var aliceDH = new DiffieHellmanProtocol();
            var bobDH = new DiffieHellmanProtocol(aliceDH.P, aliceDH.G);

            // 2. Вырабатывают общий секрет
            BigInteger aliceSecret = aliceDH.CalculateSharedSecret(bobDH.PublicKey);
            BigInteger bobSecret = bobDH.CalculateSharedSecret(aliceDH.PublicKey);

            // 3. Превращают секрет в ключ для TripleDES (24 байта)
            int keySize = 24; 
            byte[] aliceKey = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, keySize);
            byte[] bobKey = DiffieHellmanProtocol.DeriveSymmetricKey(bobSecret, keySize);

            // Генерируем IV (публичный параметр, передается с файлом)
            byte[] publicIV = new byte[8];
            new Random().NextBytes(publicIV);

            diagnostics.AppendLine("1. Key Exchange: Success");
            diagnostics.AppendLine($"   Algorithm:    TripleDES (192-bit key)");
            diagnostics.AppendLine($"   Shared Key:   {BitConverter.ToString(aliceKey).Substring(0, 10)}...");


            string encryptedFilePath = Path.GetTempFileName();
            
            // Алиса настраивает свой крипто-контекст
            var aliceContext = new DesModes.CipherContext(
                aliceKey, 
                DesModes.CipherMode.CBC, 
                DesModes.PaddingMode.PKCS7, 
                publicIV,
                new KeyValuePair<string, object>("Algorithm", "TripleDES")
            );

            var encryptWatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Алиса шифрует файл
            await aliceContext.EncryptAsync(inputFilePath, encryptedFilePath);
            
            encryptWatch.Stop();
            diagnostics.AppendLine($"2. Alice Encrypted file. Time: {encryptWatch.ElapsedMilliseconds} ms");

            string decryptedFilePath = Path.GetTempFileName();

            // Боб настраивает СВОЙ контекст (используя свой вычисленный ключ bobKey)
            var bobContext = new DesModes.CipherContext(
                bobKey, 
                DesModes.CipherMode.CBC, 
                DesModes.PaddingMode.PKCS7, 
                publicIV, 
                new KeyValuePair<string, object>("Algorithm", "TripleDES")
            );

            var decryptWatch = System.Diagnostics.Stopwatch.StartNew();

            // Боб дешифрует файл
            await bobContext.DecryptAsync(encryptedFilePath, decryptedFilePath);

            decryptWatch.Stop();
            diagnostics.AppendLine($"3. Bob Decrypted file.   Time: {decryptWatch.ElapsedMilliseconds} ms");

            byte[] originalBytes = await File.ReadAllBytesAsync(inputFilePath);
            byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFilePath);

            Assert.Equal(originalBytes, decryptedBytes);

            diagnostics.AppendLine($"4. Verification: Success. MD5 matched (implicitly via byte compare).");
            
            if (File.Exists(encryptedFilePath)) File.Delete(encryptedFilePath);
            if (File.Exists(decryptedFilePath)) File.Delete(decryptedFilePath);

            _output.WriteLine(diagnostics.ToString());
        }
    }
}