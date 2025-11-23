using Xunit;
using System;
using System.Linq;
using CryptoLib.DES.Algorithms.TripleDES;
using CryptoLib.DES.Interfaces;

namespace CryptoTests
{
    public class TripleDESTests
    {
        // 24 байта (192 бита) - стандартный ключ для 3-Key TripleDES
        private readonly byte[] _tripleDesKey = 
        {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // K1
            0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, // K2
            0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23  // K3
        };

        private readonly byte[] _block = { 0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74 }; // "Now is t"

        /// <summary>
        /// Проверяет, что зашифрованный и затем расшифрованный блок совпадает с исходным.
        /// (Round-trip test)
        /// </summary>
        [Fact]
        public void TripleDES_EncryptDecrypt_ShouldReturnOriginalData()
        {
            
            var tdes = new TripleDESAlgorithm();
            tdes.SetRoundKeys(_tripleDesKey);

            
            byte[] encrypted = tdes.EncryptBlock(_block);
            byte[] decrypted = tdes.DecryptBlock(encrypted);

            
            Assert.NotEqual(_block, encrypted); // Шифротекст не должен совпадать с открытым текстом
            Assert.Equal(_block, decrypted);    // После расшифровки должны получить исходное
        }

        

        /// <summary>
        /// Проверяет, что алгоритм выбрасывает ошибку, если ключ неправильной длины.
        /// DES требует 8 байт, а TripleDES обязан требовать 24 байта.
        /// </summary>
        [Fact]
        public void TripleDES_ShouldThrow_OnWrongKeySize()
        {
            var tdes = new TripleDESAlgorithm();
            
            
            byte[] wrongKey = new byte[8]; 
            
            Assert.Throws<ArgumentException>(() => tdes.SetRoundKeys(wrongKey));
        }


        [Theory]
        [InlineData(CryptoLib.DES.Modes.CipherMode.ECB)]
        [InlineData(CryptoLib.DES.Modes.CipherMode.CBC)]
        [InlineData(CryptoLib.DES.Modes.CipherMode.PCBC)]
        [InlineData(CryptoLib.DES.Modes.CipherMode.CFB)]
        [InlineData(CryptoLib.DES.Modes.CipherMode.OFB)]
        [InlineData(CryptoLib.DES.Modes.CipherMode.CTR)]
        [InlineData(CryptoLib.DES.Modes.CipherMode.RandomDelta)]
        public async Task TripleDES_AllModes_IntegrationTest(CryptoLib.DES.Modes.CipherMode mode)
        {
            
            
            byte[] key = new byte[24];
            new Random().NextBytes(key);

            
            
            byte[] iv = new byte[8];
            new Random().NextBytes(iv);
            if (mode == CryptoLib.DES.Modes.CipherMode.ECB)
            {
                iv = null;
            }

            
            
            var algoParam = new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", "TripleDES");

            var context = new CryptoLib.DES.Modes.CipherContext(
                key, 
                mode, 
                CryptoLib.DES.Modes.PaddingMode.PKCS7, 
                iv, 
                algoParam
            );

            string originalText = $"Testing TripleDES with mode {mode}";
            byte[] inputData = System.Text.Encoding.UTF8.GetBytes(originalText);
            
            
            byte[] encryptedBuffer = new byte[128];
            byte[] decryptedBuffer = new byte[128];

            
            await context.EncryptAsync(inputData, encryptedBuffer);
            await context.DecryptAsync(encryptedBuffer, decryptedBuffer);

            
            
            byte[] resultBytes = decryptedBuffer.Take(inputData.Length).ToArray();
            string resultText = System.Text.Encoding.UTF8.GetString(resultBytes);

            Assert.Equal(originalText, resultText);
        }

        // Вспомогательный метод для перевода HEX строки в байты
        private byte[] HexToBytes(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}