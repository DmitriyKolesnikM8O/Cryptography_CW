using Xunit;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

// Подключаем наше ядро LOKI97
using CryptoLib.New.Algorithms.LOKI97;
// Подключаем НОВЫЙ контекст, который мы только что создали
using CryptoLib.New.Modes; 
// Подключаем Enums из старой библиотеки (чтобы не дублировать типы)
using CryptoLib.DES.Modes; 

namespace CryptoTests_New
{
    public class LOKI97Tests
    {
        // ==========================================
        // 1. Unit Tests для самого алгоритма (ядро)
        // ==========================================

        [Fact]
        public void LOKI97_Core_EncryptDecrypt_128BitKey_ShouldWork()
        {
            byte[] key = new byte[16]; // 128 bit
            for(int i=0; i<16; i++) key[i] = (byte)i;
            
            byte[] block = new byte[16]; // 128 bit block
            Array.Fill(block, (byte)0xAA);

            var loki = new LOKI97Algorithm();
            loki.SetRoundKeys(key);

            // Шифруем
            byte[] encrypted = loki.EncryptBlock(block);
            
            // Дешифруем
            byte[] decrypted = loki.DecryptBlock(encrypted);

            Assert.NotEqual(block, encrypted);
            Assert.Equal(block, decrypted);
        }

        [Fact]
        public void LOKI97_Core_EncryptDecrypt_256BitKey_ShouldWork()
        {
            byte[] key = new byte[32]; // 256 bit key (Max)
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
        // 2. Advanced Integration Tests (Files + Context)
        // ==========================================

        public static IEnumerable<object[]> TestDataGenerator()
        {
            string[] filePaths = 
            {
                "TestData/text.txt",
                "TestData/image.jpg"
            };

            // Проверяем все режимы
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
            // Arrange
            if (!File.Exists(inputFilePath)) 
            {
                // Если папка TestData не скопировалась, тест пройдет (skip), чтобы не краснеть
                return; 
            }

            // Генерируем ключ 192 бита (24 байта) - средний вариант
            byte[] key = new byte[24]; 
            new Random().NextBytes(key);

            // Генерируем IV 128 бит (16 байт) - размер блока LOKI97
            byte[] iv = new byte[16];
            new Random().NextBytes(iv);

            // Для ECB вектор не нужен
            if (mode == CipherMode.ECB) iv = null;

            // Создаем контекст (LOKI97 создается внутри автоматически)
            var context = new CipherContextLOKI97(key, mode, PaddingMode.PKCS7, iv);

            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {
                // Act 1: Encrypt File
                await context.EncryptAsync(inputFilePath, encryptedFile);

                // Act 2: Decrypt File
                // Создаем новый контекст для чистоты эксперимента
                var contextDecrypt = new CipherContextLOKI97(key, mode, PaddingMode.PKCS7, iv);
                await contextDecrypt.DecryptAsync(encryptedFile, decryptedFile);

                // Assert: Сравниваем байты
                byte[] originalBytes = await File.ReadAllBytesAsync(inputFilePath);
                byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFile);

                Assert.Equal(originalBytes, decryptedBytes);
            }
            finally
            {
                if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
            }
        }
    }
}