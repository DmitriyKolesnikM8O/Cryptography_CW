using CryptoLib.DES.Algorithms.DES;
using CryptoLib.DES.Modes;

/*
1. DESAlgorithm_EncryptDecrypt - шифрует ли вообще
2. ECB_Mode - простейший режим шифрования
3. CBC_Mode - режим сцепления блоков
4. WithRandomData - рандомные данные
5. FileEncryption - файловые операции
6. AllCipherModes - все 7 режимов шифрования
7. AllPaddingModes - все 4 режима дополнения
*/


namespace CryptoTests
{
    public class DESTests
    {
        private readonly byte[] _testKey = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        private readonly byte[] _testIV = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        private readonly byte[] _testData = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        /// <summary>
        /// Тестирует базовую функциональность DES алгоритма - шифрование и дешифрование одного блока
        /// Что проверяет: корректность работы ядра DES алгоритма без режимов шифрования
        /// Ожидаемое поведение: зашифрованные и затем расшифрованные данные должны совпадать с исходными
        /// </summary>
        [Fact]
        public void DESAlgorithm_EncryptDecrypt_ShouldReturnOriginalData()
        {

            var des = new DESAlgorithm();
            des.SetRoundKeys(_testKey);


            byte[] encrypted = des.EncryptBlock(_testData);
            byte[] decrypted = des.DecryptBlock(encrypted);


            Assert.Equal(_testData, decrypted);
        }

        /// <summary>
        /// Тестирует режим ECB (Electronic Codebook) - простейший режим шифрования
        /// Что проверяет: корректность работы ECB режима с дополнением PKCS7
        /// Ожидаемое поведение: независимые блоки шифруются одинаково, данные восстанавливаются полностью
        /// </summary>
        [Fact]
        public async Task CipherContext_ECB_Mode_ShouldEncryptDecrypt()
        {

            var context = new CipherContext(_testKey, CipherMode.ECB, PaddingMode.PKCS7, null);

            byte[] testData = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98];


            byte[] outputEncrypt = new byte[100];
            await context.EncryptAsync(testData, outputEncrypt);

            byte[] outputDecrypt = new byte[100];
            await context.DecryptAsync(outputEncrypt, outputDecrypt);


            Assert.Equal(testData, outputDecrypt.Take(testData.Length).ToArray());
        }

        /// <summary>
        /// Тестирует режим CBC (Cipher Block Chaining) - режим сцепления блоков
        /// Что проверяет: корректность работы CBC режима с вектором инициализации
        /// Ожидаемое поведение: каждый блок зависит от предыдущего, данные восстанавливаются полностью
        /// </summary>
        [Fact]
        public async Task CipherContext_CBC_Mode_ShouldEncryptDecrypt()
        {

            var context = new CipherContext(_testKey, CipherMode.CBC, PaddingMode.PKCS7, _testIV);

            byte[] testData = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98];


            byte[] outputEncrypt = new byte[100];
            await context.EncryptAsync(testData, outputEncrypt);

            byte[] outputDecrypt = new byte[100];
            await context.DecryptAsync(outputEncrypt, outputDecrypt);


            Assert.Equal(testData, outputDecrypt.Take(testData.Length).ToArray());
        }

        /// <summary>
        /// Тестирует работу с большими объемами случайных данных
        /// Что проверяет: стабильность алгоритма при обработке данных произвольного размера и содержания
        /// Ожидаемое поведение: 1KB случайных данных должны быть корректно зашифрованы и расшифрованы
        /// </summary>
        [Fact]
        public async Task CipherContext_WithRandomData_ShouldWorkCorrectly()
        {

            var context = new CipherContext(_testKey, CipherMode.CBC, PaddingMode.PKCS7, _testIV);
            Random random = new(42);
            byte[] randomData = new byte[1024]; // 1KB случайных данных
            random.NextBytes(randomData);


            byte[] encrypted = new byte[1100];
            await context.EncryptAsync(randomData, encrypted);

            byte[] decrypted = new byte[1100];
            await context.DecryptAsync(encrypted, decrypted);


            Assert.Equal(randomData, decrypted.Take(randomData.Length).ToArray());
        }

        /// <summary>
        /// Тестирует файловые операции шифрования и дешифрования
        /// Что проверяет: корректность работы с файловой системой и текстовыми данными
        /// Ожидаемое поведение: текстовый файл должен быть зашифрован в бинарный и корректно восстановлен
        /// </summary>
        [Fact]
        public async Task CipherContext_FileEncryption_ShouldWork()
        {

            var context = new CipherContext(_testKey, CipherMode.CBC, PaddingMode.PKCS7, _testIV);

            string testText = "Hello, DES Encryption! This is a test message for file encryption.";
            string inputFile = "test_input.txt";
            string encryptedFile = "test_encrypted.dat";
            string decryptedFile = "test_decrypted.txt";


            await File.WriteAllTextAsync(inputFile, testText);

            try
            {

                await context.EncryptAsync(inputFile, encryptedFile);
                await context.DecryptAsync(encryptedFile, decryptedFile);


                string decryptedText = await File.ReadAllTextAsync(decryptedFile);
                Assert.Equal(testText, decryptedText);
            }
            finally
            {

                if (File.Exists(inputFile)) File.Delete(inputFile);
                if (File.Exists(encryptedFile)) File.Delete(encryptedFile);
                if (File.Exists(decryptedFile)) File.Delete(decryptedFile);
            }
        }

        /// <summary>
        /// Параметризованный тест всех режимов шифрования
        /// Что проверяет: корректность работы всех 7 режимов шифрования (ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta)
        /// Ожидаемое поведение: каждый режим должен корректно шифровать и дешифровать данные
        /// </summary>
        [Theory]
        [InlineData(CipherMode.ECB)]
        [InlineData(CipherMode.CBC)]
        [InlineData(CipherMode.PCBC)]
        [InlineData(CipherMode.CFB)]
        [InlineData(CipherMode.OFB)]
        [InlineData(CipherMode.CTR)]
        [InlineData(CipherMode.RandomDelta)]
        public async Task AllCipherModes_ShouldWorkCorrectly(CipherMode mode)
        {

            byte[]? iv = mode == CipherMode.ECB ? null : _testIV;
            var context = new CipherContext(_testKey, mode, PaddingMode.PKCS7, iv);

            byte[] testData = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98];


            byte[] encrypted = new byte[100];
            await context.EncryptAsync(testData, encrypted);

            byte[] decrypted = new byte[100];
            await context.DecryptAsync(encrypted, decrypted);


            Assert.Equal(testData, decrypted.Take(testData.Length).ToArray());
        }

        /// <summary>
        /// Параметризованный тест всех режимов дополнения (padding)
        /// Что проверяет: корректность работы всех 4 режимов паддинга (Zeros, PKCS7, ANSI X.923, ISO 10126)
        /// Ожидаемое поведение: каждый режим паддинга должен корректно добавлять и удалять дополнение
        /// </summary>
        [Theory]
        [InlineData(PaddingMode.Zeros)]
        [InlineData(PaddingMode.PKCS7)]
        [InlineData(PaddingMode.ANSIX923)]
        [InlineData(PaddingMode.ISO10126)]
        public async Task AllPaddingModes_ShouldWorkCorrectly(PaddingMode padding)
        {

            var context = new CipherContext(_testKey, CipherMode.CBC, padding, _testIV);

            byte[] testData = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];


            byte[] encrypted = new byte[100];
            await context.EncryptAsync(testData, encrypted);

            byte[] decrypted = new byte[100];
            await context.DecryptAsync(encrypted, decrypted);


            Assert.Equal(testData, decrypted.Take(testData.Length).ToArray());
        }
        

    }
}