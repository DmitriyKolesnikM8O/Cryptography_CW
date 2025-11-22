using CryptoLib.DES.Algorithms.DEAL;
using CryptoLib.DES.Modes;

/*
1. DEAL128_EncryptDecrypt - базовое шифрование/дешифрование 128-битным ключом
2. DEAL192_EncryptDecrypt - базовое шифрование/дешифрование 192-битным ключом
3. DEAL256_EncryptDecrypt - базовое шифрование/дешифрование 256-битным ключом
4. CipherContext_WithDEAL128 - интеграция DEAL с CipherContext и CBC режимом
5. DEAL128_WithDifferentDataSizes - работа с данными разного размера (16, 32, 48, 64 байт)
6. DEAL_AllKeySizes - тест всех размеров ключей (128, 192, 256 бит)
7. DEAL128_WithAllCipherModes - тест всех режимов шифрования (ECB, CBC, PCBC, CFB, OFB, CTR)
8. DEALKeyScheduler_ShouldGenerateCorrectNumberOfKeys - проверка генерации раундовых ключей
*/


namespace CryptoTests
{
    public class DEALTests
    {
        private readonly byte[] _testKey128 = [
            0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
        ];

        private readonly byte[] _testKey192 = [
            0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x33, 0x55, 0x77, 0x99, 0xBB, 0xDD, 0xFF
        ];

        private readonly byte[] _testKey256 = [
            0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            0x11, 0x33, 0x55, 0x77, 0x99, 0xBB, 0xDD, 0xFF,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE
        ];

        private readonly byte[] _testIV = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ];

        private readonly byte[] _testData = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ];

        /// <summary>
        /// Тестирует DEAL-128 алгоритм - базовое шифрование и дешифрование
        /// Что проверяет: корректность работы DEAL с 128-битным ключом
        /// Ожидаемое поведение: зашифрованные и затем расшифрованные данные должны совпадать с исходными
        /// </summary>
        [Fact]
        public void DEAL128_EncryptDecrypt_ShouldReturnOriginalData()
        {
            
            var deal = new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_128);
            deal.SetRoundKeys(_testKey128);

            
            byte[] encrypted = deal.EncryptBlock(_testData);
            byte[] decrypted = deal.DecryptBlock(encrypted);

            
            Assert.Equal(_testData, decrypted);
        }

        /// <summary>
        /// Тестирует DEAL-192 алгоритм - базовое шифрование и дешифрование
        /// Что проверяет: корректность работы DEAL с 192-битным ключом
        /// Ожидаемое поведение: зашифрованные и затем расшифрованные данные должны совпадать с исходными
        /// </summary>
        [Fact]
        public void DEAL192_EncryptDecrypt_ShouldReturnOriginalData()
        {
            
            var deal = new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_192);
            deal.SetRoundKeys(_testKey192);

            
            byte[] encrypted = deal.EncryptBlock(_testData);
            byte[] decrypted = deal.DecryptBlock(encrypted);

            
            Assert.Equal(_testData, decrypted);
        }

        /// <summary>
        /// Тестирует DEAL-256 алгоритм - базовое шифрование и дешифрование
        /// Что проверяет: корректность работы DEAL с 256-битным ключом
        /// Ожидаемое поведение: зашифрованные и затем расшифрованные данные должны совпадать с исходными
        /// </summary>
        [Fact]
        public void DEAL256_EncryptDecrypt_ShouldReturnOriginalData()
        {
            
            var deal = new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_256);
            deal.SetRoundKeys(_testKey256);

            
            byte[] encrypted = deal.EncryptBlock(_testData);
            byte[] decrypted = deal.DecryptBlock(encrypted);

            
            Assert.Equal(_testData, decrypted);
        }

        /// <summary>
        /// Тестирует DEAL в контексте шифрования с режимом CBC
        /// Что проверяет: интеграцию DEAL с CipherContext и режимами шифрования
        /// Ожидаемое поведение: данные должны корректно шифроваться и дешифроваться через CipherContext
        /// </summary>
        [Fact]
        public async Task CipherContext_WithDEAL128_ShouldWorkCorrectly()
        {
            
            var context = new CipherContext(_testKey128, CipherMode.CBC, PaddingMode.PKCS7, _testIV,
                new KeyValuePair<string, object>("Algorithm", "DEAL"));

            byte[] testData = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
            ];

            
            byte[] encrypted = new byte[100];
            await context.EncryptAsync(testData, encrypted);

            byte[] decrypted = new byte[100];
            await context.DecryptAsync(encrypted, decrypted);

            
            Assert.Equal(testData, decrypted.Take(testData.Length).ToArray());
        }

        /// <summary>
        /// Тестирует DEAL с различными размерами данных
        /// Что проверяет: корректность работы с данными разного размера
        /// Ожидаемое поведение: данные разного размера должны корректно шифроваться и дешифроваться
        /// </summary>
        [Theory]
        [InlineData(16)]   // Один блок
        [InlineData(32)]   // Два блока  
        [InlineData(48)]   // Три блока
        [InlineData(64)]   // Четыре блока
        public async Task DEAL128_WithDifferentDataSizes_ShouldWorkCorrectly(int dataSize)
        {
            
            
            var context = new CipherContext(_testKey128, CipherMode.CBC, PaddingMode.PKCS7, _testIV);

            byte[] testData = new byte[dataSize];
            new Random(42).NextBytes(testData);

            int expectedEncryptedSize = dataSize + 16; 
            
            
            byte[] encrypted = new byte[expectedEncryptedSize];
            await context.EncryptAsync(testData, encrypted);

            byte[] decrypted = new byte[expectedEncryptedSize];
            await context.DecryptAsync(encrypted, decrypted);

            
            Assert.Equal(testData, decrypted.Take(testData.Length).ToArray());
        }

        /// <summary>
        /// Тестирует все ключевые размеры DEAL алгоритма
        /// Что проверяет: корректность работы DEAL с 128, 192 и 256-битными ключами
        /// Ожидаемое поведение: все варианты ключей должны работать корректно
        /// </summary>
        [Theory]
        [InlineData(DEALKeyScheduler.KeyType.KEY_SIZE_128)]
        [InlineData(DEALKeyScheduler.KeyType.KEY_SIZE_192)]
        [InlineData(DEALKeyScheduler.KeyType.KEY_SIZE_256)]
        public void DEAL_AllKeySizes_ShouldWorkCorrectly(DEALKeyScheduler.KeyType keyType)
        {
            
            byte[] key = keyType switch
            {
                DEALKeyScheduler.KeyType.KEY_SIZE_128 => _testKey128,
                DEALKeyScheduler.KeyType.KEY_SIZE_192 => _testKey192,
                DEALKeyScheduler.KeyType.KEY_SIZE_256 => _testKey256,
                _ => throw new ArgumentException("Unknown key type")
            };

            var deal = new DEALAlgorithm(keyType);
            deal.SetRoundKeys(key);

            
            byte[] encrypted = deal.EncryptBlock(_testData);
            byte[] decrypted = deal.DecryptBlock(encrypted);

            
            Assert.Equal(_testData, decrypted);
        }

        /// <summary>
        /// Тестирует DEAL с различными режимами шифрования
        /// </summary>
        [Theory]
        [InlineData(CipherMode.ECB)]
        [InlineData(CipherMode.CBC)]
        [InlineData(CipherMode.PCBC)]
        [InlineData(CipherMode.CFB)]
        [InlineData(CipherMode.OFB)]
        [InlineData(CipherMode.CTR)]
        public async Task DEAL128_WithAllCipherModes_ShouldWorkCorrectly(CipherMode mode)
        {
            
            byte[]? iv = mode == CipherMode.ECB ? null : _testIV;
            
            byte[] testData = [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
            ];

            var context = new CipherContext(_testKey128, mode, PaddingMode.Zeros, iv,
                new KeyValuePair<string, object>("Algorithm", "DEAL"));

            
            byte[] encrypted = new byte[16];
            await context.EncryptAsync(testData, encrypted);

            byte[] decrypted = new byte[16]; 
            await context.DecryptAsync(encrypted, decrypted);

            // Assert
            Assert.Equal(testData, decrypted);
        }


        /// <summary>
        /// Тестирует корректность работы KeyScheduler для DEAL
        /// Что проверяет: правильность генерации раундовых ключей
        /// Ожидаемое поведение: KeyScheduler должен генерировать правильное количество раундовых ключей
        /// </summary>
        [Theory]
        [InlineData(DEALKeyScheduler.KeyType.KEY_SIZE_128, 6)]
        [InlineData(DEALKeyScheduler.KeyType.KEY_SIZE_192, 8)]
        [InlineData(DEALKeyScheduler.KeyType.KEY_SIZE_256, 8)]
        public void DEALKeyScheduler_ShouldGenerateCorrectNumberOfKeys(DEALKeyScheduler.KeyType keyType, int expectedRounds)
        {
            
            byte[] key = keyType switch
            {
                DEALKeyScheduler.KeyType.KEY_SIZE_128 => _testKey128,
                DEALKeyScheduler.KeyType.KEY_SIZE_192 => _testKey192,
                DEALKeyScheduler.KeyType.KEY_SIZE_256 => _testKey256,
                _ => throw new ArgumentException("Unknown key type")
            };

            var keyScheduler = new DEALKeyScheduler(keyType);

            
            byte[][] roundKeys = keyScheduler.ExpandKey(key);

            
            Assert.Equal(expectedRounds, roundKeys.Length);
            foreach (var roundKey in roundKeys)
            {
                Assert.NotNull(roundKey);
                Assert.Equal(8, roundKey.Length);
            }
        }
    }
}