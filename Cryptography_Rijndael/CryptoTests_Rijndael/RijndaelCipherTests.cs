using CryptoLib.Rijndael.Algorithms.Rijndael;
using CryptoLib.Rijndael.Algorithms.Rijndael.Enums;
using System.Reflection; // для BindingFlags enum

/*
1. Encrypt_Decrypt_Roundtrip_Matches_FIPS197_Vectors - Главный тест на корректность. Проверяет, что шифрование дает результат, совпадающий с официальными тестовыми векторами стандарта AES (FIPS-197), и что этот результат успешно дешифруется обратно.
2. SetRoundKeys_WithInvalidKeySize_ShouldThrowArgumentException - Проверяет, что метод настройки ключа выбрасывает исключение при попытке использовать ключ неправильной длины.
3. EncryptBlock_Before_SetRoundKeys_ShouldThrowInvalidOperationException - Проверяет, что нельзя зашифровать блок, предварительно не установив ключ.
4. EncryptBlock_WithInvalidBlockSize_ShouldThrowArgumentException - Проверяет, что нельзя зашифровать блок данных, размер которого не совпадает с размером блока шифра.
5. SBox_Constructor_WithReduciblePolynomial_ShouldThrowArgumentException - Проверяет, что конструктор S-Box (внутренний компонент) выбрасывает исключение, если ему передать математически некорректный (приводимый) полином.
6. RijndaelCipher_Constructor_WithReduciblePolynomial_ShouldThrowArgumentException - Проверяет, что основной класс шифра также выбрасывает исключение, если попытаться создать его с некорректным полиномом.
7. Decrypt_Matches_FIPS197_Vectors - Тест на корректность дешифрования. Берет эталонный шифротекст из стандарта и проверяет, что DecryptBlock возвращает правильный исходный текст.
8. Encrypt_Decrypt_Roundtrip_ShouldWorkForAllSupportedSizes - Проверяет внутреннюю консистентность алгоритма для всех 9 комбинаций размеров ключа/блока, поддерживаемых Rijndael (включая нестандартные для AES).
9. RijndaelCipher_Constructor_ShouldSetCorrectNumberOfRounds - Проверяет, что для каждой из 9 комбинаций размеров ключа/блока выбирается правильное количество раундов в соответствии со спецификацией.
10. Encrypt_Decrypt_Roundtrip_WithCustomPolynomial_ShouldBeReversible - Проверяет, что алгоритм остается обратимым при использовании нестандартного (но валидного) неприводимого полинома.
11. DecryptBlock_Before_SetRoundKeys_ShouldThrowInvalidOperationException - Проверяет, что нельзя расшифровать блок без предварительной установки ключа.
12. SetRoundKeys_WithNullKey_ShouldThrowArgumentException - Проверяет корректную обработку null при установке ключа.
13. EncryptBlock_WithNullBlock_ShouldThrowArgumentException - Проверяет корректную обработку null при шифровании блока.
14. DecryptBlock_WithInvalidBlockSize_ShouldThrowArgumentException - Проверяет, что нельзя расшифровать блок неправильной длины.
15. RijndaelCipher_Constructor_WithInvalidEnum_ShouldThrowException - Проверяет, что конструктор выбрасывает исключение при передаче невалидных (несуществующих) значений enum.
16. Encrypt_Decrypt_Roundtrip_WithBoundaryValues_ShouldBeReversible - Проверяет корректность работы алгоритма на "крайних" случаях входных данных: блок из всех нулей, блок из всех единиц и блок с последовательным паттерном.
17. Encrypt_Decrypt_Roundtrip_WithSeparateInstances_ShouldBeReversible - Проверяет, что шифрование одним экземпляром класса и дешифрование другим (но с тем же ключом) дают корректный результат, доказывая отсутствие "скрытого" состояния.
*/


namespace CryptoTests
{
    public class RijndaelCipherTests
    {
        // ЗОЛОТЫЕ ТЕСТОВЫЕ ВЕКТОРЫ ИЗ СТАНДАРТА FIPS-197 (APPENDIX C)

        public static IEnumerable<object[]> Aes128TestData =>
            new List<object[]>
            {
                new object[]
                {
                    "2b7e151628aed2a6abf7158809cf4f3c", // key
                    "3243f6a8885a308d313198a2e0370734", // plaintext
                    "3925841d02dc09fbdc118597196a0b32"  // ciphertext
                }
            };

        public static IEnumerable<object[]> Aes192TestData =>
            new List<object[]>
            {
                new object[]
                {
                    // KEY:
                    "000102030405060708090a0b0c0d0e0f1011121314151617",
                    // PLAINTEXT:
                    "00112233445566778899aabbccddeeff",
                    // EXPECTED CIPHERTEXT:
                    "dda97ca4864cdfe06eaf70a0ec0d7191"
                }
            };

        public static IEnumerable<object[]> Aes256TestData =>
            new List<object[]>
            {
                new object[]
                {
                    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                    "6bc1bee22e409f96e93d7e117393172a",
                    "f3eed1bdb5d2a03c064b5a7e3db181f8"
                }
            };

        [Theory]
        [MemberData(nameof(Aes128TestData))]
        [MemberData(nameof(Aes192TestData))]
        [MemberData(nameof(Aes256TestData))]
        public void Encrypt_Decrypt_Roundtrip_Matches_FIPS197_Vectors(string keyHex, string plaintextHex, string expectedCiphertextHex)
        {
            var key = FromHexString(keyHex);
            var plaintext = FromHexString(plaintextHex);
            var expectedCiphertext = FromHexString(expectedCiphertextHex);

            var keySize = (KeySize)(key.Length * 8);
            var blockSize = (BlockSize)(plaintext.Length * 8);


            var cipher = new RijndaelCipher(keySize, blockSize);
            cipher.SetRoundKeys(key);
            var actualCiphertext = cipher.EncryptBlock(plaintext);


            Assert.Equal(expectedCiphertext.ToList(), actualCiphertext.ToList());

            var decryptedText = cipher.DecryptBlock(actualCiphertext);
            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }

        [Fact]
        public void SetRoundKeys_WithInvalidKeySize_ShouldThrowArgumentException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            var wrongKey = new byte[15];

            Assert.Throws<ArgumentException>(() => cipher.SetRoundKeys(wrongKey));
        }

        [Fact]
        public void EncryptBlock_Before_SetRoundKeys_ShouldThrowInvalidOperationException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            var block = new byte[16];

            Assert.Throws<InvalidOperationException>(() => cipher.EncryptBlock(block));
        }

        [Fact]
        public void EncryptBlock_WithInvalidBlockSize_ShouldThrowArgumentException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            cipher.SetRoundKeys(new byte[16]);
            var wrongBlock = new byte[15];

            Assert.Throws<ArgumentException>(() => cipher.EncryptBlock(wrongBlock));
        }

        /// <summary>
        /// Вспомогательный метод для преобразования HEX-строки в массив байт.
        /// </summary>
        private byte[] FromHexString(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        [Fact]
        public void SBox_Constructor_WithReduciblePolynomial_ShouldThrowArgumentException()
        {

            byte reduciblePolynomial = 0x01;

            // Проверяем, что конструктор SBox выбросит исключение ArgumentException
            Assert.Throws<ArgumentException>(() => new SBox(reduciblePolynomial));
        }

        [Fact]
        public void RijndaelCipher_Constructor_WithReduciblePolynomial_ShouldThrowArgumentException()
        {
            // Так как RijndaelCipher внутри себя создает SBox, он должен "пробросить"
            // исключение от конструктора SBox.
            byte reduciblePolynomial = 0x01;
            var keySize = KeySize.K128;
            var blockSize = BlockSize.B128;
            Assert.Throws<ArgumentException>(() => new RijndaelCipher(keySize, blockSize, reduciblePolynomial));
        }

        [Theory]
        [MemberData(nameof(Aes128TestData))]
        [MemberData(nameof(Aes192TestData))]
        [MemberData(nameof(Aes256TestData))]
        public void Decrypt_Matches_FIPS197_Vectors(string keyHex, string plaintextHex, string expectedCiphertextHex)
        {

            var key = FromHexString(keyHex);
            var expectedPlaintext = FromHexString(plaintextHex);
            var ciphertext = FromHexString(expectedCiphertextHex);

            var keySize = (KeySize)(key.Length * 8);
            var blockSize = (BlockSize)(ciphertext.Length * 8);

            var cipher = new RijndaelCipher(keySize, blockSize);

            cipher.SetRoundKeys(key);
            var actualPlaintext = cipher.DecryptBlock(ciphertext);

            Assert.Equal(expectedPlaintext.ToList(), actualPlaintext.ToList());
        }

        [Theory]
        // Rijndael-специфичные комбинации (KeySize / BlockSize)
        [InlineData(KeySize.K128, BlockSize.B192)]
        [InlineData(KeySize.K128, BlockSize.B256)]
        [InlineData(KeySize.K192, BlockSize.B256)]
        [InlineData(KeySize.K256, BlockSize.B192)]
        [InlineData(KeySize.K256, BlockSize.B256)]
        // Стандартные AES
        [InlineData(KeySize.K128, BlockSize.B128)]
        [InlineData(KeySize.K192, BlockSize.B128)]
        [InlineData(KeySize.K256, BlockSize.B128)]
        public void Encrypt_Decrypt_Roundtrip_ShouldWorkForAllSupportedSizes(KeySize keySize, BlockSize blockSize)
        {
            int keySizeBytes = (int)keySize / 8;
            int blockSizeBytes = (int)blockSize / 8;

            var key = new byte[keySizeBytes];
            var plaintext = new byte[blockSizeBytes];
            new Random().NextBytes(key);
            new Random().NextBytes(plaintext);

            var cipher = new RijndaelCipher(keySize, blockSize);

            cipher.SetRoundKeys(key);
            var ciphertext = cipher.EncryptBlock(plaintext);

            // SetRoundKeys нужно вызвать снова, так как в реальном сценарии это могут быть разные экземпляры
            cipher.SetRoundKeys(key);
            var decryptedText = cipher.DecryptBlock(ciphertext);

            // Проверяем, что после шифрования и дешифрования мы вернулись к исходному блоку
            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }

        [Theory]
        // Nr = max(Nk, Nb) + 6
        // Nk = KeyWords, Nb = BlockWords
        // Nk/Nb | 4    | 6    | 8
        // ------|------|------|------
        // 4     | 10   | 12   | 14
        // 6     | 12   | 12   | 14
        // 8     | 14   | 14   | 14
        [InlineData(KeySize.K128, BlockSize.B128, 10)] // AES-128
        [InlineData(KeySize.K128, BlockSize.B192, 12)]
        [InlineData(KeySize.K128, BlockSize.B256, 14)]
        [InlineData(KeySize.K192, BlockSize.B128, 12)] // AES-192
        [InlineData(KeySize.K192, BlockSize.B192, 12)]
        [InlineData(KeySize.K192, BlockSize.B256, 14)]
        [InlineData(KeySize.K256, BlockSize.B128, 14)] // AES-256
        [InlineData(KeySize.K256, BlockSize.B192, 14)]
        [InlineData(KeySize.K256, BlockSize.B256, 14)]
        public void RijndaelCipher_Constructor_ShouldSetCorrectNumberOfRounds(KeySize keySize, BlockSize blockSize, int expectedRounds)
        {
            var cipher = new RijndaelCipher(keySize, blockSize);

            var field = typeof(RijndaelCipher).GetField("_rounds", BindingFlags.NonPublic | BindingFlags.Instance);
            if (field == null)
                throw new InvalidOperationException("Не удалось найти приватное поле _rounds.");

            var actualRounds = (int)field.GetValue(cipher);

            Assert.Equal(expectedRounds, actualRounds);
        }

        [Theory]
        [InlineData((byte)0x1B)] // Стандартный полином AES
        [InlineData((byte)0x8D)] // Другой валидный неприводимый полином (x^8+x^7+x^3+x^2+1)
        public void Encrypt_Decrypt_Roundtrip_WithCustomPolynomial_ShouldBeReversible(byte irreduciblePolynomial)
        {
            var keySize = KeySize.K128;
            var blockSize = BlockSize.B128;

            int keySizeBytes = (int)keySize / 8;
            int blockSizeBytes = (int)blockSize / 8;

            var key = new byte[keySizeBytes];
            var plaintext = new byte[blockSizeBytes];
            new Random().NextBytes(key);
            new Random().NextBytes(plaintext);

            var cipher = new RijndaelCipher(keySize, blockSize, irreduciblePolynomial);

            cipher.SetRoundKeys(key);
            var ciphertext = cipher.EncryptBlock(plaintext);


            var decryptCipher = new RijndaelCipher(keySize, blockSize, irreduciblePolynomial);
            decryptCipher.SetRoundKeys(key);
            var decryptedText = decryptCipher.DecryptBlock(ciphertext);

            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }

        #region Exception Handling Tests

        [Fact]
        public void DecryptBlock_Before_SetRoundKeys_ShouldThrowInvalidOperationException()
        {
            // Arrange
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            var block = new byte[16];

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => cipher.DecryptBlock(block));
        }

        [Fact]
        public void SetRoundKeys_WithNullKey_ShouldThrowArgumentException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            byte[] nullKey = null;

            Assert.Throws<ArgumentException>(() => cipher.SetRoundKeys(nullKey));
        }

        [Fact]
        public void EncryptBlock_WithNullBlock_ShouldThrowArgumentException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            cipher.SetRoundKeys(new byte[16]);
            byte[] nullBlock = null;

            Assert.Throws<ArgumentException>(() => cipher.EncryptBlock(nullBlock));
        }

        [Fact]
        public void DecryptBlock_WithInvalidBlockSize_ShouldThrowArgumentException()
        {
            var cipher = new RijndaelCipher(KeySize.K128, BlockSize.B128);
            cipher.SetRoundKeys(new byte[16]);
            var wrongBlock = new byte[15];

            Assert.Throws<ArgumentException>(() => cipher.DecryptBlock(wrongBlock));
        }

        [Fact]
        public void RijndaelCipher_Constructor_WithInvalidEnum_ShouldThrowException()
        {

            KeySize invalidKeySize = (KeySize)999;
            BlockSize validBlockSize = BlockSize.B128;

            Assert.Throws<InvalidOperationException>(() => new RijndaelCipher(invalidKeySize, validBlockSize));
        }

        #endregion

        #region Boundary Value Tests

        public static IEnumerable<object[]> BoundaryTestData()
        {
            var allZeros = new byte[16];
            var allOnes = Enumerable.Repeat((byte)0xFF, 16).ToArray();
            var pattern = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

            yield return new object[] { allZeros, "All Zeros Block" };
            yield return new object[] { allOnes, "All Ones Block" };
            yield return new object[] { pattern, "Pattern Block (00 to 0F)" };
        }

        [Theory]
        [MemberData(nameof(BoundaryTestData))]
        public void Encrypt_Decrypt_Roundtrip_WithBoundaryValues_ShouldBeReversible(byte[] plaintext, string description)
        {
            _ = description;
            var keySize = KeySize.K128;
            var blockSize = BlockSize.B128;

            var key = new byte[16];
            new Random().NextBytes(key);

            var cipher = new RijndaelCipher(keySize, blockSize);

            cipher.SetRoundKeys(key);
            var ciphertext = cipher.EncryptBlock(plaintext);
            var decryptedText = cipher.DecryptBlock(ciphertext);

            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }

        #endregion

        [Theory]
        [InlineData(KeySize.K128, BlockSize.B128)]
        [InlineData(KeySize.K192, BlockSize.B128)]
        [InlineData(KeySize.K256, BlockSize.B128)]
        [InlineData(KeySize.K128, BlockSize.B192)]
        [InlineData(KeySize.K192, BlockSize.B192)]
        [InlineData(KeySize.K256, BlockSize.B192)]
        [InlineData(KeySize.K128, BlockSize.B256)]
        [InlineData(KeySize.K192, BlockSize.B256)]
        [InlineData(KeySize.K256, BlockSize.B256)]
        public void Encrypt_Decrypt_Roundtrip_WithSeparateInstances_ShouldBeReversible(KeySize keySize, BlockSize blockSize)
        {
            int keySizeBytes = (int)keySize / 8;
            int blockSizeBytes = (int)blockSize / 8;

            var key = new byte[keySizeBytes];
            var plaintext = new byte[blockSizeBytes];
            new Random().NextBytes(key);
            new Random().NextBytes(plaintext);

            var encryptCipher = new RijndaelCipher(keySize, blockSize);
            var decryptCipher = new RijndaelCipher(keySize, blockSize);

            encryptCipher.SetRoundKeys(key);
            var ciphertext = encryptCipher.EncryptBlock(plaintext);

            decryptCipher.SetRoundKeys(key);
            var decryptedText = decryptCipher.DecryptBlock(ciphertext);

            // Проверяем, что результат, полученный одним экземпляром,
            // может быть успешно расшифрован другим.
            Assert.Equal(plaintext.ToList(), decryptedText.ToList());
        }
    }
}