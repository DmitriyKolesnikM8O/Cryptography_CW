using Xunit;
using System;
using System.Numerics;
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;

// Подключаем наш новый протокол
using CryptoLib.New.Protocols.DiffieHellman;

// Подключаем библиотеку DES (используем псевдоним DesModes, чтобы не путать с другими режимами)
using DesModes = CryptoLib.DES.Modes;

// Подключаем библиотеку Rijndael
using CryptoLib.Rijndael.Algorithms.Rijndael;
using CryptoLib.Rijndael.Algorithms.Rijndael.Enums;

namespace CryptoTests_New
{
    public class DiffieHellman_UniversalTests
    {
        [Fact]
        public async Task DiffieHellman_Universal_Distribution_Demo()
        {
            // ====================================================================================
            // ЭТАП 1: УСТАНОВЛЕНИЕ ЗАЩИЩЕННОГО КАНАЛА (Diffie-Hellman)
            // ====================================================================================
            
            // 1. Алиса и Боб генерируют свои пары ключей (Приватный + Публичный)
            var aliceDH = new DiffieHellmanProtocol();
            
            // (В реальности публичный ключ передается по сети)
            var bobDH = new DiffieHellmanProtocol(aliceDH.P, aliceDH.G);

            // 2. Алиса и Боб обмениваются публичными ключами и вычисляют общий математический секрет
            BigInteger aliceSecret = aliceDH.CalculateSharedSecret(bobDH.PublicKey);
            BigInteger bobSecret = bobDH.CalculateSharedSecret(aliceDH.PublicKey);

            // Проверка: Секреты должны совпадать байт в байт
            Assert.Equal(aliceSecret, bobSecret); 


            // ====================================================================================
            // ЭТАП 2: ИНТЕГРАЦИЯ С DES (Требуется ключ 8 байт / 64 бита)
            // ====================================================================================
            {
                int keySize = 8;
                // Превращаем общий секрет в ключ для DES
                byte[] aliceKey = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, keySize);
                byte[] bobKey = DiffieHellmanProtocol.DeriveSymmetricKey(bobSecret, keySize);

                // Генерируем IV (Вектор инициализации), который передается открыто вместе с сообщением
                byte[] iv = GenerateIV(8);

                // --- АЛИСА ШИФРУЕТ ---
                var aliceContext = new DesModes.CipherContext(
                    aliceKey,
                    DesModes.CipherMode.CBC,
                    DesModes.PaddingMode.PKCS7,
                    iv,
                    new KeyValuePair<string, object>("Algorithm", "DES") // Явное указание алгоритма
                );

                string message = "Secret DES message via DH";
                byte[] input = Encoding.UTF8.GetBytes(message);
                byte[] encrypted = new byte[128]; // Буфер с запасом
                
                await aliceContext.EncryptAsync(input, encrypted);

                // --- БОБ ДЕШИФРУЕТ ---
                var bobContext = new DesModes.CipherContext(
                    bobKey, // Боб использует СВОЙ ключ, полученный из DH
                    DesModes.CipherMode.CBC,
                    DesModes.PaddingMode.PKCS7,
                    iv,     // И тот же IV, который пришел с сообщением
                    new KeyValuePair<string, object>("Algorithm", "DES")
                );

                byte[] decrypted = new byte[128];
                await bobContext.DecryptAsync(encrypted, decrypted);
                
                // Убираем нулевые байты из буфера и сверяем текст
                string result = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                Assert.Contains(message, result);
            }

            // ====================================================================================
            // ЭТАП 3: ИНТЕГРАЦИЯ С TripleDES (Требуется ключ 24 байта / 192 бита)
            // ====================================================================================
            {
                int keySize = 24;
                // Превращаем тот же секрет в более длинный ключ для 3DES
                byte[] aliceKey = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, keySize);
                byte[] bobKey = DiffieHellmanProtocol.DeriveSymmetricKey(bobSecret, keySize);

                // IV для 3DES такой же как у DES (8 байт)
                byte[] iv = GenerateIV(8);

                // --- АЛИСА ШИФРУЕТ ---
                var aliceContext = new DesModes.CipherContext(
                    aliceKey,
                    DesModes.CipherMode.CBC,
                    DesModes.PaddingMode.PKCS7,
                    iv,
                    new KeyValuePair<string, object>("Algorithm", "TripleDES") // Явное указание 3DES
                );

                string message = "Super Secret 3DES message via DH";
                byte[] input = Encoding.UTF8.GetBytes(message);
                byte[] encrypted = new byte[128];
                
                await aliceContext.EncryptAsync(input, encrypted);

                // --- БОБ ДЕШИФРУЕТ ---
                var bobContext = new DesModes.CipherContext(
                    bobKey,
                    DesModes.CipherMode.CBC,
                    DesModes.PaddingMode.PKCS7,
                    iv,
                    new KeyValuePair<string, object>("Algorithm", "TripleDES")
                );

                byte[] decrypted = new byte[128];
                await bobContext.DecryptAsync(encrypted, decrypted);
                
                string result = Encoding.UTF8.GetString(decrypted).TrimEnd('\0');
                Assert.Contains(message, result);
            }

            // ====================================================================================
            // ЭТАП 4: ИНТЕГРАЦИЯ С RIJNDAEL (AES) (Требуется ключ 32 байта / 256 бит)
            // ====================================================================================
            {
                int keySizeBytes = 32; // AES-256 (32 байта)
                // Генерируем ключ из секрета DH
                byte[] aliceKey = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, keySizeBytes);
                byte[] bobKey = DiffieHellmanProtocol.DeriveSymmetricKey(bobSecret, keySizeBytes);

                // --- АЛИСА ШИФРУЕТ ---
                // Создаем шифр: Ключ 256 бит, Блок 128 бит (стандарт AES)
                // Используем правильные Enums из твоей библиотеки
                var aliceRijndael = new RijndaelCipher(KeySize.K256, CryptoLib.Rijndael.Algorithms.Rijndael.Enums.BlockSize.B128);
                aliceRijndael.SetRoundKeys(aliceKey); // Устанавливаем ключ

                string message = "RijndaelBlock123"; // Ровно 16 байт (128 бит) для теста одного блока
                byte[] inputBlock = Encoding.UTF8.GetBytes(message);
                
                byte[] encryptedBlock = aliceRijndael.EncryptBlock(inputBlock);

                // --- БОБ ДЕШИФРУЕТ ---
                var bobRijndael = new RijndaelCipher(KeySize.K256, CryptoLib.Rijndael.Algorithms.Rijndael.Enums.BlockSize.B128);
                bobRijndael.SetRoundKeys(bobKey); // Боб использует свой ключ
                
                byte[] decryptedBlock = bobRijndael.DecryptBlock(encryptedBlock);

                string result = Encoding.UTF8.GetString(decryptedBlock);
                Assert.Equal(message, result);
            }
        }

        /// <summary>
        /// Вспомогательный метод для генерации случайного IV
        /// </summary>
        private byte[] GenerateIV(int size)
        {
            byte[] iv = new byte[size];
            new Random().NextBytes(iv);
            return iv;
        }
    }
}