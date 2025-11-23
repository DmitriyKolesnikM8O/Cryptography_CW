using Xunit;
using System;
using System.Numerics;
using System.Text;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Linq;

using CryptoLib.New.Protocols.DiffieHellman;

using DesModes = CryptoLib.DES.Modes;

using CryptoLib.Rijndael.Algorithms.Rijndael;
using CryptoLib.Rijndael.Algorithms.Rijndael.Enums;

namespace CryptoTests_New
{
    public class DiffieHellman_UniversalTests
    {
        [Fact]
        public async Task DiffieHellman_Universal_Distribution_Demo()
        {
            
            // 1. Алиса и Боб генерируют свои пары ключей (Приватный + Публичный)
            var aliceDH = new DiffieHellmanProtocol();
            
            var bobDH = new DiffieHellmanProtocol(aliceDH.P, aliceDH.G);

            // 2. Алиса и Боб обмениваются публичными ключами и вычисляют общий математический секрет
            BigInteger aliceSecret = aliceDH.CalculateSharedSecret(bobDH.PublicKey);
            BigInteger bobSecret = bobDH.CalculateSharedSecret(aliceDH.PublicKey);

            // Секреты должны совпадать байт в байт
            Assert.Equal(aliceSecret, bobSecret); 

            {
                int keySize = 8;
                // Превращаем общий секрет в ключ для DES
                byte[] aliceKey = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, keySize);
                byte[] bobKey = DiffieHellmanProtocol.DeriveSymmetricKey(bobSecret, keySize);

                // Генерируем IV (Вектор инициализации), который передается открыто вместе с сообщением
                byte[] iv = GenerateIV(8);

                // Алиса в стране Чудев Шифрует
                var aliceContext = new DesModes.CipherContext(
                    aliceKey,
                    DesModes.CipherMode.CBC,
                    DesModes.PaddingMode.PKCS7,
                    iv,
                    new KeyValuePair<string, object>("Algorithm", "DES")
                );

                string message = "Secret DES message via DH";
                byte[] input = Encoding.UTF8.GetBytes(message);
                byte[] encrypted = new byte[128];
                
                await aliceContext.EncryptAsync(input, encrypted);

                // Боб дешифрует
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

            {
                int keySize = 24;
                byte[] aliceKey = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, keySize);
                byte[] bobKey = DiffieHellmanProtocol.DeriveSymmetricKey(bobSecret, keySize);

                byte[] iv = GenerateIV(8);

                var aliceContext = new DesModes.CipherContext(
                    aliceKey,
                    DesModes.CipherMode.CBC,
                    DesModes.PaddingMode.PKCS7,
                    iv,
                    new KeyValuePair<string, object>("Algorithm", "TripleDES")
                );

                string message = "Super Secret 3DES message via DH";
                byte[] input = Encoding.UTF8.GetBytes(message);
                byte[] encrypted = new byte[128];
                
                await aliceContext.EncryptAsync(input, encrypted);

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

            {
                int keySizeBytes = 32; // AES-256 (32 байта)
                byte[] aliceKey = DiffieHellmanProtocol.DeriveSymmetricKey(aliceSecret, keySizeBytes);
                byte[] bobKey = DiffieHellmanProtocol.DeriveSymmetricKey(bobSecret, keySizeBytes);

                // Шифровка для Алиски
                // Создаем шифр: Ключ 256 бит, Блок 128 бит (стандарт AES)
                // Используем правильные Enums из твоей библиотеки
                var aliceRijndael = new RijndaelCipher(KeySize.K256, CryptoLib.Rijndael.Algorithms.Rijndael.Enums.BlockSize.B128);
                aliceRijndael.SetRoundKeys(aliceKey);

                string message = "RijndaelBlock123";
                byte[] inputBlock = Encoding.UTF8.GetBytes(message);
                
                byte[] encryptedBlock = aliceRijndael.EncryptBlock(inputBlock);

                // Дешифровка для Боба
                var bobRijndael = new RijndaelCipher(KeySize.K256, CryptoLib.Rijndael.Algorithms.Rijndael.Enums.BlockSize.B128);
                bobRijndael.SetRoundKeys(bobKey);
                
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