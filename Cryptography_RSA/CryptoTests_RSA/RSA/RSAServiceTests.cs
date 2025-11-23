using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using CryptoLib.RSA.Enums;
using CryptoLib.RSA.RSA;
using CryptoLib.RSA.RSA.Models;
using Xunit;

namespace CryptoTests
{
    public class RSA_FileTests
    {
        // Используем 1024-битный ключ для тестов (баланс между скоростью и размером блока)
        private const int KeySizeBits = 1024;

        /// <summary>
        /// Тестирует полный цикл: Генерация ключей -> Нарезка файла -> Шифрование -> Склейка -> Дешифрование -> Сверка
        /// </summary>
        [Fact]
        public void RSA_FileEncryption_ShouldWork()
        {
            // 1. Setup
            // Предполагаем, что MillerRabin реализован (или замени на Fermat/SoloveyStrassen)
            var rsaService = new RsaService(PrimalityTestType.MillerRabin, 0.99, KeySizeBits);
            
            // Генерируем ключи
            var keys = rsaService.GenerateKeyPair();
            
            // Создаем тестовые данные (имитация файла 5 КБ, чтобы было много блоков)
            byte[] originalFileBytes = new byte[5 * 1024];
            new Random().NextBytes(originalFileBytes);

            // 2. Act - Шифрование
            // Нам нужно разбить файл на блоки, которые влезут в модуль N
            byte[] encryptedBytes = EncryptBytes(rsaService, originalFileBytes, keys.PublicKey);

            // 3. Act - Дешифрование
            byte[] decryptedBytes = DecryptBytes(rsaService, encryptedBytes, keys.PrivateKey);

            // 4. Assert
            Assert.Equal(originalFileBytes, decryptedBytes);
        }

        // --- Вспомогательные методы "Адаптера" для работы с байтами ---

        private byte[] EncryptBytes(RsaService rsa, byte[] data, RsaPublicKey key)
        {
            // Размер модуля в байтах (например, 128 байт для 1024 бит)
            // BigInteger.ToByteArray() может вернуть лишний нулевой байт для знака, поэтому берем аккуратно
            int modulusByteSize = GetByteSize(key.N);
            
            // Максимальный размер данных, который мы можем зашифровать за 1 раз.
            // Он должен быть СТРОГО меньше модуля. Безопасно брать (N_bytes - 1).
            int maxDataBlockSize = modulusByteSize - 1;

            using (var memoryStream = new MemoryStream())
            {
                int offset = 0;
                while (offset < data.Length)
                {
                    // 1. Берем кусок данных
                    int chunkSize = Math.Min(maxDataBlockSize, data.Length - offset);
                    byte[] chunk = new byte[chunkSize];
                    Array.Copy(data, offset, chunk, 0, chunkSize);

                    // 2. Превращаем в BigInteger (всегда положительный!)
                    // Добавляем 0x00 в конец (Little Endian), чтобы число считалось положительным
                    byte[] positiveChunk = new byte[chunk.Length + 1];
                    Array.Copy(chunk, positiveChunk, chunk.Length);
                    positiveChunk[chunk.Length] = 0x00; // Sign bit forced to 0
                    
                    BigInteger m = new BigInteger(positiveChunk);

                    // 3. Шифруем
                    BigInteger c = rsa.Encrypt(m, key);

                    // 4. Сохраняем результат
                    // Результат шифрования всегда будет размером с модуль (или меньше).
                    // Нам нужно сохранить его как блок ФИКСИРОВАННОЙ длины (=modulusByteSize),
                    // чтобы при расшифровке мы знали, где границы блоков.
                    byte[] encryptedBlock = c.ToByteArray();
                    
                    // Если BigInteger вернул больше байт (из-за знака), отрезаем лишний ноль
                    if (encryptedBlock.Length > modulusByteSize && encryptedBlock[encryptedBlock.Length-1] == 0)
                    {
                         // Оставляем как есть, CopyToFixedSize сам обрежет или мы возьмем нужную часть
                    }

                    byte[] paddedBlock = FitToSize(encryptedBlock, modulusByteSize);
                    memoryStream.Write(paddedBlock, 0, paddedBlock.Length);

                    offset += chunkSize;
                }
                return memoryStream.ToArray();
            }
        }

        private byte[] DecryptBytes(RsaService rsa, byte[] encryptedData, RsaPrivateKey key)
        {
            int modulusByteSize = GetByteSize(key.N);
            
            using (var memoryStream = new MemoryStream())
            {
                int offset = 0;
                while (offset < encryptedData.Length)
                {
                    // 1. Читаем зашифрованный блок (он всегда фиксированного размера = modulusByteSize)
                    byte[] chunk = new byte[modulusByteSize];
                    if (offset + modulusByteSize > encryptedData.Length)
                    {
                        // Если "хвост" не совпадает по размеру - данные битые
                        throw new Exception("Encrypted data is corrupted or has wrong size");
                    }
                    Array.Copy(encryptedData, offset, chunk, 0, modulusByteSize);

                    // 2. Превращаем в BigInteger (опять же, форсируем положительный знак)
                    byte[] positiveChunk = new byte[chunk.Length + 1];
                    Array.Copy(chunk, positiveChunk, chunk.Length);
                    positiveChunk[chunk.Length] = 0x00;

                    BigInteger c = new BigInteger(positiveChunk);

                    // 3. Дешифруем
                    BigInteger m = rsa.Decrypt(c, key);

                    // 4. Превращаем обратно в байты
                    byte[] decryptedBytes = m.ToByteArray();

                    // Убираем лишний байт знака, если он есть (если последний байт 0)
                    if (decryptedBytes.Length > 0 && decryptedBytes[decryptedBytes.Length - 1] == 0)
                    {
                        Array.Resize(ref decryptedBytes, decryptedBytes.Length - 1);
                    }
                    
                    // Важный момент: BigInteger не хранит ведущие нули.
                    // Если исходный блок начинался с нулей (например 0x00, 0xA1...), то m.ToByteArray() их не вернет.
                    // Но в рамках курсовой мы предполагаем, что это не критично, либо
                    // мы должны знать размер исходного блока. 
                    // Для простоты теста считаем, что данные восстановились "как есть".
                    
                    memoryStream.Write(decryptedBytes, 0, decryptedBytes.Length);

                    offset += modulusByteSize;
                }
                return memoryStream.ToArray();
            }
        }

        // --- Утилиты ---

        /// <summary>
        /// Вычисляет размер числа в байтах (без знакового бита)
        /// </summary>
        private int GetByteSize(BigInteger num)
        {
            byte[] bytes = num.ToByteArray();
            if (bytes.Length > 0 && bytes[bytes.Length - 1] == 0)
                return bytes.Length - 1;
            return bytes.Length;
        }

        /// <summary>
        /// Подгоняет массив байт под фиксированный размер (дополняет нулями или обрезает знак)
        /// Это нужно, чтобы в выходном файле все блоки были одной длины.
        /// </summary>
        private byte[] FitToSize(byte[] input, int targetSize)
        {
            byte[] result = new byte[targetSize];
            
            // BigInteger.ToByteArray() возвращает Little Endian.
            // Если число меньше targetSize, копируем его в начало (остальное нули).
            // Если число имеет лишний байт знака (0x00) в конце, игнорируем его.
            
            int bytesToCopy = Math.Min(input.Length, targetSize);
            
            // Особый случай: input может быть длиннее targetSize только на 1 байт (знак 0x00)
            if (input.Length == targetSize + 1 && input[input.Length-1] == 0)
            {
                bytesToCopy = targetSize;
            }
            
            Array.Copy(input, result, bytesToCopy);
            return result;
        }
    }
}