using System;
using CryptoLib.DES.Interfaces;

namespace CryptoLib.DES.Algorithms.DEAL
{
    /// <summary>
    /// Реализует специализированную сеть Фейстеля для алгоритма DEAL.
    /// В отличие от классической сети, DEAL работает с блоками размером 128 бит (16 байт)
    /// и использует алгоритм DES в качестве своей раундовой функции F.
    /// </summary>
    /// <param name="keyScheduler">Планировщик ключей, отвечающий за генерацию раундовых ключей DEAL.</param>
    /// <param name="feistelFunction">Раундовая функция F, которая для DEAL является инкапсуляцией шифра DES.</param>
    /// <param name="rounds">Количество раундов шифрования (6 для DEAL-128/192, 8 для DEAL-256).</param>
    public class FeistelNetworkDEAL(
        IKeyScheduler keyScheduler,
        IFeistelFunction feistelFunction,
        int rounds) : ISymmetricCipher
    {
        private readonly IKeyScheduler _keyScheduler = keyScheduler ?? throw new ArgumentNullException(nameof(keyScheduler));
        private readonly IFeistelFunction _feistelFunction = feistelFunction ?? throw new ArgumentNullException(nameof(feistelFunction));
        private readonly int _rounds = rounds > 0 ? rounds : throw new ArgumentException("Количество раундов должно быть положительным", nameof(rounds));
        private byte[][]? _roundKeys;
        private bool _keysSet = false;

        public int BlockSize => 16;

        public int KeySize => throw new NotImplementedException("KeySize определяется в DEALAlgorithm");

        /// <summary>
        /// Генерирует и устанавливает раундовые ключи на основе основного ключа DEAL.
        /// Этот метод должен быть вызван перед началом любой операции шифрования или дешифрования.
        /// </summary>
        /// <param name="key">Основной ключ алгоритма DEAL (16, 24 или 32 байта).</param>
        /// <exception cref="ArgumentNullException">Вызывается, если ключ равен null.</exception>
        /// <exception cref="ArgumentException">Вызывается, если длина ключа не соответствует поддерживаемым размерам DEAL.</exception>
        public void SetRoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));


            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("DEAL key must be 16, 24, or 32 bytes");

            _roundKeys = _keyScheduler.ExpandKey(key);
            _keysSet = true;
        }

        /// <summary>
        /// Шифрует один 128-битный (16-байтный) блок данных с использованием сети Фейстеля DEAL.
        /// </summary>
        /// <param name="block">Входной блок открытого текста размером 16 байт.</param>
        /// <returns>Зашифрованный блок данных размером 16 байт.</returns>
        /// <exception cref="InvalidOperationException">Вызывается, если раундовые ключи не были установлены.</exception>
        /// <exception cref="ArgumentNullException">Вызывается, если входной блок равен null.</exception>
        /// <exception cref="ArgumentException">Вызывается, если размер входного блока не равен 16 байтам.</exception>
        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Раундовые ключи не установлены. Вызовите SetRoundKeys сначала.");
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSize)
                throw new ArgumentException($"Размер блока должен быть {BlockSize} байт для DEAL");

            int halfSize = 8; // 64 бита
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            for (int round = 0; round < _rounds; round++)
            {
                byte[] temp = right;

                byte[] feistelResult = _feistelFunction.Execute(right, _roundKeys[round]);

                right = XorBlocks(left, feistelResult);
                left = temp;
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, 0, halfSize);
            Array.Copy(right, 0, result, halfSize, halfSize);

            return result;
        }

        /// <summary>
        /// Дешифрует один 128-битный (16-байтный) блок данных.
        /// Процесс является обратным шифрованию и использует раундовые ключи в обратном порядке.
        /// </summary>
        /// <param name="block">Входной блок шифротекста размером 16 байт.</param>
        /// <returns>Расшифрованный блок данных размером 16 байт.</returns>
        /// <exception cref="InvalidOperationException">Вызывается, если раундовые ключи не были установлены.</exception>
        /// <exception cref="ArgumentNullException">Вызывается, если входной блок равен null.</exception>
        /// <exception cref="ArgumentException">Вызывается, если размер входного блока не равен 16 байтам.</exception>
        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Раундовые ключи не установлены. Вызовите SetRoundKeys сначала.");
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSize)
                throw new ArgumentException($"Размер блока должен быть {BlockSize} байт для DEAL");

            int halfSize = 8; // 64 бита
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            for (int round = _rounds - 1; round >= 0; round--)
            {
                byte[] temp = left;

                byte[] feistelResult = _feistelFunction.Execute(left, _roundKeys[round]);

                left = XorBlocks(right, feistelResult);
                right = temp;
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, 0, halfSize);
            Array.Copy(right, 0, result, halfSize, halfSize);

            return result;
        }

        /// <summary>
        /// Выполняет операцию XOR между двумя блоками данных
        /// </summary>
        private byte[] XorBlocks(byte[] block1, byte[] block2)
        {
            if (block1.Length != block2.Length)
                throw new ArgumentException("Блоки должны быть одинакового размера");

            byte[] result = new byte[block1.Length];
            for (int i = 0; i < block1.Length; i++)
            {
                result[i] = (byte)(block1[i] ^ block2[i]);
            }
            return result;
        }
    }
}