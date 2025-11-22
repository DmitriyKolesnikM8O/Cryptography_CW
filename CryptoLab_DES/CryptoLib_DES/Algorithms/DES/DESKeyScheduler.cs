using CryptoLib.DES.Core;
using CryptoLib.DES.Interfaces;

namespace CryptoLib.DES.Algorithms.DES
{
    /// <summary>
    /// Реализует планировщик ключей для алгоритма DES.
    /// Этот класс отвечает за генерацию (расширение) 16 раундовых 48-битных ключей из одного 64-битного основного ключа.
    /// Процесс включает начальную перестановку (PC1), разделение на две 28-битные половины, циклические сдвиги и сжимающую перестановку (PC2) для каждого раунда.
    /// </summary>
    public class DESKeyScheduler : IKeyScheduler
    {
        /// <summary>
        /// Генерирует 16 раундовых 48-битных ключей из основного 64-битного ключа DES.
        /// </summary>
        /// <param name="inputKey">Основной 64-битный (8-байтный) ключ DES. Биты четности игнорируются в процессе генерации.</param>
        /// <returns>Зубчатый массив (16x6 байт), где каждый элемент является 48-битным раундовым ключом.</returns>
        /// <exception cref="ArgumentException">Вызывается, если длина ключа не равна 8 байтам.</exception>
        public byte[][] ExpandKey(byte[] inputKey)
        {
            if (inputKey.Length != 8)
                throw new ArgumentException("DES key must be 64 bits (8 bytes)");

            byte[][] roundKeys = new byte[16][];

            // 1. Начальная перестановка ключа (Permuted Choice 1): 64 бита -> 56 бит (биты четности отбрасываются)
            byte[] pc1Key = BitPermutation.PermutationBytes(inputKey, DESTables.PC1, false, false);

            // 2. Разделение 56-битного ключа на две 28-битные половины (C0 и D0)
            uint left = Get28Bits(pc1Key, 0);
            uint right = Get28Bits(pc1Key, 28);

            // 3. Генерация 16 раундовых ключей
            for (int i = 0; i < 16; i++)
            {
               // 3a. Циклический сдвиг влево для каждой половины. Количество сдвигов зависит от номера раунда.
                left = LeftShift28(left, DESTables.SHIFTS[i]);
                right = LeftShift28(right, DESTables.SHIFTS[i]);

                // 3b. Объединение сдвинутых половин (56 бит) и применение сжимающей перестановки (Permuted Choice 2): 56 бит -> 48 бит
                byte[] combined = Combine28Bits(left, right);
                roundKeys[i] = BitPermutation.PermutationBytes(combined, DESTables.PC2, false, false);
            }

            return roundKeys;
        }

        /// <summary>
        /// Вспомогательный метод для извлечения 28 бит из массива байтов, начиная с указанной битовой позиции.
        /// Результат упаковывается в 32-битное беззнаковое целое (uint) для удобства битовых операций.
        /// </summary>
        private uint Get28Bits(byte[] data, int startBit)
        {
            uint result = 0;
            for (int i = 0; i < 28; i++)
            {
                int byteIndex = (startBit + i) / 8;
                int bitIndex = (startBit + i) % 8;
                if (byteIndex < data.Length)
                {
                    bool bitValue = (data[byteIndex] & (1 << (7 - bitIndex))) != 0;
                    if (bitValue)
                        result |= 1u << (27 - i);
                }
            }
            return result;
        }

        /// <summary>
        /// Вспомогательный метод для объединения двух 28-битных половин (left и right) в один 56-битный (7-байтный) массив.
        /// </summary>
        private byte[] Combine28Bits(uint left, uint right)
        {
            byte[] result = new byte[7]; // 56 бит = 7 байт
            for (int i = 0; i < 28; i++)
            {
                bool leftBit = (left & (1u << (27 - i))) != 0;
                bool rightBit = (right & (1u << (27 - i))) != 0;

                int byteIndex = i / 8;
                int bitIndex = i % 8;

                if (leftBit)
                    result[byteIndex] |= (byte)(1 << (7 - bitIndex));

                if (rightBit)
                    result[byteIndex + 3] |= (byte)(1 << (7 - (i % 8)));
            }
            return result;
        }

        /// <summary>
        /// Выполняет циклический сдвиг влево на указанное количество позиций для 28-битного значения.
        /// Операция использует 32-битный `uint`, но эмулирует 28-битную арифметику,
        /// обеспечивая перенос битов, вышедших за 28-ю позицию, в начало.
        /// Маска 0x0FFFFFFF (28 единичных бит) гарантирует, что старшие 4 бита `uint` всегда будут нулевыми.
        /// </summary>
        private uint LeftShift28(uint value, int shifts)
        {
            return ((value << shifts) | (value >> (28 - shifts))) & 0x0FFFFFFF;
        }
    }
}