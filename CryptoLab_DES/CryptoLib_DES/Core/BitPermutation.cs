namespace CryptoLib.DES.Core
{
    /// <summary>
    /// Статический класс, предоставляющий утилитарные методы для выполнения битовых перестановок
    /// на основе таблицы перестановок (P-блока).
    /// Выполняем диффузию - изменение одного бита приводит к изменению как можно большего числа бит в шифротексте
    /// </summary>
    public static class BitPermutation
    {
        /// <summary>
        /// Выполняет битовую перестановку для входного массива байтов и возвращает результат в новом массиве.
        /// Проходим тут перед началом 16 раундов для начальное (IP) перестановки, после 16 раундов для конечной (IP^(-1)),
        /// также расширяем внутри раундовой функции с 32 до 48, переставляем в конце раундовой функции с помощью S таблиц,
        /// используем при генерации раундовых ключей для выбора 56 из 64 и затем 48 из 56 для каждого раунда.
        /// </summary>
        /// <param name="inputValue">Входной массив байтов, биты которого будут переставляться.</param>
        /// <param name="pBlock">Таблица перестановок (P-блок). Массив, указывающий новые позиции для каждого бита.</param>
        /// <param name="indexingRule">
        /// Правило индексации битов в байте.
        /// <c>true</c> для LSB-first (младший бит справа, бит 0 = маска 0x01).
        /// <c>false</c> для MSB-first (старший бит слева, бит 0 = маска 0x80).
        /// </param>
        /// <param name="zeroIndex">
        /// Определяет, является ли нумерация в P-блоке 0-индексированной (<c>true</c>) или 1-индексированной (<c>false</c>).
        /// </param>
        /// <returns>Новый массив байтов, содержащий результат перестановки.</returns>
        public static byte[] PermutationBytes(
            byte[] inputValue,
            int[] pBlock,
            bool indexingRule,
            bool zeroIndex)
        {
            if (inputValue == null || pBlock == null)
                throw new ArgumentException("Input array or P-Block is null in PermutationBytes");

            int outputBitLength = pBlock.Length;
            int outputByteLength = (outputBitLength + 7) / 8; //округляем вверх, чтобы не отбрасывать нужное
            byte[] result = new byte[outputByteLength];

            PermutationBytes(inputValue, pBlock, result, indexingRule, zeroIndex);
            return result;
        }

        /// <summary>
        /// Выполняет битовую перестановку для входного массива байтов и записывает результат в предоставленный массив <paramref name="destination"/>.
        /// </summary>
        /// <param name="inputValue">Входной массив байтов, биты которого будут переставляться.</param>
        /// <param name="pBlock">Таблица перестановок (P-блок)</param>
        /// <param name="destination">Массив байтов, в который будет записан результат перестановки. Содержимое будет перезаписано.</param>
        /// <param name="indexingRule">
        /// Правило индексации битов в байте.
        /// <c>true</c> для LSB-first (младший бит справа, бит 0 = маска 0x01).
        /// <c>false</c> для MSB-first (старший бит слева, бит 0 = маска 0x80).
        /// </param>
        /// <param name="zeroIndex">
        /// Определяет, является ли нумерация в P-блоке 0-индексированной (<c>true</c>) или 1-индексированной (<c>false</c>).
        /// </param>
        public static void PermutationBytes(
            byte[] inputValue,
            int[] pBlock,
            byte[] destination,
            bool indexingRule,
            bool zeroIndex)
        {
            if (inputValue == null || pBlock == null || destination == null)
                throw new ArgumentException("Input, P-Block, or destination is null in PermutationBytes");

            if (destination.Length * 8 < pBlock.Length)
                throw new ArgumentException("Destination array is too small for the permutation result.");


            int inputBitLength = inputValue.Length * 8;
            int indexOffset = zeroIndex ? 0 : 1;

            //проверка на корректность данных: что не пытаемся взять блок из места, которого нет
            int minP = int.MaxValue, maxP = int.MinValue;
            for (int i = 0; i < pBlock.Length; i++)
            {
                if (pBlock[i] < minP) minP = pBlock[i];
                if (pBlock[i] > maxP) maxP = pBlock[i];
            }
            if (minP < indexOffset || maxP >= inputBitLength + indexOffset)
            {
                throw new ArgumentException($"P-Block contains an index out of the valid range.");
            }


            Array.Clear(destination, 0, destination.Length);

            // Основной цикл перестановки
            // i - номер бита в результате
            for (int i = 0; i < pBlock.Length; i++)
            {
                //номер бита, который должны прочитать, с поправкой на offset
                int sourceBitIndex = pBlock[i] - indexOffset;

                // дальше читаем и вставляем по переданному правилу
                // LSB - читаем биты справа налево (10101010 -> номера 76543210)
                // МSB - читаем биты слева направо (10101010 -> номера 01234567)
                bool bitValue = indexingRule ?
                    GetBitLSB(inputValue, sourceBitIndex) :
                    GetBitMSB(inputValue, sourceBitIndex);

                if (indexingRule)
                {
                    SetBitLSB(destination, i, bitValue);
                }
                else
                {
                    SetBitMSB(destination, i, bitValue);
                }
            }
        }

        /// <summary>
        /// Получает значение бита по указанному индексу, используя нумерацию LSB-first (младший бит справа).
        /// В этой схеме бит 0 - это самый правый бит (маска 0x01), а бит 7 - самый левый (маска 0x80).
        /// </summary>
        private static bool GetBitLSB(byte[] data, int bitIndex)
        {
            // bitIndex >> 3 ~ bitIndex / 8; bitIndex & 7 ~ bitIndex % 8
            return (data[bitIndex >> 3] & (1 << (bitIndex & 7))) != 0;
        }

        /// <summary>
        /// Получает значение бита по указанному индексу, используя нумерацию MSB-first (старший бит слева).
        /// В этой схеме бит 0 - это самый левый бит (маска 0x80), а бит 7 - самый правый (маска 0x01).
        /// </summary>
        private static bool GetBitMSB(byte[] data, int bitIndex)
        {
            // 7 - ... -> инверсия индекса, единственное отличие
            return (data[bitIndex >> 3] & (1 << (7 - (bitIndex & 7)))) != 0;
        }

        /// <summary>
        /// Устанавливает значение бита по указанному индексу, используя нумерацию LSB-first (младший бит справа).
        /// </summary>
        private static void SetBitLSB(byte[] data, int bitIndex, bool value)
        {
            int byteIndex = bitIndex >> 3;
            int bitInByte = bitIndex & 7;
            if (value)
                data[byteIndex] |= (byte)(1 << bitInByte);
            else
                data[byteIndex] &= (byte)~(1 << bitInByte);
        }

        /// <summary>
        /// Устанавливает значение бита по указанному индексу, используя нумерацию MSB-first (старший бит слева).
        /// </summary>
        private static void SetBitMSB(byte[] data, int bitIndex, bool value)
        {
            int byteIndex = bitIndex >> 3;
            int bitInByte = 7 - (bitIndex & 7);
            if (value)
                data[byteIndex] |= (byte)(1 << bitInByte);
            else
                data[byteIndex] &= (byte)~(1 << bitInByte);
        }
    }
}