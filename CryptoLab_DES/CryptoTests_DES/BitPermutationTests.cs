using CryptoLib.DES.Core;


/*
1. LSB + нумерация 0
2. LSB + нумерация 1
3. MSB + нумерация 0
4. MSB + нумерация 1
5. Невалидный P-блок
6. Один бит
7. Пустой P-блок 
8. Полная перестановка
9. Перестановка через границу байтов
10. Граничные значения индексов
11. Симметричная перестановка
*/


namespace CryptoTests
{
    public class BitPermutationTests
    {
        private readonly byte[] Input64Bits = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        private readonly int[] SmallPBlock = [0, 7, 8, 15, 63];

        /// <summary>
        /// Тестирует базовый случай LSB режима с нумерацией с 0
        /// Что проверяет: правильность извлечения и записи битов в LSB порядке
        /// Ожидаемое поведение: биты 0,7,8,15,63 извлекаются как 0,1,0,1,0 
        /// и записываются в младшие биты байта = 00001010b = 0x0A
        /// </summary>
        [Fact]
        public void PermuteBits_LsbToMsb_IndexFromZero_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = true;
            bool startIndexZero = true;


            byte[] expected = "\n"u8.ToArray();

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, SmallPBlock, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует LSB режим с нумерацией с 1 (как в некоторых стандартах)
        /// Что проверяет: корректность работы смещения индексов при нумерации с 1
        /// Ожидаемое поведение: P-блок {1,8,9,16,64} должен дать тот же результат,
        /// что и {0,7,8,15,63} при нумерации с 0
        /// </summary>
        [Fact]
        public void PermuteBits_LsbToMsb_IndexFromOne_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = true;
            bool startIndexZero = false;

            int[] pBlockFromOne = SmallPBlock.Select(i => i + 1).ToArray();
            byte[] expected = "\n"u8.ToArray();

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, pBlockFromOne, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует базовый случай MSB режима с нумерацией с 0 (стандарт для многих алгоритмов)
        /// Что проверяет: правильность извлечения и записи битов в MSB порядке
        /// Ожидаемое поведение: биты 0,7,8,15,63 извлекаются как 1,0,1,0,0
        /// и записываются в старшие биты байта = 10100000b = 0xA0
        /// </summary>
        [Fact]
        public void PermuteBits_MsbToLsb_IndexFromZero_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = false;
            bool startIndexZero = true;


            byte[] expected = [0xA0];

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, SmallPBlock, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует MSB режим с нумерацией с 1 (как в DES)
        /// Что проверяет: корректность работы MSB режима с нумерацией с 1
        /// Ожидаемое поведение: P-блок {1,8,9,16,64} должен дать тот же результат,
        /// что и {0,7,8,15,63} при нумерации с 0 в MSB режиме
        /// </summary>
        [Fact]
        public void PermuteBits_MsbToLsb_IndexFromOne_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = false;
            bool startIndexZero = false;

            int[] pBlockFromOne = SmallPBlock.Select(i => i + 1).ToArray();
            byte[] expected = [0xA0];

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, pBlockFromOne, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует обработку ошибок при невалидных индексах P-блока
        /// Что проверяет: корректность валидации входных данных
        /// Ожидаемое поведение: при передаче индекса 64 (при 64-битном входе)
        /// должен выбрасываться ArgumentException
        /// </summary>
        [Fact]
        public void PermuteBits_InvalidPBlock_ThrowsException()
        {
            int[] invalidPBlock = [0, 64];
            bool indexFromLsb = true;
            bool startIndexZero = true;

            Assert.Throws<ArgumentException>(() =>
            {
                BitPermutation.PermutationBytes(Input64Bits, invalidPBlock, indexFromLsb, startIndexZero);
            });
        }

        /// <summary>
        /// Тестирует граничный случай - перестановку одного бита
        /// Что проверяет: корректность работы при минимальном количестве битов
        /// Ожидаемое поведение: извлечение бита 7 (MSB первого байта = 1)
        /// и запись его в результат = 00000001b = 0x01
        /// </summary>
        [Fact]
        public void PermuteBits_SingleBit_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = true;
            bool startIndexZero = true;

            int[] singleBitPBlock = [7];


            byte[] expected = [0x01];

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, singleBitPBlock, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует граничный случай - пустой P-блок
        /// Что проверяет: корректность обработки нулевого количества битов
        /// Ожидаемое поведение: возвращается пустой массив байтов
        /// </summary>
        [Fact]
        public void PermuteBits_EmptyPBlock_ShouldReturnEmptyArray()
        {
            int[] emptyPBlock = [];
            byte[] expected = [];

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, emptyPBlock, true, true);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Дополнительный тест: проверка полной 64-битной перестановки
        /// Что проверяет: корректность работы с максимальным количеством битов
        /// Ожидаемое поведение: создается 8-байтовый результат без ошибок
        /// </summary>
        [Fact]
        public void PermuteBits_Full64BitPermutation_ShouldReturnCorrectSize()
        {
            bool indexFromLsb = false;
            bool startIndexZero = false;

            // P-блок, который просто меняет порядок байтов
            int[] fullPBlock = new int[64];
            for (int i = 0; i < 64; i++)
            {
                fullPBlock[i] = 64 - i; // Обратный порядок
            }

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, fullPBlock, indexFromLsb, startIndexZero);

            Assert.NotNull(actual);
            Assert.Equal(8, actual.Length); // 64 бита = 8 байт
        }

        /// <summary>
        /// Дополнительный тест: Проверка перестановки, затрагивающей границу байтов (биты 6, 7, 8, 9).
        /// </summary>
        [Fact]
        public void PermuteBits_CrossByteBoundary_ShouldReturnCorrectResult()
        {
            int[] crossBlock = [6, 7, 8, 9]; // 4 бита

            // 1. LSB-режим (Output: LSB-first)
            // Input (0xFE, 0xDC): LSB bits 6, 7 (Byte 0) = 1, 1; LSB bits 0, 1 (Byte 1) = 0, 0.
            // Stream: 1, 1, 0, 0. Result byte (LSB-first): 1*2^0 + 1*2^1 = 3 (0x03)
            byte[] actualLsb = BitPermutation.PermutationBytes(Input64Bits, crossBlock, true, true);
            Assert.Equal(new byte[] { 0x03 }, actualLsb);

            // 2. MSB-режим (Output: MSB-first)
            // Input (0xFE, 0xDC): MSB bits 6, 7 (Byte 0) = 1, 0; MSB bits 0, 1 (Byte 1) = 1, 1.
            // Stream: 1, 0, 1, 1. Result byte (MSB-first): 1*2^7 + 0*2^6 + 1*2^5 + 1*2^4 = 176 (0xB0)
            byte[] actualMsb = BitPermutation.PermutationBytes(Input64Bits, crossBlock, false, true);
            Assert.Equal(new byte[] { 0xB0 }, actualMsb);
        }

        /// <summary>
        /// Дополнительный тест: Проверка максимального валидного индекса (63) и невалидного (64).
        /// </summary>
        [Fact]
        public void PermuteBits_MaxIndexBoundary_ShouldReturnCorrectResult()
        {
            // Индексация с 0. Максимальный индекс: 63.
            int[] pBlockMax = [63]; // Бит 63 = MSB data[7] (LSB mode) или LSB data[7] (MSB mode)

            // Вход: 0x10. MSB (бит 63) = 0. LSB (бит 56) = 0.

            // LSB Mode (бит 63 = MSB data[7] = 0) -> [0x00]
            byte[] actualLsb = BitPermutation.PermutationBytes(Input64Bits, pBlockMax, true, true);
            Assert.Equal(new byte[] { 0x00 }, actualLsb);

            // MSB Mode (бит 63 = LSB data[7] = 0) -> [0x00]
            byte[] actualMsb = BitPermutation.PermutationBytes(Input64Bits, pBlockMax, false, true);
            Assert.Equal(new byte[] { 0x00 }, actualMsb);

            // Проверка, что тест InvalidPBlock_ThrowsException работает корректно и с MSB/Index 1
            // Max index for IndexFromOne=false is 64. Index 65 must fail.
            int[] invalidPBlock = [65];
            Assert.Throws<ArgumentException>(() =>
            {
                BitPermutation.PermutationBytes(Input64Bits, invalidPBlock, false, false);
            });
        }
        
        /// <summary>
        /// Дополнительный тест: симметричная перестановка, тесты на то, что 
        /// обратная перестановка возвращает исходные данные.
        /// </summary>
        [Fact]
        public void PermuteBits_SymmetricPermutation_ShouldReturnOriginal()
        {
            // P-блок, который просто копирует биты в том же порядке
            int[] identityPBlock = Enumerable.Range(0, 64).ToArray();
            
            byte[] original = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
            
            byte[] permuted = BitPermutation.PermutationBytes(original, identityPBlock, true, true);
            
            // В LSB режиме с нумерацией 0 идентичная перестановка должна дать тот же результат
            Assert.Equal(original, permuted);
        }
    }
}