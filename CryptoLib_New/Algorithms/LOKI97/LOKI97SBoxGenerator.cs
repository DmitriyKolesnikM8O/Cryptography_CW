using System;

namespace CryptoLib.New.Algorithms.LOKI97
{
    /// <summary>
    /// Генератор S-блоков для LOKI97 на основе заданного неприводимого полинома.
    /// Реализует арифметику в поле GF(2^8).
    /// </summary>
    internal static class LOKI97SBoxGenerator
    {
        // Константа Дельта (Золотое сечение) остается статической, так как она не зависит от полинома
        public const ulong DELTA = 0x9E3779B97F4A7C15;

        /// <summary>
        /// Генерирует S-Box 1 (x^3) и S-Box 2 (x^-1) для заданного полинома.
        /// </summary>
        public static (byte[] S1, byte[] S2) GenerateSBoxes(byte polynomial)
        {
            byte[] s1 = new byte[256];
            byte[] s2 = new byte[256];

            // Полином в формате int (добавляем старший 9-й бит, который неявный в byte)
            // Например, для AES 0x1B это на самом деле 0x11B (x^8 + x^4 + x^3 + x + 1)
            int fullPoly = 0x100 | polynomial;

            for (int i = 0; i < 256; i++)
            {
                // S1: x^3 = x * x * x
                byte x = (byte)i;
                byte x2 = GF_Multiply(x, x, fullPoly); // x^2
                byte x3 = GF_Multiply(x2, x, fullPoly); // x^3
                s1[i] = x3;

                // S2: x^-1 (Мультипликативная инверсия)
                // В GF(2^8) a^(2^8 - 2) = a^254 = a^-1
                s2[i] = GF_Inverse(x, fullPoly);
            }

            return (s1, s2);
        }

        /// <summary>
        /// Умножение двух чисел в поле GF(2^8) по модулю полинома.
        /// Использует алгоритм "Peasant's algorithm" (сдвиг и XOR).
        /// </summary>
        private static byte GF_Multiply(byte a, byte b, int poly)
        {
            int p = 0;
            int aa = a;
            int bb = b;

            for (int i = 0; i < 8; i++)
            {
                if ((bb & 1) != 0)
                {
                    p ^= aa;
                }

                bool highBitSet = (aa & 0x80) != 0;
                aa <<= 1;
                
                if (highBitSet)
                {
                    aa ^= poly; // XOR с полиномом
                }
                
                bb >>= 1;
            }

            return (byte)p;
        }

        /// <summary>
        /// Вычисление обратного элемента (x^-1).
        /// Используем свойство: a^-1 = a^254 в GF(2^8).
        /// Возведение в степень методом "Square and Multiply".
        /// </summary>
        private static byte GF_Inverse(byte b, int poly)
        {
            if (b == 0) return 0; // 0 не имеет обратного, обычно возвращают 0

            // Нам нужно вычислить b^254
            // 254 в двоичном = 11111110
            
            byte result = 1;
            byte baseVal = b;
            int exponent = 254;

            while (exponent > 0)
            {
                if ((exponent & 1) != 0)
                {
                    result = GF_Multiply(result, baseVal, poly);
                }
                baseVal = GF_Multiply(baseVal, baseVal, poly); // square
                exponent >>= 1;
            }

            return result;
        }
    }
}