using CryptoLib.DES.Core;
using CryptoLib.DES.Interfaces;

namespace CryptoLib.DES.Algorithms.DES
{
    /// <summary>
    /// Реализует раундовую функцию F (функцию Фейстеля) для алгоритма DES.
    /// Функция выполняет расширение входных данных, XOR с раундовым ключом, замену через S-блоки и финальную перестановку.
    /// Класс является потокобезопасным, так как не хранит состояния между вызовами.
    /// </summary>
    public class DESFeistelFunction : IFeistelFunction
    {

        /// <summary>
        /// Выполняет одно полное преобразование раундовой функции DES.
        /// </summary>
        /// <param name="inputBlock">Входной 32-битный (4-байтный) блок данных (обычно правая половина блока из сети Фейстеля).</param>
        /// <param name="roundKey">48-битный (6-байтный) раундовый ключ для текущего раунда.</param>
        /// <returns>Выходной 32-битный (4-байтный) блок данных после всех преобразований.</returns>
        /// <exception cref="ArgumentException">Вызывается, если размер входного блока или раундового ключа не соответствует 
        /// требуемым (4 и 6 байт соответственно).</exception>
        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock.Length != 4)
                throw new ArgumentException("Input block must be 32 bits (4 bytes)");
            if (roundKey.Length != 6)
                throw new ArgumentException("Round key must be 48 bits (6 bytes)");

            // 1. Расширение (Expansion) - 32 бита -> 48 бит
            byte[] expanded = new byte[6];
            BitPermutation.PermutationBytes(inputBlock, DESTables.E, expanded, false, false);

            // 2. Сложение с ключом (XOR)
            byte[] xored = XorWithKey(expanded, roundKey);

            // 3. Замена (Substitution) через S-блоки - 48 бит -> 32 бита
            byte[] substituted = SBoxSubstitution(xored);

            // 4. Перестановка (Permutation) - P-блок
            byte[] result = new byte[4];
            BitPermutation.PermutationBytes(substituted, DESTables.P, result, false, false);

            return result;
        }

        /// <summary>
        /// Вспомогательный метод для выполнения побитовой операции XOR над двумя массивами байтов.
        /// </summary>
        private byte[] XorWithKey(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i]);
            }
            return result;
        }

        /// <summary>
        /// Выполняет основной нелинейный этап преобразования - замену через S-блоки (S-boxes).
        /// Принимает 48-битные данные (результат XOR), разбивает их на восемь 6-битных блоков, 
        /// применяет к каждому соответствующий S-блок и объединяет 4-битные результаты в один 32-битный выходной блок.
        /// </summary>
        private byte[] SBoxSubstitution(byte[] data)
        {
            byte[] result = new byte[4];
            for (int i = 0; i < 8; i++)
            {
                // Извлечение 6-битного блока из 48-битного потока
                int byteIndex = i * 6 / 8;
                int bitOffset = i * 6 % 8;

                int block;
                if (bitOffset <= 2)
                {
                    block = (data[byteIndex] >> (2 - bitOffset)) & 0x3F;
                }
                else
                {
                    block = ((data[byteIndex] << (bitOffset - 2)) | (data[byteIndex + 1] >> (10 - bitOffset))) & 0x3F;
                }

                // Определение строки и столбца в таблице S-блока
                int row = ((block & 0x20) >> 4) | (block & 0x01);
                int col = (block & 0x1E) >> 1;

                // Получение 4-битного значения из S-блока
                int sboxValue = DESTables.S_BOX[i, row, col];

                // Запись 4-битного значения в результирующий 32-битный массив
                int resultByteIndex = i / 2;
                int resultBitOffset = 4 * (1 - (i % 2)); // 4 для четных i, 0 для нечетных
                result[resultByteIndex] |= (byte)(sboxValue << resultBitOffset);
            }
            return result;
        }
    }
}