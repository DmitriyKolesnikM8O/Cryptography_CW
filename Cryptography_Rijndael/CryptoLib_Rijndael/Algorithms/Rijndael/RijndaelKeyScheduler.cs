namespace CryptoLib.Rijndael.Algorithms.Rijndael
{
    /// <summary>
    /// Отвечает за процедуру расширения ключа (Key Schedule) для алгоритма Rijndael.
    /// Генерирует набор раундовых ключей из исходного мастер-ключа.
    /// </summary>
    public class RijndaelKeyScheduler
    {
        private readonly SBox _sBox;

        /// <summary>
        /// Константы раундов (Rcon), используемые в процедуре расширения ключа.
        /// Rcon[i] = [RC[i], 0, 0, 0], где RC[i] = x^(i-1) в поле GF(2^8).
        /// </summary>
        private static readonly byte[] Rcon = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
            0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97,
            0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91
        };

        /// <summary>
        /// Инициализирует новый экземпляр Key Scheduler.
        /// </summary>
        /// <param name="sBox">Экземпляр SBox для выполнения операции SubWord.</param>
        public RijndaelKeyScheduler(SBox sBox)
        {
            _sBox = sBox;
        }

        /// <summary>
        /// Выполняет расширение ключа в точном соответствии со стандартом FIPS-197.
        /// </summary>
        /// <param name="key">Мастер-ключ.</param>
        /// <param name="blockSizeBytes">Размер блока в байтах.</param>
        /// <param name="keySizeBytes">Размер ключа в байтах.</param>
        /// <param name="rounds">Количество раундов.</param>
        /// <returns>Двумерный массив, содержащий раундовые ключи.</returns>
        public byte[][] ExpandKey(byte[] key, int blockSizeBytes, int keySizeBytes, int rounds)
        {
            int nk = keySizeBytes / 4; // Количество 32-битных слов в ключе (4, 6, или 8)
            int nb = blockSizeBytes / 4; // Количество 32-битных слов в блоке

            
            // Общее количество 32-битных слов в расширенном ключе
            int expandedKeyWordsCount = nb * (rounds + 1);
            var w = new byte[expandedKeyWordsCount * 4];

            // Шаг 1: Первые Nk слов расширенного ключа - это сам мастер-ключ
            Array.Copy(key, w, keySizeBytes);

            // Шаг 2: Генерируем оставшиеся слова
            for (int i = nk; i < expandedKeyWordsCount; i++)
            {
                // Берем предыдущее слово w[i-1]
                var temp = new byte[4];
                Array.Copy(w, (i - 1) * 4, temp, 0, 4);

                // Если это первое слово нового блока ключа (i кратно Nk),
                // применяем к нему сложную трансформацию g()
                if (i % nk == 0)
                {
                    temp = SubWord(RotWord(temp));
                    temp[0] ^= Rcon[i / nk];
                }
                // Для 256-битных ключей (Nk > 6), если i-4 кратно Nk,
                // применяем дополнительную трансформацию h()
                else if (nk > 6 && i % nk == 4)
                {
                    temp = SubWord(temp);
                }

                // Новое слово w[i] = w[i-Nk] XOR temp
                int prevWordIndex = (i - nk) * 4;
                int currentWordIndex = i * 4;

                w[currentWordIndex]     = (byte)(w[prevWordIndex] ^ temp[0]);
                w[currentWordIndex + 1] = (byte)(w[prevWordIndex + 1] ^ temp[1]);
                w[currentWordIndex + 2] = (byte)(w[prevWordIndex + 2] ^ temp[2]);
                w[currentWordIndex + 3] = (byte)(w[prevWordIndex + 3] ^ temp[3]);
            }

            return FormatRoundKeys(w, blockSizeBytes, rounds);
        }

        /// <summary>
        /// Применяет S-Box к каждому байту 4-байтного слова (операция SubWord).
        /// </summary>
        private byte[] SubWord(byte[] word) => 
            [_sBox.SBoxTable[word[0]], _sBox.SBoxTable[word[1]], _sBox.SBoxTable[word[2]], _sBox.SBoxTable[word[3]]];
        
        /// <summary>
        /// Выполняет циклический сдвиг байтов в слове влево: [b0,b1,b2,b3] -> [b1,b2,b3,b0] (операция RotWord).
        /// </summary>
        private byte[] RotWord(byte[] word) => 
            [word[1], word[2], word[3], word[0]];

        /// <summary>
        /// Преобразует плоский массив расширенного ключа в массив раундовых ключей для удобства использования.
        /// </summary>
        private byte[][] FormatRoundKeys(byte[] expandedKey, int blockSizeBytes, int rounds)
        {
            var roundKeys = new byte[rounds + 1][];
            for (int i = 0; i <= rounds; i++)
            {
                roundKeys[i] = new byte[blockSizeBytes];
                Array.Copy(expandedKey, i * blockSizeBytes, roundKeys[i], 0, blockSizeBytes);
            }
            return roundKeys;
        }
    }
}