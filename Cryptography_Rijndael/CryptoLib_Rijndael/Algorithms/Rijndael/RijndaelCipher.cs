using CryptoLib.Rijndael.Algorithms.Rijndael.GaloisField;
using CryptoLib.Rijndael.Algorithms.Rijndael.Enums;
using CryptoLib.Rijndael.Interfaces;

namespace CryptoLib.Rijndael.Algorithms.Rijndael
{
    /// <summary>
    /// Реализует симметричный алгоритм шифрования Rijndael в соответствии с интерфейсом ISymmetricCipher.
    /// </summary>
    public class RijndaelCipher : ISymmetricCipher
    {
        /// <summary>
        /// Получает размер блока алгоритма в байтах.
        /// </summary>
        public int BlockSize { get; }

        /// <summary>
        /// Получает размер ключа алгоритма в байтах.
        /// </summary>
        public int KeySize { get; }

        private readonly int _rounds;
        private readonly SBox _sBox;
        private byte[][]? _roundKeys;

        /// <summary>
        /// Инициализирует новый экземпляр шифра Rijndael с заданной конфигурацией.
        /// </summary>
        /// <param name="keySizeEnum">Размер ключа (128, 192 или 256 бит).</param>
        /// <param name="blockSizeEnum">Размер блока (128, 192 или 256 бит).</param>
        /// <param name="irreduciblePolynomial">Неприводимый полином для операций в поле GF(2^8). Для AES стандарт 0x1B.</param>
        public RijndaelCipher(KeySize keySizeEnum, BlockSize blockSizeEnum, byte irreduciblePolynomial = 0x1B)
        {
            KeySize = (int)keySizeEnum / 8;
            BlockSize = (int)blockSizeEnum / 8;
            _rounds = GetNumberOfRounds(KeySize, BlockSize);
            _sBox = new SBox(irreduciblePolynomial);
        }

        /// <summary>
        /// Устанавливает ключ и генерирует на его основе раундовые ключи.
        /// Этот метод должен быть вызван перед шифрованием/дешифрованием.
        /// </summary>
        /// <param name="key">Мастер-ключ. Длина должна соответствовать свойству KeySize.</param>
        public void SetRoundKeys(byte[] key)
        {
            if (key == null || key.Length != KeySize)
            {
                throw new ArgumentException($"Key length must be {KeySize} bytes.");
            }
            var keyScheduler = new RijndaelKeyScheduler(_sBox);
            _roundKeys = keyScheduler.ExpandKey(key, BlockSize, KeySize, _rounds);
        }

        /// <summary>
        /// Выполняет шифрование одного блока данных.
        /// </summary>
        /// <param name="block">Блок данных для шифрования. Длина должна соответствовать свойству BlockSize.</param>
        /// <returns>Зашифрованный блок данных.</returns>
        public byte[] EncryptBlock(byte[] block)
        {
            if (_roundKeys == null)
                throw new InvalidOperationException("Round keys are not set. Call SetRoundKeys() first.");
            if (block == null || block.Length != BlockSize)
                throw new ArgumentException($"Block must not be null and size must be {BlockSize} bytes.");

            // 1. Преобразуем входной блок в матрицу состояния (state)
            var state = ToStateMatrix(block);

            // 2. Начальный раунд - наложение первого раундового ключа
            AddRoundKey(state, 0);

            // 3. Основные раунды
            for (int round = 1; round < _rounds; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, round);
            }

            // 4. Финальный раунд (без MixColumns)
            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, _rounds);

            // 5. Преобразуем состояние обратно в плоский массив байт
            return FromStateMatrix(state);
        }

        /// <summary>
        /// Выполняет дешифрование одного блока данных.
        /// </summary>
        /// <param name="block">Блок данных для дешифрования. Длина должна соответствовать свойству BlockSize.</param>
        /// <returns>Расшифрованный блок данных.</returns>
        public byte[] DecryptBlock(byte[] block)
        {
            if (_roundKeys == null)
                throw new InvalidOperationException("Round keys are not set. Call SetRoundKeys() first.");
            if (block == null || block.Length != BlockSize)
                throw new ArgumentException($"Block must not be null and size must be {BlockSize} bytes.");

            // 1. Преобразуем входной блок в матрицу состояния (state)
            var state = ToStateMatrix(block);

            // 2. "Обратный" финальный раунд
            AddRoundKey(state, _rounds);
            InvShiftRows(state);
            InvSubBytes(state);

            // 3. "Обратные" основные раунды (в обратном порядке)
            for (int round = _rounds - 1; round >= 1; round--)
            {
                AddRoundKey(state, round);
                InvMixColumns(state);
                InvShiftRows(state);
                InvSubBytes(state);
            }

            // 4. "Обратный" начальный раунд
            AddRoundKey(state, 0);

            // 5. Преобразуем состояние обратно в плоский массив байт
            return FromStateMatrix(state);
        }

        /// <summary>
        /// Определяет количество раундов на основе размеров ключа и блока согласно спецификации Rijndael.
        /// </summary>
        /// <param name="keySizeBytes">Размер ключа в байтах.</param>
        /// <param name="blockSizeBytes">Размер блока в байтах.</param>
        /// <returns>Количество раундов шифрования.</returns>
        private int GetNumberOfRounds(int keySizeBytes, int blockSizeBytes)
        {
            // Количество 32-битных слов в ключе и блоке
            int nk = keySizeBytes / 4;
            int nb = blockSizeBytes / 4;

            if (nk <= 6 && nb <= 6)
            {
                if (nk > 4 || nb > 4) return 12;
                return 10;
            }
            if (nk <= 8 && nb <= 8)
            {
                return 14;
            }

            throw new InvalidOperationException("Unsupported key/block size combination for determining number of rounds.");

        }

        #region Private Helper Methods for Encryption

        /// <summary>
        /// Преобразует 1D-массив байт в 2D-матрицу состояния (4xNb).
        /// Заполнение происходит по колонкам.
        /// </summary>
        private byte[,] ToStateMatrix(byte[] block)
        {
            int nb = BlockSize / 4; // Количество колонок
            var state = new byte[4, nb];
            for (int c = 0; c < nb; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    state[r, c] = block[c * 4 + r];
                }
            }
            return state;
        }

        /// <summary>
        /// Преобразует 2D-матрицу состояния обратно в 1D-массив байт.
        /// </summary>
        private byte[] FromStateMatrix(byte[,] state)
        {
            int nb = BlockSize / 4;
            var block = new byte[BlockSize];
            for (int c = 0; c < nb; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    block[c * 4 + r] = state[r, c];
                }
            }
            return block;
        }

        /// <summary>
        /// Преобразование AddRoundKey: XOR состояния с раундовым ключом.
        /// </summary>
        private void AddRoundKey(byte[,] state, int round)
        {
            int nb = BlockSize / 4;
            for (int c = 0; c < nb; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    state[r, c] ^= _roundKeys![round][c * 4 + r];
                }
            }
        }

        /// <summary>
        /// Преобразование SubBytes: нелинейная замена байтов с помощью S-Box.
        /// </summary>
        private void SubBytes(byte[,] state)
        {
            int nb = BlockSize / 4;
            for (int c = 0; c < nb; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    state[r, c] = _sBox.SBoxTable[state[r, c]];
                }
            }
        }

        /// <summary>
        /// Преобразование ShiftRows: циклический сдвиг строк состояния.
        /// </summary>
        private void ShiftRows(byte[,] state)
        {
            int nb = BlockSize / 4;
            // Сдвиги для разных размеров блока
            int[] shifts = nb switch
            {
                4 => [0, 1, 2, 3], // 128-bit block (AES)
                6 => [0, 1, 2, 3], // 192-bit block
                8 => [0, 1, 3, 4], // 256-bit block
                _ => throw new InvalidOperationException("Unsupported block size.")
            };

            for (int r = 1; r < 4; r++) // Первая строка (r=0) не сдвигается
            {
                var tempRow = new byte[nb];
                for (int c = 0; c < nb; c++)
                {
                    tempRow[c] = state[r, c];
                }
                for (int c = 0; c < nb; c++)
                {
                    state[r, c] = tempRow[(c + shifts[r]) % nb];
                }
            }
        }

        /// <summary>
        /// Преобразование MixColumns: смешивание данных внутри каждой колонки.
        /// </summary>
        private void MixColumns(byte[,] state)
        {
            int nb = BlockSize / 4;
            var tempCol = new byte[4];

            for (int c = 0; c < nb; c++)
            {
                // Копируем текущую колонку для обработки
                for (int r = 0; r < 4; r++)
                {
                    tempCol[r] = state[r, c];
                }

                // Выполняем умножение на фиксированный полином в поле GF(2^8)
                // {s_0_c}' = ({02} • {s_0_c}) ⊕ ({03} • {s_1_c}) ⊕ {s_2_c} ⊕ {s_3_c}
                // {s_1_c}' = {s_0_c} ⊕ ({02} • {s_1_c}) ⊕ ({03} • {s_2_c}) ⊕ {s_3_c}
                // {s_2_c}' = {s_0_c} ⊕ {s_1_c} ⊕ ({02} • {s_2_c}) ⊕ ({03} • {s_3_c})
                // {s_3_c}' = ({03} • {s_0_c}) ⊕ {s_1_c} ⊕ {s_2_c} ⊕ ({02} • {s_3_c})
                state[0, c] = (byte)(GaloisFieldMath.Multiply(tempCol[0], 2, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[1], 3, 0x1B) ^ tempCol[2] ^ tempCol[3]);
                state[1, c] = (byte)(tempCol[0] ^ GaloisFieldMath.Multiply(tempCol[1], 2, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[2], 3, 0x1B) ^ tempCol[3]);
                state[2, c] = (byte)(tempCol[0] ^ tempCol[1] ^ GaloisFieldMath.Multiply(tempCol[2], 2, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[3], 3, 0x1B));
                state[3, c] = (byte)(GaloisFieldMath.Multiply(tempCol[0], 3, 0x1B) ^ tempCol[1] ^ tempCol[2] ^ GaloisFieldMath.Multiply(tempCol[3], 2, 0x1B));
            }
        }

        #endregion

        #region Private Helper Methods for Decryption

        /// <summary>
        /// Преобразование InvSubBytes: обратная нелинейная замена байтов с помощью Inverse S-Box.
        /// </summary>
        private void InvSubBytes(byte[,] state)
        {
            int nb = BlockSize / 4;
            for (int c = 0; c < nb; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    state[r, c] = _sBox.InverseSBoxTable[state[r, c]];
                }
            }
        }

        /// <summary>
        /// Преобразование InvShiftRows: обратный циклический сдвиг строк состояния (вправо).
        /// </summary>
        private void InvShiftRows(byte[,] state)
        {
            int nb = BlockSize / 4;
            // Сдвиги те же, что и при шифровании, но применяются в обратную сторону.
            int[] shifts = nb switch
            {
                4 => [0, 1, 2, 3], // 128-bit block (AES)
                6 => [0, 1, 2, 3], // 192-bit block
                8 => [0, 1, 3, 4], // 256-bit block
                _ => throw new InvalidOperationException("Unsupported block size.")
            };

            for (int r = 1; r < 4; r++) // Первая строка (r=0) не сдвигается
            {
                var tempRow = new byte[nb];
                for (int c = 0; c < nb; c++)
                {
                    tempRow[c] = state[r, c];
                }
                for (int c = 0; c < nb; c++)
                {
                    // Сдвиг вправо эквивалентен сдвигу влево на (nb - shift)
                    state[r, c] = tempRow[(c + nb - shifts[r]) % nb];
                }
            }
        }

        /// <summary>
        /// Преобразование InvMixColumns: обратное смешивание данных внутри каждой колонки.
        /// </summary>
        private void InvMixColumns(byte[,] state)
        {
            int nb = BlockSize / 4;
            var tempCol = new byte[4];

            for (int c = 0; c < nb; c++)
            {
                for (int r = 0; r < 4; r++)
                {
                    tempCol[r] = state[r, c];
                }

                // Умножение на обратную матрицу полиномов: {0E, 0B, 0D, 09}
                state[0, c] = (byte)(GaloisFieldMath.Multiply(tempCol[0], 0x0E, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[1], 0x0B, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[2], 0x0D, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[3], 0x09, 0x1B));
                state[1, c] = (byte)(GaloisFieldMath.Multiply(tempCol[0], 0x09, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[1], 0x0E, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[2], 0x0B, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[3], 0x0D, 0x1B));
                state[2, c] = (byte)(GaloisFieldMath.Multiply(tempCol[0], 0x0D, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[1], 0x09, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[2], 0x0E, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[3], 0x0B, 0x1B));
                state[3, c] = (byte)(GaloisFieldMath.Multiply(tempCol[0], 0x0B, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[1], 0x0D, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[2], 0x09, 0x1B) ^ GaloisFieldMath.Multiply(tempCol[3], 0x0E, 0x1B));
            }
        }

        #endregion
        
    }
    
    
}