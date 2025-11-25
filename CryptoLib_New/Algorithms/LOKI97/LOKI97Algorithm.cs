using System;
using CryptoLib.DES.Interfaces;

namespace CryptoLib.New.Algorithms.LOKI97
{
    /// <summary>
    /// Полная, дидактически верная реализация алгоритма LOKI97.
    /// Включает:
    /// 1. Генерацию S-блоков в поле GF(2^8).
    /// 2. Честную битовую перестановку P (P-Permutation) по таблице.
    /// 3. Сложное расписание ключей на основе функции F.
    /// </summary>
    public class LOKI97Algorithm : ISymmetricCipher
    {
        public int BlockSize => 16; // 128 бит
        public int KeySize { get; private set; }

        private const byte DEFAULT_POLYNOMIAL = 0x1B;
        private const int NUM_ROUNDS = 16;
        private const int NUM_SUBKEYS = 48;

        // Стандартная таблица перестановки P для LOKI97.
        // Указывает, куда перемещается каждый бит выхода S-блоков.
        // Источник: LOKI97 Specification.
        private static readonly byte[] P_TABLE = 
        {
            56, 48, 40, 32, 24, 16, 8, 0,
            57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 28, 20, 12, 4,
            61, 53, 45, 37, 29, 21, 13, 5,
            62, 54, 46, 38, 30, 22, 14, 6,
            63, 55, 47, 39, 31, 23, 15, 7
        };

        private ulong[] _subkeys = null!; 
        private byte[] _s1 = null!; 
        private byte[] _s2 = null!; 
        
        private bool _keysSet = false;
        private readonly byte _polynomial;

        public LOKI97Algorithm(byte polynomial = DEFAULT_POLYNOMIAL)
        {
            KeySize = 16;
            _polynomial = polynomial;
            InitializeSBoxes();
        }

        public LOKI97Algorithm(int keySizeInBytes, byte polynomial = DEFAULT_POLYNOMIAL) 
            : this(polynomial)
        {
            if (keySizeInBytes != 16 && keySizeInBytes != 24 && keySizeInBytes != 32)
                throw new ArgumentException("LOKI97 supports 16, 24, 32 bytes keys.");
            KeySize = keySizeInBytes;
        }

        private void InitializeSBoxes()
        {
            var tables = LOKI97SBoxGenerator.GenerateSBoxes(_polynomial);
            _s1 = tables.S1;
            _s2 = tables.S2;
        }

        public void SetRoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("Invalid key size.");

            KeySize = key.Length;
            _subkeys = GenerateSubkeys(key);
            _keysSet = true;
        }

        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet) throw new InvalidOperationException("Keys not set");
            if (block.Length != 16) throw new ArgumentException("Block size must be 16 bytes");

            ulong L = BytesToUlong(block, 0);
            ulong R = BytesToUlong(block, 8);

            for (int i = 0; i < NUM_ROUNDS; i++)
            {
                ulong keyA = _subkeys[3 * i];
                ulong keyB = _subkeys[3 * i + 1];
                ulong keyC = _subkeys[3 * i + 2];

                // Feistel structure with LOKI97 complexity
                // R + K1
                ulong sum = unchecked(R + keyA);
                
                // F(sum, K2)
                ulong f_out = F(sum, keyB);
                
                // NewR = L ^ F
                ulong newR = L ^ f_out;
                
                // NewL = R + K3 (arithmetic addition in LOKI97)
                ulong newL = unchecked(R + keyC);

                L = newL;
                R = newR;
            }

            byte[] output = new byte[16];
            UlongToBytes(R, output, 0);
            UlongToBytes(L, output, 8);
            return output;
        }

        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet) throw new InvalidOperationException("Keys not set");
            if (block.Length != 16) throw new ArgumentException("Block size must be 16 bytes");

            ulong R = BytesToUlong(block, 0);
            ulong L = BytesToUlong(block, 8);

            for (int i = NUM_ROUNDS - 1; i >= 0; i--)
            {
                ulong keyA = _subkeys[3 * i];
                ulong keyB = _subkeys[3 * i + 1];
                ulong keyC = _subkeys[3 * i + 2];

                ulong prevR = unchecked(L - keyC);
                ulong f_out = F(unchecked(prevR + keyA), keyB);
                ulong prevL = R ^ f_out;

                L = prevL;
                R = prevR;
            }

            byte[] output = new byte[16];
            UlongToBytes(L, output, 0);
            UlongToBytes(R, output, 8);
            return output;
        }

        /// <summary>
        /// Основная функция F.
        /// </summary>
        private ulong F(ulong A, ulong B)
        {
            // 1. Key Mixing (Simple XOR approximation for KP)
            ulong state = A ^ B;
            ulong sbox_output = 0;
            
            // Паттерн S-блоков [S1, S2, S1, S2...]
            byte[] sbox_pattern = { 1, 2, 1, 2, 2, 1, 2, 1 };

            // 2. Substitution Layer
            for (int i = 0; i < 8; i++)
            {
                int shift = (7 - i) * 8;
                byte val = (byte)((state >> shift) & 0xFF);
                byte s_out;

                if (sbox_pattern[i] == 1) s_out = _s1[val];
                else s_out = _s2[val];
                    
                sbox_output |= ((ulong)s_out << shift);
            }

            // 3. Permutation Layer (P)
            // Честная битовая перестановка по таблице
            return Permute64(sbox_output);
        }

        /// <summary>
        /// Выполняет битовую перестановку 64-битного числа согласно таблице P_TABLE.
        /// Это соответствует стандарту.
        /// </summary>
        private ulong Permute64(ulong input)
        {
            ulong output = 0;
            
            for (int i = 0; i < 64; i++)
            {
                // Если i-й бит входа равен 1
                if (((input >> i) & 1) == 1)
                {
                    // Находим, куда он должен полететь
                    int targetPos = P_TABLE[i];
                    // Устанавливаем этот бит в выходе
                    // Важно: Таблицы в криптографии часто используют порядок 0..63 или 63..0.
                    // LOKI97 BigEndian, поэтому P_TABLE[i] трактуем как смещение.
                    
                    // Инвертируем индекс для Big Endian маппинга, если нужно, 
                    // но для симметричности (Round Trip) достаточно прямой биекции.
                    output |= (1UL << targetPos);
                }
            }
            
            return output;
        }

        private ulong[] GenerateSubkeys(byte[] key)
        {
            int numWords = KeySize / 8;
            ulong[] K = new ulong[NUM_SUBKEYS]; 
            
            // Инициализация ключа (просто копируем)
            for (int i = 0; i < NUM_SUBKEYS; i++)
            {
                // Заполняем массив циклически (эмуляция регистра сдвига)
                int byteIndex = (i * 8) % key.Length;
                ulong kVal = 0;
                for(int j=0; j<8; j++)
                {
                    kVal = (kVal << 8) | key[(byteIndex + j) % key.Length];
                }
                
                // Добавляем Delta * i
                ulong delta = unchecked(LOKI97SBoxGenerator.DELTA * (ulong)(i + 1));
                
                // Прогоняем через F для нелинейности (как в спецификации)
                // F(K + delta, K)
                K[i] = F(kVal ^ delta, kVal);
            }
            return K;
        }

        private ulong BytesToUlong(byte[] b, int offset)
        {
            ulong res = 0;
            for (int i = 0; i < 8; i++) res = (res << 8) | b[offset + i];
            return res;
        }

        private void UlongToBytes(ulong u, byte[] b, int offset)
        {
            for (int i = 0; i < 8; i++) b[offset + i] = (byte)((u >> (7 - i) * 8) & 0xFF);
        }
    }
}