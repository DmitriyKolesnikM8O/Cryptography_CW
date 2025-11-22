using CryptoLib.DES.Interfaces;

namespace CryptoLib.DES.Algorithms
{
    /// <summary>
    /// Реализует обобщенную (генерическую) сеть Фейстеля. Класс является конфигурируемым и использует
    /// инъекцию зависимостей для определения конкретного алгоритма: планировщика ключей (<see cref="IKeyScheduler"/>)
    /// и раундовой функции (<see cref="IFeistelFunction"/>).
    /// </summary>
    public class FeistelNetwork : ISymmetricCipher
    {
        private readonly IKeyScheduler _keyScheduler;
        private readonly IFeistelFunction _feistelFunction;
        private readonly int _rounds;
        private byte[][] _roundKeys = default!;

        /// <summary>
        /// Инициализирует новый экземпляр класса FeistelNetwork с заданными компонентами алгоритма и количеством раундов.
        /// </summary>
        /// <param name="keyScheduler">Планировщик ключей, отвечающий за генерацию раундовых ключей из основного.</param>
        /// <param name="feistelFunction">Раундовая функция F, выполняющая основное криптографическое преобразование.</param>
        /// <param name="rounds">Количество раундов шифрования.</param>
        public FeistelNetwork(
            IKeyScheduler keyScheduler,
            IFeistelFunction feistelFunction,
            int rounds)
        {
            _keyScheduler = keyScheduler;
            _feistelFunction = feistelFunction;
            _rounds = rounds;
        }

        public int BlockSize => 8;
        public int KeySize => 8;

        /// <summary>
        /// Генерирует и устанавливает раундовые ключи для последующих операций шифрования/дешифрования.
        /// Этот метод должен быть вызван перед вызовом EncryptBlock или DecryptBlock.
        /// </summary>
        /// <param name="key">Основной ключ шифрования.</param>
        public void SetRoundKeys(byte[] key)
        {
            _roundKeys = _keyScheduler.ExpandKey(key);
        }

        /// <summary>
        /// Шифрует один блок данных с использованием сети Фейстеля.
        /// </summary>
        /// <param name="block">Входной блок открытого текста (должен быть равен <see cref="BlockSize"/>).</param>
        /// <returns>Зашифрованный блок данных.</returns>
        public byte[] EncryptBlock(byte[] block)
        {
            if (_roundKeys == null) throw new InvalidOperationException("Round keys not set.");

            int halfSize = BlockSize / 2;
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            for (int round = 0; round < _rounds; round++)
            {
                byte[] tempLeft = (byte[])left.Clone();
                left = right;
                byte[] feistelResult = _feistelFunction.Execute(right, _roundKeys[round]);
                right = XorBlocks(tempLeft, feistelResult);
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, 0, halfSize);
            Array.Copy(right, 0, result, halfSize, halfSize);
            return result;
        }


        /// <summary>
        /// Дешифрует один блок данных.
        /// Процесс является обратным шифрованию и использует раундовые ключи в обратном порядке.
        /// </summary>
        /// <param name="block">Входной блок шифротекста (должен быть равен <see cref="BlockSize"/>).</param>
        /// <returns>Расшифрованный блок данных.</returns>  
        public byte[] DecryptBlock(byte[] block)
        {
            if (_roundKeys == null) throw new InvalidOperationException("Round keys not set.");

            int halfSize = BlockSize / 2;
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            for (int round = _rounds - 1; round >= 0; round--)
            {
                byte[] tempRight = (byte[])right.Clone();
                right = left;
                byte[] feistelResult = _feistelFunction.Execute(left, _roundKeys[round]);
                left = XorBlocks(tempRight, feistelResult);
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, 0, halfSize);
            Array.Copy(right, 0, result, halfSize, halfSize);
            return result;
        }

        /// <summary>
        /// Вспомогательный метод для выполнения операции побитового "исключающего ИЛИ" (XOR) над двумя блоками одинаковой длины.
        /// </summary>
        /// <param name="block1">Первый блок.</param>
        /// <param name="block2">Второй блок.</param>
        /// <returns>Новый массив байтов, являющийся результатом операции XOR.</returns>
        private byte[] XorBlocks(byte[] block1, byte[] block2)
        {
            byte[] result = new byte[block1.Length];
            for (int i = 0; i < block1.Length; i++)
            {
                result[i] = (byte)(block1[i] ^ block2[i]);
            }
            return result;
        }
    }
}