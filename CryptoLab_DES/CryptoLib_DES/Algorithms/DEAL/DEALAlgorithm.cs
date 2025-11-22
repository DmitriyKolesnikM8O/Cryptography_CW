using CryptoLib.DES.Interfaces;

namespace CryptoLib.DES.Algorithms.DEAL
{
    /// <summary>
    /// Представляет собой основную реализацию симметричного блочного шифра DEAL.
    /// Этот класс конфигурирует и инкапсулирует внутреннюю сеть Фейстеля (<see cref="FeistelNetworkDEAL"/>)
    /// и ее компоненты (<see cref="DEALKeyScheduler"/>, <see cref="DEALFeistelFunction"/>) в соответствии с выбранным размером ключа.
    /// </summary>
    public class DEALAlgorithm : ISymmetricCipher
    {
        private readonly FeistelNetworkDEAL _feistelNetwork;
        private readonly DEALKeyScheduler.KeyType _keyType;
        private bool _keysSet = false;

        /// <summary>
        /// Инициализирует новый экземпляр алгоритма DEAL с указанным типом (размером) ключа.
        /// </summary>
        /// <param name="keyType">
        /// Тип ключа, определяющий размер ключа (128, 192 или 256 бит) и соответствующее количество раундов.
        /// По умолчанию используется KEY_SIZE_128.
        /// </param>
        /// <exception cref="ArgumentException">Вызывается, если указан недопустимый тип ключа.</exception>
        public DEALAlgorithm(DEALKeyScheduler.KeyType keyType = DEALKeyScheduler.KeyType.KEY_SIZE_128)
        {
            _keyType = keyType;

            var keyScheduler = new DEALKeyScheduler(keyType);
            var feistelFunction = new DEALFeistelFunction();

            int rounds = keyType switch
            {
                DEALKeyScheduler.KeyType.KEY_SIZE_128 => 6,
                DEALKeyScheduler.KeyType.KEY_SIZE_192 => 8,
                DEALKeyScheduler.KeyType.KEY_SIZE_256 => 8,
                _ => throw new ArgumentException("Invalid key type")
            };

            _feistelNetwork = new FeistelNetworkDEAL(keyScheduler, feistelFunction, rounds);
        }

        public int BlockSize => 16; // 128 бит для DEAL

        public int KeySize => _keyType switch
        {
            DEALKeyScheduler.KeyType.KEY_SIZE_128 => 16,
            DEALKeyScheduler.KeyType.KEY_SIZE_192 => 24,
            DEALKeyScheduler.KeyType.KEY_SIZE_256 => 32,
            _ => throw new InvalidOperationException("Unknown key type")
        };

        /// <summary>
        /// Устанавливает раундовые ключи для алгоритма.
        /// Метод проверяет соответствие длины ключа выбранному типу и делегирует генерацию ключей внутренней сети Фейстеля.
        /// </summary>
        /// <param name="key">Основной ключ шифрования.</param>
        /// <exception cref="ArgumentException">Вызывается, если длина ключа не соответствует <see cref="KeySize"/>.</exception>
        public void SetRoundKeys(byte[] key)
        {
            if (key.Length != KeySize)
                throw new ArgumentException($"DEAL key must be {KeySize} bytes for {_keyType}");

            _feistelNetwork.SetRoundKeys(key);
            _keysSet = true;
        }

        /// <summary>
        /// Шифрует один 128-битный блок данных.
        /// Является оберткой над методом <c>EncryptBlock</c> внутренней сети Фейстеля.
        /// </summary>
        /// <param name="block">Входной блок открытого текста (16 байт).</param>
        /// <returns>Зашифрованный блок данных (16 байт).</returns>
        /// <exception cref="InvalidOperationException">Вызывается, если раундовые ключи не были установлены.</exception>
        /// <exception cref="ArgumentException">Вызывается, если размер блока не равен <see cref="BlockSize"/>.</exception>
        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes for DEAL");

            return _feistelNetwork.EncryptBlock(block);
        }

        /// <summary>
        /// Дешифрует один 128-битный блок данных.
        /// Является оберткой над методом <c>DecryptBlock</c> внутренней сети Фейстеля.
        /// </summary>
        /// <param name="block">Входной блок шифротекста (16 байт).</param>
        /// <returns>Расшифрованный блок данных (16 байт).</returns>
        /// <exception cref="InvalidOperationException">Вызывается, если раундовые ключи не были установлены.</exception>
        /// <exception cref="ArgumentException">Вызывается, если размер блока не равен <see cref="BlockSize"/>.</exception>
        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes for DEAL");

            return _feistelNetwork.DecryptBlock(block);
        }
    }
}