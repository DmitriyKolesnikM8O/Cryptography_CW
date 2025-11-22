using CryptoLib.DES.Interfaces;

namespace CryptoLib.DES.Algorithms.DES
{
    /// <summary>
    /// Представляет собой основную реализацию симметричного блочного шифра DES (Data Encryption Standard).
    /// Этот класс выступает в роли фасада, который собирает и конфигурирует все необходимые компоненты DES:
    /// обобщенную сеть Фейстеля (<see cref="FeistelNetwork"/>), планировщик ключей (<see cref="DESKeyScheduler"/>)
    /// и раундовую функцию (<see cref="DESFeistelFunction"/>) со стандартными 16 раундами.
    /// </summary>
    public class DESAlgorithm : ISymmetricCipher
    {
        private readonly FeistelNetwork _feistelNetwork;
        private bool _keysSet = false;

        /// <summary>
        /// Инициализирует новый экземпляр алгоритма DES.
        /// В конструкторе создаются и связываются все составные части, необходимые для работы шифра.
        /// </summary>
        public DESAlgorithm()
        {

            var keyScheduler = new DESKeyScheduler();
            var feistelFunction = new DESFeistelFunction();
            _feistelNetwork = new FeistelNetwork(keyScheduler, feistelFunction, 16);
        }

        public int BlockSize => 8;
        public int KeySize => 8;

        /// <summary>
        /// Устанавливает раундовые ключи для алгоритма на основе предоставленного основного ключа.
        /// Этот метод должен быть вызван перед началом любой операции шифрования или дешифрования.
        /// </summary>
        /// <param name="key">Основной 64-битный ключ шифрования (8 байт).</param>
        /// <exception cref="ArgumentException">Вызывается, если длина ключа не равна <see cref="KeySize"/>.</exception>
        public void SetRoundKeys(byte[] key)
        {
            if (key.Length != KeySize)
                throw new ArgumentException($"DES key must be {KeySize} bytes");

            _feistelNetwork.SetRoundKeys(key);
            _keysSet = true;
        }

        /// <summary>
        /// Шифрует один 64-битный блок данных.
        /// Является оберткой над методом <c>EncryptBlock</c> внутренней сети Фейстеля.
        /// </summary>
        /// <param name="block">Входной блок открытого текста (8 байт).</param>
        /// <returns>Зашифрованный блок данных (8 байт).</returns>
        /// <exception cref="InvalidOperationException">Вызывается, если раундовые ключи не были установлены.</exception>
        /// <exception cref="ArgumentException">Вызывается, если размер блока не равен <see cref="BlockSize"/>.</exception>
        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");

            return _feistelNetwork.EncryptBlock(block);
        }

        /// <summary>
        /// Дешифрует один 64-битный блок данных.
        /// Является оберткой над методом <c>DecryptBlock</c> внутренней сети Фейстеля.
        /// </summary>
        /// <param name="block">Входной блок шифротекста (8 байт).</param>
        /// <returns>Расшифрованный блок данных (8 байт).</returns>
        /// <exception cref="InvalidOperationException">Вызывается, если раундовые ключи не были установлены.</exception>
        /// <exception cref="ArgumentException">Вызывается, если размер блока не равен <see cref="BlockSize"/>.</exception>
        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");

            return _feistelNetwork.DecryptBlock(block);
        }
    }
}