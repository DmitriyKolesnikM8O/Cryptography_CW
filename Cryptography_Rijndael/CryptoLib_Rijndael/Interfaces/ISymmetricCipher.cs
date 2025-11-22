namespace CryptoLib.Rijndael.Interfaces
{
    /// <summary>
    /// Интерфейс для выполнения шифрования и дешифрования симметричным алгоритмом
    /// </summary>
    public interface ISymmetricCipher
    {
        /// <summary>
        /// Настраивает раундовые ключи для алгоритма
        /// </summary>
        /// <param name="key">Ключ шифрования/дешифрования (массив байтов)</param>
        void SetRoundKeys(byte[] key);

        /// <summary>
        /// Выполняет шифрование одного блока данных
        /// </summary>
        /// <param name="block">Блок данных для шифрования (массив байтов)</param>
        /// <returns>Зашифрованный блок данных (массив байтов)</returns>
        byte[] EncryptBlock(byte[] block);

        /// <summary>
        /// Выполняет дешифрование одного блока данных
        /// </summary>
        /// <param name="block">Блок данных для дешифрования (массив байтов)</param>
        /// <returns>Расшифрованный блок данных (массив байтов)</returns>
        byte[] DecryptBlock(byte[] block);

        /// <summary>
        /// Получает размер блока алгоритма в байтах
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Получает размер ключа алгоритма в байтах
        /// </summary>
        int KeySize { get; }
    }
}