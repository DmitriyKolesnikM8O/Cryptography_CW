namespace CryptoLib.DES.Interfaces
{
    /// <summary>
    /// Интерфейс для процедуры расширения ключа (генерации раундовых ключей)
    /// </summary>
    public interface IKeyScheduler
    {
        /// <summary>
        /// Выполняет расширение ключа - генерацию раундовых ключей из исходного ключа
        /// </summary>
        /// <param name="inputKey">Исходный ключ шифрования (массив байтов)</param>
        /// <returns>
        /// Массив раундовых ключей. Каждый раундовый ключ - массив байтов.
        /// Размер массива соответствует количеству раундов алгоритма.
        /// </returns>
        byte[][] ExpandKey(byte[] inputKey);
    }
}