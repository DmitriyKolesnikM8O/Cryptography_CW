namespace CryptoLib.Rijndael.Algorithms.Rijndael.Enums
{
    /// <summary>
    /// Определяет поддерживаемые размеры ключа для алгоритма Rijndael в битах.
    /// </summary>
    public enum KeySize
    {
        /// <summary>
        /// Размер ключа 128 бит (16 байт).
        /// </summary>
        K128 = 128,

        /// <summary>
        /// Размер ключа 192 бита (24 байта).
        /// </summary>
        K192 = 192,

        /// <summary>
        /// Размер ключа 256 бит (32 байта).
        /// </summary>
        K256 = 256
    }
}