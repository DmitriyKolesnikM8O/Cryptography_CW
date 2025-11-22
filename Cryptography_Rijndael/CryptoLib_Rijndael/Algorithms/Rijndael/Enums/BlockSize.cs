namespace CryptoLib.Rijndael.Algorithms.Rijndael.Enums
{
    /// <summary>
    /// Определяет поддерживаемые размеры блока для алгоритма Rijndael в битах.
    /// </summary>
    public enum BlockSize
    {
        /// <summary>
        /// Размер блока 128 бит (16 байт). Стандарт для AES.
        /// </summary>
        B128 = 128,

        /// <summary>
        /// Размер блока 192 бита (24 байта).
        /// </summary>
        B192 = 192,

        /// <summary>
        /// Размер блока 256 бит (32 байта).
        /// </summary>
        B256 = 256
    }
}