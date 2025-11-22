namespace CryptoLib.DES.Interfaces
{
    /// <summary>
    /// Интерфейс для выполнения шифрующего преобразования (раундовой функции)
    /// </summary>
    public interface IFeistelFunction
    {
        /// <summary>
        /// Выполняет шифрующее преобразование над входным блоком с использованием раундового ключа
        /// </summary>
        /// <param name="inputBlock">Входной блок данных (массив байтов)</param>
        /// <param name="roundKey">Раундовый ключ (массив байтов)</param>
        /// <returns>Выходной блок после преобразования (массив байтов)</returns>
        byte[] Execute(byte[] inputBlock, byte[] roundKey);
    }
}