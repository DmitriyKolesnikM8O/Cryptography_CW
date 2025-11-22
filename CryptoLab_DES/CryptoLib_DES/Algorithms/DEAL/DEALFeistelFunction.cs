using CryptoLib.DES.Algorithms.DES;
using CryptoLib.DES.Interfaces;

namespace CryptoLib.DES.Algorithms.DEAL
{
    /// <summary>
    /// Реализует раундовую функцию F для алгоритма DEAL.
    /// Ключевой особенностью DEAL является использование полноценного алгоритма DES в качестве своей раундовой функции.
    /// Этот класс инкапсулирует вызов DES, обеспечивая при этом потокобезопасность.
    /// </summary>
    public class DEALFeistelFunction : IFeistelFunction
    {
        /// <summary>
        /// Обеспечивает потокобезопасность, предоставляя каждому потоку свой собственный экземпляр DESAlgorithm.
        /// Это необходимо для предотвращения конфликтов состояний (например, раундовых ключей) при параллельном выполнении.
        /// </summary>
        private readonly ThreadLocal<DESAlgorithm> _threadLocalDes;

        /// <summary>
        /// Инициализирует новый экземпляр класса DEALFeistelFunction.
        /// Создает фабрику для ленивой инициализации экземпляров DESAlgorithm для каждого потока.
        /// </summary>
        public DEALFeistelFunction()
        {
            _threadLocalDes = new ThreadLocal<DESAlgorithm>(() => new DESAlgorithm());
        }

        /// <summary>
        /// Выполняет преобразование раундовой функции DEAL над входным блоком.
        /// В качестве преобразования используется шифрование алгоритмом DES.
        /// </summary>
        /// <param name="inputBlock">Входной 64-битный (8-байтный) блок данных. В контексте сети Фейстеля DEAL - это правая половина блока.</param>
        /// <param name="roundKey">Раундовый ключ для данного раунда. Для DEAL это валидный 64-битный ключ DES.</param>
        /// <returns>Выходной 64-битный (8-байтный) блок данных после шифрования DES.</returns>
        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {

            DESAlgorithm des = _threadLocalDes.Value!;

            des.SetRoundKeys(roundKey);
            return des.EncryptBlock(inputBlock);
        }
    }
}