using System.Numerics;

namespace CryptoLib.RSA.Interfaces
{
    /// <summary>
    /// Предоставляет интерфейс для вероятностного теста простоты.
    /// </summary>
    public interface IPrimalityTest
    {
        /// <summary>
        /// Проверяет, является ли число вероятно простым.
        /// </summary>
        /// <param name="number">Тестируемое целое число.</param>
        /// <param name="probability">
        /// Минимальная требуемая вероятность того, что число простое,
        /// в диапазоне [0.5, 1).
        /// </param>
        /// <returns>
        /// true, если число вероятно простое с заданной вероятностью.
        /// false, если число точно составное.
        /// </returns>
        bool IsPrime(BigInteger number, double probability);
    }
}