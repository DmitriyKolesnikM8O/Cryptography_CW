using System.Numerics;

namespace CryptoLib.RSA.Interfaces
{
    /// <summary>
    /// Определяет контракт для stateless-сервиса, выполняющего базовые
    /// криптографические математические операции.
    /// </summary>
    public interface ICryptoMathService
    {
        /// <summary>
        /// Вычисляет Наибольший Общий Делитель (НОД) двух целых чисел
        /// при помощи алгоритма Евклида.
        /// </summary>
        /// <param name="a">Первое целое число.</param>
        /// <param name="b">Второе целое число.</param>
        /// <returns>Наибольший общий делитель чисел a и b.</returns>
        BigInteger Gcd(BigInteger a, BigInteger b);

        /// <summary>
        /// Выполняет расширенный алгоритм Евклида для нахождения НОД
        /// двух чисел, а также коэффициентов x и y, удовлетворяющих
        /// соотношению Безу: a*x + b*y = НОД(a, b).
        /// </summary>
        /// <param name="a">Первое целое число.</param>
        /// <param name="b">Второе целое число.</param>
        /// <returns>Кортеж, содержащий (НОД, x, y).</returns>
        (BigInteger Gcd, BigInteger X, BigInteger Y) ExtendedGcd(BigInteger a, BigInteger b);

        /// <summary>
        /// Выполняет операцию возведения в степень по модулю (value^exponent) mod modulus.
        /// Использует алгоритм бинарного возведения в степень для эффективности.
        /// </summary>
        /// <param name="value">Основание.</param>
        /// <param name="exponent">Показатель степени (должен быть неотрицательным).</param>
        /// <param name="modulus">Модуль (должен быть больше 0).</param>
        /// <returns>Результат операции (value^exponent) mod modulus.</returns>
        BigInteger ModPow(BigInteger value, BigInteger exponent, BigInteger modulus);

        /// <summary>
        /// Вычисляет символ Лежандра (a/p).
        /// </summary>
        /// <param name="a">Целое число.</param>
        /// <param name="p">Нечетное простое число.</param>
        /// <returns>1, -1 или 0.</returns>
        int LegendreSymbol(BigInteger a, BigInteger p);

        /// <summary>
        /// Вычисляет символ Якоби (a/n).
        /// </summary>
        /// <param name="a">Целое число.</param>
        /// <param name="n">Положительное нечетное целое число.</param>
        /// <returns>1, -1 или 0.</returns>
        int JacobiSymbol(BigInteger a, BigInteger n);
    }

    
}