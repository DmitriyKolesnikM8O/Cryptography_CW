using System.Numerics;
using System.Security.Cryptography;
using CryptoLib.RSA.Interfaces;

namespace CryptoLib.RSA.Primality
{
    /// <summary>
    /// Базовый абстрактный класс для вероятностных тестов простоты,
    /// реализующий поведенческий паттерн "Шаблонный метод".
    /// </summary>
    public abstract class PrimalityTestBase : IPrimalityTest
    {
        protected readonly ICryptoMathService _mathService;

        protected PrimalityTestBase(ICryptoMathService mathService)
        {
            _mathService = mathService ?? throw new ArgumentNullException(nameof(mathService));
        }

        /// <summary>
        /// скелет алгоритма проверки на простоту.
        /// </summary>
        public bool IsPrime(BigInteger number, double probability)
        {
            if (number < 2) return false;
            if (number == 2 || number == 3) return true;
            if (number % 2 == 0) return false;

            if (probability < 0.5 || probability >= 1)
                throw new ArgumentOutOfRangeException(nameof(probability), "Вероятность должна быть в диапазоне [0.5, 1).");

            int k = CalculateIterations(probability);

            for (int i = 0; i < k; i++)
            {

                if (!PerformSingleIteration(number))
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Метод, который должны реализовать дочерние классы.
        /// Определяет логику одной итерации конкретного теста.
        /// </summary>
        /// <param name="number">Тестируемое число.</param>
        /// <returns>false, если найден свидетель того, что число составное. true в ином случае.</returns>
        protected abstract bool PerformSingleIteration(BigInteger number);

        /// <summary>
        /// Вычисляет количество итераций 'k', необходимое для достижения
        /// вероятности 'p'. Для большинства тестов (Соловей-Штрассен, Миллер-Рабин)
        /// вероятность ошибки в одном раунде <= 1/2.
        /// Вероятность ошибки после 'k' раундов <= (1/2)^k.
        /// Мы хотим, чтобы 1 - (1/2)^k >= p, откуда (1/2)^k <= 1-p.
        /// k >= -log2(1-p).
        /// </summary>
        private int CalculateIterations(double probability)
        {
            return (int)Math.Ceiling(-Math.Log2(1 - probability));

            // return 1; Это если нужно показать, как Ферма и Соловей-Разбойник умирают под 561 и другими числами Кармайкла
        }
        
        /// <summary>
        /// Вспомогательный метод для генерации случайного BigInteger в заданном диапазоне [minValue, maxValue].
        /// Эта реализация использует метод отбора (rejection sampling) для обеспечения равномерного распределения.
        /// </summary>
        public static BigInteger GenerateRandomBigInteger(BigInteger minValue, BigInteger maxValue)
        {
            if (minValue > maxValue)
                throw new ArgumentException("minValue не может быть больше maxValue");

            var range = maxValue - minValue;
            var bytes = range.ToByteArray();
            BigInteger result;

            using (var rng = RandomNumberGenerator.Create())
            {
                do
                {
                    rng.GetBytes(bytes);
                    bytes[bytes.Length - 1] &= 0x7F;
                    result = new BigInteger(bytes);
                } while (result > range);
            }

            return result + minValue;
        }
    }
}