using System.Numerics;
using CryptoLib.RSA.Interfaces;
using System.Security.Cryptography;

namespace CryptoLib.RSA.Primality.Implementations
{
    /// <summary>
    /// Реализация вероятностного теста простоты Ферма.
    /// Данный тест не является надежным и может давать ложноположительные
    /// результаты для чисел Кармайкла.
    /// </summary>
    public class FermatTest : PrimalityTestBase
    {
        // Используем один статический экземпляр Random для всего класса
        private static readonly Random _random = new Random();

        public FermatTest(ICryptoMathService mathService) : base(mathService)
        {
        }

        /// <summary>
        /// Реализует одну итерацию теста Ферма.
        /// </summary>
        /// <param name="number">Тестируемое число n.</param>
        /// <returns>false, если n точно составное. true, если n может быть простым.</returns>
        protected override bool PerformSingleIteration(BigInteger number)
        {
            // Выбираем случайное число 'a' (свидетеля) в диапазоне [2, n - 2].
            // Мы избегаем 1 и n-1, так как они не являются сильными свидетелями.
            BigInteger witness = GenerateRandomBigInteger(2, number - 2);


            // Вычисляем a^(n-1) mod n с помощью нашего сервиса.
            BigInteger result = _mathService.ModPow(witness, number - 1, number);

            // Согласно Малой теореме Ферма, если результат не равен 1,
            // то число 'number' гарантированно является составным.
            if (result != 1)
            {
                return false;
            }

            return true;
        }

    }
}