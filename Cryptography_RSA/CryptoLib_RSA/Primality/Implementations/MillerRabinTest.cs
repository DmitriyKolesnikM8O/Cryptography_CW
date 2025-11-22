using System.Numerics;
using CryptoLib.RSA.Interfaces;

namespace CryptoLib.RSA.Primality.Implementations
{
    /// <summary>
    /// Реализация вероятностного теста простоты Миллера-Рабина.
    /// </summary>
    public class MillerRabinTest : PrimalityTestBase
    {
        public MillerRabinTest(ICryptoMathService mathService) : base(mathService)
        {
        }

        /// <summary>
        /// Реализует одну итерацию теста Миллера-Рабина.
        /// </summary>
        /// <param name="number">Тестируемое число n.</param>
        /// <returns>false, если n точно составное. true, если n может быть простым.</returns>
        protected override bool PerformSingleIteration(BigInteger number)
        {
            // Представляем (n - 1) в виде 2^s * d, где d - нечетное.
            BigInteger d = number - 1;
            int s = 0;
            while ((d & 1) == 0) // // d % 2 == 0
            {
                d >>= 1;
                s++;
            }

            // Выбираем случайного свидетеля 'a' в диапазоне [2, n - 2].
            var witness = GenerateRandomBigInteger(2, number - 2);

            // Вычисляем x = a^d mod n.
            var x = _mathService.ModPow(witness, d, number);

            // Если x = 1 или x = n - 1, то n может быть простым.
            if (x == 1 || x == number - 1)
            {
                return true;
            }

            // Повторяем s-1 раз: x = x^2 mod n.
            for (int r = 1; r < s; r++)
            {
                x = _mathService.ModPow(x, 2, number);

                // Если x = 1, то предыдущее значение было нетривиальным корнем из 1.
                // Число точно составное.
                if (x == 1) return false;

                // Если x = n - 1, то n проходит проверку для данного свидетеля.
                if (x == number - 1) return true;
            }

            return false;
        }
    }
}