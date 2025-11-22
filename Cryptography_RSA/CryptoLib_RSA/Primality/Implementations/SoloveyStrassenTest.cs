using System.Numerics;
using CryptoLib.RSA.Interfaces;

namespace CryptoLib.RSA.Primality.Implementations
{
    /// <summary>
    /// Реализация вероятностного теста простоты Соловея-Штрассена.
    /// </summary>
    public class SoloveyStrassenTest : PrimalityTestBase
    {
        public SoloveyStrassenTest(ICryptoMathService mathService) : base(mathService)
        {
        }

        /// <summary>
        /// Реализует одну итерацию теста Соловея-Штрассена.
        /// </summary>
        /// <param name="number">Тестируемое число n.</param>
        /// <returns>false, если n точно составное. true, если n может быть простым.</returns>
        protected override bool PerformSingleIteration(BigInteger number)
        {
            
            var witness = GenerateRandomBigInteger(2, number - 2);
            var jacobiSymbol = _mathService.JacobiSymbol(witness, number);

            // Если символ Якоби равен 0, то НОД(a, n) > 1, и число точно составное.
            if (jacobiSymbol == 0)
            {
                return false;
            }

            // Вычисляем левую часть сравнения: a^((n-1)/2) mod n.
            var exponent = (number - 1) / 2;
            var modPowResult = _mathService.ModPow(witness, exponent, number);

            // Приводим символ Якоби к каноническому виду для сравнения.
            // Символ Якоби может быть -1, а результат ModPow всегда положителен.
            // В кольце вычетов по модулю n, -1 эквивалентно n - 1.
            BigInteger canonicalJacobi;
            if (jacobiSymbol == -1)
            {
                canonicalJacobi = number - 1;
            }
            else
            {
                canonicalJacobi = jacobiSymbol;
            }
            
            // Проверяем критерий Эйлера. Если он не выполняется,
            // число 'number' гарантированно является составным.
            if (modPowResult != canonicalJacobi)
            {
                return false;
            }
            return true;
        }
    }
}